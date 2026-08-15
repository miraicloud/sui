// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Signer-owned randomness DKG state and threshold-share operations.
//!
//! Private DKG material is never returned by this module. The validator receives only the
//! public transcript, the local public contribution and partial signatures for a typed round.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use fastcrypto::{
    encoding::{Encoding, Hex},
    error::FastCryptoError,
    groups::bls12381,
    hash::{Blake2b256, HashFunction},
    serde_helpers::ToFromByteArray,
    traits::{KeyPair as _, ToFromBytes as _},
};
use fastcrypto_tbls::{
    dkg_v1,
    nodes::{Nodes, PartyId},
    tbls::ThresholdBls,
    types::ThresholdBls12381MinSig,
};
use rand::{SeedableRng, rngs::OsRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sui_types::{
    crypto::{AuthorityKeyPair, RandomnessPartialSignature, RandomnessRound},
    messages_consensus::{VersionedDkgConfirmation, VersionedDkgMessage},
};
use thiserror::Error;

use crate::{config::ensure_private_file, protocol::ChainId};

type PkG = bls12381::G2Element;
type EncG = bls12381::G2Element;

const STATE_VERSION: u16 = 1;
const CHECKSUM_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgSessionStatus {
    pub epoch: u64,
    pub party_id: PartyId,
    pub threshold: u16,
    pub processed_messages: usize,
    pub confirmations: usize,
    pub merged: bool,
    pub shares_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgMergeResult {
    pub confirmation: Vec<u8>,
    pub used_messages: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgCompleteResult {
    pub public_output: Vec<u8>,
    pub threshold: u16,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistedRandomnessState {
    version: u16,
    chain_id: ChainId,
    sessions: BTreeMap<u64, DkgSession>,
}

#[derive(Clone, Serialize, Deserialize)]
struct DkgSession {
    nodes: Nodes<EncG>,
    threshold: u16,
    party: dkg_v1::Party<PkG, EncG>,
    local_message: Option<VersionedDkgMessage>,
    processed_messages: BTreeMap<PartyId, dkg_v1::ProcessedMessage<PkG, EncG>>,
    used_messages: Option<dkg_v1::UsedProcessedMessages<PkG, EncG>>,
    local_confirmation: Option<VersionedDkgConfirmation>,
    confirmations: BTreeMap<PartyId, VersionedDkgConfirmation>,
    output: Option<dkg_v1::Output<PkG, EncG>>,
}

pub trait RandomnessStateStore: Send + Sync + 'static {
    fn load(&self) -> Result<Option<PersistedRandomnessState>, RandomnessError>;
    fn save(&self, state: &PersistedRandomnessState) -> Result<(), RandomnessError>;
}

pub struct FileRandomnessStateStore {
    path: PathBuf,
}

impl FileRandomnessStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl RandomnessStateStore for FileRandomnessStateStore {
    fn load(&self) -> Result<Option<PersistedRandomnessState>, RandomnessError> {
        if !self.path.exists() {
            return Ok(None);
        }
        ensure_private_file(&self.path).map_err(RandomnessError::InvalidStateFile)?;
        let mut bytes = Vec::new();
        File::open(&self.path)?.read_to_end(&mut bytes)?;
        if bytes.len() < CHECKSUM_BYTES {
            return Err(RandomnessError::CorruptState(self.path.clone()));
        }
        let checksum_offset = bytes.len() - CHECKSUM_BYTES;
        let expected: [u8; CHECKSUM_BYTES] = bytes[checksum_offset..]
            .try_into()
            .map_err(|_| RandomnessError::CorruptState(self.path.clone()))?;
        let payload = &bytes[..checksum_offset];
        let actual: [u8; CHECKSUM_BYTES] = Blake2b256::digest(payload).into();
        if actual != expected {
            return Err(RandomnessError::CorruptState(self.path.clone()));
        }
        let state = bcs::from_bytes(payload).map_err(RandomnessError::Deserialize)?;
        Ok(Some(state))
    }

    fn save(&self, state: &PersistedRandomnessState) -> Result<(), RandomnessError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| RandomnessError::InvalidStatePath(self.path.clone()))?;
        let payload = bcs::to_bytes(state).map_err(RandomnessError::Serialize)?;
        let checksum: [u8; CHECKSUM_BYTES] = Blake2b256::digest(&payload).into();
        let temporary = temporary_path(&self.path);

        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&payload)?;
            file.write_all(&checksum)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let suffix: u64 = rand::random();
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "randomness-state".into());
    name.push(format!(".tmp-{}-{suffix:016x}", std::process::id()));
    path.with_file_name(name)
}

pub struct RandomnessSessionManager<S: RandomnessStateStore> {
    store: S,
    protocol_key: AuthorityKeyPair,
    state: Mutex<PersistedRandomnessState>,
}

impl<S: RandomnessStateStore> RandomnessSessionManager<S> {
    pub fn open(
        store: S,
        chain_id: ChainId,
        protocol_key: AuthorityKeyPair,
    ) -> Result<Self, RandomnessError> {
        let state = store.load()?.unwrap_or(PersistedRandomnessState {
            version: STATE_VERSION,
            chain_id,
            sessions: BTreeMap::new(),
        });
        if state.version != STATE_VERSION {
            return Err(RandomnessError::UnsupportedStateVersion(state.version));
        }
        if state.chain_id != chain_id {
            return Err(RandomnessError::ChainMismatch);
        }
        Ok(Self {
            store,
            protocol_key,
            state: Mutex::new(state),
        })
    }

    pub fn initialize(
        &self,
        epoch: u64,
        nodes_bytes: &[u8],
        threshold: u16,
    ) -> Result<DkgSessionStatus, RandomnessError> {
        let nodes: Nodes<EncG> =
            bcs::from_bytes(nodes_bytes).map_err(RandomnessError::Deserialize)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RandomnessError::LockPoisoned)?;
        if let Some(session) = state.sessions.get(&epoch) {
            if session.nodes != nodes || session.threshold != threshold {
                return Err(RandomnessError::SessionMismatch(epoch));
            }
            return Ok(session.status(epoch));
        }

        let randomness_private_key = bls12381::Scalar::from_byte_array(
            self.protocol_key
                .copy()
                .private()
                .as_bytes()
                .try_into()
                .map_err(|_| RandomnessError::InvalidProtocolKey)?,
        )
        .map_err(|_| RandomnessError::InvalidProtocolKey)?;
        let random_oracle = fastcrypto_tbls::random_oracle::RandomOracle::new(&format!(
            "dkg {} {}",
            Hex::encode(state.chain_id),
            epoch
        ));
        let party = dkg_v1::Party::new(
            fastcrypto_tbls::ecies_v1::PrivateKey::from(randomness_private_key),
            nodes.clone(),
            threshold,
            random_oracle,
            &mut rand::thread_rng(),
        )?;
        let session = DkgSession {
            nodes,
            threshold,
            party,
            local_message: None,
            processed_messages: BTreeMap::new(),
            used_messages: None,
            local_confirmation: None,
            confirmations: BTreeMap::new(),
            output: None,
        };
        let status = session.status(epoch);
        let mut candidate = state.clone();
        candidate.sessions.insert(epoch, session);
        self.store.save(&candidate)?;
        *state = candidate;
        Ok(status)
    }

    pub fn status(&self, epoch: u64) -> Result<DkgSessionStatus, RandomnessError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RandomnessError::LockPoisoned)?;
        Ok(state
            .sessions
            .get(&epoch)
            .ok_or(RandomnessError::UnknownEpoch(epoch))?
            .status(epoch))
    }

    pub fn create_message(&self, epoch: u64) -> Result<Vec<u8>, RandomnessError> {
        self.mutate_session(epoch, |session| {
            if let Some(message) = &session.local_message {
                return bcs::to_bytes(message).map_err(RandomnessError::Serialize);
            }
            let message = VersionedDkgMessage::create(1, &session.party)?;
            let bytes = bcs::to_bytes(&message).map_err(RandomnessError::Serialize)?;
            session.local_message = Some(message);
            Ok(bytes)
        })
    }

    pub fn process_message(
        &self,
        epoch: u64,
        message_bytes: &[u8],
    ) -> Result<PartyId, RandomnessError> {
        let message: VersionedDkgMessage =
            bcs::from_bytes(message_bytes).map_err(RandomnessError::Deserialize)?;
        if !message.is_valid_version(1) {
            return Err(RandomnessError::UnsupportedDkgVersion);
        }
        let sender = message.sender();
        self.mutate_session(epoch, |session| {
            if let Some(previous) = session.processed_messages.get(&sender) {
                if previous.message != message.clone().unwrap_v1() {
                    return Err(RandomnessError::ConflictingMessage(sender));
                }
                return Ok(sender);
            }
            if session.used_messages.is_some() {
                return Err(RandomnessError::SessionSealed(epoch));
            }
            let processed = session
                .party
                .process_message(message.unwrap_v1(), &mut rand::thread_rng())?;
            session.processed_messages.insert(sender, processed);
            Ok(sender)
        })
    }

    pub fn try_merge(&self, epoch: u64) -> Result<DkgMergeResult, RandomnessError> {
        self.mutate_session(epoch, |session| {
            if let (Some(confirmation), Some(used_messages)) =
                (&session.local_confirmation, &session.used_messages)
            {
                return merge_result(confirmation, used_messages);
            }
            let messages = session
                .processed_messages
                .values()
                .cloned()
                .collect::<Vec<_>>();
            let (confirmation, used_messages) = session.party.merge(&messages)?;
            let confirmation = VersionedDkgConfirmation::V1(confirmation);
            let result = merge_result(&confirmation, &used_messages)?;
            session.local_confirmation = Some(confirmation);
            session.used_messages = Some(used_messages);
            Ok(result)
        })
    }

    pub fn add_confirmation(
        &self,
        epoch: u64,
        confirmation_bytes: &[u8],
    ) -> Result<PartyId, RandomnessError> {
        let confirmation: VersionedDkgConfirmation =
            bcs::from_bytes(confirmation_bytes).map_err(RandomnessError::Deserialize)?;
        if !confirmation.is_valid_version(1) {
            return Err(RandomnessError::UnsupportedDkgVersion);
        }
        let sender = confirmation.sender();
        self.mutate_session(epoch, |session| {
            if let Some(previous) = session.confirmations.get(&sender) {
                if previous != &confirmation {
                    return Err(RandomnessError::ConflictingConfirmation(sender));
                }
                return Ok(sender);
            }
            if session.output.is_some() {
                return Err(RandomnessError::SessionSealed(epoch));
            }
            session.confirmations.insert(sender, confirmation);
            Ok(sender)
        })
    }

    pub fn try_complete(&self, epoch: u64) -> Result<DkgCompleteResult, RandomnessError> {
        self.mutate_session(epoch, |session| {
            if let Some(output) = &session.output {
                return complete_result(output, session.threshold);
            }
            let used_messages = session
                .used_messages
                .as_ref()
                .ok_or(RandomnessError::NotMerged(epoch))?;
            let confirmations = session
                .confirmations
                .values()
                .map(|confirmation| {
                    confirmation
                        .as_v1()
                        .cloned()
                        .ok_or(RandomnessError::UnsupportedDkgVersion)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let rng = &mut StdRng::from_rng(OsRng)
                .map_err(|error| RandomnessError::Rng(error.to_string()))?;
            let output = session.party.complete(used_messages, &confirmations, rng)?;
            let result = complete_result(&output, session.threshold)?;
            session.output = Some(output);
            Ok(result)
        })
    }

    pub fn partial_sign(
        &self,
        epoch: u64,
        round: RandomnessRound,
    ) -> Result<Vec<u8>, RandomnessError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RandomnessError::LockPoisoned)?;
        let session = state
            .sessions
            .get(&epoch)
            .ok_or(RandomnessError::UnknownEpoch(epoch))?;
        let shares = session
            .output
            .as_ref()
            .and_then(|output| output.shares.as_ref())
            .filter(|shares| !shares.is_empty())
            .ok_or(RandomnessError::SharesUnavailable(epoch))?;
        let signatures: Vec<RandomnessPartialSignature> =
            ThresholdBls12381MinSig::partial_sign_batch(shares.iter(), &round.signature_message());
        bcs::to_bytes(&signatures).map_err(RandomnessError::Serialize)
    }

    fn mutate_session<T>(
        &self,
        epoch: u64,
        mutate: impl FnOnce(&mut DkgSession) -> Result<T, RandomnessError>,
    ) -> Result<T, RandomnessError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RandomnessError::LockPoisoned)?;
        let mut candidate = state.clone();
        let session = candidate
            .sessions
            .get_mut(&epoch)
            .ok_or(RandomnessError::UnknownEpoch(epoch))?;
        let result = mutate(session)?;
        self.store.save(&candidate)?;
        *state = candidate;
        Ok(result)
    }
}

impl DkgSession {
    fn status(&self, epoch: u64) -> DkgSessionStatus {
        DkgSessionStatus {
            epoch,
            party_id: self.party.id,
            threshold: self.threshold,
            processed_messages: self.processed_messages.len(),
            confirmations: self.confirmations.len(),
            merged: self.used_messages.is_some(),
            shares_ready: self
                .output
                .as_ref()
                .and_then(|output| output.shares.as_ref())
                .is_some_and(|shares| !shares.is_empty()),
        }
    }
}

fn merge_result(
    confirmation: &VersionedDkgConfirmation,
    used_messages: &dkg_v1::UsedProcessedMessages<PkG, EncG>,
) -> Result<DkgMergeResult, RandomnessError> {
    Ok(DkgMergeResult {
        confirmation: bcs::to_bytes(confirmation).map_err(RandomnessError::Serialize)?,
        used_messages: used_messages
            .0
            .iter()
            .map(|processed| {
                bcs::to_bytes(&VersionedDkgMessage::V1(processed.message.clone()))
                    .map_err(RandomnessError::Serialize)
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn complete_result(
    output: &dkg_v1::Output<PkG, EncG>,
    threshold: u16,
) -> Result<DkgCompleteResult, RandomnessError> {
    let public_output = dkg_v1::Output {
        nodes: output.nodes.clone(),
        vss_pk: output.vss_pk.clone(),
        shares: None,
    };
    Ok(DkgCompleteResult {
        public_output: bcs::to_bytes(&public_output).map_err(RandomnessError::Serialize)?,
        threshold,
    })
}

#[derive(Debug, Error)]
pub enum RandomnessError {
    #[error("randomness state belongs to another chain")]
    ChainMismatch,
    #[error("invalid protocol key")]
    InvalidProtocolKey,
    #[error("randomness session for epoch {0} is unknown")]
    UnknownEpoch(u64),
    #[error("randomness session parameters conflict for epoch {0}")]
    SessionMismatch(u64),
    #[error("randomness session for epoch {0} is sealed")]
    SessionSealed(u64),
    #[error("randomness session for epoch {0} has not merged messages")]
    NotMerged(u64),
    #[error("randomness shares are unavailable for epoch {0}")]
    SharesUnavailable(u64),
    #[error("dealer message from party {0} conflicts with durable state")]
    ConflictingMessage(PartyId),
    #[error("confirmation from party {0} conflicts with durable state")]
    ConflictingConfirmation(PartyId),
    #[error("unsupported DKG version")]
    UnsupportedDkgVersion,
    #[error("unsupported randomness state version {0}")]
    UnsupportedStateVersion(u16),
    #[error("randomness state lock poisoned")]
    LockPoisoned,
    #[error("randomness state path is invalid: {0}")]
    InvalidStatePath(PathBuf),
    #[error("randomness state is corrupt: {0}")]
    CorruptState(PathBuf),
    #[error("randomness state file is invalid: {0}")]
    InvalidStateFile(anyhow::Error),
    #[error("failed to serialize randomness state: {0}")]
    Serialize(bcs::Error),
    #[error("failed to deserialize randomness state: {0}")]
    Deserialize(bcs::Error),
    #[error("failed to initialize secure randomness: {0}")]
    Rng(String),
    #[error(transparent)]
    Crypto(#[from] FastCryptoError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fastcrypto_tbls::{
        ecies_v1, nodes::Node, tbls::ThresholdBls as _, types::ThresholdBls12381MinSig,
    };
    use sui_types::crypto::get_authority_key_pair;
    use tempfile::TempDir;

    use super::*;

    #[derive(Clone, Default)]
    struct MemoryStore(Arc<Mutex<Option<PersistedRandomnessState>>>);

    impl RandomnessStateStore for MemoryStore {
        fn load(&self) -> Result<Option<PersistedRandomnessState>, RandomnessError> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn save(&self, state: &PersistedRandomnessState) -> Result<(), RandomnessError> {
            *self.0.lock().unwrap() = Some(state.clone());
            Ok(())
        }
    }

    #[test]
    fn completes_dkg_without_exporting_shares_and_partial_signs() {
        let chain_id = [7; 32];
        let keys = (0..4)
            .map(|_| get_authority_key_pair().1)
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            keys.iter()
                .enumerate()
                .map(|(id, key)| {
                    let public = bls12381::G2Element::from_byte_array(
                        key.public().as_bytes().try_into().unwrap(),
                    )
                    .unwrap();
                    Node {
                        id: id.try_into().unwrap(),
                        pk: ecies_v1::PublicKey::from(public),
                        weight: 1,
                    }
                })
                .collect(),
        )
        .unwrap();
        let nodes_bytes = bcs::to_bytes(&nodes).unwrap();
        let managers = keys
            .iter()
            .map(|key| {
                RandomnessSessionManager::open(MemoryStore::default(), chain_id, key.copy())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for manager in &managers {
            manager.initialize(9, &nodes_bytes, 2).unwrap();
        }
        let messages = managers
            .iter()
            .map(|manager| manager.create_message(9).unwrap())
            .collect::<Vec<_>>();
        for manager in &managers {
            for message in &messages {
                manager.process_message(9, message).unwrap();
            }
        }
        let confirmations = managers
            .iter()
            .map(|manager| manager.try_merge(9).unwrap().confirmation)
            .collect::<Vec<_>>();
        for manager in &managers {
            for confirmation in &confirmations {
                manager.add_confirmation(9, confirmation).unwrap();
            }
        }

        let mut partials = Vec::new();
        let mut public_output = None;
        for manager in &managers {
            let complete = manager.try_complete(9).unwrap();
            let output: dkg_v1::Output<PkG, EncG> =
                bcs::from_bytes(&complete.public_output).unwrap();
            assert!(output.shares.is_none());
            public_output.get_or_insert(output);
            let encoded = manager.partial_sign(9, RandomnessRound(3)).unwrap();
            partials.extend(bcs::from_bytes::<Vec<RandomnessPartialSignature>>(&encoded).unwrap());
        }
        let output = public_output.unwrap();
        let signature = ThresholdBls12381MinSig::aggregate(2, partials.iter()).unwrap();
        ThresholdBls12381MinSig::verify(
            &output.vss_pk.c0(),
            &RandomnessRound(3).signature_message(),
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn file_store_restarts_with_the_same_dealer_message() {
        let directory = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (_, key) = get_authority_key_pair();
        let public =
            bls12381::G2Element::from_byte_array(key.public().as_bytes().try_into().unwrap())
                .unwrap();
        let nodes = Nodes::new(vec![Node {
            id: 0,
            pk: ecies_v1::PublicKey::from(public),
            weight: 2,
        }])
        .unwrap();
        let path = directory.path().join("randomness.bcs");
        let manager = RandomnessSessionManager::open(
            FileRandomnessStateStore::new(&path),
            [8; 32],
            key.copy(),
        )
        .unwrap();
        manager
            .initialize(11, &bcs::to_bytes(&nodes).unwrap(), 1)
            .unwrap();
        let first = manager.create_message(11).unwrap();
        drop(manager);

        let manager =
            RandomnessSessionManager::open(FileRandomnessStateStore::new(path), [8; 32], key)
                .unwrap();
        assert_eq!(manager.create_message(11).unwrap(), first);
    }

    #[test]
    fn conflicts_fail_closed() {
        let keys = (0..4)
            .map(|_| get_authority_key_pair().1)
            .collect::<Vec<_>>();
        let nodes = Nodes::new(
            keys.iter()
                .enumerate()
                .map(|(id, key)| {
                    let public = bls12381::G2Element::from_byte_array(
                        key.public().as_bytes().try_into().unwrap(),
                    )
                    .unwrap();
                    Node {
                        id: id.try_into().unwrap(),
                        pk: ecies_v1::PublicKey::from(public),
                        weight: 1,
                    }
                })
                .collect(),
        )
        .unwrap();
        let manager =
            RandomnessSessionManager::open(MemoryStore::default(), [9; 32], keys[0].copy())
                .unwrap();
        let other = RandomnessSessionManager::open(MemoryStore::default(), [9; 32], keys[1].copy())
            .unwrap();
        let encoded_nodes = bcs::to_bytes(&nodes).unwrap();
        manager.initialize(1, &encoded_nodes, 2).unwrap();
        other.initialize(1, &encoded_nodes, 2).unwrap();
        let message = other.create_message(1).unwrap();
        manager.process_message(1, &message).unwrap();

        let conflicting_other =
            RandomnessSessionManager::open(MemoryStore::default(), [9; 32], keys[1].copy())
                .unwrap();
        conflicting_other.initialize(1, &encoded_nodes, 2).unwrap();
        let conflicting = conflicting_other.create_message(1).unwrap();
        assert!(matches!(
            manager.process_message(1, &conflicting),
            Err(RandomnessError::ConflictingMessage(1))
        ));
        assert!(matches!(
            manager.initialize(1, &encoded_nodes, 1),
            Err(RandomnessError::SessionMismatch(1))
        ));
    }
}
