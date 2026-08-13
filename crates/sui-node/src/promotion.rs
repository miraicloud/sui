// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed authorization for planned, next-epoch validator promotion.
//!
//! The on-chain committee is the only mechanism that changes a node's role. This module adds a
//! local authorization boundary: an observer whose protocol key appears in a later committee may
//! start validator components only when a durable promotion manifest binds that exact committee
//! entry to finalized on-chain evidence.

use anyhow::{Context, Result, bail, ensure};
use fastcrypto::{
    encoding::{Encoding, Hex},
    traits::{KeyPair, ToFromBytes},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use sui_config::{
    NodeConfig,
    node::{
        VALIDATOR_PROMOTION_MANIFEST_VERSION, ValidatorPromotionManifest, ValidatorPromotionTarget,
    },
};
use sui_core::{authority::AuthorityState, checkpoints::CheckpointStore};
use sui_types::{
    SUI_SYSTEM_PACKAGE_ID,
    base_types::EpochId,
    crypto::{
        AuthorityPublicKey, AuthoritySignature, NetworkPublicKey, verify_proof_of_possession,
    },
    digests::ChainIdentifier,
    effects::TransactionEffectsAPI,
    sui_system_state::epoch_start_sui_system_state::EpochStartValidatorInfoV1,
    transaction::{
        Argument, CallArg, Command, TransactionData, TransactionDataAPI, TransactionExpiration,
        TransactionKind,
    },
};

const STATE_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ValidatorPromotionPhase {
    Prepared,
    CommitteeObserved,
    Active,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ValidatorPromotionState {
    version: u64,
    plan_id: String,
    manifest_digest: String,
    phase: ValidatorPromotionPhase,
    observed_epoch: Option<EpochId>,
}

impl ValidatorPromotionState {
    fn prepared(manifest: &ValidatorPromotionManifest) -> Result<Self> {
        Ok(Self {
            version: STATE_VERSION,
            plan_id: manifest.plan_id.clone(),
            manifest_digest: manifest.digest()?,
            phase: ValidatorPromotionPhase::Prepared,
            observed_epoch: None,
        })
    }

    fn validate_manifest(&self, manifest: &ValidatorPromotionManifest) -> Result<()> {
        ensure!(
            self.version == STATE_VERSION,
            "unsupported promotion state version"
        );
        ensure!(
            self.plan_id == manifest.plan_id,
            "promotion state plan ID mismatch"
        );
        ensure!(
            self.manifest_digest == manifest.digest()?,
            "promotion manifest changed after it was prepared"
        );
        Ok(())
    }

    fn observe_target_committee(&mut self, epoch: EpochId) -> Result<()> {
        ensure!(
            self.phase != ValidatorPromotionPhase::Retired,
            "retired promotion plan cannot be reactivated"
        );
        self.phase = ValidatorPromotionPhase::CommitteeObserved;
        self.observed_epoch = Some(epoch);
        Ok(())
    }

    fn activate(&mut self, epoch: EpochId) -> Result<()> {
        ensure!(
            self.phase != ValidatorPromotionPhase::Retired,
            "retired promotion plan cannot be reactivated"
        );
        self.phase = ValidatorPromotionPhase::Active;
        self.observed_epoch = Some(epoch);
        Ok(())
    }

    fn retire(&mut self, epoch: EpochId) {
        self.phase = ValidatorPromotionPhase::Retired;
        self.observed_epoch = Some(epoch);
    }

    pub fn phase(&self) -> ValidatorPromotionPhase {
        self.phase
    }
}

pub struct ValidatorPromotionGuard {
    manifest: ValidatorPromotionManifest,
    state: ValidatorPromotionState,
    state_path: PathBuf,
}

pub(crate) trait ValidatorPromotionManifestExt {
    fn load(path: &Path) -> Result<ValidatorPromotionManifest>;
    fn digest(&self) -> Result<String>;
    fn validate_static(&self, chain: ChainIdentifier, config: &NodeConfig) -> Result<()>;
    fn validate_target_validator(&self, validator: &EpochStartValidatorInfoV1) -> Result<()>;
    fn validate_source_validator(&self, validator: &EpochStartValidatorInfoV1) -> Result<()>;
}

impl ValidatorPromotionManifestExt for ValidatorPromotionManifest {
    fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read promotion manifest {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse promotion manifest {}", path.display()))
    }

    fn digest(&self) -> Result<String> {
        use fastcrypto::hash::{Blake2b256, HashFunction};

        let bytes = serde_json::to_vec(self)?;
        Ok(Hex::encode(Blake2b256::digest(&bytes)))
    }

    fn validate_static(&self, chain: ChainIdentifier, config: &NodeConfig) -> Result<()> {
        ensure!(
            self.version == VALIDATOR_PROMOTION_MANIFEST_VERSION,
            "unsupported promotion manifest version"
        );
        ensure!(
            !self.plan_id.is_empty()
                && self.plan_id.len() <= 128
                && self
                    .plan_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "promotion plan ID must contain 1-128 ASCII letters, digits, '-' or '_'"
        );
        ensure!(
            self.activation_epoch == self.source_epoch.saturating_add(1),
            "promotion activation epoch must immediately follow source epoch"
        );
        ensure!(
            self.chain_identifier == Hex::encode(chain.as_bytes()),
            "promotion manifest chain identifier mismatch"
        );

        let source_protocol = parse_authority_key(&self.source_protocol_public_key)
            .context("invalid source protocol public key")?;
        let target_protocol = self.target.protocol_key()?;
        ensure!(
            source_protocol != target_protocol,
            "source and target protocol keys must be distinct"
        );
        ensure!(
            config.protocol_key_pair().public() == &target_protocol,
            "local protocol key does not match promotion target"
        );

        let target_network = self.target.network_key()?;
        let target_worker = self.target.worker_key()?;
        ensure!(
            target_network != target_worker,
            "target network and worker keys must be distinct"
        );
        ensure!(
            config.network_key_pair().public() == &target_network,
            "local network key does not match promotion target"
        );
        ensure!(
            config.worker_key_pair().public() == &target_worker,
            "local worker key does not match promotion target"
        );

        let pop_bytes = parse_canonical_hex(&self.proof_of_possession)
            .context("invalid proof of possession encoding")?;
        let pop = AuthoritySignature::from_bytes(&pop_bytes)
            .context("invalid proof of possession signature")?;
        verify_proof_of_possession(&pop, &target_protocol, self.validator_address)
            .context("invalid proof of possession for target protocol key")?;
        Ok(())
    }

    fn validate_target_validator(&self, validator: &EpochStartValidatorInfoV1) -> Result<()> {
        ensure!(
            validator.sui_address == self.validator_address,
            "promotion target validator address mismatch"
        );
        ensure!(
            validator.protocol_pubkey == self.target.protocol_key()?,
            "promotion target protocol key mismatch"
        );
        ensure!(
            validator.narwhal_network_pubkey == self.target.network_key()?,
            "promotion target network key mismatch"
        );
        ensure!(
            validator.narwhal_worker_pubkey == self.target.worker_key()?,
            "promotion target worker key mismatch"
        );
        ensure!(
            validator.sui_net_address == self.target.network_address,
            "promotion target network address mismatch"
        );
        ensure!(
            validator.p2p_address == self.target.p2p_address,
            "promotion target p2p address mismatch"
        );
        ensure!(
            validator.narwhal_primary_address == self.target.primary_address,
            "promotion target primary address mismatch"
        );
        ensure!(
            validator.narwhal_worker_address == self.target.worker_address,
            "promotion target worker address mismatch"
        );
        Ok(())
    }

    fn validate_source_validator(&self, validator: &EpochStartValidatorInfoV1) -> Result<()> {
        ensure!(
            validator.sui_address == self.validator_address,
            "promotion source validator address mismatch"
        );
        ensure!(
            validator.protocol_pubkey == parse_authority_key(&self.source_protocol_public_key)?,
            "promotion source protocol key mismatch"
        );
        Ok(())
    }
}

trait ValidatorPromotionTargetExt {
    fn protocol_key(&self) -> Result<AuthorityPublicKey>;
    fn network_key(&self) -> Result<NetworkPublicKey>;
    fn worker_key(&self) -> Result<NetworkPublicKey>;
}

impl ValidatorPromotionTargetExt for ValidatorPromotionTarget {
    fn protocol_key(&self) -> Result<AuthorityPublicKey> {
        parse_authority_key(&self.protocol_public_key).context("invalid target protocol public key")
    }

    fn network_key(&self) -> Result<NetworkPublicKey> {
        parse_network_key(&self.network_public_key).context("invalid target network public key")
    }

    fn worker_key(&self) -> Result<NetworkPublicKey> {
        parse_network_key(&self.worker_public_key).context("invalid target worker public key")
    }
}

impl ValidatorPromotionGuard {
    pub fn load(
        manifest_path: &Path,
        state_path: PathBuf,
        chain: ChainIdentifier,
        config: &NodeConfig,
    ) -> Result<Self> {
        let manifest = ValidatorPromotionManifest::load(manifest_path)?;
        manifest.validate_static(chain, config)?;

        let state = if state_path.exists() {
            let bytes = fs::read(&state_path).with_context(|| {
                format!("failed to read promotion state {}", state_path.display())
            })?;
            let state: ValidatorPromotionState =
                serde_json::from_slice(&bytes).with_context(|| {
                    format!("failed to parse promotion state {}", state_path.display())
                })?;
            state.validate_manifest(&manifest)?;
            state
        } else {
            let state = ValidatorPromotionState::prepared(&manifest)?;
            persist_state(&state_path, &state)?;
            state
        };

        Ok(Self {
            manifest,
            state,
            state_path,
        })
    }

    pub fn manifest(&self) -> &ValidatorPromotionManifest {
        &self.manifest
    }

    pub fn state(&self) -> &ValidatorPromotionState {
        &self.state
    }

    pub fn observe_target_committee(
        &mut self,
        epoch: EpochId,
        validator: &EpochStartValidatorInfoV1,
        authority_state: &AuthorityState,
        checkpoint_store: &CheckpointStore,
    ) -> Result<()> {
        ensure!(
            epoch == self.manifest.activation_epoch,
            "target protocol key did not appear at the authorized activation epoch"
        );
        self.manifest.validate_target_validator(validator)?;
        self.validate_evidence(authority_state, checkpoint_store)?;
        self.state.observe_target_committee(epoch)?;
        persist_state(&self.state_path, &self.state)
    }

    pub fn activate(
        &mut self,
        epoch: EpochId,
        validator: &EpochStartValidatorInfoV1,
        authority_state: &AuthorityState,
        checkpoint_store: &CheckpointStore,
    ) -> Result<()> {
        if self.state.phase() == ValidatorPromotionPhase::Active {
            ensure!(
                epoch >= self.manifest.activation_epoch,
                "active promotion state predates its authorized activation epoch"
            );
        } else {
            ensure!(
                epoch == self.manifest.activation_epoch,
                "fresh promotion activation must occur at the authorized activation epoch"
            );
        }
        self.manifest.validate_target_validator(validator)?;
        if self.state.phase() != ValidatorPromotionPhase::Active {
            self.validate_evidence(authority_state, checkpoint_store)?;
        }
        self.state.activate(epoch)?;
        persist_state(&self.state_path, &self.state)
    }

    pub fn retire(&mut self, epoch: EpochId) -> Result<()> {
        self.state.retire(epoch);
        persist_state(&self.state_path, &self.state)
    }

    fn validate_evidence(
        &self,
        authority_state: &AuthorityState,
        checkpoint_store: &CheckpointStore,
    ) -> Result<()> {
        let evidence = &self.manifest.evidence;
        let checkpoint = checkpoint_store
            .get_checkpoint_by_sequence_number(evidence.checkpoint_sequence_number)?
            .context("promotion evidence checkpoint is not available locally")?;
        ensure!(
            checkpoint.epoch() == self.manifest.source_epoch,
            "promotion evidence was not finalized in the source epoch"
        );
        let contents = checkpoint_store
            .get_checkpoint_contents(&checkpoint.content_digest)?
            .context("promotion evidence checkpoint contents are not available locally")?;
        ensure!(
            contents
                .iter()
                .any(|digests| digests.transaction == evidence.transaction_digest),
            "promotion transaction is not in the claimed finalized checkpoint"
        );
        let highest_executed = checkpoint_store
            .get_highest_executed_checkpoint_seq_number()?
            .context("node has not executed any checkpoints")?;
        ensure!(
            highest_executed >= evidence.checkpoint_sequence_number,
            "promotion evidence checkpoint has not been executed locally"
        );

        let transaction = authority_state
            .get_transaction_cache_reader()
            .get_transaction_block(&evidence.transaction_digest)
            .context("promotion transaction body is not available locally")?;
        validate_promotion_transaction(
            transaction.data().transaction_data(),
            &self.manifest,
            authority_state.get_chain_identifier(),
        )?;

        let effects = authority_state
            .get_transaction_cache_reader()
            .multi_get_executed_effects(&[evidence.transaction_digest])
            .pop()
            .flatten()
            .context("promotion transaction effects are not available locally")?;
        ensure!(
            effects.status().is_ok(),
            "promotion transaction did not execute successfully"
        );
        Ok(())
    }
}

fn validate_promotion_transaction(
    transaction: &TransactionData,
    manifest: &ValidatorPromotionManifest,
    chain: ChainIdentifier,
) -> Result<()> {
    ensure!(
        transaction.sender() == manifest.validator_address,
        "promotion transaction was not sent by the validator account"
    );
    ensure!(
        transaction.expiration()
            == &TransactionExpiration::ValidDuring {
                min_epoch: Some(manifest.source_epoch),
                max_epoch: Some(manifest.source_epoch),
                min_timestamp: None,
                max_timestamp: None,
                chain,
                nonce: match transaction.expiration() {
                    TransactionExpiration::ValidDuring { nonce, .. } => *nonce,
                    _ => 0,
                },
            },
        "promotion transaction must be bound to the exact source epoch and chain"
    );

    let TransactionKind::ProgrammableTransaction(pt) = transaction.kind() else {
        bail!("promotion transaction is not a programmable transaction");
    };
    ensure!(
        pt.commands.len() == REQUIRED_PROMOTION_FUNCTIONS.len(),
        "promotion transaction must contain exactly seven metadata calls"
    );
    let mut functions = BTreeSet::new();
    for command in &pt.commands {
        let Command::MoveCall(call) = command else {
            bail!("promotion transaction contains a non-Move command");
        };
        ensure!(
            call.package == SUI_SYSTEM_PACKAGE_ID
                && call.module.as_str() == "sui_system"
                && call.type_arguments.is_empty(),
            "promotion transaction contains a call outside 0x3::sui_system"
        );
        ensure!(
            functions.insert(call.function.as_str()),
            "promotion transaction contains a duplicate metadata call"
        );
        let expected_pure = expected_pure_arguments(call.function.as_str(), manifest)?;
        ensure!(
            call.arguments.len() == expected_pure.len() + 1,
            "promotion metadata call has an unexpected argument count"
        );
        ensure!(
            resolve_input(pt, call.arguments[0])? == &CallArg::SUI_SYSTEM_MUT,
            "promotion metadata call does not target the Sui system state object"
        );
        for (argument, expected) in call.arguments[1..].iter().zip(expected_pure) {
            ensure!(
                resolve_input(pt, *argument)? == &CallArg::Pure(expected),
                "promotion metadata call argument does not match the manifest"
            );
        }
    }
    ensure!(
        functions == REQUIRED_PROMOTION_FUNCTIONS.into_iter().collect(),
        "promotion transaction does not contain the complete metadata rotation"
    );
    Ok(())
}

fn resolve_input(
    pt: &sui_types::transaction::ProgrammableTransaction,
    argument: Argument,
) -> Result<&CallArg> {
    let Argument::Input(index) = argument else {
        bail!("promotion metadata calls may only use transaction inputs");
    };
    pt.inputs
        .get(index as usize)
        .context("promotion metadata call references a missing input")
}

fn expected_pure_arguments(
    function: &str,
    manifest: &ValidatorPromotionManifest,
) -> Result<Vec<Vec<u8>>> {
    let target = &manifest.target;
    let values = match function {
        "update_validator_next_epoch_protocol_pubkey" => vec![
            bcs::to_bytes(&parse_canonical_hex(&target.protocol_public_key)?)?,
            bcs::to_bytes(&parse_canonical_hex(&manifest.proof_of_possession)?)?,
        ],
        "update_validator_next_epoch_network_pubkey" => {
            vec![bcs::to_bytes(&parse_canonical_hex(
                &target.network_public_key,
            )?)?]
        }
        "update_validator_next_epoch_worker_pubkey" => {
            vec![bcs::to_bytes(&parse_canonical_hex(
                &target.worker_public_key,
            )?)?]
        }
        "update_validator_next_epoch_network_address" => {
            vec![bcs::to_bytes(&target.network_address)?]
        }
        "update_validator_next_epoch_p2p_address" => {
            vec![bcs::to_bytes(&target.p2p_address)?]
        }
        "update_validator_next_epoch_primary_address" => {
            vec![bcs::to_bytes(&target.primary_address)?]
        }
        "update_validator_next_epoch_worker_address" => {
            vec![bcs::to_bytes(&target.worker_address)?]
        }
        _ => bail!("promotion transaction contains an unexpected metadata function"),
    };
    Ok(values)
}

const REQUIRED_PROMOTION_FUNCTIONS: [&str; 7] = [
    "update_validator_next_epoch_protocol_pubkey",
    "update_validator_next_epoch_network_pubkey",
    "update_validator_next_epoch_worker_pubkey",
    "update_validator_next_epoch_network_address",
    "update_validator_next_epoch_p2p_address",
    "update_validator_next_epoch_primary_address",
    "update_validator_next_epoch_worker_address",
];

fn parse_canonical_hex(value: &str) -> Result<Vec<u8>> {
    ensure!(
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "hex value must be non-empty lowercase canonical hex"
    );
    Hex::decode(value).context("failed to decode hex")
}

fn parse_authority_key(value: &str) -> Result<AuthorityPublicKey> {
    AuthorityPublicKey::from_bytes(&parse_canonical_hex(value)?)
        .context("invalid BLS12-381 public key")
}

fn parse_network_key(value: &str) -> Result<NetworkPublicKey> {
    NetworkPublicKey::from_bytes(&parse_canonical_hex(value)?).context("invalid Ed25519 public key")
}

fn persist_state(path: &Path, state: &ValidatorPromotionState) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("promotion state path must have a parent directory")?;
    ensure!(
        parent.is_dir(),
        "promotion state parent directory does not exist"
    );

    let file_name = path
        .file_name()
        .context("promotion state path must have a file name")?
        .to_string_lossy();
    let bytes = serde_json::to_vec_pretty(state)?;

    for attempt in 0..100_u32 {
        let temporary = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create temporary promotion state"),
        };
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);

        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("failed to atomically replace promotion state");
        }
        File::open(parent)?.sync_all()?;
        return Ok(());
    }
    bail!("could not allocate a temporary promotion state path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::traits::KeyPair;
    use sui_types::crypto::{
        AuthorityKeyPair, NetworkKeyPair, generate_proof_of_possession, get_key_pair,
    };
    use sui_types::transaction::{
        GasData, ProgrammableMoveCall, ProgrammableTransaction, TransactionDataV1,
    };
    use sui_types::{base_types::SuiAddress, digests::TransactionDigest};

    fn test_manifest() -> (
        ValidatorPromotionManifest,
        NodeConfig,
        EpochStartValidatorInfoV1,
        ChainIdentifier,
    ) {
        let (_, source_protocol): (_, AuthorityKeyPair) = get_key_pair();
        let (_, target_protocol): (_, AuthorityKeyPair) = get_key_pair();
        let (_, target_network): (_, NetworkKeyPair) = get_key_pair();
        let (_, target_worker): (_, NetworkKeyPair) = get_key_pair();
        let validator_address = SuiAddress::random_for_testing_only();
        let pop = generate_proof_of_possession(&target_protocol, validator_address);
        let chain = ChainIdentifier::random();

        let target = ValidatorPromotionTarget {
            protocol_public_key: Hex::encode(target_protocol.public().as_bytes()),
            network_public_key: Hex::encode(target_network.public().as_bytes()),
            worker_public_key: Hex::encode(target_worker.public().as_bytes()),
            network_address: "/dns/validator.example/tcp/8080/http".parse().unwrap(),
            p2p_address: "/dns/validator.example/udp/8084".parse().unwrap(),
            primary_address: "/dns/validator.example/udp/8081".parse().unwrap(),
            worker_address: "/dns/validator.example/udp/8082".parse().unwrap(),
        };
        let manifest = ValidatorPromotionManifest {
            version: VALIDATOR_PROMOTION_MANIFEST_VERSION,
            plan_id: "test-plan-1".to_string(),
            chain_identifier: Hex::encode(chain.as_bytes()),
            source_epoch: 41,
            activation_epoch: 42,
            validator_address,
            source_protocol_public_key: Hex::encode(source_protocol.public().as_bytes()),
            target: target.clone(),
            proof_of_possession: Hex::encode(pop.as_ref()),
            evidence: sui_config::node::ValidatorPromotionEvidence {
                transaction_digest: TransactionDigest::random(),
                checkpoint_sequence_number: 100,
            },
        };

        let mut config: NodeConfig =
            serde_yaml::from_str(include_str!("../../sui-config/data/fullnode-template.yaml"))
                .unwrap();
        config.protocol_key_pair = sui_config::node::AuthorityKeyPairWithPath::new(target_protocol);
        config.network_key_pair = sui_config::node::KeyPairWithPath::new(
            sui_types::crypto::SuiKeyPair::Ed25519(target_network),
        );
        config.worker_key_pair = sui_config::node::KeyPairWithPath::new(
            sui_types::crypto::SuiKeyPair::Ed25519(target_worker),
        );

        let validator = EpochStartValidatorInfoV1 {
            sui_address: validator_address,
            protocol_pubkey: target.protocol_key().unwrap(),
            narwhal_network_pubkey: target.network_key().unwrap(),
            narwhal_worker_pubkey: target.worker_key().unwrap(),
            sui_net_address: target.network_address,
            p2p_address: target.p2p_address,
            narwhal_primary_address: target.primary_address,
            narwhal_worker_address: target.worker_address,
            voting_power: 1,
            hostname: "validator.example".to_string(),
        };

        (manifest, config, validator, chain)
    }

    #[test]
    fn manifest_binds_local_keys_chain_and_complete_committee_metadata() {
        let (manifest, config, validator, chain) = test_manifest();
        manifest.validate_static(chain, &config).unwrap();
        manifest.validate_target_validator(&validator).unwrap();

        let mut source_validator = validator.clone();
        source_validator.protocol_pubkey =
            parse_authority_key(&manifest.source_protocol_public_key).unwrap();
        manifest
            .validate_source_validator(&source_validator)
            .unwrap();
        source_validator.protocol_pubkey = validator.protocol_pubkey.clone();
        assert!(
            manifest
                .validate_source_validator(&source_validator)
                .is_err()
        );

        let mut wrong_validator = validator.clone();
        wrong_validator.narwhal_worker_address = "/dns/wrong.example/udp/8082".parse().unwrap();
        assert!(
            manifest
                .validate_target_validator(&wrong_validator)
                .is_err()
        );

        let mut wrong_epoch = manifest.clone();
        wrong_epoch.activation_epoch += 1;
        assert!(wrong_epoch.validate_static(chain, &config).is_err());
    }

    #[test]
    fn state_is_bound_to_immutable_manifest_and_retirement_is_terminal() {
        let (mut manifest, _, _, _) = test_manifest();
        let mut state = ValidatorPromotionState::prepared(&manifest).unwrap();
        state.observe_target_committee(42).unwrap();
        state.activate(42).unwrap();
        state.retire(43);
        assert!(state.activate(44).is_err());

        manifest.target.worker_address = "/dns/changed.example/udp/8082".parse().unwrap();
        assert!(state.validate_manifest(&manifest).is_err());
    }

    #[test]
    fn durable_state_survives_restart_and_rejects_manifest_replacement() {
        let (mut manifest, config, _, chain) = test_manifest();
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = directory.path().join("manifest.json");
        let state_path = directory.path().join("state.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut guard =
            ValidatorPromotionGuard::load(&manifest_path, state_path.clone(), chain, &config)
                .unwrap();
        assert_eq!(guard.state().phase(), ValidatorPromotionPhase::Prepared);
        guard.retire(43).unwrap();
        drop(guard);

        let guard =
            ValidatorPromotionGuard::load(&manifest_path, state_path.clone(), chain, &config)
                .unwrap();
        assert_eq!(guard.state().phase(), ValidatorPromotionPhase::Retired);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        manifest.plan_id = "replacement-plan".to_string();
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(ValidatorPromotionGuard::load(&manifest_path, state_path, chain, &config).is_err());
    }

    #[test]
    fn promotion_transaction_is_atomic_complete_and_exact_epoch_bound() {
        let (manifest, _, _, chain) = test_manifest();
        let mut inputs = vec![CallArg::SUI_SYSTEM_MUT];
        let mut commands = Vec::new();
        for function in REQUIRED_PROMOTION_FUNCTIONS {
            let mut arguments = vec![Argument::Input(0)];
            for value in expected_pure_arguments(function, &manifest).unwrap() {
                let index = inputs.len();
                inputs.push(CallArg::Pure(value));
                arguments.push(Argument::Input(index as u16));
            }
            commands.push(Command::MoveCall(Box::new(ProgrammableMoveCall {
                package: SUI_SYSTEM_PACKAGE_ID,
                module: "sui_system".to_string(),
                function: function.to_string(),
                type_arguments: vec![],
                arguments,
            })));
        }
        let transaction = TransactionData::V1(TransactionDataV1 {
            kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                inputs,
                commands,
            }),
            sender: manifest.validator_address,
            gas_data: GasData {
                payment: vec![],
                owner: manifest.validator_address,
                price: 1,
                budget: 1,
            },
            expiration: TransactionExpiration::ValidDuring {
                min_epoch: Some(manifest.source_epoch),
                max_epoch: Some(manifest.source_epoch),
                min_timestamp: None,
                max_timestamp: None,
                chain,
                nonce: 7,
            },
        });
        validate_promotion_transaction(&transaction, &manifest, chain).unwrap();

        let mut incomplete = transaction.clone();
        let TransactionKind::ProgrammableTransaction(pt) = incomplete.kind_mut() else {
            unreachable!();
        };
        pt.commands.pop();
        assert!(validate_promotion_transaction(&incomplete, &manifest, chain).is_err());

        let mut tampered = transaction.clone();
        let TransactionKind::ProgrammableTransaction(pt) = tampered.kind_mut() else {
            unreachable!();
        };
        let CallArg::Pure(value) = &mut pt.inputs[1] else {
            unreachable!();
        };
        value.push(0);
        assert!(validate_promotion_transaction(&tampered, &manifest, chain).is_err());

        let mut loosely_expiring = transaction;
        *loosely_expiring.expiration_mut() = TransactionExpiration::Epoch(manifest.source_epoch);
        assert!(validate_promotion_transaction(&loosely_expiring, &manifest, chain).is_err());
    }
}
