// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::{Digest, HolderId, LeaseCredential, LeaseGrant, LeaseId, OperationKey};

const STATE_VERSION: u16 = 1;

pub trait Clock: Send + Sync + 'static {
    fn unix_ms(&self) -> Result<u64, PolicyError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_ms(&self) -> Result<u64, PolicyError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PolicyError::ClockBeforeUnixEpoch)?;
        u64::try_from(duration.as_millis()).map_err(|_| PolicyError::ClockOverflow)
    }
}

pub trait StateStore: Send + Sync + 'static {
    fn load(&self) -> Result<Option<PersistedState>, PolicyError>;
    fn save(&self, state: &PersistedState) -> Result<(), PolicyError>;
}

#[derive(Debug)]
pub struct FileStateStore {
    path: PathBuf,
}

impl FileStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn temp_path(&self) -> PathBuf {
        let mut suffix = [0; 8];
        OsRng.fill_bytes(&mut suffix);
        self.path
            .with_extension(format!("new.{}", hex::encode(suffix)))
    }
}

impl StateStore for FileStateStore {
    fn load(&self) -> Result<Option<PersistedState>, PolicyError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(PolicyError::Io(error)),
        };
        if !metadata.file_type().is_file() {
            return Err(PolicyError::InvalidStateFile(self.path.clone()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(PolicyError::InsecureStatePermissions(self.path.clone()));
            }
        }
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) => return Err(PolicyError::Io(error)),
        };
        let state = bcs::from_bytes(&bytes).map_err(PolicyError::Deserialize)?;
        Ok(Some(state))
    }

    fn save(&self, state: &PersistedState) -> Result<(), PolicyError> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent)?;
        }

        let temp_path = self.temp_path();
        let bytes = bcs::to_bytes(state).map_err(PolicyError::Serialize)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp_path, &self.path)?;
        sync_parent(parent)?;
        Ok(())
    }
}

fn sync_parent(parent: Option<&Path>) -> Result<(), PolicyError> {
    if let Some(parent) = parent {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PersistedState {
    version: u16,
    next_generation: u64,
    last_seen_unix_ms: u64,
    current_lease: Option<LeaseRecord>,
    decisions: BTreeMap<OperationKey, Digest>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            next_generation: 1,
            last_seen_unix_ms: 0,
            current_lease: None,
            decisions: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LeaseRecord {
    holder_id: HolderId,
    generation: u64,
    lease_id: LeaseId,
    expires_at_unix_ms: u64,
}

impl LeaseRecord {
    fn grant(&self) -> LeaseGrant {
        LeaseGrant {
            generation: self.generation,
            lease_id: self.lease_id,
            expires_at_unix_ms: self.expires_at_unix_ms,
        }
    }

    fn credential_matches(&self, credential: &LeaseCredential) -> bool {
        self.holder_id == credential.holder_id
            && self.generation == credential.generation
            && self.lease_id == credential.lease_id
    }
}

pub struct SignerPolicy<S = FileStateStore, C = SystemClock> {
    store: S,
    clock: C,
    max_ttl_ms: u64,
    state: Mutex<PersistedState>,
}

impl<S: StateStore, C: Clock> SignerPolicy<S, C> {
    pub fn open(store: S, clock: C, max_ttl_ms: u64) -> Result<Self, PolicyError> {
        if max_ttl_ms == 0 {
            return Err(PolicyError::InvalidTtl);
        }
        let state = store.load()?.unwrap_or_default();
        if state.version != STATE_VERSION {
            return Err(PolicyError::UnsupportedStateVersion(state.version));
        }
        if clock.unix_ms()? < state.last_seen_unix_ms {
            return Err(PolicyError::ClockMovedBackwards);
        }
        Ok(Self {
            store,
            clock,
            max_ttl_ms,
            state: Mutex::new(state),
        })
    }

    pub fn acquire(&self, holder_id: HolderId, ttl_ms: u64) -> Result<LeaseGrant, PolicyError> {
        self.validate_ttl(ttl_ms)?;
        let now = self.clock.unix_ms()?;
        let expires_at_unix_ms = now.checked_add(ttl_ms).ok_or(PolicyError::ClockOverflow)?;
        let mut state = self.state.lock().map_err(|_| PolicyError::LockPoisoned)?;
        let mut next = state.clone();
        observe_time(&mut next, now)?;
        if let Some(lease) = &next.current_lease
            && lease.expires_at_unix_ms > now
        {
            return Err(PolicyError::LeaseHeld {
                generation: lease.generation,
                expires_at_unix_ms: lease.expires_at_unix_ms,
            });
        }

        let generation = next.next_generation;
        next.next_generation = generation
            .checked_add(1)
            .ok_or(PolicyError::GenerationExhausted)?;
        let mut lease_id = [0; 32];
        OsRng.fill_bytes(&mut lease_id);
        let lease = LeaseRecord {
            holder_id,
            generation,
            lease_id,
            expires_at_unix_ms,
        };
        next.current_lease = Some(lease.clone());
        self.store.save(&next)?;
        *state = next;
        Ok(lease.grant())
    }

    pub fn renew(
        &self,
        credential: &LeaseCredential,
        ttl_ms: u64,
    ) -> Result<LeaseGrant, PolicyError> {
        self.validate_ttl(ttl_ms)?;
        let now = self.clock.unix_ms()?;
        let expires_at_unix_ms = now.checked_add(ttl_ms).ok_or(PolicyError::ClockOverflow)?;
        let mut state = self.state.lock().map_err(|_| PolicyError::LockPoisoned)?;
        let mut next = state.clone();
        observe_time(&mut next, now)?;
        let lease = valid_lease_mut(&mut next, credential, now)?;
        lease.expires_at_unix_ms = expires_at_unix_ms;
        let grant = lease.grant();
        self.store.save(&next)?;
        *state = next;
        Ok(grant)
    }

    pub fn release(&self, credential: &LeaseCredential) -> Result<(), PolicyError> {
        let now = self.clock.unix_ms()?;
        let mut state = self.state.lock().map_err(|_| PolicyError::LockPoisoned)?;
        let mut next = state.clone();
        observe_time(&mut next, now)?;
        valid_lease(&next, credential, now)?;
        next.current_lease = None;
        self.store.save(&next)?;
        *state = next;
        Ok(())
    }

    pub fn authorize_and_execute<F>(
        &self,
        credential: &LeaseCredential,
        operation: OperationKey,
        payload_digest: Digest,
        execute: F,
    ) -> Result<Vec<u8>, PolicyError>
    where
        F: FnOnce() -> Result<Vec<u8>, String>,
    {
        let now = self.clock.unix_ms()?;
        let mut state = self.state.lock().map_err(|_| PolicyError::LockPoisoned)?;
        let mut next = state.clone();
        observe_time(&mut next, now)?;
        valid_lease(&next, credential, now)?;

        match next.decisions.get(&operation) {
            Some(previous_digest) if previous_digest != &payload_digest => {
                return Err(PolicyError::Equivocation);
            }
            Some(_) => {}
            None => {
                next.decisions.insert(operation, payload_digest);
            }
        }
        self.store.save(&next)?;
        *state = next;

        let result = execute().map_err(PolicyError::SigningFailed)?;
        let completed_at = self.clock.unix_ms()?;
        if completed_at < state.last_seen_unix_ms {
            return Err(PolicyError::ClockMovedBackwards);
        }
        valid_lease(&state, credential, completed_at)?;
        Ok(result)
    }

    fn validate_ttl(&self, ttl_ms: u64) -> Result<(), PolicyError> {
        if ttl_ms == 0 || ttl_ms > self.max_ttl_ms {
            return Err(PolicyError::InvalidTtl);
        }
        Ok(())
    }
}

fn observe_time(state: &mut PersistedState, now: u64) -> Result<(), PolicyError> {
    if now < state.last_seen_unix_ms {
        return Err(PolicyError::ClockMovedBackwards);
    }
    state.last_seen_unix_ms = now;
    Ok(())
}

fn valid_lease<'a>(
    state: &'a PersistedState,
    credential: &LeaseCredential,
    now: u64,
) -> Result<&'a LeaseRecord, PolicyError> {
    let lease = state.current_lease.as_ref().ok_or(PolicyError::NoLease)?;
    if !lease.credential_matches(credential) {
        return Err(PolicyError::StaleLease);
    }
    if lease.expires_at_unix_ms <= now {
        return Err(PolicyError::LeaseExpired);
    }
    Ok(lease)
}

fn valid_lease_mut<'a>(
    state: &'a mut PersistedState,
    credential: &LeaseCredential,
    now: u64,
) -> Result<&'a mut LeaseRecord, PolicyError> {
    let lease = state.current_lease.as_mut().ok_or(PolicyError::NoLease)?;
    if !lease.credential_matches(credential) {
        return Err(PolicyError::StaleLease);
    }
    if lease.expires_at_unix_ms <= now {
        return Err(PolicyError::LeaseExpired);
    }
    Ok(lease)
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    #[error("clock value overflow")]
    ClockOverflow,
    #[error("signer clock moved backwards")]
    ClockMovedBackwards,
    #[error("lease generation exhausted")]
    GenerationExhausted,
    #[error("lease TTL must be nonzero and no greater than the configured maximum")]
    InvalidTtl,
    #[error("another lease generation {generation} is valid until {expires_at_unix_ms}")]
    LeaseHeld {
        generation: u64,
        expires_at_unix_ms: u64,
    },
    #[error("no lease exists")]
    NoLease,
    #[error("lease has expired")]
    LeaseExpired,
    #[error("lease credential is stale or belongs to another holder")]
    StaleLease,
    #[error("request conflicts with a durable signing decision")]
    Equivocation,
    #[error("signing operation failed: {0}")]
    SigningFailed(String),
    #[error("signer state lock poisoned")]
    LockPoisoned,
    #[error("unsupported signer state version {0}")]
    UnsupportedStateVersion(u16),
    #[error("signer state path is not a regular file: {0}")]
    InvalidStateFile(PathBuf),
    #[error("signer state file is accessible by group or other users: {0}")]
    InsecureStatePermissions(PathBuf),
    #[error("failed to serialize signer state: {0}")]
    Serialize(bcs::Error),
    #[error("failed to deserialize signer state: {0}")]
    Deserialize(bcs::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };

    use tempfile::TempDir;

    use super::*;
    use crate::protocol::OperationKey;

    const MAX_TTL_MS: u64 = 10_000;

    #[derive(Clone, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn set(&self, value: u64) {
            self.0.store(value, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn unix_ms(&self) -> Result<u64, PolicyError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Default)]
    struct FailingStore {
        fail_save: AtomicBool,
        state: Mutex<Option<PersistedState>>,
    }

    impl StateStore for Arc<FailingStore> {
        fn load(&self) -> Result<Option<PersistedState>, PolicyError> {
            Ok(self.state.lock().unwrap().clone())
        }

        fn save(&self, state: &PersistedState) -> Result<(), PolicyError> {
            if self.fail_save.swap(false, Ordering::SeqCst) {
                return Err(PolicyError::Io(std::io::Error::other("injected")));
            }
            *self.state.lock().unwrap() = Some(state.clone());
            Ok(())
        }
    }

    fn holder(byte: u8) -> HolderId {
        [byte; 32]
    }

    fn credential(holder_id: HolderId, grant: &LeaseGrant) -> LeaseCredential {
        LeaseCredential {
            holder_id,
            generation: grant.generation,
            lease_id: grant.lease_id,
        }
    }

    fn block(round: u32) -> OperationKey {
        OperationKey::ConsensusBlock {
            chain_id: [9; 32],
            epoch: 7,
            round,
        }
    }

    fn policy(directory: &TempDir, clock: TestClock) -> SignerPolicy<FileStateStore, TestClock> {
        SignerPolicy::open(
            FileStateStore::new(directory.path().join("state.bcs")),
            clock,
            MAX_TTL_MS,
        )
        .unwrap()
    }

    #[test]
    fn only_one_unexpired_lease_is_granted() {
        let directory = TempDir::new().unwrap();
        let clock = TestClock::default();
        clock.set(100);
        let policy = policy(&directory, clock);

        let first = policy.acquire(holder(1), 1_000).unwrap();
        let error = policy.acquire(holder(2), 1_000).unwrap_err();
        assert!(matches!(
            error,
            PolicyError::LeaseHeld { generation: 1, .. }
        ));
        assert_eq!(first.generation, 1);
    }

    #[test]
    fn expired_holder_cannot_renew_or_sign_after_takeover() {
        let directory = TempDir::new().unwrap();
        let clock = TestClock::default();
        clock.set(100);
        let policy = policy(&directory, clock.clone());

        let first = policy.acquire(holder(1), 100).unwrap();
        let first_credential = credential(holder(1), &first);
        clock.set(200);
        let second = policy.acquire(holder(2), 100).unwrap();
        let second_credential = credential(holder(2), &second);

        assert_eq!(second.generation, 2);
        assert!(matches!(
            policy.renew(&first_credential, 100),
            Err(PolicyError::StaleLease)
        ));
        assert!(matches!(
            policy.authorize_and_execute(&first_credential, block(1), [1; 32], || Ok(vec![1])),
            Err(PolicyError::StaleLease)
        ));
        assert_eq!(
            policy
                .authorize_and_execute(&second_credential, block(1), [1; 32], || Ok(vec![2]))
                .unwrap(),
            vec![2]
        );
    }

    #[test]
    fn decision_survives_lease_transfer_and_rejects_conflict() {
        let directory = TempDir::new().unwrap();
        let clock = TestClock::default();
        clock.set(100);
        let policy = policy(&directory, clock.clone());

        let first = policy.acquire(holder(1), 100).unwrap();
        policy
            .authorize_and_execute(&credential(holder(1), &first), block(8), [3; 32], || {
                Ok(vec![4])
            })
            .unwrap();
        clock.set(200);
        let second = policy.acquire(holder(2), 100).unwrap();
        let second_credential = credential(holder(2), &second);

        assert_eq!(
            policy
                .authorize_and_execute(&second_credential, block(8), [3; 32], || Ok(vec![5]))
                .unwrap(),
            vec![5]
        );
        assert!(matches!(
            policy.authorize_and_execute(&second_credential, block(8), [4; 32], || Ok(vec![6])),
            Err(PolicyError::Equivocation)
        ));
    }

    #[test]
    fn generation_and_decisions_survive_restart() {
        let directory = TempDir::new().unwrap();
        let clock = TestClock::default();
        clock.set(100);
        {
            let policy = policy(&directory, clock.clone());
            let grant = policy.acquire(holder(1), 100).unwrap();
            policy
                .authorize_and_execute(&credential(holder(1), &grant), block(10), [7; 32], || {
                    Ok(vec![8])
                })
                .unwrap();
        }

        clock.set(200);
        let reopened = policy(&directory, clock);
        let grant = reopened.acquire(holder(2), 100).unwrap();
        assert_eq!(grant.generation, 2);
        assert!(matches!(
            reopened.authorize_and_execute(
                &credential(holder(2), &grant),
                block(10),
                [8; 32],
                || Ok(vec![9])
            ),
            Err(PolicyError::Equivocation)
        ));
    }

    #[test]
    fn failed_crypto_does_not_allow_a_conflicting_retry() {
        let directory = TempDir::new().unwrap();
        let clock = TestClock::default();
        clock.set(100);
        let policy = policy(&directory, clock);
        let grant = policy.acquire(holder(1), 100).unwrap();
        let credential = credential(holder(1), &grant);

        assert!(matches!(
            policy.authorize_and_execute(&credential, block(11), [1; 32], || Err("hsm".into())),
            Err(PolicyError::SigningFailed(_))
        ));
        assert!(matches!(
            policy.authorize_and_execute(&credential, block(11), [2; 32], || Ok(vec![1])),
            Err(PolicyError::Equivocation)
        ));
    }

    #[test]
    fn signature_is_discarded_if_lease_expires_during_crypto() {
        let directory = TempDir::new().unwrap();
        let clock = TestClock::default();
        clock.set(100);
        let policy = policy(&directory, clock.clone());
        let grant = policy.acquire(holder(1), 100).unwrap();
        let credential = credential(holder(1), &grant);

        assert!(matches!(
            policy.authorize_and_execute(&credential, block(12), [1; 32], || {
                clock.set(200);
                Ok(vec![1])
            }),
            Err(PolicyError::LeaseExpired)
        ));
    }

    #[test]
    fn failed_persistence_does_not_advance_in_memory_decision() {
        let store = Arc::new(FailingStore::default());
        let clock = TestClock::default();
        clock.set(100);
        let policy = SignerPolicy::open(store.clone(), clock, MAX_TTL_MS).unwrap();
        let grant = policy.acquire(holder(1), 100).unwrap();
        let credential = credential(holder(1), &grant);

        store.fail_save.store(true, Ordering::SeqCst);
        assert!(matches!(
            policy.authorize_and_execute(&credential, block(13), [1; 32], || Ok(vec![1])),
            Err(PolicyError::Io(_))
        ));
        assert_eq!(
            policy
                .authorize_and_execute(&credential, block(13), [2; 32], || Ok(vec![2]))
                .unwrap(),
            vec![2]
        );
    }

    #[test]
    fn clock_rollback_fails_closed_during_runtime_and_restart() {
        let directory = TempDir::new().unwrap();
        let clock = TestClock::default();
        clock.set(100);
        {
            let policy = policy(&directory, clock.clone());
            let grant = policy.acquire(holder(1), 100).unwrap();
            clock.set(99);
            assert!(matches!(
                policy.renew(&credential(holder(1), &grant), 100),
                Err(PolicyError::ClockMovedBackwards)
            ));
        }

        assert!(matches!(
            SignerPolicy::open(
                FileStateStore::new(directory.path().join("state.bcs")),
                clock,
                MAX_TTL_MS
            ),
            Err(PolicyError::ClockMovedBackwards)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_insecure_or_non_regular_state_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = TempDir::new().unwrap();
        let clock = TestClock::default();
        clock.set(100);
        let state_path = directory.path().join("state.bcs");
        {
            let policy =
                SignerPolicy::open(FileStateStore::new(&state_path), clock.clone(), MAX_TTL_MS)
                    .unwrap();
            policy.acquire(holder(1), 100).unwrap();
        }

        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            SignerPolicy::open(FileStateStore::new(&state_path), clock.clone(), MAX_TTL_MS),
            Err(PolicyError::InsecureStatePermissions(_))
        ));

        let symlink_path = directory.path().join("state-link.bcs");
        symlink(&state_path, &symlink_path).unwrap();
        assert!(matches!(
            SignerPolicy::open(FileStateStore::new(&symlink_path), clock, MAX_TTL_MS),
            Err(PolicyError::InvalidStateFile(_))
        ));
    }
}
