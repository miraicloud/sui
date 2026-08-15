// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};
use sysinfo::Disks;
use thiserror::Error;

use crate::{
    config::AgentConfig,
    protocol::{
        AgentAction, HostHealth, HostStatus, NodeProfile, OperationPhase, OperationStatus,
        ServiceState,
    },
};

const STATE_VERSION: u16 = 1;
const CHECKSUM_BYTES: usize = 32;

pub trait Supervisor: Send + Sync + 'static {
    fn status(&self) -> Result<ServiceState, AgentError>;
    fn stop(&self) -> Result<(), AgentError>;
    fn start(&self) -> Result<(), AgentError>;

    fn health(&self) -> Result<HostHealth, AgentError> {
        Ok(HostHealth {
            clock_synchronized: true,
            database_path_accessible: true,
            database_available_bytes: u64::MAX,
            database_space_sufficient: true,
            service_restart_count: 0,
            service_restarts_acceptable: true,
        })
    }
}

pub struct SystemdSupervisor {
    systemctl_path: PathBuf,
    timedatectl_path: PathBuf,
    service_name: String,
    database_path: PathBuf,
    min_database_available_bytes: u64,
    max_service_restarts: u64,
}

impl SystemdSupervisor {
    pub fn new(config: &AgentConfig) -> Self {
        Self {
            systemctl_path: config.systemctl_path.clone(),
            timedatectl_path: config.timedatectl_path.clone(),
            service_name: config.service_name.clone(),
            database_path: config.database_path.clone(),
            min_database_available_bytes: config.min_database_available_bytes,
            max_service_restarts: config.max_service_restarts,
        }
    }

    fn command(&self, action: &str) -> Result<(), AgentError> {
        let output = Command::new(&self.systemctl_path)
            .arg(action)
            .arg(&self.service_name)
            .output()?;
        if !output.status.success() {
            return Err(AgentError::SupervisorCommand {
                action: action.to_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(())
    }

    fn systemd_property(&self, property: &str) -> Result<String, AgentError> {
        let output = Command::new(&self.systemctl_path)
            .args(["show", "--property", property, "--value"])
            .arg(&self.service_name)
            .output()?;
        if !output.status.success() {
            return Err(AgentError::SupervisorCommand {
                action: format!("show {property}"),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}

impl Supervisor for SystemdSupervisor {
    fn status(&self) -> Result<ServiceState, AgentError> {
        let output = Command::new(&self.systemctl_path)
            .args(["show", "--property=ActiveState", "--value"])
            .arg(&self.service_name)
            .output()?;
        if !output.status.success() {
            return Err(AgentError::SupervisorCommand {
                action: "show".to_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(match String::from_utf8_lossy(&output.stdout).trim() {
            "active" | "activating" | "reloading" => ServiceState::Active,
            "inactive" | "deactivating" => ServiceState::Inactive,
            "failed" => ServiceState::Failed,
            other => ServiceState::Unknown(other.to_owned()),
        })
    }

    fn stop(&self) -> Result<(), AgentError> {
        self.command("stop")
    }

    fn start(&self) -> Result<(), AgentError> {
        self.command("start")
    }

    fn health(&self) -> Result<HostHealth, AgentError> {
        let clock = Command::new(&self.timedatectl_path)
            .args(["show", "--property=NTPSynchronized", "--value"])
            .output()?;
        if !clock.status.success() {
            return Err(AgentError::SupervisorCommand {
                action: "read clock synchronization".to_owned(),
                stderr: String::from_utf8_lossy(&clock.stderr).trim().to_owned(),
            });
        }
        let clock_synchronized = String::from_utf8_lossy(&clock.stdout).trim() == "yes";
        let metadata = fs::symlink_metadata(&self.database_path)?;
        let database_path_accessible =
            metadata.file_type().is_dir() && fs::read_dir(&self.database_path).is_ok();
        let canonical_database = fs::canonicalize(&self.database_path)?;
        let disks = Disks::new_with_refreshed_list();
        let database_available_bytes = disks
            .list()
            .iter()
            .filter(|disk| canonical_database.starts_with(disk.mount_point()))
            .max_by_key(|disk| disk.mount_point().components().count())
            .map(|disk| disk.available_space())
            .ok_or_else(|| AgentError::DatabaseMountNotFound(self.database_path.clone()))?;
        let service_restart_count = self
            .systemd_property("NRestarts")?
            .parse()
            .map_err(|_| AgentError::InvalidSupervisorProperty("NRestarts"))?;
        Ok(HostHealth {
            clock_synchronized,
            database_path_accessible,
            database_available_bytes,
            database_space_sufficient: database_available_bytes
                >= self.min_database_available_bytes,
            service_restart_count,
            service_restarts_acceptable: service_restart_count <= self.max_service_restarts,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PersistedOperation {
    action: AgentAction,
    phase: OperationPhase,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedAgentState {
    version: u16,
    operations: BTreeMap<String, PersistedOperation>,
    current_operation: Option<String>,
}

impl Default for PersistedAgentState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            operations: BTreeMap::new(),
            current_operation: None,
        }
    }
}

pub struct Agent<S: Supervisor> {
    config: AgentConfig,
    supervisor: S,
    state: Mutex<PersistedAgentState>,
}

impl<S: Supervisor> Agent<S> {
    pub fn open(config: AgentConfig, supervisor: S) -> Result<Self, AgentError> {
        config.validate().map_err(AgentError::InvalidConfig)?;
        validate_artifacts(&config)?;
        let state = load_state(&config.state_path)?.unwrap_or_default();
        if state.version != STATE_VERSION {
            return Err(AgentError::UnsupportedStateVersion(state.version));
        }
        Ok(Self {
            config,
            supervisor,
            state: Mutex::new(state),
        })
    }

    pub fn status(&self) -> Result<HostStatus, AgentError> {
        let state = self.state.lock().map_err(|_| AgentError::LockPoisoned)?;
        self.status_with_state(&state)
    }

    pub fn stop(&self, operation_id: &str) -> Result<HostStatus, AgentError> {
        self.execute(operation_id, AgentAction::Stop, |_| {
            self.supervisor.stop()?;
            let state = self.supervisor.status()?;
            if state != ServiceState::Inactive {
                return Err(AgentError::ServiceDidNotStop(state));
            }
            Ok(())
        })
    }

    pub fn activate(
        &self,
        operation_id: &str,
        profile: NodeProfile,
    ) -> Result<HostStatus, AgentError> {
        self.execute(
            operation_id,
            AgentAction::Activate { profile },
            |resuming| {
                let service_state = self.supervisor.status()?;
                if service_state != ServiceState::Inactive {
                    if resuming
                        && service_state == ServiceState::Active
                        && self.current_profile()? == Some(profile)
                    {
                        return Ok(());
                    }
                    return Err(AgentError::ServiceMustBeInactive(service_state));
                }
                self.switch_profile(profile)?;
                self.supervisor.start()?;
                let service_state = self.supervisor.status()?;
                if service_state != ServiceState::Active {
                    return Err(AgentError::ServiceDidNotStart(service_state));
                }
                Ok(())
            },
        )
    }

    fn execute(
        &self,
        operation_id: &str,
        action: AgentAction,
        operation: impl FnOnce(bool) -> Result<(), AgentError>,
    ) -> Result<HostStatus, AgentError> {
        validate_operation_id(operation_id)?;
        let mut state = self.state.lock().map_err(|_| AgentError::LockPoisoned)?;
        let mut resuming = false;
        if let Some(previous) = state.operations.get(operation_id) {
            if previous.action != action {
                return Err(AgentError::OperationConflict(operation_id.to_owned()));
            }
            if previous.phase == OperationPhase::Complete {
                return self.status_with_state(&state);
            }
            resuming = true;
        }
        if let Some(active) = &state.current_operation
            && active != operation_id
        {
            return Err(AgentError::OperationInProgress(active.clone()));
        }

        state.operations.insert(
            operation_id.to_owned(),
            PersistedOperation {
                action: action.clone(),
                phase: OperationPhase::Prepared,
            },
        );
        state.current_operation = Some(operation_id.to_owned());
        save_state(&self.config.state_path, &state)?;

        operation(resuming)?;

        state.operations.insert(
            operation_id.to_owned(),
            PersistedOperation {
                action,
                phase: OperationPhase::Complete,
            },
        );
        state.current_operation = None;
        save_state(&self.config.state_path, &state)?;
        self.status_with_state(&state)
    }

    fn status_with_state(&self, state: &PersistedAgentState) -> Result<HostStatus, AgentError> {
        validate_artifacts(&self.config)?;
        let operation = state.current_operation.as_ref().and_then(|operation_id| {
            state
                .operations
                .get(operation_id)
                .map(|record| OperationStatus {
                    operation_id: operation_id.clone(),
                    action: record.action.clone(),
                    phase: record.phase.clone(),
                })
        });
        Ok(HostStatus {
            host_id: self.config.host_id.clone(),
            profile: self.current_profile()?,
            service_state: self.supervisor.status()?,
            protocol_public_key: self.config.protocol_public_key.clone(),
            worker_public_key: self.config.worker_public_key.clone(),
            network_public_key: self.config.network_public_key.clone(),
            health: self.supervisor.health()?,
            operation,
        })
    }

    fn current_profile(&self) -> Result<Option<NodeProfile>, AgentError> {
        let target = match fs::read_link(&self.config.active_config_path) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(AgentError::Io(error)),
        };
        if target == self.config.observer_config_path {
            Ok(Some(NodeProfile::Observer))
        } else if target == self.config.validator_config_path {
            Ok(Some(NodeProfile::Validator))
        } else {
            Err(AgentError::UnknownProfileTarget(target))
        }
    }

    fn switch_profile(&self, profile: NodeProfile) -> Result<(), AgentError> {
        let target = match profile {
            NodeProfile::Observer => &self.config.observer_config_path,
            NodeProfile::Validator => &self.config.validator_config_path,
        };
        validate_artifacts(&self.config)?;
        if let Ok(metadata) = fs::symlink_metadata(&self.config.active_config_path)
            && !metadata.file_type().is_symlink()
        {
            return Err(AgentError::ActiveConfigNotSymlink(
                self.config.active_config_path.clone(),
            ));
        }
        let parent =
            self.config.active_config_path.parent().ok_or_else(|| {
                AgentError::InvalidStatePath(self.config.active_config_path.clone())
            })?;
        let temporary = parent.join(format!(
            ".sui-validator-profile-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &temporary)?;
        #[cfg(not(unix))]
        return Err(AgentError::UnsupportedPlatform);
        let result = fs::rename(&temporary, &self.config.active_config_path);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn validate_operation_id(operation_id: &str) -> Result<(), AgentError> {
    if operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AgentError::InvalidOperationId);
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<(), AgentError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(AgentError::InvalidArtifactFile(path.to_owned()));
    }
    Ok(())
}

fn validate_artifacts(config: &AgentConfig) -> Result<(), AgentError> {
    validate_file_digest(
        &config.observer_config_path,
        &config.observer_profile_digest,
    )?;
    validate_file_digest(
        &config.validator_config_path,
        &config.validator_profile_digest,
    )?;
    validate_file_digest(
        &config.validator_network_key_path,
        &config.validator_network_key_digest,
    )?;
    let database = fs::symlink_metadata(&config.database_path)?;
    if !database.file_type().is_dir() {
        return Err(AgentError::InvalidDatabaseDirectory(
            config.database_path.clone(),
        ));
    }
    Ok(())
}

fn validate_file_digest(path: &Path, expected: &str) -> Result<(), AgentError> {
    validate_regular_file(path)?;
    let bytes = fs::read(path)?;
    let actual: [u8; 32] = Blake2b256::digest(&bytes).into();
    let expected: [u8; 32] = hex::decode(expected)
        .expect("validated file digest")
        .try_into()
        .expect("validated file digest length");
    if actual != expected {
        return Err(AgentError::FileDigestMismatch(path.to_owned()));
    }
    Ok(())
}

fn load_state(path: &Path) -> Result<Option<PersistedAgentState>, AgentError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(AgentError::Io(error)),
    };
    if bytes.len() < CHECKSUM_BYTES {
        return Err(AgentError::CorruptState(path.to_owned()));
    }
    let checksum_offset = bytes.len() - CHECKSUM_BYTES;
    let actual: [u8; CHECKSUM_BYTES] = Blake2b256::digest(&bytes[..checksum_offset]).into();
    if actual != bytes[checksum_offset..] {
        return Err(AgentError::CorruptState(path.to_owned()));
    }
    let state = bcs::from_bytes(&bytes[..checksum_offset]).map_err(AgentError::Deserialize)?;
    Ok(Some(state))
}

fn save_state(path: &Path, state: &PersistedAgentState) -> Result<(), AgentError> {
    let parent = path
        .parent()
        .ok_or_else(|| AgentError::InvalidStatePath(path.to_owned()))?;
    let payload = bcs::to_bytes(state).map_err(AgentError::Serialize)?;
    let checksum: [u8; CHECKSUM_BYTES] = Blake2b256::digest(&payload).into();
    let temporary = parent.join(format!(
        ".sui-validator-agent-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
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
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok::<_, std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("invalid agent configuration: {0}")]
    InvalidConfig(anyhow::Error),
    #[error("invalid operation ID")]
    InvalidOperationId,
    #[error("operation ID {0} was reused for a different action")]
    OperationConflict(String),
    #[error("operation {0} must be resumed before another mutation")]
    OperationInProgress(String),
    #[error("service must be inactive before profile activation; current state is {0:?}")]
    ServiceMustBeInactive(ServiceState),
    #[error("service did not stop; current state is {0:?}")]
    ServiceDidNotStop(ServiceState),
    #[error("service did not start; current state is {0:?}")]
    ServiceDidNotStart(ServiceState),
    #[error("supervisor {action} failed: {stderr}")]
    SupervisorCommand { action: String, stderr: String },
    #[error("active config is not a symlink: {0}")]
    ActiveConfigNotSymlink(PathBuf),
    #[error("active config points to an unknown profile: {0}")]
    UnknownProfileTarget(PathBuf),
    #[error("configured artifact is not a regular file: {0}")]
    InvalidArtifactFile(PathBuf),
    #[error("configured file digest does not match {0}")]
    FileDigestMismatch(PathBuf),
    #[error("configured database path is not a directory: {0}")]
    InvalidDatabaseDirectory(PathBuf),
    #[error("could not find a mounted filesystem for database path {0}")]
    DatabaseMountNotFound(PathBuf),
    #[error("systemd returned an invalid {0} property")]
    InvalidSupervisorProperty(&'static str),
    #[error("invalid state path: {0}")]
    InvalidStatePath(PathBuf),
    #[error("corrupt agent state: {0}")]
    CorruptState(PathBuf),
    #[error("unsupported agent state version {0}")]
    UnsupportedStateVersion(u16),
    #[error("agent state lock poisoned")]
    LockPoisoned,
    #[cfg(not(unix))]
    #[error("validator profile switching requires a Unix host")]
    UnsupportedPlatform,
    #[error("failed to serialize agent state: {0}")]
    Serialize(bcs::Error),
    #[error("failed to deserialize agent state: {0}")]
    Deserialize(bcs::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use tempfile::TempDir;

    use super::*;

    #[derive(Clone)]
    struct TestSupervisor {
        active: Arc<AtomicBool>,
        fail_next_start: Arc<AtomicBool>,
        fail_after_start: Arc<AtomicBool>,
        starts: Arc<AtomicUsize>,
    }

    impl Supervisor for TestSupervisor {
        fn status(&self) -> Result<ServiceState, AgentError> {
            Ok(if self.active.load(Ordering::SeqCst) {
                ServiceState::Active
            } else {
                ServiceState::Inactive
            })
        }

        fn stop(&self) -> Result<(), AgentError> {
            self.active.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn start(&self) -> Result<(), AgentError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            if self.fail_next_start.swap(false, Ordering::SeqCst) {
                return Err(AgentError::SupervisorCommand {
                    action: "start".to_owned(),
                    stderr: "injected".to_owned(),
                });
            }
            self.active.store(true, Ordering::SeqCst);
            if self.fail_after_start.swap(false, Ordering::SeqCst) {
                return Err(AgentError::SupervisorCommand {
                    action: "start".to_owned(),
                    stderr: "injected after activation".to_owned(),
                });
            }
            Ok(())
        }
    }

    fn setup(active: bool) -> (TempDir, Agent<TestSupervisor>, TestSupervisor) {
        let directory = TempDir::new().unwrap();
        let observer = directory.path().join("observer.yaml");
        let validator = directory.path().join("validator.yaml");
        let network_key = directory.path().join("network.key");
        fs::write(&observer, "observer").unwrap();
        fs::write(&validator, "validator").unwrap();
        fs::write(&network_key, "network-key-material").unwrap();
        let config = AgentConfig {
            host_id: "validator-a".to_owned(),
            service_name: "sui-node.service".to_owned(),
            systemctl_path: "/usr/bin/systemctl".into(),
            timedatectl_path: "/usr/bin/timedatectl".into(),
            active_config_path: directory.path().join("active.yaml"),
            observer_config_path: observer.clone(),
            validator_config_path: validator.clone(),
            validator_network_key_path: network_key.clone(),
            database_path: directory.path().to_path_buf(),
            state_path: directory.path().join("agent.bcs"),
            min_database_available_bytes: 1,
            max_service_restarts: 3,
            observer_profile_digest: file_digest(&observer),
            validator_profile_digest: file_digest(&validator),
            validator_network_key_digest: file_digest(&network_key),
            protocol_public_key: hex::encode([1; 96]),
            worker_public_key: hex::encode([2; 32]),
            network_public_key: hex::encode([3; 32]),
        };
        let supervisor = TestSupervisor {
            active: Arc::new(AtomicBool::new(active)),
            fail_next_start: Arc::new(AtomicBool::new(false)),
            fail_after_start: Arc::new(AtomicBool::new(false)),
            starts: Arc::new(AtomicUsize::new(0)),
        };
        let agent = Agent::open(config, supervisor.clone()).unwrap();
        (directory, agent, supervisor)
    }

    fn file_digest(path: &Path) -> String {
        hex::encode(Blake2b256::digest(fs::read(path).unwrap()))
    }

    #[test]
    fn activation_is_atomic_and_idempotent() {
        let (_directory, agent, supervisor) = setup(false);
        let status = agent
            .activate("promote-001", NodeProfile::Validator)
            .unwrap();
        assert_eq!(status.profile, Some(NodeProfile::Validator));
        assert_eq!(status.service_state, ServiceState::Active);
        assert_eq!(supervisor.starts.load(Ordering::SeqCst), 1);

        let status = agent
            .activate("promote-001", NodeProfile::Validator)
            .unwrap();
        assert_eq!(status.service_state, ServiceState::Active);
        assert_eq!(supervisor.starts.load(Ordering::SeqCst), 1);
        assert!(matches!(
            agent.activate("promote-001", NodeProfile::Observer),
            Err(AgentError::OperationConflict(_))
        ));
    }

    #[test]
    fn failed_start_must_be_resumed_with_the_same_operation() {
        let (_directory, agent, supervisor) = setup(false);
        supervisor.fail_next_start.store(true, Ordering::SeqCst);
        assert!(
            agent
                .activate("promote-002", NodeProfile::Validator)
                .is_err()
        );
        assert!(matches!(
            agent.stop("different-operation"),
            Err(AgentError::OperationInProgress(_))
        ));

        let status = agent
            .activate("promote-002", NodeProfile::Validator)
            .unwrap();
        assert_eq!(status.service_state, ServiceState::Active);
        assert_eq!(supervisor.starts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn active_service_cannot_change_profiles() {
        let (_directory, agent, _supervisor) = setup(true);
        assert!(matches!(
            agent.activate("promote-003", NodeProfile::Validator),
            Err(AgentError::ServiceMustBeInactive(ServiceState::Active))
        ));
    }

    #[test]
    fn profile_or_network_key_tampering_fails_closed() {
        let (directory, agent, _supervisor) = setup(false);
        fs::write(directory.path().join("validator.yaml"), "tampered").unwrap();
        assert!(matches!(
            agent.status(),
            Err(AgentError::FileDigestMismatch(path))
                if path == directory.path().join("validator.yaml")
        ));

        let (directory, agent, _supervisor) = setup(false);
        fs::write(directory.path().join("network.key"), "other-key").unwrap();
        assert!(matches!(
            agent.activate("promote-tampered", NodeProfile::Validator),
            Err(AgentError::FileDigestMismatch(path))
                if path == directory.path().join("network.key")
        ));
    }

    #[test]
    fn resumed_activation_recovers_after_start_succeeded_before_reply() {
        let (_directory, agent, supervisor) = setup(false);
        supervisor.fail_after_start.store(true, Ordering::SeqCst);
        assert!(
            agent
                .activate("promote-004", NodeProfile::Validator)
                .is_err()
        );
        assert!(supervisor.active.load(Ordering::SeqCst));

        let status = agent
            .activate("promote-004", NodeProfile::Validator)
            .unwrap();
        assert_eq!(status.service_state, ServiceState::Active);
        assert_eq!(status.profile, Some(NodeProfile::Validator));
        assert_eq!(supervisor.starts.load(Ordering::SeqCst), 1);
    }
}
