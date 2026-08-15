// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};
use sui_validator_signer::{
    client::{ExternalSignerConfig, PublicKeys, SignerRpcClient},
    protocol::{HolderId, SignerStatus},
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    client::{AgentClientConfig, AgentRpcClient},
    metrics::ValidatorMetrics,
    protocol::{HostStatus, NodeProfile, ServiceState},
};

const STATE_VERSION: u16 = 1;
const CHECKSUM_BYTES: usize = 32;

#[async_trait]
pub trait AgentControl: Send + Sync {
    async fn status(&self) -> anyhow::Result<HostStatus>;
    async fn stop(&self, operation_id: String) -> anyhow::Result<HostStatus>;
    async fn activate(
        &self,
        operation_id: String,
        profile: NodeProfile,
    ) -> anyhow::Result<HostStatus>;
}

#[async_trait]
pub trait SignerControl: Send + Sync {
    async fn public_keys(&self) -> anyhow::Result<PublicKeys>;
    async fn status(&self) -> anyhow::Result<SignerStatus>;
}

#[async_trait]
pub trait MetricsSource: Send + Sync {
    async fn sample(&self) -> anyhow::Result<ValidatorMetrics>;
}

pub struct RemoteAgent {
    client: Mutex<AgentRpcClient>,
}

impl RemoteAgent {
    pub async fn connect(config: &AgentClientConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: Mutex::new(AgentRpcClient::connect(config).await?),
        })
    }
}

#[async_trait]
impl AgentControl for RemoteAgent {
    async fn status(&self) -> anyhow::Result<HostStatus> {
        Ok(self.client.lock().await.status().await?)
    }

    async fn stop(&self, operation_id: String) -> anyhow::Result<HostStatus> {
        Ok(self.client.lock().await.stop(operation_id).await?)
    }

    async fn activate(
        &self,
        operation_id: String,
        profile: NodeProfile,
    ) -> anyhow::Result<HostStatus> {
        Ok(self
            .client
            .lock()
            .await
            .activate(operation_id, profile)
            .await?)
    }
}

pub struct RemoteSigner {
    client: Mutex<SignerRpcClient>,
}

impl RemoteSigner {
    pub async fn connect(config: &ExternalSignerConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: Mutex::new(SignerRpcClient::connect(config).await?),
        })
    }
}

#[async_trait]
impl SignerControl for RemoteSigner {
    async fn public_keys(&self) -> anyhow::Result<PublicKeys> {
        Ok(self.client.lock().await.get_public_keys().await?)
    }

    async fn status(&self) -> anyhow::Result<SignerStatus> {
        Ok(self.client.lock().await.get_status().await?)
    }
}

pub struct HttpMetricsSource {
    client: reqwest::Client,
    url: String,
}

impl HttpMetricsSource {
    pub fn new(url: impl Into<String>, timeout: Duration) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder().timeout(timeout).build()?,
            url: url.into(),
        })
    }
}

#[async_trait]
impl MetricsSource for HttpMetricsSource {
    async fn sample(&self) -> anyhow::Result<ValidatorMetrics> {
        let response = self
            .client
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok(ValidatorMetrics::parse(&response)?)
    }
}

pub struct HostControl {
    pub host_id: String,
    pub expected_holder_id: HolderId,
    pub agent: Arc<dyn AgentControl>,
    pub metrics: Arc<dyn MetricsSource>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostSnapshot {
    pub host_id: String,
    pub expected_holder_id: String,
    pub status: HostStatus,
    pub metrics: ValidatorMetrics,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlSnapshot {
    pub hosts: Vec<HostSnapshot>,
    pub signer_public_keys: SignerPublicKeys,
    pub signer: SignerStatus,
    pub active_operation: Option<PromotionRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerPublicKeys {
    pub protocol_public_key: String,
    pub worker_public_key: String,
}

impl From<PublicKeys> for SignerPublicKeys {
    fn from(keys: PublicKeys) -> Self {
        Self {
            protocol_public_key: hex::encode(keys.protocol_bls12381),
            worker_public_key: hex::encode(keys.worker_ed25519),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ControllerRuntimeConfig {
    pub state_path: PathBuf,
    pub max_checkpoint_lag: u64,
    pub max_commit_lag: u64,
    pub poll_interval: Duration,
    pub handoff_timeout: Duration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PromotionPhase {
    Prepared,
    PreflightPassed,
    SourceStopped,
    LeaseFenced,
    TargetObserverStopped,
    TargetStarted,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PromotionRecord {
    pub operation_id: String,
    pub source_host: String,
    pub target_host: String,
    pub expected_source_generation: u64,
    pub phase: PromotionPhase,
    pub target_baseline: Option<ValidatorMetrics>,
    pub target_generation: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ControllerState {
    version: u16,
    active_operation: Option<String>,
    operations: BTreeMap<String, PromotionRecord>,
}

impl Default for ControllerState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            active_operation: None,
            operations: BTreeMap::new(),
        }
    }
}

pub struct ControlPlane {
    config: ControllerRuntimeConfig,
    hosts: BTreeMap<String, HostControl>,
    signer: Arc<dyn SignerControl>,
    state: Mutex<ControllerState>,
    execution: Mutex<()>,
}

impl ControlPlane {
    pub fn open(
        config: ControllerRuntimeConfig,
        hosts: impl IntoIterator<Item = HostControl>,
        signer: Arc<dyn SignerControl>,
    ) -> Result<Self, ControlError> {
        if config.poll_interval.is_zero() || config.handoff_timeout.is_zero() {
            return Err(ControlError::InvalidTiming);
        }
        let hosts = hosts
            .into_iter()
            .map(|host| (host.host_id.clone(), host))
            .collect::<BTreeMap<_, _>>();
        if hosts.len() < 2 {
            return Err(ControlError::InsufficientHosts);
        }
        let state = load_state(&config.state_path)?.unwrap_or_default();
        if state.version != STATE_VERSION {
            return Err(ControlError::UnsupportedStateVersion(state.version));
        }
        Ok(Self {
            config,
            hosts,
            signer,
            state: Mutex::new(state),
            execution: Mutex::new(()),
        })
    }

    pub async fn promotion(&self, operation_id: &str) -> Option<PromotionRecord> {
        self.state
            .lock()
            .await
            .operations
            .get(operation_id)
            .cloned()
    }

    pub async fn snapshot(&self) -> Result<ControlSnapshot, ControlError> {
        let mut hosts = Vec::with_capacity(self.hosts.len());
        for host in self.hosts.values() {
            let (status, metrics) = tokio::try_join!(
                async {
                    host.agent
                        .status()
                        .await
                        .map_err(|error| ControlError::Agent(host.host_id.clone(), error))
                },
                async {
                    host.metrics
                        .sample()
                        .await
                        .map_err(|error| ControlError::Metrics(host.host_id.clone(), error))
                }
            )?;
            hosts.push(HostSnapshot {
                host_id: host.host_id.clone(),
                expected_holder_id: hex::encode(host.expected_holder_id),
                status,
                metrics,
            });
        }
        let (signer, signer_public_keys) = tokio::try_join!(
            async { self.signer.status().await.map_err(ControlError::Signer) },
            async {
                self.signer
                    .public_keys()
                    .await
                    .map(SignerPublicKeys::from)
                    .map_err(ControlError::Signer)
            }
        )?;
        let state = self.state.lock().await;
        let active_operation = state
            .active_operation
            .as_ref()
            .and_then(|operation_id| state.operations.get(operation_id))
            .cloned();
        Ok(ControlSnapshot {
            hosts,
            signer_public_keys,
            signer,
            active_operation,
        })
    }

    pub async fn promote(
        &self,
        operation_id: String,
        source_host: String,
        target_host: String,
        expected_source_generation: u64,
    ) -> Result<PromotionRecord, ControlError> {
        validate_operation_id(&operation_id)?;
        if source_host == target_host {
            return Err(ControlError::SameHost);
        }
        let _execution = self.execution.lock().await;
        let source = self
            .hosts
            .get(&source_host)
            .ok_or_else(|| ControlError::UnknownHost(source_host.clone()))?;
        let target = self
            .hosts
            .get(&target_host)
            .ok_or_else(|| ControlError::UnknownHost(target_host.clone()))?;

        let mut record = {
            let mut state = self.state.lock().await;
            if let Some(existing) = state.operations.get(&operation_id) {
                if existing.source_host != source_host
                    || existing.target_host != target_host
                    || existing.expected_source_generation != expected_source_generation
                {
                    return Err(ControlError::OperationConflict(operation_id));
                }
                existing.clone()
            } else {
                if let Some(active) = &state.active_operation {
                    return Err(ControlError::OperationInProgress(active.clone()));
                }
                let record = PromotionRecord {
                    operation_id: operation_id.clone(),
                    source_host: source_host.clone(),
                    target_host: target_host.clone(),
                    expected_source_generation,
                    phase: PromotionPhase::Prepared,
                    target_baseline: None,
                    target_generation: None,
                };
                state.active_operation = Some(operation_id.clone());
                state
                    .operations
                    .insert(operation_id.clone(), record.clone());
                save_state(&self.config.state_path, &state)?;
                record
            }
        };

        if record.phase == PromotionPhase::Complete {
            return Ok(record);
        }

        if record.phase == PromotionPhase::Prepared {
            let baseline = self
                .preflight(source, target, expected_source_generation)
                .await?;
            record.target_baseline = Some(baseline);
            self.advance(&mut record, PromotionPhase::PreflightPassed)
                .await?;
        }

        if record.phase == PromotionPhase::PreflightPassed {
            let status = source
                .agent
                .stop(agent_operation_id(&operation_id, "stop-source"))
                .await
                .map_err(|error| ControlError::Agent(source_host.clone(), error))?;
            require_service(&status, NodeProfile::Validator, ServiceState::Inactive)?;
            self.advance(&mut record, PromotionPhase::SourceStopped)
                .await?;
        }

        if record.phase == PromotionPhase::SourceStopped {
            self.wait_for_lease_fence(source, expected_source_generation)
                .await?;
            self.advance(&mut record, PromotionPhase::LeaseFenced)
                .await?;
        }

        if record.phase == PromotionPhase::LeaseFenced {
            let source_status = source
                .agent
                .status()
                .await
                .map_err(|error| ControlError::Agent(source_host.clone(), error))?;
            require_service(
                &source_status,
                NodeProfile::Validator,
                ServiceState::Inactive,
            )?;
            let status = target
                .agent
                .stop(agent_operation_id(&operation_id, "stop-target"))
                .await
                .map_err(|error| ControlError::Agent(target_host.clone(), error))?;
            require_service(&status, NodeProfile::Observer, ServiceState::Inactive)?;
            self.advance(&mut record, PromotionPhase::TargetObserverStopped)
                .await?;
        }

        if record.phase == PromotionPhase::TargetObserverStopped {
            let status = target
                .agent
                .activate(
                    agent_operation_id(&operation_id, "start-target"),
                    NodeProfile::Validator,
                )
                .await
                .map_err(|error| ControlError::Agent(target_host.clone(), error))?;
            require_service(&status, NodeProfile::Validator, ServiceState::Active)?;
            self.advance(&mut record, PromotionPhase::TargetStarted)
                .await?;
        }

        if record.phase == PromotionPhase::TargetStarted {
            let baseline = record
                .target_baseline
                .as_ref()
                .ok_or(ControlError::MissingBaseline)?;
            let generation = self
                .wait_for_target_ready(target, baseline, expected_source_generation)
                .await?;
            record.target_generation = Some(generation);
            self.advance(&mut record, PromotionPhase::Complete).await?;
        }

        Ok(record)
    }

    async fn preflight(
        &self,
        source: &HostControl,
        target: &HostControl,
        expected_generation: u64,
    ) -> Result<ValidatorMetrics, ControlError> {
        let (
            source_status,
            target_status,
            source_metrics,
            target_metrics,
            signer_status,
            signer_public_keys,
        ) = tokio::try_join!(
            async {
                source
                    .agent
                    .status()
                    .await
                    .map_err(|error| ControlError::Agent(source.host_id.clone(), error))
            },
            async {
                target
                    .agent
                    .status()
                    .await
                    .map_err(|error| ControlError::Agent(target.host_id.clone(), error))
            },
            async {
                source
                    .metrics
                    .sample()
                    .await
                    .map_err(|error| ControlError::Metrics(source.host_id.clone(), error))
            },
            async {
                target
                    .metrics
                    .sample()
                    .await
                    .map_err(|error| ControlError::Metrics(target.host_id.clone(), error))
            },
            async { self.signer.status().await.map_err(ControlError::Signer) },
            async {
                self.signer
                    .public_keys()
                    .await
                    .map_err(ControlError::Signer)
            },
        )?;

        require_service(&source_status, NodeProfile::Validator, ServiceState::Active)?;
        require_service(&target_status, NodeProfile::Observer, ServiceState::Active)?;
        if source_status.protocol_public_key != target_status.protocol_public_key
            || source_status.worker_public_key != target_status.worker_public_key
            || source_status.network_public_key != target_status.network_public_key
        {
            return Err(ControlError::IdentityMismatch);
        }
        if source_status.protocol_public_key != hex::encode(signer_public_keys.protocol_bls12381)
            || source_status.worker_public_key != hex::encode(signer_public_keys.worker_ed25519)
        {
            return Err(ControlError::SignerIdentityMismatch);
        }
        if source_metrics.epoch != target_metrics.epoch {
            return Err(ControlError::EpochMismatch {
                source_epoch: source_metrics.epoch,
                target_epoch: target_metrics.epoch,
            });
        }
        if source_metrics.voting_right == 0 || target_metrics.voting_right != 0 {
            return Err(ControlError::VotingRoleMismatch);
        }
        if source_metrics.dkg_failed || target_metrics.dkg_failed {
            return Err(ControlError::DkgFailed);
        }
        if target_metrics.last_commit_index == 0
            || target_metrics.last_executed_checkpoint == 0
            || target_metrics.observer_subscribed_batches == 0
        {
            return Err(ControlError::ObserverNotWarm);
        }
        let checkpoint_lag = source_metrics
            .last_executed_checkpoint
            .saturating_sub(target_metrics.last_executed_checkpoint);
        if checkpoint_lag > self.config.max_checkpoint_lag {
            return Err(ControlError::CheckpointLag(checkpoint_lag));
        }
        let commit_lag = source_metrics
            .last_commit_index
            .saturating_sub(target_metrics.last_commit_index);
        if commit_lag > self.config.max_commit_lag {
            return Err(ControlError::CommitLag(commit_lag));
        }
        let lease = signer_status
            .current_lease
            .as_ref()
            .ok_or(ControlError::NoSourceLease)?;
        if lease.holder_id != source.expected_holder_id || lease.generation != expected_generation {
            return Err(ControlError::SourceLeaseMismatch);
        }
        require_randomness_ready(&signer_status, source_metrics.epoch)?;
        Ok(target_metrics)
    }

    async fn wait_for_lease_fence(
        &self,
        source: &HostControl,
        expected_generation: u64,
    ) -> Result<(), ControlError> {
        let deadline = tokio::time::Instant::now() + self.config.handoff_timeout;
        loop {
            let status = self.signer.status().await.map_err(ControlError::Signer)?;
            match status.current_lease {
                None => return Ok(()),
                Some(lease)
                    if lease.holder_id == source.expected_holder_id
                        && lease.generation == expected_generation => {}
                Some(_) => return Err(ControlError::UnexpectedLeaseHolder),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ControlError::LeaseFenceTimeout);
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn wait_for_target_ready(
        &self,
        target: &HostControl,
        baseline: &ValidatorMetrics,
        source_generation: u64,
    ) -> Result<u64, ControlError> {
        let deadline = tokio::time::Instant::now() + self.config.handoff_timeout;
        loop {
            let signer_status = self.signer.status().await.map_err(ControlError::Signer)?;
            if let Some(lease) = &signer_status.current_lease
                && lease.holder_id == target.expected_holder_id
                && lease.generation > source_generation
                && let Ok(agent_status) = target.agent.status().await
                && agent_status.profile == Some(NodeProfile::Validator)
                && agent_status.service_state == ServiceState::Active
                && let Ok(metrics) = target.metrics.sample().await
                && metrics.voting_right > 0
                && !metrics.dkg_failed
                && metrics.proposed_blocks > baseline.proposed_blocks
                && metrics.last_commit_index > baseline.last_commit_index
                && metrics.last_executed_checkpoint > baseline.last_executed_checkpoint
                && require_randomness_ready(&signer_status, metrics.epoch).is_ok()
            {
                return Ok(lease.generation);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ControlError::TargetReadinessTimeout);
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn advance(
        &self,
        record: &mut PromotionRecord,
        phase: PromotionPhase,
    ) -> Result<(), ControlError> {
        record.phase = phase;
        let mut state = self.state.lock().await;
        state
            .operations
            .insert(record.operation_id.clone(), record.clone());
        if record.phase == PromotionPhase::Complete {
            state.active_operation = None;
        }
        save_state(&self.config.state_path, &state)
    }
}

fn require_service(
    status: &HostStatus,
    profile: NodeProfile,
    service_state: ServiceState,
) -> Result<(), ControlError> {
    if status.profile != Some(profile) || status.service_state != service_state {
        return Err(ControlError::HostRoleMismatch {
            host: status.host_id.clone(),
            expected_profile: profile,
            expected_service_state: service_state,
        });
    }
    Ok(())
}

fn require_randomness_ready(status: &SignerStatus, epoch: u64) -> Result<(), ControlError> {
    if !status
        .randomness_sessions
        .iter()
        .any(|session| session.epoch == epoch && session.shares_ready)
    {
        return Err(ControlError::RandomnessNotReady(epoch));
    }
    Ok(())
}

fn validate_operation_id(operation_id: &str) -> Result<(), ControlError> {
    if operation_id.is_empty()
        || operation_id.len() > 80
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ControlError::InvalidOperationId);
    }
    Ok(())
}

fn agent_operation_id(operation_id: &str, action: &str) -> String {
    format!("{operation_id}-{action}")
}

fn load_state(path: &Path) -> Result<Option<ControllerState>, ControlError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ControlError::Io(error)),
    };
    if bytes.len() < CHECKSUM_BYTES {
        return Err(ControlError::CorruptState(path.to_owned()));
    }
    let checksum_offset = bytes.len() - CHECKSUM_BYTES;
    let checksum: [u8; CHECKSUM_BYTES] = Blake2b256::digest(&bytes[..checksum_offset]).into();
    if checksum != bytes[checksum_offset..] {
        return Err(ControlError::CorruptState(path.to_owned()));
    }
    let state = bcs::from_bytes(&bytes[..checksum_offset]).map_err(ControlError::Deserialize)?;
    Ok(Some(state))
}

fn save_state(path: &Path, state: &ControllerState) -> Result<(), ControlError> {
    let parent = path
        .parent()
        .ok_or_else(|| ControlError::InvalidStatePath(path.to_owned()))?;
    let payload = bcs::to_bytes(state).map_err(ControlError::Serialize)?;
    let checksum: [u8; CHECKSUM_BYTES] = Blake2b256::digest(&payload).into();
    let temporary = parent.join(format!(
        ".sui-validator-control-{}-{:016x}",
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
pub enum ControlError {
    #[error("invalid controller timing configuration")]
    InvalidTiming,
    #[error("at least two validator hosts are required")]
    InsufficientHosts,
    #[error("invalid operation ID")]
    InvalidOperationId,
    #[error("source and target hosts must differ")]
    SameHost,
    #[error("unknown validator host {0}")]
    UnknownHost(String),
    #[error("operation ID {0} conflicts with its durable request")]
    OperationConflict(String),
    #[error("operation {0} must finish before another promotion")]
    OperationInProgress(String),
    #[error(
        "host {host} does not have expected profile {expected_profile:?} and service state {expected_service_state:?}"
    )]
    HostRoleMismatch {
        host: String,
        expected_profile: NodeProfile,
        expected_service_state: ServiceState,
    },
    #[error("candidate validator key fingerprints differ")]
    IdentityMismatch,
    #[error("candidate protocol or worker identity does not match the external signer")]
    SignerIdentityMismatch,
    #[error("candidate epochs differ: source {source_epoch}, target {target_epoch}")]
    EpochMismatch {
        source_epoch: u64,
        target_epoch: u64,
    },
    #[error("candidate voting roles do not match active/observer expectations")]
    VotingRoleMismatch,
    #[error("randomness DKG failure metric is set")]
    DkgFailed,
    #[error("observer has not demonstrated commit, checkpoint, and subscription progress")]
    ObserverNotWarm,
    #[error("observer checkpoint lag {0} exceeds policy")]
    CheckpointLag(u64),
    #[error("observer commit lag {0} exceeds policy")]
    CommitLag(u64),
    #[error("signer reports no active source lease")]
    NoSourceLease,
    #[error("source signer lease does not match the expected holder and generation")]
    SourceLeaseMismatch,
    #[error("signer randomness shares are not ready for epoch {0}")]
    RandomnessNotReady(u64),
    #[error("signer lease changed to an unexpected holder during fencing")]
    UnexpectedLeaseHolder,
    #[error("timed out waiting for source signer lease to release or expire")]
    LeaseFenceTimeout,
    #[error("timed out waiting for target lease and validator progress")]
    TargetReadinessTimeout,
    #[error("promotion record is missing its target metrics baseline")]
    MissingBaseline,
    #[error("validator agent {0} failed: {1}")]
    Agent(String, anyhow::Error),
    #[error("validator metrics for {0} failed: {1}")]
    Metrics(String, anyhow::Error),
    #[error("validator signer status failed: {0}")]
    Signer(anyhow::Error),
    #[error("invalid controller state path: {0}")]
    InvalidStatePath(PathBuf),
    #[error("controller state is corrupt: {0}")]
    CorruptState(PathBuf),
    #[error("unsupported controller state version {0}")]
    UnsupportedStateVersion(u16),
    #[error("failed to serialize controller state: {0}")]
    Serialize(bcs::Error),
    #[error("failed to deserialize controller state: {0}")]
    Deserialize(bcs::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};

    use sui_validator_signer::protocol::{DkgSessionStatus, LeaseStatus};
    use tempfile::TempDir;

    use super::*;
    use crate::protocol::OperationStatus;

    struct Shared {
        hosts: StdMutex<BTreeMap<String, HostStatus>>,
        metrics: StdMutex<BTreeMap<String, ValidatorMetrics>>,
        signer: StdMutex<SignerStatus>,
        signer_public_keys: StdMutex<PublicKeys>,
        events: StdMutex<Vec<String>>,
        release_source_lease: bool,
        target_holder: HolderId,
    }

    struct MockAgent {
        host_id: String,
        shared: Arc<Shared>,
    }

    #[async_trait]
    impl AgentControl for MockAgent {
        async fn status(&self) -> anyhow::Result<HostStatus> {
            Ok(self.shared.hosts.lock().unwrap()[&self.host_id].clone())
        }

        async fn stop(&self, _operation_id: String) -> anyhow::Result<HostStatus> {
            self.shared
                .events
                .lock()
                .unwrap()
                .push(format!("{}-stop", self.host_id));
            let mut hosts = self.shared.hosts.lock().unwrap();
            let host = hosts.get_mut(&self.host_id).unwrap();
            host.service_state = ServiceState::Inactive;
            let result = host.clone();
            drop(hosts);
            if self.host_id == "source" && self.shared.release_source_lease {
                self.shared.signer.lock().unwrap().current_lease = None;
            }
            Ok(result)
        }

        async fn activate(
            &self,
            _operation_id: String,
            profile: NodeProfile,
        ) -> anyhow::Result<HostStatus> {
            self.shared
                .events
                .lock()
                .unwrap()
                .push(format!("{}-activate-{profile:?}", self.host_id));
            let mut hosts = self.shared.hosts.lock().unwrap();
            let host = hosts.get_mut(&self.host_id).unwrap();
            host.profile = Some(profile);
            host.service_state = ServiceState::Active;
            let result = host.clone();
            drop(hosts);
            if self.host_id == "target" && profile == NodeProfile::Validator {
                self.shared.signer.lock().unwrap().current_lease = Some(LeaseStatus {
                    holder_id: self.shared.target_holder,
                    generation: 2,
                    expires_at_unix_ms: 10_000,
                });
                let mut metrics = self.shared.metrics.lock().unwrap();
                let target = metrics.get_mut("target").unwrap();
                target.voting_right = 100;
                target.proposed_blocks += 1;
                target.last_commit_index += 1;
                target.last_executed_checkpoint += 1;
            }
            Ok(result)
        }
    }

    struct MockMetrics {
        host_id: String,
        shared: Arc<Shared>,
    }

    #[async_trait]
    impl MetricsSource for MockMetrics {
        async fn sample(&self) -> anyhow::Result<ValidatorMetrics> {
            Ok(self.shared.metrics.lock().unwrap()[&self.host_id].clone())
        }
    }

    struct MockSigner(Arc<Shared>);

    #[async_trait]
    impl SignerControl for MockSigner {
        async fn public_keys(&self) -> anyhow::Result<PublicKeys> {
            Ok(self.0.signer_public_keys.lock().unwrap().clone())
        }

        async fn status(&self) -> anyhow::Result<SignerStatus> {
            Ok(self.0.signer.lock().unwrap().clone())
        }
    }

    fn host_status(host_id: &str, profile: NodeProfile, state: ServiceState) -> HostStatus {
        HostStatus {
            host_id: host_id.to_owned(),
            profile: Some(profile),
            service_state: state,
            protocol_public_key: hex::encode([1; 96]),
            worker_public_key: hex::encode([2; 32]),
            network_public_key: hex::encode([3; 32]),
            operation: None::<OperationStatus>,
        }
    }

    fn metrics(voting_right: u64, commit: u64, checkpoint: u64, observer: u64) -> ValidatorMetrics {
        ValidatorMetrics {
            epoch: 7,
            voting_right,
            last_commit_index: commit,
            last_executed_checkpoint: checkpoint,
            proposed_blocks: if voting_right > 0 { 10 } else { 0 },
            observer_subscribed_batches: observer,
            dkg_failed: false,
        }
    }

    fn setup(
        release_source_lease: bool,
    ) -> (TempDir, ControlPlane, Arc<Shared>, HolderId, HolderId) {
        let directory = TempDir::new().unwrap();
        let source_holder = [4; 32];
        let target_holder = [5; 32];
        let shared = Arc::new(Shared {
            hosts: StdMutex::new(BTreeMap::from([
                (
                    "source".to_owned(),
                    host_status("source", NodeProfile::Validator, ServiceState::Active),
                ),
                (
                    "target".to_owned(),
                    host_status("target", NodeProfile::Observer, ServiceState::Active),
                ),
            ])),
            metrics: StdMutex::new(BTreeMap::from([
                ("source".to_owned(), metrics(100, 1_000, 2_000, 0)),
                ("target".to_owned(), metrics(0, 995, 1_998, 50)),
            ])),
            signer: StdMutex::new(SignerStatus {
                current_lease: Some(LeaseStatus {
                    holder_id: source_holder,
                    generation: 1,
                    expires_at_unix_ms: 10_000,
                }),
                next_generation: 2,
                observed_at_unix_ms: 1_000,
                last_seen_unix_ms: 1_000,
                decision_count: 10,
                randomness_sessions: vec![DkgSessionStatus {
                    epoch: 7,
                    party_id: 0,
                    threshold: 3,
                    processed_messages: 4,
                    confirmations: 4,
                    merged: true,
                    shares_ready: true,
                }],
            }),
            signer_public_keys: StdMutex::new(PublicKeys {
                protocol_bls12381: vec![1; 96],
                worker_ed25519: vec![2; 32],
            }),
            events: StdMutex::new(Vec::new()),
            release_source_lease,
            target_holder,
        });
        let hosts = [
            HostControl {
                host_id: "source".to_owned(),
                expected_holder_id: source_holder,
                agent: Arc::new(MockAgent {
                    host_id: "source".to_owned(),
                    shared: shared.clone(),
                }),
                metrics: Arc::new(MockMetrics {
                    host_id: "source".to_owned(),
                    shared: shared.clone(),
                }),
            },
            HostControl {
                host_id: "target".to_owned(),
                expected_holder_id: target_holder,
                agent: Arc::new(MockAgent {
                    host_id: "target".to_owned(),
                    shared: shared.clone(),
                }),
                metrics: Arc::new(MockMetrics {
                    host_id: "target".to_owned(),
                    shared: shared.clone(),
                }),
            },
        ];
        let control = ControlPlane::open(
            ControllerRuntimeConfig {
                state_path: directory.path().join("control.bcs"),
                max_checkpoint_lag: 5,
                max_commit_lag: 10,
                poll_interval: Duration::from_millis(5),
                handoff_timeout: Duration::from_millis(50),
            },
            hosts,
            Arc::new(MockSigner(shared.clone())),
        )
        .unwrap();
        (directory, control, shared, source_holder, target_holder)
    }

    #[tokio::test]
    async fn snapshot_maps_hosts_to_signer_identity_without_mutation() {
        let (_directory, control, shared, source_holder, _target_holder) = setup(true);
        let snapshot = control.snapshot().await.unwrap();
        assert_eq!(snapshot.hosts.len(), 2);
        assert_eq!(
            snapshot.signer.current_lease.as_ref().unwrap().holder_id,
            source_holder
        );
        assert_eq!(
            snapshot.hosts[0].expected_holder_id,
            hex::encode(source_holder)
        );
        assert_eq!(
            snapshot.signer_public_keys.protocol_public_key,
            hex::encode([1; 96])
        );
        assert!(snapshot.active_operation.is_none());
        assert!(shared.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn promotion_fences_source_before_starting_target() {
        let (_directory, control, shared, _source_holder, _target_holder) = setup(true);
        let record = control
            .promote(
                "drill-001".to_owned(),
                "source".to_owned(),
                "target".to_owned(),
                1,
            )
            .await
            .unwrap();
        assert_eq!(record.phase, PromotionPhase::Complete);
        assert_eq!(record.target_generation, Some(2));
        assert_eq!(
            *shared.events.lock().unwrap(),
            vec!["source-stop", "target-stop", "target-activate-Validator"]
        );
        {
            let hosts = shared.hosts.lock().unwrap();
            assert_eq!(hosts["source"].service_state, ServiceState::Inactive);
            assert_eq!(hosts["target"].profile, Some(NodeProfile::Validator));
        }

        let repeated = control
            .promote(
                "drill-001".to_owned(),
                "source".to_owned(),
                "target".to_owned(),
                1,
            )
            .await
            .unwrap();
        assert_eq!(repeated, record);
        assert_eq!(shared.events.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn identity_mismatch_prevents_any_mutation() {
        let (_directory, control, shared, _source_holder, _target_holder) = setup(true);
        shared
            .hosts
            .lock()
            .unwrap()
            .get_mut("target")
            .unwrap()
            .network_public_key = hex::encode([9; 32]);
        assert!(matches!(
            control
                .promote(
                    "drill-002".to_owned(),
                    "source".to_owned(),
                    "target".to_owned(),
                    1,
                )
                .await,
            Err(ControlError::IdentityMismatch)
        ));
        assert!(shared.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn signer_identity_mismatch_prevents_any_mutation() {
        let (_directory, control, shared, _source_holder, _target_holder) = setup(true);
        shared.signer_public_keys.lock().unwrap().worker_ed25519 = vec![9; 32];
        assert!(matches!(
            control
                .promote(
                    "drill-signer-mismatch".to_owned(),
                    "source".to_owned(),
                    "target".to_owned(),
                    1,
                )
                .await,
            Err(ControlError::SignerIdentityMismatch)
        ));
        assert!(shared.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn target_never_starts_before_source_lease_is_fenced() {
        let (_directory, control, shared, _source_holder, _target_holder) = setup(false);
        assert!(matches!(
            control
                .promote(
                    "drill-003".to_owned(),
                    "source".to_owned(),
                    "target".to_owned(),
                    1,
                )
                .await,
            Err(ControlError::LeaseFenceTimeout)
        ));
        assert_eq!(*shared.events.lock().unwrap(), vec!["source-stop"]);
        assert_eq!(
            shared.hosts.lock().unwrap()["target"].profile,
            Some(NodeProfile::Observer)
        );
    }
}
