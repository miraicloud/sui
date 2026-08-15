// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeSet, fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sui_validator_signer::client::ExternalSignerConfig;

use crate::{client::AgentClientConfig, config::ensure_private_file};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ControllerDaemonConfig {
    pub listen_address: SocketAddr,
    pub state_path: PathBuf,
    pub api_bearer_token_path: PathBuf,
    pub signer: ExternalSignerConfig,
    pub hosts: Vec<ControllerHostConfig>,
    #[serde(default = "default_max_checkpoint_lag")]
    pub max_checkpoint_lag: u64,
    #[serde(default = "default_max_commit_lag")]
    pub max_commit_lag: u64,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_handoff_timeout_ms")]
    pub handoff_timeout_ms: u64,
    #[serde(default = "default_metrics_timeout_ms")]
    pub metrics_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ControllerHostConfig {
    pub host_id: String,
    pub expected_holder_id: String,
    pub metrics_url: String,
    pub agent: AgentClientConfig,
}

impl ControllerDaemonConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read controller config {}", path.display()))?;
        let config: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse controller config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.listen_address.ip().is_loopback(),
            "controller must listen on a loopback address"
        );
        ensure!(self.state_path.is_absolute(), "state-path must be absolute");
        ensure!(
            self.api_bearer_token_path.is_absolute(),
            "api-bearer-token-path must be absolute"
        );
        ensure!(self.hosts.len() == 2, "exactly two hosts are required");
        ensure!(self.poll_interval_ms > 0, "poll interval must be nonzero");
        ensure!(
            self.handoff_timeout_ms > 0,
            "handoff timeout must be nonzero"
        );
        ensure!(
            self.metrics_timeout_ms > 0,
            "metrics timeout must be nonzero"
        );
        let mut host_ids = BTreeSet::new();
        let mut holder_ids = BTreeSet::new();
        for host in &self.hosts {
            ensure!(
                valid_identifier(&host.host_id),
                "invalid controller host-id"
            );
            ensure!(
                host.agent.expected_host_id == host.host_id,
                "host-id must match agent expected-host-id"
            );
            ensure!(host_ids.insert(&host.host_id), "duplicate host-id");
            let holder_id = host.parsed_holder_id()?;
            ensure!(holder_ids.insert(holder_id), "duplicate expected-holder-id");
            ensure!(
                host.metrics_url.starts_with("http://") || host.metrics_url.starts_with("https://"),
                "metrics-url must use HTTP or HTTPS"
            );
        }
        Ok(())
    }

    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }

    pub fn handoff_timeout(&self) -> Duration {
        Duration::from_millis(self.handoff_timeout_ms)
    }

    pub fn metrics_timeout(&self) -> Duration {
        Duration::from_millis(self.metrics_timeout_ms)
    }

    pub fn load_api_token(&self) -> Result<String> {
        ensure_private_file(&self.api_bearer_token_path)?;
        let token = fs::read_to_string(&self.api_bearer_token_path).with_context(|| {
            format!(
                "failed to read API bearer token {}",
                self.api_bearer_token_path.display()
            )
        })?;
        let token = token.trim().to_owned();
        ensure!(
            token.len() >= 32,
            "API bearer token must be at least 32 bytes"
        );
        ensure!(
            !token.chars().any(char::is_whitespace),
            "API bearer token must not contain whitespace"
        );
        Ok(token)
    }
}

impl ControllerHostConfig {
    pub fn parsed_holder_id(&self) -> Result<[u8; 32]> {
        ensure!(
            self.expected_holder_id == self.expected_holder_id.to_ascii_lowercase(),
            "expected-holder-id must be lowercase"
        );
        let bytes = hex::decode(&self.expected_holder_id)
            .context("expected-holder-id must be hexadecimal")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected-holder-id must contain exactly 32 bytes"))
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

const fn default_max_checkpoint_lag() -> u64 {
    5_000
}

const fn default_max_commit_lag() -> u64 {
    10_000
}

const fn default_poll_interval_ms() -> u64 {
    500
}

const fn default_handoff_timeout_ms() -> u64 {
    90_000
}

const fn default_metrics_timeout_ms() -> u64 {
    2_000
}
