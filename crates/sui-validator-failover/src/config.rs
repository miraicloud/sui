// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AgentConfig {
    pub host_id: String,
    pub service_name: String,
    pub systemctl_path: PathBuf,
    pub active_config_path: PathBuf,
    pub observer_config_path: PathBuf,
    pub validator_config_path: PathBuf,
    pub state_path: PathBuf,
    pub protocol_public_key: String,
    pub worker_public_key: String,
    pub network_public_key: String,
}

impl AgentConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read agent config {}", path.display()))?;
        let config: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse agent config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(valid_identifier(&self.host_id), "invalid host-id");
        ensure!(
            valid_service_name(&self.service_name),
            "invalid service-name"
        );
        for (name, path) in [
            ("systemctl-path", &self.systemctl_path),
            ("active-config-path", &self.active_config_path),
            ("observer-config-path", &self.observer_config_path),
            ("validator-config-path", &self.validator_config_path),
            ("state-path", &self.state_path),
        ] {
            ensure!(path.is_absolute(), "{name} must be absolute");
        }
        ensure!(
            self.observer_config_path != self.validator_config_path,
            "observer and validator profiles must differ"
        );
        validate_hex_key("protocol-public-key", &self.protocol_public_key, 96)?;
        validate_hex_key("worker-public-key", &self.worker_public_key, 32)?;
        validate_hex_key("network-public-key", &self.network_public_key, 32)?;
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_service_name(value: &str) -> bool {
    valid_identifier(value) && value.ends_with(".service")
}

fn validate_hex_key(name: &str, value: &str, expected_bytes: usize) -> Result<()> {
    let decoded = hex::decode(value).with_context(|| format!("{name} must be hexadecimal"))?;
    ensure!(
        decoded.len() == expected_bytes,
        "{name} must contain exactly {expected_bytes} bytes"
    );
    ensure!(
        value == value.to_ascii_lowercase(),
        "{name} must be lowercase"
    );
    Ok(())
}
