// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AgentConfig {
    pub host_id: String,
    pub service_name: String,
    pub systemctl_path: PathBuf,
    pub timedatectl_path: PathBuf,
    pub active_config_path: PathBuf,
    pub observer_config_path: PathBuf,
    pub validator_config_path: PathBuf,
    pub validator_network_key_path: PathBuf,
    pub database_path: PathBuf,
    pub state_path: PathBuf,
    pub min_database_available_bytes: u64,
    pub max_service_restarts: u64,
    pub observer_profile_digest: String,
    pub validator_profile_digest: String,
    pub validator_network_key_digest: String,
    pub protocol_public_key: String,
    pub worker_public_key: String,
    pub network_public_key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AgentDaemonConfig {
    pub listen_address: SocketAddr,
    pub agent: AgentConfig,
    pub authorized_client_certificate_digests: Vec<String>,
    pub tls: TlsConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub client_ca_path: PathBuf,
}

impl AgentDaemonConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read agent daemon config {}", path.display()))?;
        let config: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse agent daemon config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        self.agent.validate()?;
        ensure!(
            !self.authorized_client_certificate_digests.is_empty(),
            "at least one authorized client certificate digest is required"
        );
        for digest in &self.authorized_client_certificate_digests {
            validate_hex_key("authorized client certificate digest", digest, 32)?;
        }
        for (name, path) in [
            ("tls.certificate-path", &self.tls.certificate_path),
            ("tls.private-key-path", &self.tls.private_key_path),
            ("tls.client-ca-path", &self.tls.client_ca_path),
        ] {
            ensure!(path.is_absolute(), "{name} must be absolute");
        }
        Ok(())
    }
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
            ("timedatectl-path", &self.timedatectl_path),
            ("active-config-path", &self.active_config_path),
            ("observer-config-path", &self.observer_config_path),
            ("validator-config-path", &self.validator_config_path),
            (
                "validator-network-key-path",
                &self.validator_network_key_path,
            ),
            ("database-path", &self.database_path),
            ("state-path", &self.state_path),
        ] {
            ensure!(path.is_absolute(), "{name} must be absolute");
        }
        ensure!(
            self.observer_config_path != self.validator_config_path,
            "observer and validator profiles must differ"
        );
        ensure!(
            self.min_database_available_bytes > 0,
            "min-database-available-bytes must be nonzero"
        );
        validate_hex_key("observer-profile-digest", &self.observer_profile_digest, 32)?;
        validate_hex_key(
            "validator-profile-digest",
            &self.validator_profile_digest,
            32,
        )?;
        validate_hex_key(
            "validator-network-key-digest",
            &self.validator_network_key_digest,
            32,
        )?;
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

pub fn ensure_private_file(path: &std::path::Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "{} is not a regular file",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "private file {} must not be accessible by group or other users",
            path.display()
        );
    }
    Ok(())
}
