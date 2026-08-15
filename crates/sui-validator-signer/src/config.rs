// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::protocol::ChainId;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SignerConfig {
    pub listen_address: SocketAddr,
    pub state_path: PathBuf,
    pub randomness_state_path: PathBuf,
    pub protocol_key_path: PathBuf,
    pub worker_key_path: PathBuf,
    pub chain_id: String,
    #[serde(default = "default_max_lease_ttl_ms")]
    pub max_lease_ttl_ms: u64,
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    pub tls: TlsConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlsConfig {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub client_ca_path: PathBuf,
}

impl SignerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read signer config {}", path.display()))?;
        let config: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse signer config {}", path.display()))?;
        ensure!(config.max_lease_ttl_ms > 0, "max lease TTL must be nonzero");
        ensure!(
            config.max_payload_bytes > 0,
            "max payload size must be nonzero"
        );
        Ok(config)
    }

    pub fn parsed_chain_id(&self) -> Result<ChainId> {
        let bytes = hex::decode(&self.chain_id).context("chain-id must be hexadecimal")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("chain-id must contain exactly 32 bytes"))
    }
}

const fn default_max_lease_ttl_ms() -> u64 {
    30_000
}

const fn default_max_payload_bytes() -> usize {
    4 * 1024 * 1024
}

pub fn ensure_private_file(path: &Path) -> Result<()> {
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

pub fn ensure_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "{} is not a directory",
        path.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "private directory {} must not be accessible by group or other users",
            path.display()
        );
    }
    Ok(())
}
