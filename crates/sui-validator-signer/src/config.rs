// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::protocol::ChainId;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SignerConfig {
    pub listen_address: SocketAddr,
    pub state_path: PathBuf,
    pub randomness_state_path: PathBuf,
    pub protocol_key_path: PathBuf,
    pub worker_key_path: PathBuf,
    pub chain_id: String,
    pub lease_holder_certificate_digests: Vec<String>,
    #[serde(default)]
    pub status_reader_certificate_digests: Vec<String>,
    #[serde(default = "default_max_lease_ttl_ms")]
    pub max_lease_ttl_ms: u64,
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
    pub tls: TlsConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
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
        ensure!(
            !config.lease_holder_certificate_digests.is_empty(),
            "at least one lease-holder certificate digest is required"
        );
        ensure!(
            config.chain_id == config.chain_id.to_ascii_lowercase(),
            "chain-id must be lowercase"
        );
        config.parsed_chain_id()?;
        let lease_holders = config.authorized_lease_holders()?;
        let status_readers = config.authorized_status_readers()?;
        ensure!(
            lease_holders.is_disjoint(&status_readers),
            "lease-holder and status-reader certificate allowlists must be disjoint"
        );
        for (name, path) in [
            ("state-path", &config.state_path),
            ("randomness-state-path", &config.randomness_state_path),
            ("protocol-key-path", &config.protocol_key_path),
            ("worker-key-path", &config.worker_key_path),
            ("tls.certificate-path", &config.tls.certificate_path),
            ("tls.private-key-path", &config.tls.private_key_path),
            ("tls.client-ca-path", &config.tls.client_ca_path),
        ] {
            ensure!(path.is_absolute(), "{name} must be absolute");
        }
        ensure!(
            config.state_path != config.randomness_state_path,
            "state-path and randomness-state-path must differ"
        );
        ensure!(
            config.protocol_key_path != config.worker_key_path,
            "protocol-key-path and worker-key-path must differ"
        );
        Ok(config)
    }

    pub fn parsed_chain_id(&self) -> Result<ChainId> {
        let bytes = hex::decode(&self.chain_id).context("chain-id must be hexadecimal")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("chain-id must contain exactly 32 bytes"))
    }

    pub fn authorized_lease_holders(&self) -> Result<BTreeSet<[u8; 32]>> {
        parse_certificate_digests(
            "lease-holder certificate digest",
            &self.lease_holder_certificate_digests,
        )
    }

    pub fn authorized_status_readers(&self) -> Result<BTreeSet<[u8; 32]>> {
        parse_certificate_digests(
            "status-reader certificate digest",
            &self.status_reader_certificate_digests,
        )
    }
}

fn parse_certificate_digests(name: &str, digests: &[String]) -> Result<BTreeSet<[u8; 32]>> {
    digests
        .iter()
        .map(|digest| {
            ensure!(
                digest == &digest.to_ascii_lowercase(),
                "{name} must be lowercase"
            );
            let bytes =
                hex::decode(digest).with_context(|| format!("{name} must be hexadecimal"))?;
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("{name} must contain exactly 32 bytes"))
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn config_yaml(lease_holder: &str, status_reader: &str) -> String {
        format!(
            r#"
listen-address: "127.0.0.1:19000"
state-path: /var/lib/signer/policy.journal
randomness-state-path: /var/lib/signer/randomness.bcs
protocol-key-path: /etc/signer/protocol.key
worker-key-path: /etc/signer/worker.key
chain-id: "{chain_id}"
lease-holder-certificate-digests:
  - "{lease_holder}"
status-reader-certificate-digests:
  - "{status_reader}"
tls:
  certificate-path: /etc/signer/server.crt
  private-key-path: /etc/signer/server.key
  client-ca-path: /etc/signer/ca.crt
"#,
            chain_id = hex::encode([7; 32]),
        )
    }

    fn load(yaml: &str) -> anyhow::Result<SignerConfig> {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("signer.yaml");
        fs::write(&path, yaml).unwrap();
        SignerConfig::load(&path)
    }

    #[test]
    fn accepts_distinct_certificate_roles_and_absolute_paths() {
        load(&config_yaml(&hex::encode([1; 32]), &hex::encode([2; 32]))).unwrap();
    }

    #[test]
    fn rejects_a_status_reader_that_can_also_sign() {
        let identity = hex::encode([1; 32]);
        assert!(
            load(&config_yaml(&identity, &identity))
                .unwrap_err()
                .to_string()
                .contains("must be disjoint")
        );
    }

    #[test]
    fn rejects_relative_key_paths_and_unknown_tls_fields() {
        let valid = config_yaml(&hex::encode([1; 32]), &hex::encode([2; 32]));
        assert!(
            load(&valid.replace(
                "protocol-key-path: /etc/signer/protocol.key",
                "protocol-key-path: protocol.key"
            ))
            .unwrap_err()
            .to_string()
            .contains("must be absolute")
        );
        assert!(
            load(&valid.replace(
                "  client-ca-path: /etc/signer/ca.crt",
                "  client-ca-path: /etc/signer/ca.crt\n  unexpected: true"
            ))
            .is_err()
        );
    }
}
