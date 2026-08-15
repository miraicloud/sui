// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use consensus_config::ProtocolKeyPair;
use sui_keys::keypair_file::{read_authority_keypair_from_file, read_network_keypair_from_file};
use sui_validator_signer::{
    config::{SignerConfig, ensure_private_directory, ensure_private_file},
    policy::{FileStateStore, SignerPolicy, SystemClock},
    rpc::ValidatorSignerServer,
    service::{SignerKeys, SignerService},
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;

#[derive(Debug, Parser)]
#[command(rename_all = "kebab-case")]
struct Args {
    #[arg(long)]
    config_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .init();
    let args = Args::parse();
    let config = SignerConfig::load(&args.config_path)?;

    ensure_private_file(&config.protocol_key_path)?;
    ensure_private_file(&config.worker_key_path)?;
    ensure_private_file(&config.tls.private_key_path)?;
    let state_directory = config
        .state_path
        .parent()
        .context("state-path must have a parent directory")?;
    ensure_private_directory(state_directory)?;

    let protocol =
        read_authority_keypair_from_file(&config.protocol_key_path).with_context(|| {
            format!(
                "failed to read protocol key {}",
                config.protocol_key_path.display()
            )
        })?;
    let worker = read_network_keypair_from_file(&config.worker_key_path).with_context(|| {
        format!(
            "failed to read worker key {}",
            config.worker_key_path.display()
        )
    })?;
    let policy = SignerPolicy::open(
        FileStateStore::new(&config.state_path),
        SystemClock,
        config.max_lease_ttl_ms,
    )?;
    let service = SignerService::new(
        policy,
        SignerKeys::new(protocol, ProtocolKeyPair::new(worker)),
        config.parsed_chain_id()?,
        config.max_payload_bytes,
    );

    let certificate = fs::read(&config.tls.certificate_path).with_context(|| {
        format!(
            "failed to read TLS certificate {}",
            config.tls.certificate_path.display()
        )
    })?;
    let private_key = fs::read(&config.tls.private_key_path).with_context(|| {
        format!(
            "failed to read TLS private key {}",
            config.tls.private_key_path.display()
        )
    })?;
    let client_ca = fs::read(&config.tls.client_ca_path).with_context(|| {
        format!(
            "failed to read client CA {}",
            config.tls.client_ca_path.display()
        )
    })?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(certificate, private_key))
        .client_ca_root(Certificate::from_pem(client_ca));

    info!(
        listen_address = %config.listen_address,
        state_path = %config.state_path.display(),
        "starting external validator signer"
    );
    Server::builder()
        .tls_config(tls)?
        .add_service(ValidatorSignerServer::new(service))
        .serve(config.listen_address)
        .await?;
    Ok(())
}
