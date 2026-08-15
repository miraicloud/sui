// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use sui_validator_failover::{
    agent::{Agent, SystemdSupervisor},
    config::{AgentDaemonConfig, ensure_private_file},
    rpc::ValidatorAgentServer,
    service::AgentService,
};
use sui_validator_signer::config::ensure_private_directory;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;

bin_version::bin_version!();

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    rename_all = "kebab-case",
    version = VERSION
)]
struct Args {
    #[arg(long)]
    config_path: PathBuf,
    /// Validate pinned artifacts and TLS without invoking systemd or listening.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .init();
    let args = Args::parse();
    let config = AgentDaemonConfig::load(&args.config_path)?;
    ensure_private_file(&config.tls.private_key_path)?;
    let state_directory = config
        .agent
        .state_path
        .parent()
        .context("agent state-path must have a parent directory")?;
    ensure_private_directory(state_directory)?;
    let supervisor = SystemdSupervisor::new(&config.agent);
    let agent = Agent::open(config.agent.clone(), supervisor)?;
    let authorized_clients = config
        .authorized_client_certificate_digests
        .iter()
        .map(|digest| {
            let bytes = hex::decode(digest).expect("validated certificate digest");
            bytes
                .try_into()
                .expect("validated certificate digest length")
        })
        .collect::<Vec<_>>();
    let service = AgentService::new(agent, authorized_clients)?;

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

    if args.check_config {
        Server::builder().tls_config(tls)?;
        println!("configuration valid");
        println!("host-id: {}", config.agent.host_id);
        println!(
            "observer-profile-digest: {}",
            config.agent.observer_profile_digest
        );
        println!(
            "validator-profile-digest: {}",
            config.agent.validator_profile_digest
        );
        println!(
            "validator-network-key-digest: {}",
            config.agent.validator_network_key_digest
        );
        return Ok(());
    }

    info!(
        host_id = %config.agent.host_id,
        listen_address = %config.listen_address,
        "starting validator failover agent"
    );
    Server::builder()
        .tls_config(tls)?
        .add_service(ValidatorAgentServer::new(service))
        .serve(config.listen_address)
        .await?;
    Ok(())
}
