// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use sui_validator_failover::{
    control_config::ControllerDaemonConfig,
    controller::{
        ControlPlane, ControllerRuntimeConfig, HostControl, HttpMetricsSource, RemoteAgent,
        RemoteSigner,
    },
    dashboard,
};
use sui_validator_signer::config::ensure_private_directory;
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
    /// Query both agents, both metrics endpoints, and the signer without mutation.
    #[arg(long)]
    preflight: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .init();
    let args = Args::parse();
    let config = ControllerDaemonConfig::load(&args.config_path)?;
    let state_directory = config
        .state_path
        .parent()
        .context("state-path must have a parent directory")?;
    ensure_private_directory(state_directory)?;
    let api_token = config.load_api_token()?;

    let signer = Arc::new(RemoteSigner::connect(&config.signer).await?);
    let mut hosts = Vec::with_capacity(config.hosts.len());
    for host in &config.hosts {
        let agent = RemoteAgent::connect(&host.agent)
            .await
            .with_context(|| format!("failed to connect validator agent on {}", host.host_id))?;
        let metrics = HttpMetricsSource::new(&host.metrics_url, config.metrics_timeout())?;
        hosts.push(HostControl {
            host_id: host.host_id.clone(),
            expected_holder_id: host.parsed_holder_id()?,
            agent: Arc::new(agent),
            metrics: Arc::new(metrics),
        });
    }
    let control = Arc::new(ControlPlane::open(
        ControllerRuntimeConfig {
            state_path: config.state_path.clone(),
            max_checkpoint_lag: config.max_checkpoint_lag,
            max_commit_lag: config.max_commit_lag,
            poll_interval: config.poll_interval(),
            handoff_timeout: config.handoff_timeout(),
        },
        hosts,
        signer,
    )?);
    if args.preflight {
        let snapshot = control.snapshot().await?;
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        ensure!(
            snapshot.promotion_readiness.eligible,
            "promotion preflight failed: {}",
            snapshot
                .promotion_readiness
                .blocker
                .as_deref()
                .unwrap_or("unknown readiness failure")
        );
        return Ok(());
    }
    let app = dashboard::router(control, &api_token);
    let listener = tokio::net::TcpListener::bind(config.listen_address).await?;
    info!(
        listen_address = %config.listen_address,
        "starting loopback validator control plane"
    );
    axum::serve(listener, app).await?;
    Ok(())
}
