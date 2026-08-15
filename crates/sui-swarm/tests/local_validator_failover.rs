// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Proves that a fully stopped validator can be replaced mid-epoch by a
//! consensus observer using the validator's ordinary local signing keys.
//!
//! This test deliberately has no external signer or signer lease. The safety
//! fence is represented by `Node::stop`; production must replace that with an
//! independently verified power or fabric fence before releasing the local
//! key bundle to the target.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use consensus_config::{NetworkPublicKey, ObserverParameters, PeerRecord};
use rand::rngs::OsRng;
use sui_swarm::memory::{Node, Swarm};
use sui_swarm_config::{
    network_config_builder::ConfigBuilder, node_config_builder::FullnodeConfigBuilder,
};
use sui_types::crypto::KeypairTraits;
use sui_types::node_role::{FullNodeSyncMode, NodeRole};
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fenced_local_keys_support_reversible_mid_epoch_handoff() {
    telemetry_subscribers::init_for_testing();
    let directory = TempDir::new().unwrap();
    let config_directory = directory.path().join("network");
    let network_config = ConfigBuilder::new(&config_directory)
        .committee_size(NonZeroUsize::new(4).unwrap())
        // Keep the entire round trip in one epoch. The DKG is expected to
        // complete in epoch zero well before this deadline.
        .with_epoch_duration(180_000)
        .with_validator_observer_config(Arc::new(|index| {
            (index == 0).then_some(ObserverParameters::default())
        }))
        .build();

    let source_config = &network_config.validator_configs[0];
    let validator_name = source_config.protocol_public_key();
    let observer_port = source_config
        .consensus_config
        .as_ref()
        .unwrap()
        .parameters
        .as_ref()
        .unwrap()
        .observer
        .server_port
        .unwrap();
    let observer_host = source_config.network_address.to_socket_addr().unwrap().ip();
    let observer_peer = PeerRecord {
        public_key: NetworkPublicKey::new(source_config.network_key_pair().public().clone()),
        address: format!("/ip4/{observer_host}/udp/{observer_port}/http")
            .parse()
            .unwrap(),
    };

    let source_validator_profile = source_config.clone();
    let observer_parameters = ObserverParameters {
        peers: vec![observer_peer],
        ..Default::default()
    };
    let target_observer_profile = FullnodeConfigBuilder::new()
        .with_config_directory(config_directory.join("validator-b"))
        .with_disable_pruning(true)
        .with_observer_config(observer_parameters.clone())
        .build(&mut OsRng, &network_config);
    let target_observer_name = target_observer_profile.protocol_public_key();
    let source_observer_profile = FullnodeConfigBuilder::new()
        .with_config_directory(config_directory.join("validator-a-observer"))
        .with_db_path(source_validator_profile.db_path.clone())
        .with_disable_pruning(true)
        .with_observer_config(observer_parameters)
        .build(&mut OsRng, &network_config);

    // The target keeps its observer authority and consensus databases. Only
    // the cold-start profile and the three ordinary validator runtime keys
    // change after the source has been fenced.
    let mut target_validator_profile = source_validator_profile.clone();
    target_validator_profile.db_path = target_observer_profile.db_path.clone();
    target_validator_profile
        .consensus_config
        .as_mut()
        .unwrap()
        .db_path = target_observer_profile
        .consensus_config
        .as_ref()
        .unwrap()
        .db_path
        .clone();

    let mut swarm = Swarm::builder()
        .with_network_config(network_config)
        .with_fullnode_config(target_observer_profile.clone())
        .with_fullnode_count(1)
        .build();
    swarm.launch().await.unwrap();

    let source = swarm.node(&validator_name).unwrap();
    let target = swarm.node(&target_observer_name).unwrap();
    source.health_check(true).await.unwrap();
    target.health_check(false).await.unwrap();
    assert_eq!(
        node_role(target),
        NodeRole::FullNode(FullNodeSyncMode::ConsensusObserver)
    );
    wait_for_metric(source, "epoch_random_beacon_signer_ready", |value| {
        value == 1.0
    })
    .await;
    assert_eq!(metric(target, "current_voting_right").await, 0.0);
    assert_eq!(
        metric(target, "epoch_random_beacon_signer_ready").await,
        0.0
    );

    let (epoch, first_checkpoint) =
        wait_for_checkpoint(source, None, 2, Duration::from_secs(45)).await;
    wait_for_checkpoint(
        target,
        Some(epoch),
        first_checkpoint,
        Duration::from_secs(30),
    )
    .await;

    // A -> B. `source.stop()` is only a test substitute for a verified
    // out-of-band power/fabric fence. B cannot start until A is fully gone.
    source.stop();
    assert!(!source.is_running());
    target.stop();
    *target.config() = target_validator_profile;
    target.start().await.unwrap();
    target.health_check(true).await.unwrap();
    assert!(node_role(target).is_validator());
    wait_for_metric(target, "epoch_random_beacon_recovered_shares", |value| {
        value == 1.0
    })
    .await;
    wait_for_metric(target, "epoch_random_beacon_signer_ready", |value| {
        value == 1.0
    })
    .await;
    assert!(metric(target, "current_voting_right").await > 0.0);
    let (_, target_checkpoint) = wait_for_checkpoint(
        target,
        Some(epoch),
        first_checkpoint + 1,
        Duration::from_secs(45),
    )
    .await;

    // The retired host must return under independent observer keys before it
    // becomes eligible for a later handback.
    *source.config() = source_observer_profile;
    source.start().await.unwrap();
    source.health_check(false).await.unwrap();
    assert_eq!(
        node_role(source),
        NodeRole::FullNode(FullNodeSyncMode::ConsensusObserver)
    );
    assert_eq!(metric(source, "current_voting_right").await, 0.0);
    wait_for_checkpoint(
        source,
        Some(epoch),
        target_checkpoint,
        Duration::from_secs(30),
    )
    .await;

    // B -> A repeats the same ordering and proves the handoff is reversible
    // without an epoch transition or remote signing service.
    target.stop();
    assert!(!target.is_running());
    source.stop();
    *source.config() = source_validator_profile;
    source.start().await.unwrap();
    source.health_check(true).await.unwrap();
    assert!(node_role(source).is_validator());
    wait_for_metric(source, "epoch_random_beacon_signer_ready", |value| {
        value == 1.0
    })
    .await;
    let (_, final_checkpoint) = wait_for_checkpoint(
        source,
        Some(epoch),
        target_checkpoint + 1,
        Duration::from_secs(45),
    )
    .await;

    *target.config() = target_observer_profile;
    target.start().await.unwrap();
    target.health_check(false).await.unwrap();
    assert_eq!(
        node_role(target),
        NodeRole::FullNode(FullNodeSyncMode::ConsensusObserver)
    );
    wait_for_checkpoint(
        target,
        Some(epoch),
        final_checkpoint,
        Duration::from_secs(30),
    )
    .await;
}

fn node_role(node: &Node) -> NodeRole {
    node.get_node_handle()
        .unwrap()
        .state()
        .epoch_store_for_testing()
        .node_role()
}

async fn wait_for_checkpoint(
    node: &Node,
    exact_epoch: Option<u64>,
    minimum_checkpoint: u64,
    timeout: Duration,
) -> (u64, u64) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(handle) = node.get_node_handle() {
            let state = handle.state();
            let epoch = state.epoch_store_for_testing().epoch();
            let checkpoint = state
                .get_checkpoint_store()
                .get_highest_executed_checkpoint_seq_number()
                .unwrap()
                .unwrap_or_default();
            if let Some(expected) = exact_epoch {
                assert_eq!(epoch, expected, "handoff crossed an epoch boundary");
            }
            if checkpoint >= minimum_checkpoint {
                return (epoch, checkpoint);
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for local-key failover checkpoint progress"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_metric(node: &Node, name: &str, predicate: impl Fn(f64) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let value = metric(node, name).await;
        if predicate(value) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for metric {name}; last value was {value}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn metric(node: &Node, name: &str) -> f64 {
    let address = node.config().metrics_address;
    let body = reqwest::get(format!("http://{address}/metrics"))
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let (metric_name, value) = line.split_once(' ')?;
            (metric_name == name).then(|| value.parse::<f64>().unwrap())
        })
        .unwrap_or_else(|| panic!("metric {name} is not registered"))
}
