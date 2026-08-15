// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet, fs, num::NonZeroUsize, os::unix::fs::PermissionsExt, path::Path,
    sync::Arc, time::Duration,
};

use consensus_config::{NetworkPublicKey, ObserverParameters, PeerRecord, ProtocolKeyPair};
use fastcrypto::{
    hash::{Blake2b256, HashFunction},
    traits::{KeyPair as _, ToFromBytes as _},
};
use rand::rngs::OsRng;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sui_config::node::{AuthorityKeyPairWithPath, KeyPairWithPath};
use sui_swarm::memory::Swarm;
use sui_swarm_config::network_config_builder::ConfigBuilder;
use sui_swarm_config::node_config_builder::FullnodeConfigBuilder;
use sui_types::crypto::{NetworkKeyPair, SuiKeyPair, get_authority_key_pair, get_key_pair};
use sui_types::node_role::FullNodeSyncMode;
use sui_validator_signer::{
    client::{ExternalSignerConfig, SignerRpcClient},
    policy::{FileStateStore, SignerPolicy, SystemClock},
    rpc::ValidatorSignerServer,
    service::{SignerAccessPolicy, SignerKeys, SignerService},
};
use tempfile::TempDir;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consensus_observer_promotes_and_reverses_with_only_remote_signing() {
    telemetry_subscribers::init_for_testing();
    let directory = TempDir::new().unwrap();
    let config_directory = directory.path().join("network");
    fs::create_dir_all(&config_directory).unwrap();
    let mut network_config = ConfigBuilder::new(&config_directory)
        .committee_size(NonZeroUsize::new(4).unwrap())
        .with_epoch_duration(10_000)
        .with_validator_observer_config(Arc::new(|index| {
            (index == 0).then_some(ObserverParameters::default())
        }))
        .build();
    let chain_id = network_config.genesis.checkpoint().digest().into_inner();

    let source_config = &network_config.validator_configs[0];
    let validator_name = source_config.protocol_public_key();
    let signer_protocol = source_config.protocol_key_pair().copy();
    let signer_worker = source_config.worker_key_pair().copy();
    let expected_protocol_public_key = hex::encode(signer_protocol.public().as_bytes());
    let expected_worker_public_key = hex::encode(signer_worker.public().as_bytes());
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

    let (ca, ca_key) = certificate_authority();
    let server_identity = end_entity(
        "localhost",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        &ca_key,
    );
    let source_identity = end_entity(
        "validator-a",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
        &ca_key,
    );
    let target_identity = end_entity(
        "validator-b",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
        &ca_key,
    );
    let status_identity = end_entity(
        "status-reader",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
        &ca_key,
    );
    let signer_policy = SignerPolicy::open(
        FileStateStore::new(directory.path().join("signer-policy.journal")),
        SystemClock,
        10_000,
    )
    .unwrap();
    let signer_service = SignerService::new(
        SignerAccessPolicy::new(
            BTreeSet::from([source_identity.digest, target_identity.digest]),
            BTreeSet::from([status_identity.digest]),
        )
        .unwrap(),
        signer_policy,
        SignerKeys::new(signer_protocol, ProtocolKeyPair::new(signer_worker)),
        chain_id,
        4 * 1024 * 1024,
        directory.path().join("randomness.bcs"),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signer_address = listener.local_addr().unwrap();
    let signer_tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            server_identity.certificate.pem(),
            server_identity.key.serialize_pem(),
        ))
        .client_ca_root(Certificate::from_pem(ca.pem()));
    let signer_task = tokio::spawn(async move {
        Server::builder()
            .tls_config(signer_tls)
            .unwrap()
            .add_service(ValidatorSignerServer::new(signer_service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let source_signer_config = signer_client_config(
        directory.path(),
        "validator-a",
        signer_address,
        &ca,
        &source_identity,
        &expected_protocol_public_key,
        &expected_worker_public_key,
    );
    let target_signer_config = signer_client_config(
        directory.path(),
        "validator-b",
        signer_address,
        &ca,
        &target_identity,
        &expected_protocol_public_key,
        &expected_worker_public_key,
    );
    let status_signer_config = signer_client_config(
        directory.path(),
        "status",
        signer_address,
        &ca,
        &status_identity,
        &expected_protocol_public_key,
        &expected_worker_public_key,
    );
    {
        let source_config = &mut network_config.validator_configs[0];
        source_config.external_validator_signer = Some(source_signer_config);
        // Any accidental fallback to these unrelated local keys prevents this
        // committee identity from making progress.
        let (_, decoy_protocol) = get_authority_key_pair();
        let (_, decoy_worker): (_, NetworkKeyPair) = get_key_pair();
        source_config.protocol_key_pair = AuthorityKeyPairWithPath::new(decoy_protocol);
        source_config.worker_key_pair = KeyPairWithPath::new(SuiKeyPair::Ed25519(decoy_worker));
    }
    let source_validator_profile = network_config.validator_configs[0].clone();

    let observer_parameters = ObserverParameters {
        peers: vec![observer_peer],
        ..Default::default()
    };
    let target_observer_profile = FullnodeConfigBuilder::new()
        .with_config_directory(config_directory.join("validator-b"))
        .with_observer_config(observer_parameters.clone())
        .build(&mut OsRng, &network_config);
    let target_observer_name = target_observer_profile.protocol_public_key();
    let source_observer_profile = FullnodeConfigBuilder::new()
        .with_config_directory(config_directory.join("validator-a-observer"))
        .with_db_path(source_validator_profile.db_path.clone())
        .with_observer_config(observer_parameters)
        .build(&mut OsRng, &network_config);

    let mut target_validator_profile = source_validator_profile.clone();
    target_validator_profile.external_validator_signer = Some(target_signer_config);
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
        target
            .get_node_handle()
            .unwrap()
            .state()
            .epoch_store_for_testing()
            .node_role(),
        sui_types::node_role::NodeRole::FullNode(FullNodeSyncMode::ConsensusObserver)
    );

    let initial_generation = wait_for_signer_generation(
        &status_signer_config,
        source_identity.digest,
        None,
        Duration::from_secs(10),
    )
    .await;
    let first_checkpoint =
        wait_for_epoch_and_checkpoint(source, 1, 2, Duration::from_secs(45)).await;
    wait_for_epoch_and_checkpoint(target, 1, first_checkpoint, Duration::from_secs(30)).await;

    let mut status_client = SignerRpcClient::connect(&status_signer_config)
        .await
        .unwrap();
    let status = status_client.get_status().await.unwrap();
    assert!(
        status
            .randomness_sessions
            .iter()
            .any(|session| session.shares_ready),
        "the real Sui DKG never produced signer-owned randomness shares"
    );

    // A -> B: fence A, stop B's observer, and start B on the same on-chain
    // validator identity with a separate signer client certificate and database.
    source.stop();
    wait_for_no_lease(&mut status_client, Duration::from_secs(12)).await;
    target.stop();
    *target.config() = target_validator_profile;
    target.start().await.unwrap();
    target.health_check(true).await.unwrap();
    let target_generation = wait_for_signer_generation(
        &status_signer_config,
        target_identity.digest,
        Some(initial_generation),
        Duration::from_secs(12),
    )
    .await;
    let target_checkpoint =
        wait_for_epoch_and_checkpoint(target, 1, first_checkpoint + 1, Duration::from_secs(30))
            .await;
    assert!(target_generation > initial_generation);
    assert!(
        target
            .get_node_handle()
            .unwrap()
            .state()
            .epoch_store_for_testing()
            .node_role()
            .is_validator()
    );

    // A is demoted only after B is verified. It resumes from A's original
    // authority database using independent observer keys and endpoints.
    *source.config() = source_observer_profile;
    source.start().await.unwrap();
    source.health_check(false).await.unwrap();
    wait_for_epoch_and_checkpoint(source, 1, target_checkpoint, Duration::from_secs(30)).await;
    assert_eq!(
        source
            .get_node_handle()
            .unwrap()
            .state()
            .epoch_store_for_testing()
            .node_role(),
        sui_types::node_role::NodeRole::FullNode(FullNodeSyncMode::ConsensusObserver)
    );

    // B -> A repeats the complete fence/switch/verify/demote sequence.
    target.stop();
    wait_for_no_lease(&mut status_client, Duration::from_secs(12)).await;
    source.stop();
    *source.config() = source_validator_profile;
    source.start().await.unwrap();
    source.health_check(true).await.unwrap();
    let final_generation = wait_for_signer_generation(
        &status_signer_config,
        source_identity.digest,
        Some(target_generation),
        Duration::from_secs(12),
    )
    .await;
    let final_checkpoint =
        wait_for_epoch_and_checkpoint(source, 1, target_checkpoint + 1, Duration::from_secs(30))
            .await;
    assert!(final_generation > target_generation);

    *target.config() = target_observer_profile;
    target.start().await.unwrap();
    target.health_check(false).await.unwrap();
    wait_for_epoch_and_checkpoint(target, 1, final_checkpoint, Duration::from_secs(30)).await;

    signer_task.abort();
}

async fn wait_for_epoch_and_checkpoint(
    validator: &sui_swarm::memory::Node,
    minimum_epoch: u64,
    minimum_checkpoint: u64,
    timeout: Duration,
) -> u64 {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(handle) = validator.get_node_handle() {
            let state = handle.state();
            let epoch = state.epoch_store_for_testing().epoch();
            let checkpoint = state
                .get_checkpoint_store()
                .get_highest_executed_checkpoint_seq_number()
                .unwrap()
                .unwrap_or_default();
            if epoch >= minimum_epoch && checkpoint >= minimum_checkpoint {
                return checkpoint;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for remote-signed validator epoch/checkpoint progress"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_signer_generation(
    config: &ExternalSignerConfig,
    holder_id: [u8; 32],
    greater_than: Option<u64>,
    timeout: Duration,
) -> u64 {
    let mut client = SignerRpcClient::connect(config).await.unwrap();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let status = client.get_status().await.unwrap();
        if let Some(lease) = status.current_lease
            && lease.holder_id == holder_id
            && greater_than.is_none_or(|generation| lease.generation > generation)
        {
            return lease.generation;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for validator signer lease generation"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_no_lease(client: &mut SignerRpcClient, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if client.get_status().await.unwrap().current_lease.is_none() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for stopped node to release or expire its lease"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct TestIdentity {
    certificate: rcgen::Certificate,
    key: KeyPair,
    digest: [u8; 32],
}

fn certificate_authority() -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    (certificate, key)
}

fn end_entity(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> TestIdentity {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, ca, ca_key).unwrap();
    let digest = Blake2b256::digest(certificate.der().as_ref()).into();
    TestIdentity {
        certificate,
        key,
        digest,
    }
}

fn signer_client_config(
    directory: &Path,
    name: &str,
    signer_address: std::net::SocketAddr,
    ca: &rcgen::Certificate,
    identity: &TestIdentity,
    expected_protocol_public_key: &str,
    expected_worker_public_key: &str,
) -> ExternalSignerConfig {
    let ca_path = directory.join(format!("{name}-ca.pem"));
    let certificate_path = directory.join(format!("{name}.pem"));
    let private_key_path = directory.join(format!("{name}.key"));
    fs::write(&ca_path, ca.pem()).unwrap();
    fs::write(&certificate_path, identity.certificate.pem()).unwrap();
    fs::write(&private_key_path, identity.key.serialize_pem()).unwrap();
    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600)).unwrap();
    ExternalSignerConfig {
        endpoint: format!("https://{signer_address}"),
        server_name: "localhost".to_owned(),
        ca_certificate_path: ca_path,
        client_certificate_path: certificate_path,
        client_private_key_path: private_key_path,
        expected_protocol_public_key: expected_protocol_public_key.to_owned(),
        expected_worker_public_key: expected_worker_public_key.to_owned(),
        request_timeout_ms: 1_000,
        lease_ttl_ms: 5_000,
    }
}
