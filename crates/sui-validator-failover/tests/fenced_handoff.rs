// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddr,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use consensus_config::ProtocolKeyPair;
use fastcrypto::{
    groups::bls12381,
    hash::{Blake2b256, HashFunction},
    serde_helpers::ToFromByteArray as _,
    traits::{KeyPair as _, ToFromBytes as _},
};
use fastcrypto_tbls::{ecies_v1, nodes::Node, nodes::Nodes};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sui_types::crypto::{NetworkKeyPair, get_authority_key_pair, get_key_pair};
use sui_validator_failover::{
    agent::{Agent, AgentError, Supervisor},
    client::AgentClientConfig,
    config::AgentConfig,
    controller::{
        ControlPlane, ControllerRuntimeConfig, HostControl, MetricsSource, RemoteAgent,
        RemoteSigner,
    },
    metrics::ValidatorMetrics,
    protocol::{NodeProfile, ServiceState},
    rpc::ValidatorAgentServer,
    service::AgentService,
};
use sui_validator_signer::{
    blocking::BlockingValidatorSigner,
    client::{ClientError as SignerClientError, ExternalSignerConfig, SignerRpcClient},
    policy::{FileStateStore, SignerPolicy, SystemClock},
    protocol::{RandomnessDkgRequest, RandomnessDkgResponse},
    randomness::{FileRandomnessStateStore, RandomnessSessionManager},
    rpc::ValidatorSignerServer,
    service::{SignerAccessPolicy, SignerKeys, SignerService},
};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Code,
    transport::{Certificate, Identity, Server, ServerTlsConfig},
};

const CHAIN_ID: [u8; 32] = [7; 32];
const EPOCH: u64 = 7;

#[derive(Clone)]
struct TestSupervisor {
    active: Arc<Mutex<bool>>,
    signer_config: Option<ExternalSignerConfig>,
    signer: Arc<Mutex<Option<BlockingValidatorSigner>>>,
    metrics: Arc<Mutex<BTreeMap<String, ValidatorMetrics>>>,
    host_id: String,
}

impl Supervisor for TestSupervisor {
    fn status(&self) -> Result<ServiceState, AgentError> {
        Ok(if *self.active.lock().unwrap() {
            ServiceState::Active
        } else {
            ServiceState::Inactive
        })
    }

    fn stop(&self) -> Result<(), AgentError> {
        *self.active.lock().unwrap() = false;
        self.signer.lock().unwrap().take();
        Ok(())
    }

    fn start(&self) -> Result<(), AgentError> {
        if let Some(config) = &self.signer_config {
            let signer =
                BlockingValidatorSigner::connect(config.clone(), CHAIN_ID).map_err(|error| {
                    AgentError::SupervisorCommand {
                        action: "start".to_owned(),
                        stderr: error.to_string(),
                    }
                })?;
            *self.signer.lock().unwrap() = Some(signer);
            let mut metrics = self.metrics.lock().unwrap();
            let target = metrics.get_mut(&self.host_id).unwrap();
            target.voting_right = 100;
            target.proposed_blocks += 1;
            target.last_commit_index += 1;
            target.last_executed_checkpoint += 1;
        }
        *self.active.lock().unwrap() = true;
        Ok(())
    }
}

#[derive(Clone)]
struct TestMetrics {
    host_id: String,
    values: Arc<Mutex<BTreeMap<String, ValidatorMetrics>>>,
}

#[async_trait]
impl MetricsSource for TestMetrics {
    async fn sample(&self) -> anyhow::Result<ValidatorMetrics> {
        Ok(self.values.lock().unwrap()[&self.host_id].clone())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_mtls_services_fence_a_stale_source_before_target_signing() {
    let directory = TempDir::new().unwrap();
    let (ca, ca_key) = certificate_authority();
    let signer_server = end_entity(
        "localhost",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        &ca_key,
    );
    let source_identity = client_identity("source-validator", &ca, &ca_key);
    let target_identity = client_identity("target-validator", &ca, &ca_key);
    let status_identity = client_identity("status-reader", &ca, &ca_key);
    let controller_identity = client_identity("controller", &ca, &ca_key);

    let (_, protocol) = get_authority_key_pair();
    let peer_protocol_keys = (0..3)
        .map(|_| get_authority_key_pair().1)
        .collect::<Vec<_>>();
    let nodes = Nodes::new(
        std::iter::once(protocol.public())
            .chain(peer_protocol_keys.iter().map(|key| key.public()))
            .enumerate()
            .map(|(id, public_key)| {
                let public =
                    bls12381::G2Element::from_byte_array(public_key.as_bytes().try_into().unwrap())
                        .unwrap();
                Node {
                    id: id.try_into().unwrap(),
                    pk: ecies_v1::PublicKey::from(public),
                    weight: 1,
                }
            })
            .collect(),
    )
    .unwrap();
    let peer_managers = peer_protocol_keys
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            RandomnessSessionManager::open(
                FileRandomnessStateStore::new(
                    directory
                        .path()
                        .join(format!("peer-randomness-{index}.bcs")),
                ),
                CHAIN_ID,
                key,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let (_, worker): (_, NetworkKeyPair) = get_key_pair();
    let protocol_public_key = hex::encode(protocol.public().as_bytes());
    let worker_public_key = hex::encode(worker.public().as_bytes());
    let network_public_key = hex::encode([3; 32]);
    let signer_policy = SignerPolicy::open(
        FileStateStore::new(directory.path().join("signer-policy.journal")),
        SystemClock,
        2_000,
    )
    .unwrap();
    let signer_service = SignerService::new(
        SignerAccessPolicy::new(
            BTreeSet::from([source_identity.digest, target_identity.digest]),
            BTreeSet::from([status_identity.digest]),
        )
        .unwrap(),
        signer_policy,
        SignerKeys::new(protocol, ProtocolKeyPair::new(worker)),
        CHAIN_ID,
        1_024 * 1_024,
        directory.path().join("randomness.bcs"),
    )
    .unwrap();
    let (signer_address, signer_task) = spawn_signer(signer_service, &signer_server, &ca).await;

    let source_signer_config = signer_client_config(
        directory.path(),
        "source",
        signer_address,
        &ca,
        &source_identity,
        &protocol_public_key,
        &worker_public_key,
        1_500,
    );
    let target_signer_config = signer_client_config(
        directory.path(),
        "target",
        signer_address,
        &ca,
        &target_identity,
        &protocol_public_key,
        &worker_public_key,
        1_500,
    );
    let status_signer_config = signer_client_config(
        directory.path(),
        "status",
        signer_address,
        &ca,
        &status_identity,
        &protocol_public_key,
        &worker_public_key,
        1_500,
    );

    let mut stale_source = SignerRpcClient::connect(&source_signer_config)
        .await
        .unwrap();
    let source_lease = stale_source.acquire_lease().await.unwrap().credential;
    prepare_randomness(
        &mut stale_source,
        source_lease.clone(),
        bcs::to_bytes(&nodes).unwrap(),
        &peer_managers,
    )
    .await;

    let metrics = Arc::new(Mutex::new(BTreeMap::from([
        ("source".to_owned(), validator_metrics(100, 1_000, 2_000, 0)),
        ("target".to_owned(), validator_metrics(0, 995, 1_998, 50)),
    ])));
    let controller_digest = controller_identity.digest;
    let source_agent = make_agent(
        directory.path().join("source-host"),
        "source",
        NodeProfile::Validator,
        TestSupervisor {
            active: Arc::new(Mutex::new(true)),
            signer_config: None,
            signer: Arc::new(Mutex::new(None)),
            metrics: metrics.clone(),
            host_id: "source".to_owned(),
        },
        &protocol_public_key,
        &worker_public_key,
        &network_public_key,
    );
    let target_signer_handle = Arc::new(Mutex::new(None));
    let target_agent = make_agent(
        directory.path().join("target-host"),
        "target",
        NodeProfile::Observer,
        TestSupervisor {
            active: Arc::new(Mutex::new(true)),
            signer_config: Some(target_signer_config.clone()),
            signer: target_signer_handle.clone(),
            metrics: metrics.clone(),
            host_id: "target".to_owned(),
        },
        &protocol_public_key,
        &worker_public_key,
        &network_public_key,
    );
    let source_agent_server = end_entity(
        "localhost",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        &ca_key,
    );
    let target_agent_server = end_entity(
        "localhost",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        &ca_key,
    );
    let (source_address, source_task) =
        spawn_agent(source_agent, controller_digest, &source_agent_server, &ca).await;
    let (target_address, target_task) =
        spawn_agent(target_agent, controller_digest, &target_agent_server, &ca).await;
    let source_agent_config = agent_client_config(
        directory.path(),
        "source-agent",
        "source",
        source_address,
        &ca,
        &controller_identity,
    );
    let target_agent_config = agent_client_config(
        directory.path(),
        "target-agent",
        "target",
        target_address,
        &ca,
        &controller_identity,
    );

    let control = ControlPlane::open(
        ControllerRuntimeConfig {
            state_path: directory.path().join("controller.bcs"),
            max_checkpoint_lag: 5,
            max_commit_lag: 10,
            poll_interval: Duration::from_millis(20),
            handoff_timeout: Duration::from_secs(3),
        },
        [
            HostControl {
                host_id: "source".to_owned(),
                expected_holder_id: source_identity.digest,
                agent: Arc::new(RemoteAgent::connect(&source_agent_config).await.unwrap()),
                metrics: Arc::new(TestMetrics {
                    host_id: "source".to_owned(),
                    values: metrics.clone(),
                }),
            },
            HostControl {
                host_id: "target".to_owned(),
                expected_holder_id: target_identity.digest,
                agent: Arc::new(RemoteAgent::connect(&target_agent_config).await.unwrap()),
                metrics: Arc::new(TestMetrics {
                    host_id: "target".to_owned(),
                    values: metrics.clone(),
                }),
            },
        ],
        Arc::new(RemoteSigner::connect(&status_signer_config).await.unwrap()),
    )
    .unwrap();

    let record = control
        .promote(
            "e2e-fenced-handoff".to_owned(),
            "source".to_owned(),
            "target".to_owned(),
            source_lease.generation,
        )
        .await
        .unwrap();
    assert_eq!(record.target_generation, Some(source_lease.generation + 1));
    assert!(target_signer_handle.lock().unwrap().is_some());
    let snapshot = control.snapshot().await.unwrap();
    let source = snapshot
        .hosts
        .iter()
        .find(|host| host.host_id == "source")
        .unwrap();
    assert_eq!(source.status.profile, Some(NodeProfile::Observer));
    assert_eq!(source.status.service_state, ServiceState::Active);

    let stale_result = stale_source
        .randomness_partial_sign(source_lease, CHAIN_ID, EPOCH, 99)
        .await;
    assert!(matches!(
        stale_result,
        Err(SignerClientError::Rpc {
            code: Code::PermissionDenied,
            ..
        })
    ));

    source_task.abort();
    target_task.abort();
    signer_task.abort();
}

async fn prepare_randomness(
    client: &mut SignerRpcClient,
    credential: sui_validator_signer::protocol::LeaseCredential,
    nodes: Vec<u8>,
    peers: &[RandomnessSessionManager<FileRandomnessStateStore>],
) {
    client
        .randomness_dkg(
            credential.clone(),
            CHAIN_ID,
            RandomnessDkgRequest::Initialize {
                epoch: EPOCH,
                nodes: nodes.clone(),
                threshold: 2,
            },
        )
        .await
        .unwrap();
    for peer in peers {
        peer.initialize(EPOCH, &nodes, 2).unwrap();
    }
    let RandomnessDkgResponse::Message(signer_message) = client
        .randomness_dkg(
            credential.clone(),
            CHAIN_ID,
            RandomnessDkgRequest::CreateMessage { epoch: EPOCH },
        )
        .await
        .unwrap()
    else {
        panic!("unexpected DKG message response")
    };
    let mut messages = vec![signer_message];
    messages.extend(peers.iter().map(|peer| peer.create_message(EPOCH).unwrap()));
    for message in &messages {
        client
            .randomness_dkg(
                credential.clone(),
                CHAIN_ID,
                RandomnessDkgRequest::ProcessMessage {
                    epoch: EPOCH,
                    message: message.clone(),
                },
            )
            .await
            .unwrap();
        for peer in peers {
            peer.process_message(EPOCH, message).unwrap();
        }
    }
    let RandomnessDkgResponse::Merged {
        confirmation: signer_confirmation,
        ..
    } = client
        .randomness_dkg(
            credential.clone(),
            CHAIN_ID,
            RandomnessDkgRequest::TryMerge { epoch: EPOCH },
        )
        .await
        .unwrap()
    else {
        panic!("unexpected DKG merge response")
    };
    let mut confirmations = vec![signer_confirmation];
    confirmations.extend(
        peers
            .iter()
            .map(|peer| peer.try_merge(EPOCH).unwrap().confirmation),
    );
    for confirmation in &confirmations {
        client
            .randomness_dkg(
                credential.clone(),
                CHAIN_ID,
                RandomnessDkgRequest::AddConfirmation {
                    epoch: EPOCH,
                    confirmation: confirmation.clone(),
                },
            )
            .await
            .unwrap();
        for peer in peers {
            peer.add_confirmation(EPOCH, confirmation).unwrap();
        }
    }
    let RandomnessDkgResponse::Complete { .. } = client
        .randomness_dkg(
            credential,
            CHAIN_ID,
            RandomnessDkgRequest::TryComplete { epoch: EPOCH },
        )
        .await
        .unwrap()
    else {
        panic!("unexpected DKG completion response")
    };
}

fn make_agent(
    directory: PathBuf,
    host_id: &str,
    profile: NodeProfile,
    supervisor: TestSupervisor,
    protocol_public_key: &str,
    worker_public_key: &str,
    network_public_key: &str,
) -> Agent<TestSupervisor> {
    fs::create_dir_all(&directory).unwrap();
    let observer = directory.join("observer.yaml");
    let validator = directory.join("validator.yaml");
    let network_key = directory.join("network.key");
    let active = directory.join("active.yaml");
    fs::write(&observer, format!("host: {host_id}\nrole: observer\n")).unwrap();
    fs::write(&validator, format!("host: {host_id}\nrole: validator\n")).unwrap();
    fs::write(&network_key, "test-network-key-material").unwrap();
    symlink(
        match profile {
            NodeProfile::Observer => &observer,
            NodeProfile::Validator => &validator,
        },
        &active,
    )
    .unwrap();
    Agent::open(
        AgentConfig {
            host_id: host_id.to_owned(),
            service_name: "sui-node.service".to_owned(),
            systemctl_path: "/usr/bin/systemctl".into(),
            active_config_path: active,
            observer_config_path: observer.clone(),
            validator_config_path: validator.clone(),
            validator_network_key_path: network_key.clone(),
            state_path: directory.join("agent.bcs"),
            observer_profile_digest: file_digest(&observer),
            validator_profile_digest: file_digest(&validator),
            validator_network_key_digest: file_digest(&network_key),
            protocol_public_key: protocol_public_key.to_owned(),
            worker_public_key: worker_public_key.to_owned(),
            network_public_key: network_public_key.to_owned(),
        },
        supervisor,
    )
    .unwrap()
}

async fn spawn_signer(
    service: SignerService,
    identity: &TestIdentity,
    ca: &rcgen::Certificate,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tls = server_tls(identity, ca);
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(ValidatorSignerServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (address, task)
}

async fn spawn_agent(
    agent: Agent<TestSupervisor>,
    controller_digest: [u8; 32],
    identity: &TestIdentity,
    ca: &rcgen::Certificate,
) -> (SocketAddr, JoinHandle<()>) {
    let service = AgentService::new(agent, [controller_digest]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tls = server_tls(identity, ca);
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(ValidatorAgentServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (address, task)
}

fn signer_client_config(
    directory: &Path,
    name: &str,
    address: SocketAddr,
    ca: &rcgen::Certificate,
    identity: &TestIdentity,
    protocol_public_key: &str,
    worker_public_key: &str,
    lease_ttl_ms: u64,
) -> ExternalSignerConfig {
    let (ca_path, certificate_path, private_key_path) =
        write_client_files(directory, name, ca, identity);
    ExternalSignerConfig {
        endpoint: format!("https://{address}"),
        server_name: "localhost".to_owned(),
        ca_certificate_path: ca_path,
        client_certificate_path: certificate_path,
        client_private_key_path: private_key_path,
        expected_protocol_public_key: protocol_public_key.to_owned(),
        expected_worker_public_key: worker_public_key.to_owned(),
        request_timeout_ms: 1_000,
        lease_ttl_ms,
    }
}

fn agent_client_config(
    directory: &Path,
    name: &str,
    host_id: &str,
    address: SocketAddr,
    ca: &rcgen::Certificate,
    identity: &TestIdentity,
) -> AgentClientConfig {
    let (ca_path, certificate_path, private_key_path) =
        write_client_files(directory, name, ca, identity);
    AgentClientConfig {
        endpoint: format!("https://{address}"),
        server_name: "localhost".to_owned(),
        ca_certificate_path: ca_path,
        client_certificate_path: certificate_path,
        client_private_key_path: private_key_path,
        expected_host_id: host_id.to_owned(),
        request_timeout_ms: 1_000,
    }
}

fn write_client_files(
    directory: &Path,
    name: &str,
    ca: &rcgen::Certificate,
    identity: &TestIdentity,
) -> (PathBuf, PathBuf, PathBuf) {
    let ca_path = directory.join(format!("{name}-ca.pem"));
    let certificate_path = directory.join(format!("{name}.pem"));
    let private_key_path = directory.join(format!("{name}.key"));
    fs::write(&ca_path, ca.pem()).unwrap();
    fs::write(&certificate_path, identity.certificate.pem()).unwrap();
    fs::write(&private_key_path, identity.key.serialize_pem()).unwrap();
    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600)).unwrap();
    (ca_path, certificate_path, private_key_path)
}

fn validator_metrics(
    voting_right: u64,
    commit: u64,
    checkpoint: u64,
    observer: u64,
) -> ValidatorMetrics {
    ValidatorMetrics {
        epoch: EPOCH,
        voting_right,
        last_commit_index: commit,
        last_executed_checkpoint: checkpoint,
        proposed_blocks: if voting_right > 0 { 10 } else { 0 },
        observer_subscribed_batches: observer,
        dkg_failed: false,
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

fn client_identity(name: &str, ca: &rcgen::Certificate, ca_key: &KeyPair) -> TestIdentity {
    end_entity(name, ExtendedKeyUsagePurpose::ClientAuth, ca, ca_key)
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

fn server_tls(identity: &TestIdentity, ca: &rcgen::Certificate) -> ServerTlsConfig {
    ServerTlsConfig::new()
        .identity(Identity::from_pem(
            identity.certificate.pem(),
            identity.key.serialize_pem(),
        ))
        .client_ca_root(Certificate::from_pem(ca.pem()))
}

fn file_digest(path: &Path) -> String {
    hex::encode(Blake2b256::digest(fs::read(path).unwrap()))
}
