// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::{
    config::ensure_private_file,
    protocol::{HostStatus, NodeProfile, Request, RequestV1, Response, ResponseV1},
    rpc::{AgentRpcRequest, ValidatorAgentClient},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AgentClientConfig {
    pub endpoint: String,
    pub server_name: String,
    pub ca_certificate_path: PathBuf,
    pub client_certificate_path: PathBuf,
    pub client_private_key_path: PathBuf,
    pub expected_host_id: String,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

pub struct AgentRpcClient {
    inner: ValidatorAgentClient<Channel>,
    request_timeout: Duration,
    expected_host_id: String,
}

impl AgentRpcClient {
    pub async fn connect(config: &AgentClientConfig) -> Result<Self, ClientError> {
        if config.request_timeout_ms == 0 {
            return Err(ClientError::InvalidRequestTimeout);
        }
        ensure_private_file(&config.client_private_key_path)
            .map_err(ClientError::InvalidPrivateKeyFile)?;
        let ca_certificate = fs::read(&config.ca_certificate_path)?;
        let client_certificate = fs::read(&config.client_certificate_path)?;
        let client_private_key = fs::read(&config.client_private_key_path)?;
        let tls = ClientTlsConfig::new()
            .domain_name(config.server_name.clone())
            .ca_certificate(Certificate::from_pem(ca_certificate))
            .identity(Identity::from_pem(client_certificate, client_private_key));
        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        let endpoint = Endpoint::from_shared(config.endpoint.clone())?
            .connect_timeout(request_timeout)
            .tls_config(tls)?;
        let channel = endpoint.connect().await?;
        let mut client = Self {
            inner: ValidatorAgentClient::new(channel),
            request_timeout,
            expected_host_id: config.expected_host_id.clone(),
        };
        client.status().await?;
        Ok(client)
    }

    pub async fn status(&mut self) -> Result<HostStatus, ClientError> {
        self.call(RequestV1::GetStatus).await
    }

    pub async fn stop(&mut self, operation_id: String) -> Result<HostStatus, ClientError> {
        self.call(RequestV1::Stop { operation_id }).await
    }

    pub async fn activate(
        &mut self,
        operation_id: String,
        profile: NodeProfile,
    ) -> Result<HostStatus, ClientError> {
        self.call(RequestV1::Activate {
            operation_id,
            profile,
        })
        .await
    }

    async fn call(&mut self, request: RequestV1) -> Result<HostStatus, ClientError> {
        let body = bcs::to_bytes(&Request::V1(request)).map_err(ClientError::Encode)?;
        let rpc = self.inner.execute(AgentRpcRequest { body });
        let response = tokio::time::timeout(self.request_timeout, rpc)
            .await
            .map_err(|_| ClientError::Timeout)??
            .into_inner();
        let status = match bcs::from_bytes(&response.body).map_err(ClientError::Decode)? {
            Response::V1(ResponseV1::Status(status)) => status,
        };
        if status.host_id != self.expected_host_id {
            return Err(ClientError::HostIdMismatch {
                expected: self.expected_host_id.clone(),
                actual: status.host_id,
            });
        }
        Ok(status)
    }
}

const fn default_request_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("request timeout must be nonzero")]
    InvalidRequestTimeout,
    #[error("validator agent request timed out")]
    Timeout,
    #[error("validator agent host ID mismatch: expected {expected}, got {actual}")]
    HostIdMismatch { expected: String, actual: String },
    #[error("failed to encode agent request: {0}")]
    Encode(bcs::Error),
    #[error("failed to decode agent response: {0}")]
    Decode(bcs::Error),
    #[error("private key file is invalid: {0}")]
    InvalidPrivateKeyFile(anyhow::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
    #[error("validator agent rejected request ({code:?}): {message}")]
    Rpc { code: tonic::Code, message: String },
}

impl From<tonic::Status> for ClientError {
    fn from(status: tonic::Status) -> Self {
        Self::Rpc {
            code: status.code(),
            message: status.message().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use fastcrypto::hash::{Blake2b256, HashFunction};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use tempfile::TempDir;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

    use super::*;
    use crate::{
        agent::{Agent, AgentError, Supervisor},
        config::AgentConfig,
        protocol::ServiceState,
        rpc::ValidatorAgentServer,
        service::AgentService,
    };

    #[derive(Clone)]
    struct TestSupervisor(Arc<AtomicBool>);

    impl Supervisor for TestSupervisor {
        fn status(&self) -> Result<ServiceState, AgentError> {
            Ok(if self.0.load(Ordering::SeqCst) {
                ServiceState::Active
            } else {
                ServiceState::Inactive
            })
        }

        fn stop(&self) -> Result<(), AgentError> {
            self.0.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn start(&self) -> Result<(), AgentError> {
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn mutual_tls_agent_is_allowlisted_and_host_bound() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = TempDir::new().unwrap();
        let (ca_certificate, ca_key) = certificate_authority();
        let (server_certificate, server_key) = end_entity(
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca_certificate,
            &ca_key,
        );
        let (client_certificate, client_key) = end_entity(
            "controller",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca_certificate,
            &ca_key,
        );
        let (other_certificate, other_key) = end_entity(
            "other-controller",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca_certificate,
            &ca_key,
        );
        let ca_path = directory.path().join("ca.pem");
        let client_certificate_path = directory.path().join("client.pem");
        let client_private_key_path = directory.path().join("client.key");
        let other_certificate_path = directory.path().join("other.pem");
        let other_private_key_path = directory.path().join("other.key");
        fs::write(&ca_path, ca_certificate.pem()).unwrap();
        fs::write(&client_certificate_path, client_certificate.pem()).unwrap();
        fs::write(&other_certificate_path, other_certificate.pem()).unwrap();
        write_private(&client_private_key_path, &client_key.serialize_pem());
        write_private(&other_private_key_path, &other_key.serialize_pem());

        let observer = directory.path().join("observer.yaml");
        let validator = directory.path().join("validator.yaml");
        let network_key = directory.path().join("network.key");
        fs::write(&observer, "observer").unwrap();
        fs::write(&validator, "validator").unwrap();
        fs::write(&network_key, "network-key-material").unwrap();
        let agent = Agent::open(
            AgentConfig {
                host_id: "validator-a".to_owned(),
                service_name: "sui-node.service".to_owned(),
                systemctl_path: "/usr/bin/systemctl".into(),
                active_config_path: directory.path().join("active.yaml"),
                observer_config_path: observer.clone(),
                validator_config_path: validator.clone(),
                validator_network_key_path: network_key.clone(),
                state_path: directory.path().join("agent.bcs"),
                observer_profile_digest: hex::encode(Blake2b256::digest(
                    fs::read(&observer).unwrap(),
                )),
                validator_profile_digest: hex::encode(Blake2b256::digest(
                    fs::read(&validator).unwrap(),
                )),
                validator_network_key_digest: hex::encode(Blake2b256::digest(
                    fs::read(&network_key).unwrap(),
                )),
                protocol_public_key: hex::encode([1; 96]),
                worker_public_key: hex::encode([2; 32]),
                network_public_key: hex::encode([3; 32]),
            },
            TestSupervisor(Arc::new(AtomicBool::new(false))),
        )
        .unwrap();
        let client_digest = Blake2b256::digest(client_certificate.der().as_ref()).into();
        let service = AgentService::new(agent, [client_digest]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                server_certificate.pem(),
                server_key.serialize_pem(),
            ))
            .client_ca_root(Certificate::from_pem(ca_certificate.pem()));
        let server = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(ValidatorAgentServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let base_config = AgentClientConfig {
            endpoint: format!("https://{address}"),
            server_name: "localhost".to_owned(),
            ca_certificate_path: ca_path,
            client_certificate_path,
            client_private_key_path,
            expected_host_id: "validator-a".to_owned(),
            request_timeout_ms: 1_000,
        };
        let mut client = AgentRpcClient::connect(&base_config).await.unwrap();
        let status = client
            .activate("promote-001".to_owned(), NodeProfile::Validator)
            .await
            .unwrap();
        assert_eq!(status.host_id, "validator-a");
        assert_eq!(status.profile, Some(NodeProfile::Validator));
        assert_eq!(status.service_state, ServiceState::Active);

        let mut wrong_host = base_config.clone();
        wrong_host.expected_host_id = "validator-b".to_owned();
        assert!(matches!(
            AgentRpcClient::connect(&wrong_host).await,
            Err(ClientError::HostIdMismatch { .. })
        ));

        let unauthorized = AgentClientConfig {
            client_certificate_path: other_certificate_path,
            client_private_key_path: other_private_key_path,
            expected_host_id: "validator-a".to_owned(),
            ..base_config
        };
        assert!(matches!(
            AgentRpcClient::connect(&unauthorized).await,
            Err(ClientError::Rpc {
                code: tonic::Code::PermissionDenied,
                ..
            })
        ));
        server.abort();
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
        ca_certificate: &rcgen::Certificate,
        ca_key: &KeyPair,
    ) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, ca_certificate, ca_key).unwrap();
        (certificate, key)
    }

    fn write_private(path: &std::path::Path, pem: &str) {
        fs::write(path, pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}
