// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::{
    Code,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

use crate::{
    config::ensure_private_file,
    protocol::{
        ChainId, LeaseCredential, OperationKey, RandomnessDkgRequest, RandomnessDkgResponse,
        Request, RequestV1, Response, ResponseV1, SignerStatus,
    },
    rpc::{RpcRequest, ValidatorSignerClient},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExternalSignerConfig {
    pub endpoint: String,
    pub server_name: String,
    pub ca_certificate_path: PathBuf,
    pub client_certificate_path: PathBuf,
    pub client_private_key_path: PathBuf,
    pub expected_protocol_public_key: String,
    pub expected_worker_public_key: String,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_lease_ttl_ms")]
    pub lease_ttl_ms: u64,
}

impl ExternalSignerConfig {
    pub fn expected_public_keys(&self) -> Result<PublicKeys, ClientError> {
        let protocol_bls12381 = hex::decode(&self.expected_protocol_public_key)
            .map_err(|_| ClientError::InvalidExpectedPublicKey("protocol"))?;
        let worker_ed25519 = hex::decode(&self.expected_worker_public_key)
            .map_err(|_| ClientError::InvalidExpectedPublicKey("worker"))?;
        if protocol_bls12381.len() != 96 {
            return Err(ClientError::InvalidExpectedPublicKey("protocol"));
        }
        if worker_ed25519.len() != 32 {
            return Err(ClientError::InvalidExpectedPublicKey("worker"));
        }
        Ok(PublicKeys {
            protocol_bls12381,
            worker_ed25519,
        })
    }

    fn request_timeout(&self) -> Result<Duration, ClientError> {
        if self.request_timeout_ms == 0 {
            return Err(ClientError::InvalidRequestTimeout);
        }
        Ok(Duration::from_millis(self.request_timeout_ms))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeys {
    pub protocol_bls12381: Vec<u8>,
    pub worker_ed25519: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveLease {
    pub credential: LeaseCredential,
    pub expires_at_unix_ms: u64,
}

pub struct SignerRpcClient {
    inner: ValidatorSignerClient<Channel>,
    request_timeout: Duration,
    lease_ttl_ms: u64,
}

impl SignerRpcClient {
    pub async fn connect(config: &ExternalSignerConfig) -> Result<Self, ClientError> {
        ensure_private_file(&config.client_private_key_path)
            .map_err(ClientError::InvalidPrivateKeyFile)?;
        if config.lease_ttl_ms == 0 {
            return Err(ClientError::InvalidLeaseTtl);
        }

        let ca_certificate = fs::read(&config.ca_certificate_path)?;
        let client_certificate = fs::read(&config.client_certificate_path)?;
        let client_private_key = fs::read(&config.client_private_key_path)?;
        let tls = ClientTlsConfig::new()
            .domain_name(config.server_name.clone())
            .ca_certificate(Certificate::from_pem(ca_certificate))
            .identity(Identity::from_pem(client_certificate, client_private_key));
        let request_timeout = config.request_timeout()?;
        let endpoint = Endpoint::from_shared(config.endpoint.clone())?
            .connect_timeout(request_timeout)
            .tls_config(tls)?;
        let channel = endpoint.connect().await?;
        let mut client = Self {
            inner: ValidatorSignerClient::new(channel),
            request_timeout,
            lease_ttl_ms: config.lease_ttl_ms,
        };
        let actual = client.get_public_keys().await?;
        let expected = config.expected_public_keys()?;
        if actual != expected {
            return Err(ClientError::PublicKeyMismatch);
        }
        Ok(client)
    }

    pub async fn get_public_keys(&mut self) -> Result<PublicKeys, ClientError> {
        match self.call(RequestV1::GetPublicKeys).await? {
            ResponseV1::PublicKeys {
                protocol_bls12381,
                worker_ed25519,
            } => Ok(PublicKeys {
                protocol_bls12381,
                worker_ed25519,
            }),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub async fn get_status(&mut self) -> Result<SignerStatus, ClientError> {
        match self.call(RequestV1::GetStatus).await? {
            ResponseV1::Status(status) => Ok(status),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub async fn acquire_lease(&mut self) -> Result<ActiveLease, ClientError> {
        match self
            .call(RequestV1::AcquireLease {
                ttl_ms: self.lease_ttl_ms,
            })
            .await?
        {
            ResponseV1::Lease(grant) => Ok(ActiveLease {
                credential: LeaseCredential {
                    holder_id: grant.holder_id,
                    generation: grant.generation,
                    lease_id: grant.lease_id,
                },
                expires_at_unix_ms: grant.expires_at_unix_ms,
            }),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub async fn renew_lease(
        &mut self,
        credential: &LeaseCredential,
    ) -> Result<ActiveLease, ClientError> {
        match self
            .call(RequestV1::RenewLease {
                credential: credential.clone(),
                ttl_ms: self.lease_ttl_ms,
            })
            .await?
        {
            ResponseV1::Lease(grant)
                if grant.holder_id == credential.holder_id
                    && grant.generation == credential.generation
                    && grant.lease_id == credential.lease_id =>
            {
                Ok(ActiveLease {
                    credential: credential.clone(),
                    expires_at_unix_ms: grant.expires_at_unix_ms,
                })
            }
            ResponseV1::Lease(_) => Err(ClientError::LeaseChangedDuringRenewal),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub async fn release_lease(&mut self, credential: LeaseCredential) -> Result<(), ClientError> {
        match self.call(RequestV1::ReleaseLease { credential }).await? {
            ResponseV1::Released => Ok(()),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub async fn sign(
        &mut self,
        credential: LeaseCredential,
        operation: OperationKey,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        match self
            .call(RequestV1::Sign {
                credential,
                operation,
                payload,
            })
            .await?
        {
            ResponseV1::Signature(signature) => Ok(signature),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub async fn randomness_dkg(
        &mut self,
        credential: LeaseCredential,
        chain_id: ChainId,
        request: RandomnessDkgRequest,
    ) -> Result<RandomnessDkgResponse, ClientError> {
        match self
            .call(RequestV1::RandomnessDkg {
                credential,
                chain_id,
                request,
            })
            .await?
        {
            ResponseV1::RandomnessDkg(response) => Ok(response),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub async fn randomness_partial_sign(
        &mut self,
        credential: LeaseCredential,
        chain_id: ChainId,
        epoch: u64,
        round: u64,
    ) -> Result<Vec<u8>, ClientError> {
        match self
            .call(RequestV1::RandomnessPartialSign {
                credential,
                chain_id,
                epoch,
                round,
            })
            .await?
        {
            ResponseV1::RandomnessPartialSignatures(signatures) => Ok(signatures),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    async fn call(&mut self, request: RequestV1) -> Result<ResponseV1, ClientError> {
        let body = bcs::to_bytes(&Request::V1(request)).map_err(ClientError::Encode)?;
        let rpc = self.inner.execute(RpcRequest { body });
        let response = tokio::time::timeout(self.request_timeout, rpc)
            .await
            .map_err(|_| ClientError::Timeout)??
            .into_inner();
        match bcs::from_bytes(&response.body).map_err(ClientError::Decode)? {
            Response::V1(response) => Ok(response),
        }
    }
}

const fn default_request_timeout_ms() -> u64 {
    1_000
}

const fn default_lease_ttl_ms() -> u64 {
    5_000
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("expected {0} public key is invalid")]
    InvalidExpectedPublicKey(&'static str),
    #[error("request timeout must be nonzero")]
    InvalidRequestTimeout,
    #[error("lease TTL must be nonzero")]
    InvalidLeaseTtl,
    #[error("external signer public keys do not match configuration")]
    PublicKeyMismatch,
    #[error("lease identity changed during renewal")]
    LeaseChangedDuringRenewal,
    #[error("external signer returned an unexpected response")]
    UnexpectedResponse,
    #[error("external signer request timed out")]
    Timeout,
    #[error("private key file is invalid: {0}")]
    InvalidPrivateKeyFile(anyhow::Error),
    #[error("failed to encode signer request: {0}")]
    Encode(bcs::Error),
    #[error("failed to decode signer response: {0}")]
    Decode(bcs::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),
    #[error("external signer rejected request ({code:?}): {message}")]
    Rpc { code: Code, message: String },
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
    use std::fs;

    use consensus_config::ProtocolKeyPair;
    use consensus_core::{TestBlock, consensus_block_signing_payload, serialize_consensus_block};
    use fastcrypto::{
        groups::bls12381,
        serde_helpers::ToFromByteArray as _,
        traits::{KeyPair as _, ToFromBytes as _, VerifyingKey as _},
    };
    use fastcrypto_tbls::{ecies_v1, nodes::Node, nodes::Nodes};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use shared_crypto::intent::{Intent, IntentMessage, IntentScope};
    use sui_types::crypto::{NetworkKeyPair, get_authority_key_pair, get_key_pair};
    use sui_types::effects::TransactionEffects;
    use tempfile::TempDir;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Identity, Server, ServerTlsConfig};

    use super::*;
    use crate::{
        blocking::BlockingAuthoritySigner,
        policy::{FileStateStore, SignerPolicy, SystemClock},
        rpc::ValidatorSignerServer,
        service::{SignerKeys, SignerService},
    };

    #[test]
    fn validates_expected_public_key_lengths() {
        let mut config = ExternalSignerConfig {
            endpoint: "https://signer.example:19000".to_owned(),
            server_name: "signer.example".to_owned(),
            ca_certificate_path: "ca.pem".into(),
            client_certificate_path: "client.pem".into(),
            client_private_key_path: "client.key".into(),
            expected_protocol_public_key: hex::encode([1; 96]),
            expected_worker_public_key: hex::encode([2; 32]),
            request_timeout_ms: 1_000,
            lease_ttl_ms: 5_000,
        };
        assert_eq!(
            config.expected_public_keys().unwrap(),
            PublicKeys {
                protocol_bls12381: vec![1; 96],
                worker_ed25519: vec![2; 32],
            }
        );

        config.expected_worker_public_key = hex::encode([2; 31]);
        assert!(matches!(
            config.expected_public_keys(),
            Err(ClientError::InvalidExpectedPublicKey("worker"))
        ));
    }

    #[tokio::test]
    async fn mutual_tls_client_acquires_lease_and_signs() {
        let directory = TempDir::new().unwrap();
        let (ca_certificate, ca_key) = certificate_authority();
        let (server_certificate, server_key) = end_entity(
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca_certificate,
            &ca_key,
        );
        let (client_certificate, client_key) = end_entity(
            "validator-a",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca_certificate,
            &ca_key,
        );
        let ca_path = directory.path().join("ca.pem");
        let client_certificate_path = directory.path().join("client.pem");
        let client_private_key_path = directory.path().join("client.key");
        fs::write(&ca_path, ca_certificate.pem()).unwrap();
        fs::write(&client_certificate_path, client_certificate.pem()).unwrap();
        write_private(&client_private_key_path, &client_key.serialize_pem());

        let (_, protocol) = get_authority_key_pair();
        let (_, worker): (_, NetworkKeyPair) = get_key_pair();
        let worker = ProtocolKeyPair::new(worker);
        let protocol_public = protocol.public().clone();
        let worker_public = worker.public();
        let expected_protocol_public_key = hex::encode(protocol.public().as_bytes());
        let expected_worker_public_key = hex::encode(worker.public().to_bytes());
        let policy = SignerPolicy::open(
            FileStateStore::new(directory.path().join("state.bcs")),
            SystemClock,
            10_000,
        )
        .unwrap();
        let service = SignerService::new(
            policy,
            SignerKeys::new(protocol, worker),
            [7; 32],
            1_024,
            directory.path().join("randomness.bcs"),
        )
        .unwrap();
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
                .add_service(ValidatorSignerServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let config = ExternalSignerConfig {
            endpoint: format!("https://{address}"),
            server_name: "localhost".to_owned(),
            ca_certificate_path: ca_path,
            client_certificate_path,
            client_private_key_path,
            expected_protocol_public_key,
            expected_worker_public_key,
            request_timeout_ms: 1_000,
            lease_ttl_ms: 5_000,
        };
        let mut client = SignerRpcClient::connect(&config).await.unwrap();
        let credential = client.acquire_lease().await.unwrap().credential;
        let block = TestBlock::new(2, 0).set_epoch(1).build();
        let serialized_block = serialize_consensus_block(&block).unwrap();
        let signature = client
            .sign(
                credential.clone(),
                OperationKey::ConsensusBlock {
                    chain_id: [7; 32],
                    epoch: 1,
                    round: 2,
                },
                serialized_block,
            )
            .await
            .unwrap();
        let status = client.get_status().await.unwrap();
        assert_eq!(status.decision_count, 1);
        assert_eq!(
            status.current_lease.as_ref().unwrap().holder_id,
            credential.holder_id
        );
        assert_eq!(
            status.current_lease.unwrap().generation,
            credential.generation
        );
        let signature = consensus_config::ProtocolKeySignature::from_bytes(&signature).unwrap();
        worker_public
            .verify(
                &consensus_block_signing_payload(&block).unwrap(),
                &signature,
            )
            .unwrap();
        client.renew_lease(&credential).await.unwrap();
        client.release_lease(credential).await.unwrap();

        let (blocking, block_signature) = tokio::task::spawn_blocking({
            let config = config.clone();
            move || {
                let blocking = BlockingAuthoritySigner::connect(config, [7; 32]).unwrap();
                let signature = blocking.sign_consensus_block(&block).unwrap();
                (blocking, signature)
            }
        })
        .await
        .unwrap();
        worker_public
            .verify(
                &consensus_block_signing_payload(&TestBlock::new(2, 0).set_epoch(1).build())
                    .unwrap(),
                &block_signature,
            )
            .unwrap();
        let mut dkg_public_keys = vec![protocol_public.clone()];
        dkg_public_keys.extend((0..3).map(|_| {
            let (_, key) = get_authority_key_pair();
            key.public().clone()
        }));
        let nodes = Nodes::new(
            dkg_public_keys
                .iter()
                .enumerate()
                .map(|(id, public_key)| {
                    let public = bls12381::G2Element::from_byte_array(
                        public_key.as_bytes().try_into().unwrap(),
                    )
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
        let (response, message_response) = tokio::task::spawn_blocking({
            let blocking = blocking.clone();
            move || {
                let response = blocking
                    .randomness_dkg(RandomnessDkgRequest::Initialize {
                        epoch: 1,
                        nodes: bcs::to_bytes(&nodes).unwrap(),
                        threshold: 2,
                    })
                    .unwrap();
                let message = blocking
                    .randomness_dkg(RandomnessDkgRequest::CreateMessage { epoch: 1 })
                    .unwrap();
                (response, message)
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            response,
            RandomnessDkgResponse::Status(crate::protocol::DkgSessionStatus {
                party_id: 0,
                shares_ready: false,
                ..
            })
        ));
        assert!(matches!(
            message_response,
            RandomnessDkgResponse::Message(_)
        ));
        let mut payload = bcs::to_bytes(&IntentMessage::new(
            Intent::sui_app(IntentScope::TransactionEffects),
            TransactionEffects::default(),
        ))
        .unwrap();
        payload.extend(bcs::to_bytes(&1_u64).unwrap());
        let signed_payload = payload.clone();
        let authority_signature =
            tokio::task::spawn_blocking(move || blocking.sign_authority(&signed_payload))
                .await
                .unwrap()
                .unwrap();
        protocol_public
            .verify(&payload, &authority_signature)
            .unwrap();
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
