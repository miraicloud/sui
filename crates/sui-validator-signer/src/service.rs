// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use consensus_config::ProtocolKeyPair;
use consensus_core::{
    BlockAPI as _, ConsensusError, consensus_block_signing_payload, deserialize_consensus_block,
};
use fastcrypto::{
    hash::{Blake2b256, HashFunction},
    traits::{KeyPair as _, Signer as _, ToFromBytes as _},
};
use sui_types::crypto::{AuthorityKeyPair, AuthoritySignature};
use thiserror::Error;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

use crate::{
    authority_payload::{AuthorityPayloadError, classify_authority_payload},
    policy::{FileStateStore, PolicyError, SignerPolicy, SystemClock},
    protocol::{
        ChainId, HolderId, LeaseCredential, OperationKey, Request, RequestV1, Response, ResponseV1,
    },
    rpc::{RpcRequest, RpcResponse, ValidatorSigner},
};

pub struct SignerKeys {
    protocol: AuthorityKeyPair,
    worker: ProtocolKeyPair,
}

impl SignerKeys {
    pub fn new(protocol: AuthorityKeyPair, worker: ProtocolKeyPair) -> Self {
        Self { protocol, worker }
    }

    fn public_keys(&self) -> ResponseV1 {
        ResponseV1::PublicKeys {
            protocol_bls12381: self.protocol.public().as_bytes().to_vec(),
            worker_ed25519: self.worker.public().to_bytes().to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct SignerService {
    policy: Arc<SignerPolicy<FileStateStore, SystemClock>>,
    keys: Arc<SignerKeys>,
    chain_id: ChainId,
    max_payload_bytes: usize,
}

impl SignerService {
    pub fn new(
        policy: SignerPolicy<FileStateStore, SystemClock>,
        keys: SignerKeys,
        chain_id: ChainId,
        max_payload_bytes: usize,
    ) -> Self {
        Self {
            policy: Arc::new(policy),
            keys: Arc::new(keys),
            chain_id,
            max_payload_bytes,
        }
    }

    fn handle(&self, holder_id: HolderId, request: Request) -> Result<Response, ServiceError> {
        let response = match request {
            Request::V1(request) => self.handle_v1(holder_id, request)?,
        };
        Ok(Response::V1(response))
    }

    fn handle_v1(
        &self,
        holder_id: HolderId,
        request: RequestV1,
    ) -> Result<ResponseV1, ServiceError> {
        match request {
            RequestV1::GetPublicKeys => Ok(self.keys.public_keys()),
            RequestV1::GetStatus => Ok(ResponseV1::Status(self.policy.status()?)),
            RequestV1::AcquireLease { ttl_ms } => {
                Ok(ResponseV1::Lease(self.policy.acquire(holder_id, ttl_ms)?))
            }
            RequestV1::RenewLease { credential, ttl_ms } => {
                verify_holder(holder_id, &credential)?;
                Ok(ResponseV1::Lease(self.policy.renew(&credential, ttl_ms)?))
            }
            RequestV1::ReleaseLease { credential } => {
                verify_holder(holder_id, &credential)?;
                self.policy.release(&credential)?;
                Ok(ResponseV1::Released)
            }
            RequestV1::Sign {
                credential,
                operation,
                payload,
            } => {
                verify_holder(holder_id, &credential)?;
                self.verify_signing_request(&operation, &payload)?;
                let digest = Blake2b256::digest(&payload).into();
                let keys = self.keys.clone();
                let signature = self.policy.authorize_and_execute(
                    &credential,
                    operation.clone(),
                    digest,
                    move || sign(&keys, &operation, &payload),
                )?;
                Ok(ResponseV1::Signature(signature))
            }
        }
    }

    fn verify_signing_request(
        &self,
        operation: &OperationKey,
        payload: &[u8],
    ) -> Result<(), ServiceError> {
        if operation.chain_id() != &self.chain_id {
            return Err(ServiceError::ChainMismatch);
        }
        if payload.is_empty() || payload.len() > self.max_payload_bytes {
            return Err(ServiceError::InvalidPayloadSize);
        }
        if matches!(
            operation,
            OperationKey::DkgContribution { .. } | OperationKey::RandomnessPartialSignature { .. }
        ) {
            return Err(ServiceError::TypedRandomnessOperationRequired);
        }
        if matches!(
            operation,
            OperationKey::TransactionEffects { .. } | OperationKey::CheckpointSummary { .. }
        ) && &classify_authority_payload(self.chain_id, payload)? != operation
        {
            return Err(ServiceError::AuthorityOperationMismatch);
        }
        if let OperationKey::ConsensusBlock { epoch, round, .. } = operation {
            let block = deserialize_consensus_block(payload)?;
            if block.epoch() != *epoch || block.round() != *round {
                return Err(ServiceError::ConsensusOperationMismatch);
            }
        }
        Ok(())
    }
}

fn verify_holder(
    authenticated_holder: HolderId,
    credential: &LeaseCredential,
) -> Result<(), ServiceError> {
    if authenticated_holder != credential.holder_id {
        return Err(ServiceError::ClientIdentityMismatch);
    }
    Ok(())
}

fn sign(keys: &SignerKeys, operation: &OperationKey, payload: &[u8]) -> Result<Vec<u8>, String> {
    match operation {
        OperationKey::ConsensusBlock { .. } => {
            let block = deserialize_consensus_block(payload).map_err(|error| error.to_string())?;
            let message =
                consensus_block_signing_payload(&block).map_err(|error| error.to_string())?;
            Ok(keys.worker.sign(&message).to_bytes().to_vec())
        }
        OperationKey::TransactionEffects { .. } | OperationKey::CheckpointSummary { .. } => {
            let signature: AuthoritySignature = keys.protocol.sign(payload);
            Ok(signature.as_ref().to_vec())
        }
        OperationKey::DkgContribution { .. } | OperationKey::RandomnessPartialSignature { .. } => {
            Err("randomness operations require a typed signer API".to_owned())
        }
    }
}

#[tonic::async_trait]
impl ValidatorSigner for SignerService {
    async fn execute(
        &self,
        request: TonicRequest<RpcRequest>,
    ) -> Result<TonicResponse<RpcResponse>, Status> {
        let holder_id = authenticated_holder_id(&request)?;
        let body = request.into_inner().body;
        let service = self.clone();
        let response = tokio::task::spawn_blocking(move || {
            let request = bcs::from_bytes(&body).map_err(ServiceError::Decode)?;
            let response = service.handle(holder_id, request)?;
            bcs::to_bytes(&response).map_err(ServiceError::Encode)
        })
        .await
        .map_err(|_| Status::internal("signer request task failed"))?
        .map_err(Status::from)?;
        Ok(TonicResponse::new(RpcResponse { body: response }))
    }
}

fn authenticated_holder_id(request: &TonicRequest<RpcRequest>) -> Result<HolderId, Status> {
    let certificates = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("client certificate is required"))?;
    let certificate = certificates
        .first()
        .ok_or_else(|| Status::unauthenticated("client certificate is required"))?;
    Ok(Blake2b256::digest(certificate.as_ref()).into())
}

#[derive(Debug, Error)]
enum ServiceError {
    #[error("authenticated client does not match lease holder")]
    ClientIdentityMismatch,
    #[error("request chain does not match signer configuration")]
    ChainMismatch,
    #[error("signing payload is empty or exceeds the configured limit")]
    InvalidPayloadSize,
    #[error("DKG and randomness requests require the typed randomness API")]
    TypedRandomnessOperationRequired,
    #[error("authority signing payload does not match its operation key")]
    AuthorityOperationMismatch,
    #[error("consensus block does not match its operation key")]
    ConsensusOperationMismatch,
    #[error("invalid consensus block: {0}")]
    ConsensusBlock(#[from] ConsensusError),
    #[error(transparent)]
    AuthorityPayload(#[from] AuthorityPayloadError),
    #[error("invalid signer request: {0}")]
    Decode(bcs::Error),
    #[error("failed to encode signer response: {0}")]
    Encode(bcs::Error),
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

impl From<ServiceError> for Status {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::ClientIdentityMismatch => Status::permission_denied(error.to_string()),
            ServiceError::ChainMismatch
            | ServiceError::InvalidPayloadSize
            | ServiceError::TypedRandomnessOperationRequired
            | ServiceError::AuthorityOperationMismatch
            | ServiceError::ConsensusOperationMismatch
            | ServiceError::ConsensusBlock(_)
            | ServiceError::AuthorityPayload(_)
            | ServiceError::Decode(_) => Status::invalid_argument(error.to_string()),
            ServiceError::Policy(
                PolicyError::NoLease
                | PolicyError::LeaseExpired
                | PolicyError::StaleLease
                | PolicyError::ClockMovedBackwards,
            ) => Status::permission_denied(error.to_string()),
            ServiceError::Policy(
                PolicyError::LeaseHeld { .. } | PolicyError::Equivocation | PolicyError::InvalidTtl,
            ) => Status::failed_precondition(error.to_string()),
            ServiceError::Encode(_)
            | ServiceError::Policy(
                PolicyError::ClockBeforeUnixEpoch
                | PolicyError::ClockOverflow
                | PolicyError::GenerationExhausted
                | PolicyError::InvalidStateTransition
                | PolicyError::CorruptJournal(_)
                | PolicyError::JournalRecordTooLarge(_)
                | PolicyError::SigningFailed(_)
                | PolicyError::LockPoisoned
                | PolicyError::UnsupportedStateVersion(_)
                | PolicyError::InvalidStateFile(_)
                | PolicyError::InsecureStatePermissions(_)
                | PolicyError::Serialize(_)
                | PolicyError::Deserialize(_)
                | PolicyError::Io(_),
            ) => Status::internal("signer internal error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use consensus_config::{ProtocolKeySignature, ProtocolPublicKey};
    use consensus_core::{TestBlock, consensus_block_signing_payload, serialize_consensus_block};
    use fastcrypto::traits::{ToFromBytes as _, VerifyingKey as _};
    use shared_crypto::intent::{Intent, IntentMessage, IntentScope};
    use sui_types::crypto::{
        AuthorityPublicKey, NetworkKeyPair, get_authority_key_pair, get_key_pair,
    };
    use sui_types::effects::{TransactionEffects, TransactionEffectsAPI as _};
    use tempfile::TempDir;

    use super::*;
    use crate::protocol::{LeaseGrant, Request, RequestV1, Response};

    struct Fixture {
        _directory: TempDir,
        service: SignerService,
        protocol_public: AuthorityPublicKey,
        worker_public: ProtocolPublicKey,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = TempDir::new().unwrap();
            let (_, protocol) = get_authority_key_pair();
            let (_, worker): (_, NetworkKeyPair) = get_key_pair();
            let worker = ProtocolKeyPair::new(worker);
            let protocol_public = protocol.public().clone();
            let worker_public = worker.public();
            let policy = SignerPolicy::open(
                FileStateStore::new(directory.path().join("state.bcs")),
                SystemClock,
                10_000,
            )
            .unwrap();
            Self {
                _directory: directory,
                service: SignerService::new(
                    policy,
                    SignerKeys::new(protocol, worker),
                    [7; 32],
                    1_024,
                ),
                protocol_public,
                worker_public,
            }
        }

        fn acquire(&self, holder_id: HolderId) -> LeaseCredential {
            let response = self
                .service
                .handle(
                    holder_id,
                    Request::V1(RequestV1::AcquireLease { ttl_ms: 1_000 }),
                )
                .unwrap();
            let Response::V1(ResponseV1::Lease(LeaseGrant {
                holder_id,
                generation,
                lease_id,
                ..
            })) = response
            else {
                panic!("unexpected response")
            };
            LeaseCredential {
                holder_id,
                generation,
                lease_id,
            }
        }

        fn sign(
            &self,
            holder_id: HolderId,
            credential: LeaseCredential,
            operation: OperationKey,
            payload: Vec<u8>,
        ) -> Result<Vec<u8>, ServiceError> {
            let response = self.service.handle(
                holder_id,
                Request::V1(RequestV1::Sign {
                    credential,
                    operation,
                    payload,
                }),
            )?;
            let Response::V1(ResponseV1::Signature(signature)) = response else {
                panic!("unexpected response")
            };
            Ok(signature)
        }
    }

    #[test]
    fn signs_consensus_blocks_with_worker_key() {
        let fixture = Fixture::new();
        let holder_id = [1; 32];
        let credential = fixture.acquire(holder_id);
        let block = TestBlock::new(11, 0).set_epoch(9).build();
        let payload = serialize_consensus_block(&block).unwrap();
        let signature = fixture
            .sign(
                holder_id,
                credential,
                OperationKey::ConsensusBlock {
                    chain_id: [7; 32],
                    epoch: 9,
                    round: 11,
                },
                payload.clone(),
            )
            .unwrap();
        let signature = ProtocolKeySignature::from_bytes(&signature).unwrap();
        let message = consensus_block_signing_payload(&block).unwrap();
        fixture.worker_public.verify(&message, &signature).unwrap();
    }

    #[test]
    fn signs_effects_with_protocol_key() {
        let fixture = Fixture::new();
        let holder_id = [1; 32];
        let credential = fixture.acquire(holder_id);
        let effects = TransactionEffects::default();
        let transaction_digest = effects.transaction_digest().into_inner();
        let mut payload = bcs::to_bytes(&IntentMessage::new(
            Intent::sui_app(IntentScope::TransactionEffects),
            effects,
        ))
        .unwrap();
        payload.extend(bcs::to_bytes(&9_u64).unwrap());
        let signature = fixture
            .sign(
                holder_id,
                credential,
                OperationKey::TransactionEffects {
                    chain_id: [7; 32],
                    epoch: 9,
                    transaction_digest,
                },
                payload.clone(),
            )
            .unwrap();
        let signature = AuthoritySignature::from_bytes(&signature).unwrap();
        fixture
            .protocol_public
            .verify(&payload, &signature)
            .unwrap();
    }

    #[test]
    fn rejects_wrong_holder_chain_conflicts_and_untyped_randomness() {
        let fixture = Fixture::new();
        let holder_id = [1; 32];
        let credential = fixture.acquire(holder_id);
        let block = OperationKey::ConsensusBlock {
            chain_id: [7; 32],
            epoch: 9,
            round: 11,
        };
        let first = serialize_consensus_block(
            &TestBlock::new(11, 0)
                .set_epoch(9)
                .set_timestamp_ms(1)
                .build(),
        )
        .unwrap();
        let conflicting = serialize_consensus_block(
            &TestBlock::new(11, 0)
                .set_epoch(9)
                .set_timestamp_ms(2)
                .build(),
        )
        .unwrap();

        assert!(matches!(
            fixture.sign([2; 32], credential.clone(), block.clone(), first.clone()),
            Err(ServiceError::ClientIdentityMismatch)
        ));
        fixture
            .sign(holder_id, credential.clone(), block.clone(), first.clone())
            .unwrap();
        assert!(matches!(
            fixture.sign(holder_id, credential.clone(), block, conflicting),
            Err(ServiceError::Policy(PolicyError::Equivocation))
        ));
        assert!(matches!(
            fixture.sign(
                holder_id,
                credential.clone(),
                OperationKey::ConsensusBlock {
                    chain_id: [8; 32],
                    epoch: 9,
                    round: 12,
                },
                first
            ),
            Err(ServiceError::ChainMismatch)
        ));
        assert!(matches!(
            fixture.sign(
                holder_id,
                credential,
                OperationKey::RandomnessPartialSignature {
                    chain_id: [7; 32],
                    epoch: 9,
                    round: 1,
                },
                vec![4]
            ),
            Err(ServiceError::TypedRandomnessOperationRequired)
        ));
    }
}
