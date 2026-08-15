// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{sync::mpsc as std_mpsc, thread, time::Duration};

use consensus_config::{ProtocolKeySignature, ProtocolPublicKey};
use consensus_core::{
    Block, BlockAPI as _, BlockSigningService, ConsensusError, ConsensusResult,
    serialize_consensus_block,
};
use fastcrypto::{
    ed25519::Ed25519PublicKey,
    traits::{Signer, ToFromBytes as _},
};
use sui_types::crypto::AuthoritySignature;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use crate::{
    authority_payload::{AuthorityPayloadError, classify_authority_payload},
    client::{ClientError, ExternalSignerConfig, SignerRpcClient},
    protocol::ChainId,
};

const COMMAND_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct BlockingValidatorSigner {
    commands: Option<mpsc::Sender<Command>>,
    worker_public_key: ProtocolPublicKey,
    chain_id: ChainId,
}

pub type BlockingAuthoritySigner = BlockingValidatorSigner;

impl BlockingValidatorSigner {
    pub fn connect(
        config: ExternalSignerConfig,
        chain_id: ChainId,
    ) -> Result<Self, BlockingSignerError> {
        let worker_public_key = configured_worker_public_key(&config)?;
        let startup_timeout =
            Duration::from_millis(config.request_timeout_ms.saturating_mul(3).max(1_000));
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (startup_sender, startup_receiver) = std_mpsc::sync_channel(1);
        thread::Builder::new()
            .name("sui-external-authority-signer".to_owned())
            .spawn(move || run(config, chain_id, receiver, startup_sender))
            .map_err(BlockingSignerError::Spawn)?;

        match startup_receiver.recv_timeout(startup_timeout) {
            Ok(Ok(())) => Ok(Self {
                commands: Some(commands),
                worker_public_key,
                chain_id,
            }),
            Ok(Err(message)) => Err(BlockingSignerError::Startup(message)),
            Err(std_mpsc::RecvTimeoutError::Timeout) => Err(BlockingSignerError::StartupTimeout),
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                Err(BlockingSignerError::WorkerStopped)
            }
        }
    }

    /// Creates a signer handle for a non-validator process. It deliberately has no
    /// remote lease and fails closed if any authority signing path reaches it.
    pub fn standby(
        config: &ExternalSignerConfig,
        chain_id: ChainId,
    ) -> Result<Self, BlockingSignerError> {
        Ok(Self {
            commands: None,
            worker_public_key: configured_worker_public_key(config)?,
            chain_id,
        })
    }

    pub fn sign_authority(
        &self,
        payload: &[u8],
    ) -> Result<AuthoritySignature, BlockingSignerError> {
        let (sender, receiver) = std_mpsc::sync_channel(1);
        self.commands
            .as_ref()
            .ok_or(BlockingSignerError::Standby)?
            .blocking_send(Command::SignAuthority {
                payload: payload.to_vec(),
                response: sender,
            })
            .map_err(|_| BlockingSignerError::WorkerStopped)?;
        let bytes = receiver
            .recv()
            .map_err(|_| BlockingSignerError::WorkerStopped)??;
        AuthoritySignature::from_bytes(&bytes).map_err(BlockingSignerError::InvalidSignature)
    }

    pub fn sign_consensus_block(
        &self,
        block: &Block,
    ) -> Result<ProtocolKeySignature, BlockingSignerError> {
        let payload = serialize_consensus_block(block)?;
        let operation = crate::protocol::OperationKey::ConsensusBlock {
            chain_id: self.chain_id,
            epoch: block.epoch(),
            round: block.round(),
        };
        let (sender, receiver) = std_mpsc::sync_channel(1);
        self.commands
            .as_ref()
            .ok_or(BlockingSignerError::Standby)?
            .blocking_send(Command::SignConsensusBlock {
                operation,
                payload,
                response: sender,
            })
            .map_err(|_| BlockingSignerError::WorkerStopped)?;
        let bytes = receiver
            .recv()
            .map_err(|_| BlockingSignerError::WorkerStopped)??;
        ProtocolKeySignature::from_bytes(&bytes).map_err(BlockingSignerError::InvalidSignature)
    }
}

impl Signer<AuthoritySignature> for BlockingValidatorSigner {
    fn sign(&self, message: &[u8]) -> AuthoritySignature {
        self.sign_authority(message)
            .unwrap_or_else(|error| panic!("external authority signer failed closed: {error}"))
    }
}

impl BlockSigningService for BlockingValidatorSigner {
    fn public_key(&self) -> ProtocolPublicKey {
        self.worker_public_key.clone()
    }

    fn sign_block(&self, block: &Block) -> ConsensusResult<ProtocolKeySignature> {
        self.sign_consensus_block(block)
            .map_err(|error| ConsensusError::BlockSigningFailure(error.to_string()))
    }
}

enum Command {
    SignAuthority {
        payload: Vec<u8>,
        response: std_mpsc::SyncSender<Result<Vec<u8>, BlockingSignerError>>,
    },
    SignConsensusBlock {
        operation: crate::protocol::OperationKey,
        payload: Vec<u8>,
        response: std_mpsc::SyncSender<Result<Vec<u8>, BlockingSignerError>>,
    },
}

fn run(
    config: ExternalSignerConfig,
    chain_id: ChainId,
    receiver: mpsc::Receiver<Command>,
    startup: std_mpsc::SyncSender<Result<(), String>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = startup.send(Err(format!("failed to create signer runtime: {error}")));
            return;
        }
    };
    runtime.block_on(run_async(config, chain_id, receiver, startup));
}

async fn run_async(
    config: ExternalSignerConfig,
    chain_id: ChainId,
    mut receiver: mpsc::Receiver<Command>,
    startup: std_mpsc::SyncSender<Result<(), String>>,
) {
    let mut client = match SignerRpcClient::connect(&config).await {
        Ok(client) => client,
        Err(error) => {
            let _ = startup.send(Err(error.to_string()));
            return;
        }
    };
    let lease = match client.acquire_lease().await {
        Ok(lease) => lease,
        Err(error) => {
            let _ = startup.send(Err(error.to_string()));
            return;
        }
    };
    let credential = lease.credential;
    let _ = startup.send(Ok(()));

    let renew_period = Duration::from_millis((config.lease_ttl_ms / 3).max(1));
    let mut renew = tokio::time::interval(renew_period);
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    renew.tick().await;

    loop {
        tokio::select! {
            _ = renew.tick() => {
                if let Err(error) = client.renew_lease(&credential).await {
                    warn!(%error, "external signer lease renewal failed; signing remains fail closed at the signer");
                }
            }
            command = receiver.recv() => {
                let Some(command) = command else {
                    let _ = client.release_lease(credential).await;
                    return;
                };
                match command {
                    Command::SignAuthority { payload, response } => {
                        let result = sign_authority(
                            &mut client,
                            credential.clone(),
                            chain_id,
                            payload,
                        )
                        .await;
                        let _ = response.send(result);
                    }
                    Command::SignConsensusBlock {
                        operation,
                        payload,
                        response,
                    } => {
                        let result = client
                            .sign(credential.clone(), operation, payload)
                            .await
                            .map_err(BlockingSignerError::Client);
                        let _ = response.send(result);
                    }
                }
            }
        }
    }
}

fn configured_worker_public_key(
    config: &ExternalSignerConfig,
) -> Result<ProtocolPublicKey, BlockingSignerError> {
    let keys = config.expected_public_keys()?;
    let key = Ed25519PublicKey::from_bytes(&keys.worker_ed25519)
        .map_err(BlockingSignerError::InvalidSignature)?;
    Ok(ProtocolPublicKey::new(key))
}

async fn sign_authority(
    client: &mut SignerRpcClient,
    credential: crate::protocol::LeaseCredential,
    chain_id: ChainId,
    payload: Vec<u8>,
) -> Result<Vec<u8>, BlockingSignerError> {
    let operation = classify_authority_payload(chain_id, &payload)?;
    client
        .sign(credential, operation, payload)
        .await
        .map_err(BlockingSignerError::Client)
}

#[derive(Debug, Error)]
pub enum BlockingSignerError {
    #[error("external signer is in standby mode")]
    Standby,
    #[error("failed to spawn external signer worker: {0}")]
    Spawn(std::io::Error),
    #[error("external signer startup failed: {0}")]
    Startup(String),
    #[error("external signer startup timed out")]
    StartupTimeout,
    #[error("external signer worker stopped")]
    WorkerStopped,
    #[error(transparent)]
    AuthorityPayload(#[from] AuthorityPayloadError),
    #[error("invalid consensus block signing request: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("external signer request failed: {0}")]
    Client(#[from] ClientError),
    #[error("external signer returned an invalid BLS signature: {0}")]
    InvalidSignature(fastcrypto::error::FastCryptoError),
}

#[cfg(test)]
mod tests {
    use fastcrypto::traits::KeyPair as _;

    use super::*;

    #[test]
    fn standby_signer_fails_closed_without_connecting() {
        let (_, worker): (_, sui_types::crypto::NetworkKeyPair) = sui_types::crypto::get_key_pair();
        let config = ExternalSignerConfig {
            endpoint: "https://127.0.0.1:1".to_owned(),
            server_name: "unused".to_owned(),
            ca_certificate_path: "unused".into(),
            client_certificate_path: "unused".into(),
            client_private_key_path: "unused".into(),
            expected_protocol_public_key: hex::encode([1; 96]),
            expected_worker_public_key: hex::encode(worker.public().as_bytes()),
            request_timeout_ms: 1_000,
            lease_ttl_ms: 5_000,
        };
        let signer = BlockingValidatorSigner::standby(&config, [7; 32]).unwrap();
        assert!(matches!(
            signer.sign_authority(b"must not sign"),
            Err(BlockingSignerError::Standby)
        ));
    }
}
