// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

pub type ChainId = [u8; 32];
pub type Digest = [u8; 32];
pub type HolderId = [u8; 32];
pub type LeaseId = [u8; 32];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseGrant {
    pub holder_id: HolderId,
    pub generation: u64,
    pub lease_id: LeaseId,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseCredential {
    pub holder_id: HolderId,
    pub generation: u64,
    pub lease_id: LeaseId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerStatus {
    pub current_lease: Option<LeaseStatus>,
    pub next_generation: u64,
    pub last_seen_unix_ms: u64,
    pub decision_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseStatus {
    pub holder_id: HolderId,
    pub generation: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DkgSessionStatus {
    pub epoch: u64,
    pub party_id: u16,
    pub threshold: u16,
    pub processed_messages: u64,
    pub confirmations: u64,
    pub merged: bool,
    pub shares_ready: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RandomnessDkgRequest {
    Initialize {
        epoch: u64,
        nodes: Vec<u8>,
        threshold: u16,
    },
    GetStatus {
        epoch: u64,
    },
    CreateMessage {
        epoch: u64,
    },
    ProcessMessage {
        epoch: u64,
        message: Vec<u8>,
    },
    TryMerge {
        epoch: u64,
    },
    AddConfirmation {
        epoch: u64,
        confirmation: Vec<u8>,
    },
    TryComplete {
        epoch: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RandomnessDkgResponse {
    Status(DkgSessionStatus),
    Message(Vec<u8>),
    MessageProcessed {
        sender: u16,
    },
    Merged {
        confirmation: Vec<u8>,
        used_messages: Vec<Vec<u8>>,
    },
    ConfirmationProcessed {
        sender: u16,
    },
    Complete {
        public_output: Vec<u8>,
        threshold: u16,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum OperationKey {
    ConsensusBlock {
        chain_id: ChainId,
        epoch: u64,
        round: u32,
    },
    TransactionEffects {
        chain_id: ChainId,
        epoch: u64,
        transaction_digest: Digest,
    },
    CheckpointSummary {
        chain_id: ChainId,
        epoch: u64,
        sequence_number: u64,
    },
    DkgContribution {
        chain_id: ChainId,
        epoch: u64,
        stage: DkgStage,
    },
    RandomnessPartialSignature {
        chain_id: ChainId,
        epoch: u64,
        round: u64,
    },
}

impl OperationKey {
    pub fn chain_id(&self) -> &ChainId {
        match self {
            Self::ConsensusBlock { chain_id, .. }
            | Self::TransactionEffects { chain_id, .. }
            | Self::CheckpointSummary { chain_id, .. }
            | Self::DkgContribution { chain_id, .. }
            | Self::RandomnessPartialSignature { chain_id, .. } => chain_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum DkgStage {
    Message,
    Confirmation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Request {
    V1(RequestV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RequestV1 {
    GetPublicKeys,
    AcquireLease {
        ttl_ms: u64,
    },
    RenewLease {
        credential: LeaseCredential,
        ttl_ms: u64,
    },
    ReleaseLease {
        credential: LeaseCredential,
    },
    Sign {
        credential: LeaseCredential,
        operation: OperationKey,
        payload: Vec<u8>,
    },
    GetStatus,
    RandomnessDkg {
        credential: LeaseCredential,
        chain_id: ChainId,
        request: RandomnessDkgRequest,
    },
    RandomnessPartialSign {
        credential: LeaseCredential,
        chain_id: ChainId,
        epoch: u64,
        round: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Response {
    V1(ResponseV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ResponseV1 {
    PublicKeys {
        protocol_bls12381: Vec<u8>,
        worker_ed25519: Vec<u8>,
    },
    Lease(LeaseGrant),
    Released,
    Signature(Vec<u8>),
    Status(SignerStatus),
    RandomnessDkg(RandomnessDkgResponse),
    RandomnessPartialSignatures(Vec<u8>),
}
