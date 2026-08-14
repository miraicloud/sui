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
}
