// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, PartialEq, prost::Message)]
pub struct RpcRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RpcResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
}

mod generated {
    include!(concat!(
        env!("OUT_DIR"),
        "/sui_validator_signer.ValidatorSigner.rs"
    ));
}

pub use generated::{
    validator_signer_client::ValidatorSignerClient,
    validator_signer_server::{ValidatorSigner, ValidatorSignerServer},
};
