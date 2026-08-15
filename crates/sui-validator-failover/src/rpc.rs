// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, PartialEq, prost::Message)]
pub struct AgentRpcRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct AgentRpcResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
}

mod generated {
    include!(concat!(
        env!("OUT_DIR"),
        "/sui_validator_failover.ValidatorAgent.rs"
    ));
}

pub use generated::{
    validator_agent_client::ValidatorAgentClient,
    validator_agent_server::{ValidatorAgent, ValidatorAgentServer},
};
