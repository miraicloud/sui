// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeProfile {
    Observer,
    Validator,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceState {
    Active,
    Inactive,
    Failed,
    Unknown(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentAction {
    Stop,
    Activate { profile: NodeProfile },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationPhase {
    Prepared,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationStatus {
    pub operation_id: String,
    pub action: AgentAction,
    pub phase: OperationPhase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostStatus {
    pub host_id: String,
    pub profile: Option<NodeProfile>,
    pub service_state: ServiceState,
    pub protocol_public_key: String,
    pub worker_public_key: String,
    pub network_public_key: String,
    pub operation: Option<OperationStatus>,
}
