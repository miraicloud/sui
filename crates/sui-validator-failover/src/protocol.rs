// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

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
    pub health: HostHealth,
    pub operation: Option<OperationStatus>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostHealth {
    pub clock_synchronized: bool,
    pub database_path_accessible: bool,
    pub database_available_bytes: u64,
    pub database_space_sufficient: bool,
    pub service_restart_count: u64,
    pub service_restarts_acceptable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Request {
    V1(RequestV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RequestV1 {
    GetStatus,
    Stop {
        operation_id: String,
    },
    Activate {
        operation_id: String,
        profile: NodeProfile,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Response {
    V1(ResponseV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ResponseV1 {
    Status(HostStatus),
}
