// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeSet, sync::Arc};

use fastcrypto::hash::{Blake2b256, HashFunction};
use thiserror::Error;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

use crate::{
    agent::{Agent, AgentError, Supervisor},
    protocol::{Request, RequestV1, Response, ResponseV1},
    rpc::{AgentRpcRequest, AgentRpcResponse, ValidatorAgent},
};

pub type ClientCertificateDigest = [u8; 32];

pub struct AgentService<S: Supervisor> {
    agent: Arc<Agent<S>>,
    authorized_clients: Arc<BTreeSet<ClientCertificateDigest>>,
}

impl<S: Supervisor> Clone for AgentService<S> {
    fn clone(&self) -> Self {
        Self {
            agent: self.agent.clone(),
            authorized_clients: self.authorized_clients.clone(),
        }
    }
}

impl<S: Supervisor> AgentService<S> {
    pub fn new(
        agent: Agent<S>,
        authorized_clients: impl IntoIterator<Item = ClientCertificateDigest>,
    ) -> Result<Self, ServiceError> {
        let authorized_clients = authorized_clients.into_iter().collect::<BTreeSet<_>>();
        if authorized_clients.is_empty() {
            return Err(ServiceError::EmptyAllowlist);
        }
        Ok(Self {
            agent: Arc::new(agent),
            authorized_clients: Arc::new(authorized_clients),
        })
    }

    fn handle(&self, request: Request) -> Result<Response, ServiceError> {
        let response = match request {
            Request::V1(RequestV1::GetStatus) => ResponseV1::Status(self.agent.status()?),
            Request::V1(RequestV1::Stop { operation_id }) => {
                ResponseV1::Status(self.agent.stop(&operation_id)?)
            }
            Request::V1(RequestV1::Activate {
                operation_id,
                profile,
            }) => ResponseV1::Status(self.agent.activate(&operation_id, profile)?),
        };
        Ok(Response::V1(response))
    }
}

#[tonic::async_trait]
impl<S: Supervisor> ValidatorAgent for AgentService<S> {
    async fn execute(
        &self,
        request: TonicRequest<AgentRpcRequest>,
    ) -> Result<TonicResponse<AgentRpcResponse>, Status> {
        let digest = client_certificate_digest(&request)?;
        if !self.authorized_clients.contains(&digest) {
            return Err(Status::permission_denied(
                "client certificate is not authorized",
            ));
        }
        let body = request.into_inner().body;
        let service = self.clone();
        let response = tokio::task::spawn_blocking(move || {
            let request = bcs::from_bytes(&body).map_err(ServiceError::Decode)?;
            let response = service.handle(request)?;
            bcs::to_bytes(&response).map_err(ServiceError::Encode)
        })
        .await
        .map_err(|_| Status::internal("agent request task failed"))?
        .map_err(Status::from)?;
        Ok(TonicResponse::new(AgentRpcResponse { body: response }))
    }
}

fn client_certificate_digest<T>(
    request: &TonicRequest<T>,
) -> Result<ClientCertificateDigest, Status> {
    let certificates = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("client certificate is required"))?;
    let certificate = certificates
        .first()
        .ok_or_else(|| Status::unauthenticated("client certificate is required"))?;
    Ok(Blake2b256::digest(certificate.as_ref()).into())
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("authorized client certificate allowlist must not be empty")]
    EmptyAllowlist,
    #[error("invalid agent request: {0}")]
    Decode(bcs::Error),
    #[error("failed to encode agent response: {0}")]
    Encode(bcs::Error),
    #[error(transparent)]
    Agent(#[from] AgentError),
}

impl From<ServiceError> for Status {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::EmptyAllowlist | ServiceError::Decode(_) => {
                Status::invalid_argument(error.to_string())
            }
            ServiceError::Agent(
                AgentError::InvalidOperationId | AgentError::OperationConflict(_),
            ) => Status::invalid_argument(error.to_string()),
            ServiceError::Agent(
                AgentError::OperationInProgress(_)
                | AgentError::ServiceMustBeInactive(_)
                | AgentError::ServiceDidNotStop(_)
                | AgentError::ServiceDidNotStart(_),
            ) => Status::failed_precondition(error.to_string()),
            ServiceError::Encode(_) | ServiceError::Agent(_) => Status::internal(error.to_string()),
        }
    }
}
