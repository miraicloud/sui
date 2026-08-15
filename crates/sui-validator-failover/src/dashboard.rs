// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::controller::{ControlPlane, ControlSnapshot, PromotionRecord};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

#[derive(Clone)]
struct DashboardState {
    control: Arc<ControlPlane>,
    token_digest: [u8; 32],
    jobs: Arc<Mutex<BTreeMap<String, PromotionJob>>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum PromotionJob {
    Running,
    Complete { record: PromotionRecord },
    Failed { error: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromoteRequest {
    operation_id: String,
    source_host: String,
    target_host: String,
    expected_source_generation: u64,
}

#[derive(Debug, Serialize)]
struct PromotionView {
    record: Option<PromotionRecord>,
    job: Option<PromotionJob>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn router(control: Arc<ControlPlane>, api_token: &str) -> Router {
    let state = DashboardState {
        control,
        token_digest: Blake2b256::digest(api_token.as_bytes()).into(),
        jobs: Arc::new(Mutex::new(BTreeMap::new())),
    };
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/promotions", post(promote))
        .route("/api/v1/promotions/{operation_id}", get(promotion))
        .with_state(state)
}

async fn index() -> Response {
    let mut response = Html(DASHBOARD_HTML).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

async fn health() -> &'static str {
    "ok"
}

async fn overview(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<ControlSnapshot>, ApiError> {
    authorize(&state, &headers)?;
    state
        .control
        .snapshot()
        .await
        .map(Json)
        .map_err(|error| ApiError::Unavailable(error.to_string()))
}

async fn promotion(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> Result<Json<PromotionView>, ApiError> {
    authorize(&state, &headers)?;
    let record = state.control.promotion(&operation_id).await;
    let job = state.jobs.lock().await.get(&operation_id).cloned();
    if record.is_none() && job.is_none() {
        return Err(ApiError::NotFound);
    }
    Ok(Json(PromotionView { record, job }))
}

async fn promote(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(request): Json<PromoteRequest>,
) -> Result<(StatusCode, Json<PromotionView>), ApiError> {
    authorize(&state, &headers)?;
    let existing_job = state.jobs.lock().await.get(&request.operation_id).cloned();
    if let Some(job @ (PromotionJob::Running | PromotionJob::Complete { .. })) = existing_job {
        let record = state.control.promotion(&request.operation_id).await;
        return Ok((
            StatusCode::OK,
            Json(PromotionView {
                record,
                job: Some(job),
            }),
        ));
    }

    state
        .jobs
        .lock()
        .await
        .insert(request.operation_id.clone(), PromotionJob::Running);
    let response = PromotionView {
        record: state.control.promotion(&request.operation_id).await,
        job: Some(PromotionJob::Running),
    };
    let task_state = state.clone();
    let operation_id = request.operation_id.clone();
    tokio::spawn(async move {
        let result = task_state
            .control
            .promote(
                request.operation_id,
                request.source_host,
                request.target_host,
                request.expected_source_generation,
            )
            .await;
        let job = match result {
            Ok(record) => PromotionJob::Complete { record },
            Err(error) => PromotionJob::Failed {
                error: error.to_string(),
            },
        };
        task_state.jobs.lock().await.insert(operation_id, job);
    });
    Ok((StatusCode::ACCEPTED, Json(response)))
}

fn authorize(state: &DashboardState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(candidate) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(ApiError::Unauthorized);
    };
    let candidate: [u8; 32] = Blake2b256::digest(candidate.as_bytes()).into();
    if !constant_time_equal(&candidate, &state.token_digest) {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for index in 0..left.len() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

enum ApiError {
    Unauthorized,
    NotFound,
    Unavailable(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "authentication required".to_owned(),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "promotion not found".to_owned()),
            Self::Unavailable(message) => (StatusCode::SERVICE_UNAVAILABLE, message),
        };
        let mut response = (status, Json(ErrorBody { error: message })).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"validator-control\""),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_is_exact() {
        assert!(constant_time_equal(&[7; 32], &[7; 32]));
        assert!(!constant_time_equal(&[7; 32], &[8; 32]));
    }

    #[test]
    fn embedded_dashboard_uses_only_same_origin_api() {
        assert!(DASHBOARD_HTML.contains("/api/v1/overview"));
        assert!(!DASHBOARD_HTML.contains("grpc://"));
        assert!(!DASHBOARD_HTML.contains("https://signer"));
    }
}
