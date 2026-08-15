// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidatorMetrics {
    pub epoch: u64,
    pub voting_right: u64,
    pub last_commit_index: u64,
    pub last_executed_checkpoint: u64,
    pub proposed_blocks: u64,
    pub observer_subscribed_batches: u64,
    pub dkg_failed: bool,
}

impl ValidatorMetrics {
    pub fn parse(text: &str) -> Result<Self, MetricsError> {
        let mut values: BTreeMap<&str, f64> = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((series, value)) = line.rsplit_once(char::is_whitespace) else {
                continue;
            };
            let Ok(value) = value.trim().parse::<f64>() else {
                continue;
            };
            if !value.is_finite() || value < 0.0 {
                continue;
            }
            let name = series.split('{').next().unwrap_or(series);
            for metric in REQUIRED_METRICS {
                if name == *metric || name.ends_with(&format!("_{metric}")) {
                    *values.entry(metric).or_default() += value;
                }
            }
        }

        Ok(Self {
            epoch: integer(&values, "current_epoch")?,
            voting_right: integer(&values, "current_voting_right")?,
            last_commit_index: integer(&values, "last_commit_index")?,
            last_executed_checkpoint: integer(&values, "last_executed_checkpoint")?,
            proposed_blocks: integer(&values, "proposed_blocks")?,
            observer_subscribed_batches: integer(
                &values,
                "observer_subscribed_blocks_batch_size_count",
            )?,
            dkg_failed: integer(&values, "epoch_random_beacon_dkg_failed")? != 0,
        })
    }
}

const REQUIRED_METRICS: &[&str] = &[
    "current_epoch",
    "current_voting_right",
    "last_commit_index",
    "last_executed_checkpoint",
    "proposed_blocks",
    "observer_subscribed_blocks_batch_size_count",
    "epoch_random_beacon_dkg_failed",
];

fn integer(values: &BTreeMap<&str, f64>, name: &'static str) -> Result<u64, MetricsError> {
    let value = values
        .get(name)
        .copied()
        .ok_or(MetricsError::Missing(name))?;
    if value > u64::MAX as f64 || value.fract() != 0.0 {
        return Err(MetricsError::Invalid(name));
    }
    Ok(value as u64)
}

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("required validator metric is missing: {0}")]
    Missing(&'static str),
    #[error("validator metric is not a nonnegative integer: {0}")]
    Invalid(&'static str),
    #[error("failed to fetch validator metrics: {0}")]
    Fetch(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefixed_and_labelled_metrics() {
        let metrics = ValidatorMetrics::parse(
            r#"
                current_epoch 42
                current_voting_right 100
                consensus_last_commit_index 900
                last_executed_checkpoint 1200
                consensus_proposed_blocks{force="false"} 7
                consensus_proposed_blocks{force="true"} 2
                consensus_observer_subscribed_blocks_batch_size_count 33
                epoch_random_beacon_dkg_failed 0
            "#,
        )
        .unwrap();
        assert_eq!(metrics.epoch, 42);
        assert_eq!(metrics.proposed_blocks, 9);
        assert_eq!(metrics.observer_subscribed_batches, 33);
        assert!(!metrics.dkg_failed);
    }

    #[test]
    fn missing_metrics_fail_closed() {
        assert!(matches!(
            ValidatorMetrics::parse("current_epoch 42"),
            Err(MetricsError::Missing("current_voting_right"))
        ));
    }
}
