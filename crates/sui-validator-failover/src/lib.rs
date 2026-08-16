// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed state model for local-key validator handoff.
//!
//! This crate deliberately contains no signing RPC. It models the cold control
//! path that must power-fence the old validator, stop the target observer, and
//! independently re-check the fence before releasing a one-generation runtime
//! key envelope.

use std::{error::Error, fmt};

const MAX_FENCE_EVIDENCE_TTL_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PromotionPhase {
    Active,
    Prechecked,
    SourceStopRequested,
    FenceRequested,
    FenceConfirmed,
    TargetObserverStopped,
    KeysReleased,
    ValidatorStarted,
    ValidatorProven,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationAuthority {
    FenceController,
    EnvelopeService,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionManifest {
    pub operation_id: String,
    pub source_host: String,
    pub target_host: String,
    pub chain_genesis_digest: [u8; 32],
    pub validator_protocol_public_key: [u8; 96],
    pub validator_worker_public_key: [u8; 32],
    pub validator_network_public_key: [u8; 32],
    pub target_config_digest: [u8; 32],
    pub target_binary_digest: [u8; 32],
    pub current_generation: u64,
    pub target_baseline_checkpoint: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PowerOffObservation {
    pub authority: ObservationAuthority,
    pub operation_id: String,
    pub source_host: String,
    pub current_generation: u64,
    pub provider_request_id: String,
    pub observed_off: bool,
    pub observed_at_ms: u64,
    pub valid_until_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorProof {
    pub voting_right: u64,
    pub executed_checkpoint: u64,
    pub randomness_signer_ready: bool,
    pub dkg_failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeState {
    pub available: bool,
    pub highest_issued_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailoverState {
    manifest: PromotionManifest,
    phase: PromotionPhase,
    source_powered: bool,
    source_has_runtime_keys: bool,
    source_validator_running: bool,
    target_powered: bool,
    target_observer_running: bool,
    target_has_runtime_keys: bool,
    target_validator_running: bool,
}

impl FailoverState {
    pub fn new(manifest: PromotionManifest) -> Result<Self, FailoverError> {
        if !valid_identifier(&manifest.operation_id)
            || !valid_identifier(&manifest.source_host)
            || !valid_identifier(&manifest.target_host)
            || manifest.source_host == manifest.target_host
            || manifest.current_generation == u64::MAX
            || manifest.chain_genesis_digest == [0; 32]
            || manifest.validator_protocol_public_key == [0; 96]
            || manifest.validator_worker_public_key == [0; 32]
            || manifest.validator_network_public_key == [0; 32]
            || manifest.target_config_digest == [0; 32]
            || manifest.target_binary_digest == [0; 32]
        {
            return Err(FailoverError::InvalidManifest);
        }
        let state = Self {
            manifest,
            phase: PromotionPhase::Active,
            source_powered: true,
            source_has_runtime_keys: true,
            source_validator_running: true,
            target_powered: true,
            target_observer_running: true,
            target_has_runtime_keys: false,
            target_validator_running: false,
        };
        state.validate_safety()?;
        Ok(state)
    }

    pub fn phase(&self) -> PromotionPhase {
        self.phase
    }

    pub fn target_generation(&self) -> u64 {
        self.manifest.current_generation + 1
    }

    pub fn precheck(&mut self) -> Result<(), FailoverError> {
        if !self.advance_required(PromotionPhase::Active, PromotionPhase::Prechecked)? {
            return Ok(());
        }
        if !self.source_powered
            || !self.source_has_runtime_keys
            || !self.source_validator_running
            || !self.target_powered
            || !self.target_observer_running
            || self.target_has_runtime_keys
            || self.target_validator_running
        {
            return Err(FailoverError::PrecheckFailed);
        }
        self.finish(PromotionPhase::Prechecked)
    }

    pub fn request_source_stop(&mut self) -> Result<(), FailoverError> {
        if !self.advance_required(
            PromotionPhase::Prechecked,
            PromotionPhase::SourceStopRequested,
        )? {
            return Ok(());
        }
        self.source_validator_running = false;
        self.finish(PromotionPhase::SourceStopRequested)
    }

    pub fn request_fence(&mut self) -> Result<(), FailoverError> {
        if !self.advance_required(
            PromotionPhase::SourceStopRequested,
            PromotionPhase::FenceRequested,
        )? {
            return Ok(());
        }
        self.finish(PromotionPhase::FenceRequested)
    }

    pub fn confirm_fence(
        &mut self,
        observation: &PowerOffObservation,
        now_ms: u64,
    ) -> Result<(), FailoverError> {
        if self.phase >= PromotionPhase::FenceConfirmed {
            return Ok(());
        }
        self.require_phase(PromotionPhase::FenceRequested)?;
        self.validate_power_off_observation(
            observation,
            ObservationAuthority::FenceController,
            now_ms,
        )?;
        self.source_powered = false;
        self.source_has_runtime_keys = false;
        self.source_validator_running = false;
        self.finish(PromotionPhase::FenceConfirmed)
    }

    pub fn stop_target_observer(&mut self) -> Result<(), FailoverError> {
        if !self.advance_required(
            PromotionPhase::FenceConfirmed,
            PromotionPhase::TargetObserverStopped,
        )? {
            return Ok(());
        }
        self.target_observer_running = false;
        self.finish(PromotionPhase::TargetObserverStopped)
    }

    pub fn release_keys(
        &mut self,
        independent_observation: &PowerOffObservation,
        envelope: &mut EnvelopeState,
        now_ms: u64,
    ) -> Result<(), FailoverError> {
        if self.phase >= PromotionPhase::KeysReleased {
            return Ok(());
        }
        self.require_phase(PromotionPhase::TargetObserverStopped)?;
        if !envelope.available {
            return Err(FailoverError::EnvelopeUnavailable);
        }
        self.validate_power_off_observation(
            independent_observation,
            ObservationAuthority::EnvelopeService,
            now_ms,
        )?;
        if self.source_powered || self.source_has_runtime_keys {
            return Err(FailoverError::SourceNotFenced);
        }
        if envelope.highest_issued_generation != self.manifest.current_generation {
            return Err(FailoverError::GenerationConflict {
                expected: self.manifest.current_generation,
                actual: envelope.highest_issued_generation,
            });
        }
        envelope.highest_issued_generation = self.target_generation();
        self.target_has_runtime_keys = true;
        self.finish(PromotionPhase::KeysReleased)
    }

    pub fn start_target_validator(&mut self) -> Result<(), FailoverError> {
        if !self.advance_required(
            PromotionPhase::KeysReleased,
            PromotionPhase::ValidatorStarted,
        )? {
            return Ok(());
        }
        if !self.target_powered || self.target_observer_running || !self.target_has_runtime_keys {
            return Err(FailoverError::TargetNotReady);
        }
        self.target_validator_running = true;
        self.finish(PromotionPhase::ValidatorStarted)
    }

    pub fn prove_target_validator(&mut self, proof: ValidatorProof) -> Result<(), FailoverError> {
        if self.phase >= PromotionPhase::ValidatorProven {
            return Ok(());
        }
        self.require_phase(PromotionPhase::ValidatorStarted)?;
        if proof.voting_right == 0
            || proof.executed_checkpoint <= self.manifest.target_baseline_checkpoint
            || !proof.randomness_signer_ready
            || proof.dkg_failed
        {
            return Err(FailoverError::InvalidValidatorProof);
        }
        self.finish(PromotionPhase::ValidatorProven)
    }

    pub fn complete(&mut self) -> Result<(), FailoverError> {
        if !self.advance_required(PromotionPhase::ValidatorProven, PromotionPhase::Complete)? {
            return Ok(());
        }
        self.finish(PromotionPhase::Complete)
    }

    /// Models a retired source reboot after a completed promotion. Its
    /// validator keys were held in tmpfs and remain unavailable after power
    /// loss, so it can only return as an observer.
    pub fn return_source_as_observer(&mut self) -> Result<(), FailoverError> {
        self.require_phase(PromotionPhase::Complete)?;
        self.source_powered = true;
        self.source_has_runtime_keys = false;
        self.source_validator_running = false;
        self.validate_safety()
    }

    pub fn validate_safety(&self) -> Result<(), FailoverError> {
        let source_holds_keys = self.source_powered && self.source_has_runtime_keys;
        let target_holds_keys = self.target_powered && self.target_has_runtime_keys;
        if source_holds_keys && target_holds_keys
            || self.source_validator_running
                && (!self.source_powered || !self.source_has_runtime_keys)
            || self.target_validator_running
                && (!self.target_powered
                    || !self.target_has_runtime_keys
                    || self.target_observer_running)
            || self.target_has_runtime_keys && self.phase < PromotionPhase::KeysReleased
        {
            return Err(FailoverError::SafetyInvariantViolated);
        }
        Ok(())
    }

    fn validate_power_off_observation(
        &self,
        observation: &PowerOffObservation,
        authority: ObservationAuthority,
        now_ms: u64,
    ) -> Result<(), FailoverError> {
        let ttl = observation
            .valid_until_ms
            .checked_sub(observation.observed_at_ms)
            .ok_or(FailoverError::InvalidFenceObservation)?;
        if observation.authority != authority
            || observation.operation_id != self.manifest.operation_id
            || observation.source_host != self.manifest.source_host
            || observation.current_generation != self.manifest.current_generation
            || !valid_identifier(&observation.provider_request_id)
            || !observation.observed_off
            || observation.observed_at_ms > now_ms
            || now_ms > observation.valid_until_ms
            || ttl > MAX_FENCE_EVIDENCE_TTL_MS
        {
            return Err(FailoverError::InvalidFenceObservation);
        }
        Ok(())
    }

    fn advance_required(
        &self,
        expected: PromotionPhase,
        completed: PromotionPhase,
    ) -> Result<bool, FailoverError> {
        if self.phase >= completed {
            Ok(false)
        } else if self.phase == expected {
            Ok(true)
        } else {
            Err(FailoverError::WrongPhase {
                expected,
                actual: self.phase,
            })
        }
    }

    fn require_phase(&self, expected: PromotionPhase) -> Result<(), FailoverError> {
        if self.phase != expected {
            return Err(FailoverError::WrongPhase {
                expected,
                actual: self.phase,
            });
        }
        Ok(())
    }

    fn finish(&mut self, phase: PromotionPhase) -> Result<(), FailoverError> {
        self.phase = phase;
        self.validate_safety()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailoverError {
    InvalidManifest,
    PrecheckFailed,
    InvalidFenceObservation,
    EnvelopeUnavailable,
    SourceNotFenced,
    TargetNotReady,
    InvalidValidatorProof,
    SafetyInvariantViolated,
    WrongPhase {
        expected: PromotionPhase,
        actual: PromotionPhase,
    },
    GenerationConflict {
        expected: u64,
        actual: u64,
    },
}

impl fmt::Display for FailoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for FailoverError {}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 1_000_000;

    fn manifest(generation: u64) -> PromotionManifest {
        PromotionManifest {
            operation_id: "promote-a-to-b-001".to_owned(),
            source_host: "validator-a".to_owned(),
            target_host: "validator-b".to_owned(),
            chain_genesis_digest: [1; 32],
            validator_protocol_public_key: [2; 96],
            validator_worker_public_key: [3; 32],
            validator_network_public_key: [4; 32],
            target_config_digest: [5; 32],
            target_binary_digest: [6; 32],
            current_generation: generation,
            target_baseline_checkpoint: 42,
        }
    }

    fn observation(authority: ObservationAuthority, generation: u64) -> PowerOffObservation {
        PowerOffObservation {
            authority,
            operation_id: "promote-a-to-b-001".to_owned(),
            source_host: "validator-a".to_owned(),
            current_generation: generation,
            provider_request_id: "ipmi-request-001".to_owned(),
            observed_off: true,
            observed_at_ms: NOW_MS - 1_000,
            valid_until_ms: NOW_MS + 1_000,
        }
    }

    fn reach_target_observer_stopped(state: &mut FailoverState) {
        state.precheck().unwrap();
        state.request_source_stop().unwrap();
        state.request_fence().unwrap();
        state
            .confirm_fence(
                &observation(ObservationAuthority::FenceController, 7),
                NOW_MS,
            )
            .unwrap();
        state.stop_target_observer().unwrap();
    }

    #[test]
    fn complete_handoff_preserves_single_key_holder_and_is_idempotent() {
        let mut state = FailoverState::new(manifest(7)).unwrap();
        let mut envelope = EnvelopeState {
            available: true,
            highest_issued_generation: 7,
        };

        state.precheck().unwrap();
        state.precheck().unwrap();
        state.request_source_stop().unwrap();
        state.request_fence().unwrap();
        state
            .confirm_fence(
                &observation(ObservationAuthority::FenceController, 7),
                NOW_MS,
            )
            .unwrap();
        state.stop_target_observer().unwrap();
        state
            .release_keys(
                &observation(ObservationAuthority::EnvelopeService, 7),
                &mut envelope,
                NOW_MS,
            )
            .unwrap();
        state
            .release_keys(
                &observation(ObservationAuthority::EnvelopeService, 7),
                &mut envelope,
                NOW_MS + MAX_FENCE_EVIDENCE_TTL_MS,
            )
            .unwrap();
        state.start_target_validator().unwrap();
        state
            .prove_target_validator(ValidatorProof {
                voting_right: 48,
                executed_checkpoint: 43,
                randomness_signer_ready: true,
                dkg_failed: false,
            })
            .unwrap();
        state.complete().unwrap();
        state.return_source_as_observer().unwrap();

        assert_eq!(state.phase(), PromotionPhase::Complete);
        assert_eq!(envelope.highest_issued_generation, 8);
        state.validate_safety().unwrap();
    }

    #[test]
    fn key_release_is_impossible_before_both_fence_checks_and_observer_stop() {
        let mut state = FailoverState::new(manifest(7)).unwrap();
        let release_observation = observation(ObservationAuthority::EnvelopeService, 7);
        let mut envelope = EnvelopeState {
            available: true,
            highest_issued_generation: 7,
        };

        for advance in 0..5 {
            assert!(matches!(
                state.release_keys(&release_observation, &mut envelope, NOW_MS),
                Err(FailoverError::WrongPhase { .. })
            ));
            assert_eq!(envelope.highest_issued_generation, 7);
            assert!(!state.target_has_runtime_keys);
            state.validate_safety().unwrap();
            match advance {
                0 => state.precheck().unwrap(),
                1 => state.request_source_stop().unwrap(),
                2 => state.request_fence().unwrap(),
                3 => state
                    .confirm_fence(
                        &observation(ObservationAuthority::FenceController, 7),
                        NOW_MS,
                    )
                    .unwrap(),
                4 => state.stop_target_observer().unwrap(),
                _ => unreachable!(),
            }
        }

        state
            .release_keys(&release_observation, &mut envelope, NOW_MS)
            .unwrap();
        assert_eq!(envelope.highest_issued_generation, 8);
        state.validate_safety().unwrap();
    }

    #[test]
    fn stale_wrong_or_overlong_fence_evidence_fails_closed() {
        let cases = [
            {
                let mut value = observation(ObservationAuthority::FenceController, 7);
                value.observed_off = false;
                value
            },
            {
                let mut value = observation(ObservationAuthority::FenceController, 7);
                value.source_host = "validator-c".to_owned();
                value
            },
            {
                let mut value = observation(ObservationAuthority::FenceController, 6);
                value.current_generation = 6;
                value
            },
            {
                let mut value = observation(ObservationAuthority::FenceController, 7);
                value.valid_until_ms = NOW_MS - 1;
                value
            },
            {
                let mut value = observation(ObservationAuthority::FenceController, 7);
                value.valid_until_ms = value.observed_at_ms + MAX_FENCE_EVIDENCE_TTL_MS + 1;
                value
            },
            observation(ObservationAuthority::EnvelopeService, 7),
        ];

        for value in cases {
            let mut state = FailoverState::new(manifest(7)).unwrap();
            state.precheck().unwrap();
            state.request_source_stop().unwrap();
            state.request_fence().unwrap();
            assert_eq!(
                state.confirm_fence(&value, NOW_MS),
                Err(FailoverError::InvalidFenceObservation)
            );
            assert_eq!(state.phase(), PromotionPhase::FenceRequested);
        }
    }

    #[test]
    fn controller_rollback_cannot_reissue_an_envelope_generation() {
        let mut state = FailoverState::new(manifest(7)).unwrap();
        reach_target_observer_stopped(&mut state);
        let mut envelope = EnvelopeState {
            available: true,
            // Generation 8 was already issued by an operation omitted from a
            // restored controller database.
            highest_issued_generation: 8,
        };
        assert_eq!(
            state.release_keys(
                &observation(ObservationAuthority::EnvelopeService, 7),
                &mut envelope,
                NOW_MS,
            ),
            Err(FailoverError::GenerationConflict {
                expected: 7,
                actual: 8,
            })
        );
        assert!(!state.target_has_runtime_keys);
        state.validate_safety().unwrap();
    }

    #[test]
    fn unavailable_envelope_state_and_invalid_validator_proof_fail_closed() {
        let mut state = FailoverState::new(manifest(7)).unwrap();
        reach_target_observer_stopped(&mut state);
        let mut envelope = EnvelopeState {
            available: false,
            highest_issued_generation: 7,
        };
        assert_eq!(
            state.release_keys(
                &observation(ObservationAuthority::EnvelopeService, 7),
                &mut envelope,
                NOW_MS,
            ),
            Err(FailoverError::EnvelopeUnavailable)
        );
        envelope.available = true;
        state
            .release_keys(
                &observation(ObservationAuthority::EnvelopeService, 7),
                &mut envelope,
                NOW_MS,
            )
            .unwrap();
        state.start_target_validator().unwrap();
        assert_eq!(
            state.prove_target_validator(ValidatorProof {
                voting_right: 0,
                executed_checkpoint: 43,
                randomness_signer_ready: true,
                dkg_failed: false,
            }),
            Err(FailoverError::InvalidValidatorProof)
        );
        assert_eq!(state.phase(), PromotionPhase::ValidatorStarted);
        state.validate_safety().unwrap();
    }

    #[test]
    fn invalid_manifests_are_rejected() {
        let mut same_host = manifest(7);
        same_host.target_host = same_host.source_host.clone();
        assert_eq!(
            FailoverState::new(same_host),
            Err(FailoverError::InvalidManifest)
        );

        let mut zero_chain = manifest(7);
        zero_chain.chain_genesis_digest = [0; 32];
        assert_eq!(
            FailoverState::new(zero_chain),
            Err(FailoverError::InvalidManifest)
        );
    }
}
