// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use shared_crypto::intent::{Intent, IntentMessage, IntentScope};
use sui_types::{
    effects::{TransactionEffects, TransactionEffectsAPI as _},
    messages_checkpoint::CheckpointSummary,
};
use thiserror::Error;

use crate::protocol::{ChainId, OperationKey};

const SERIALIZED_EPOCH_LENGTH: usize = 8;

pub fn classify_authority_payload(
    chain_id: ChainId,
    payload: &[u8],
) -> Result<OperationKey, AuthorityPayloadError> {
    let message_length = payload
        .len()
        .checked_sub(SERIALIZED_EPOCH_LENGTH)
        .ok_or(AuthorityPayloadError::TooShort)?;
    let (message, serialized_epoch) = payload.split_at(message_length);
    let epoch: u64 = bcs::from_bytes(serialized_epoch).map_err(AuthorityPayloadError::Epoch)?;
    let scope = message
        .first()
        .copied()
        .ok_or(AuthorityPayloadError::TooShort)?;

    match scope {
        value if value == IntentScope::TransactionEffects as u8 => {
            let message: IntentMessage<TransactionEffects> =
                bcs::from_bytes(message).map_err(AuthorityPayloadError::Message)?;
            if message.intent != Intent::sui_app(IntentScope::TransactionEffects) {
                return Err(AuthorityPayloadError::InvalidIntent);
            }
            Ok(OperationKey::TransactionEffects {
                chain_id,
                epoch,
                transaction_digest: message.value.transaction_digest().into_inner(),
            })
        }
        value if value == IntentScope::CheckpointSummary as u8 => {
            let message: IntentMessage<CheckpointSummary> =
                bcs::from_bytes(message).map_err(AuthorityPayloadError::Message)?;
            if message.intent != Intent::sui_app(IntentScope::CheckpointSummary)
                || message.value.epoch != epoch
            {
                return Err(AuthorityPayloadError::InvalidIntent);
            }
            Ok(OperationKey::CheckpointSummary {
                chain_id,
                epoch,
                sequence_number: message.value.sequence_number,
            })
        }
        _ => Err(AuthorityPayloadError::UnsupportedIntentScope(scope)),
    }
}

#[derive(Debug, Error)]
pub enum AuthorityPayloadError {
    #[error("authority signing payload is too short")]
    TooShort,
    #[error("authority signing payload has an invalid epoch: {0}")]
    Epoch(bcs::Error),
    #[error("authority signing payload is malformed: {0}")]
    Message(bcs::Error),
    #[error("authority signing payload has an invalid intent")]
    InvalidIntent,
    #[error("authority signing payload uses unsupported intent scope {0}")]
    UnsupportedIntentScope(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_effects_operation_from_canonical_payload() {
        let effects = TransactionEffects::default();
        let expected_digest = effects.transaction_digest().into_inner();
        let mut payload = bcs::to_bytes(&IntentMessage::new(
            Intent::sui_app(IntentScope::TransactionEffects),
            effects,
        ))
        .unwrap();
        payload.extend(bcs::to_bytes(&7_u64).unwrap());

        assert_eq!(
            classify_authority_payload([3; 32], &payload).unwrap(),
            OperationKey::TransactionEffects {
                chain_id: [3; 32],
                epoch: 7,
                transaction_digest: expected_digest,
            }
        );
    }

    #[test]
    fn rejects_unsupported_and_truncated_payloads() {
        assert!(matches!(
            classify_authority_payload([0; 32], &[1, 2]),
            Err(AuthorityPayloadError::TooShort)
        ));

        let mut payload = bcs::to_bytes(&IntentMessage::new(
            Intent::sui_app(IntentScope::PersonalMessage),
            vec![1_u8],
        ))
        .unwrap();
        payload.extend(bcs::to_bytes(&7_u64).unwrap());
        assert!(matches!(
            classify_authority_payload([0; 32], &payload),
            Err(AuthorityPayloadError::UnsupportedIntentScope(_))
        ));
    }
}
