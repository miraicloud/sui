// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::validator_commands::{
    SuiValidatorCommand, SuiValidatorCommandResponse, ValidatorPromotionDraft,
    ValidatorPromotionTargetRequest, build_promotion_transaction_kind, get_validator_summary,
    validate_prepared_promotion_transaction, validate_promotion_target_request,
};
use anyhow::Ok;
use fastcrypto::{
    encoding::{Base64, Encoding, Hex},
    traits::{KeyPair, ToFromBytes},
};
use shared_crypto::intent::{Intent, IntentMessage};
use sui_config::node::{VALIDATOR_PROMOTION_MANIFEST_VERSION, ValidatorPromotionTarget};
use sui_types::crypto::{
    AuthorityKeyPair, NetworkKeyPair, SuiKeyPair, generate_proof_of_possession,
    get_authority_key_pair, get_key_pair,
};
use sui_types::digests::ChainIdentifier;
use sui_types::transaction::{GasData, TransactionData, TransactionDataAPI, TransactionExpiration};
use sui_types::{base_types::SuiAddress, crypto::Signature, transaction::Transaction};
use test_cluster::TestClusterBuilder;

#[tokio::test]
async fn test_print_raw_rgp_txn() -> Result<(), anyhow::Error> {
    let test_cluster = TestClusterBuilder::new().build().await;
    let keypair: &SuiKeyPair = test_cluster
        .swarm
        .config()
        .validator_configs
        .first()
        .unwrap()
        .account_key_pair
        .keypair();
    let validator_address: SuiAddress = SuiAddress::from(&keypair.public());
    let mut context = test_cluster.wallet;
    let sui_client = context.grpc_client()?;
    let (_, summary) = get_validator_summary(&sui_client, validator_address)
        .await?
        .unwrap();
    let operation_cap_id = summary.operation_cap_id().parse()?;

    // Execute the command and get the serialized transaction data.
    let response = SuiValidatorCommand::DisplayGasPriceUpdateRawTxn {
        sender_address: validator_address,
        new_gas_price: 42,
        operation_cap_id,
        gas_budget: None,
    }
    .execute(&mut context)
    .await?;
    let SuiValidatorCommandResponse::DisplayGasPriceUpdateRawTxn {
        data,
        serialized_data,
    } = response
    else {
        panic!("Expected DisplayGasPriceUpdateRawTxn");
    };

    // Construct the signed transaction and execute it.
    let deserialized_data =
        bcs::from_bytes::<TransactionData>(&Base64::decode(&serialized_data).unwrap())?;
    let signature = Signature::new_secure(
        &IntentMessage::new(Intent::sui_transaction(), deserialized_data),
        keypair,
    );
    let txn = Transaction::from_data(data, vec![signature]);
    context.execute_transaction_must_succeed(txn).await;
    let (_, summary) = get_validator_summary(&sui_client, validator_address)
        .await?
        .unwrap();

    // Check that the gas price is updated correctly.
    assert_eq!(summary.next_epoch_gas_price(), 42);
    Ok(())
}

#[test]
fn planned_promotion_is_unsigned_atomic_and_exact_epoch_bound() {
    let validator_address = SuiAddress::random_for_testing_only();
    let (_, source_protocol): (_, AuthorityKeyPair) = get_authority_key_pair();
    let (_, target_protocol): (_, AuthorityKeyPair) = get_authority_key_pair();
    let (_, target_network): (_, NetworkKeyPair) = get_key_pair();
    let (_, target_worker): (_, NetworkKeyPair) = get_key_pair();
    let pop = generate_proof_of_possession(&target_protocol, validator_address);
    let target = ValidatorPromotionTarget {
        protocol_public_key: Hex::encode(target_protocol.public().as_bytes()),
        network_public_key: Hex::encode(target_network.public().as_bytes()),
        worker_public_key: Hex::encode(target_worker.public().as_bytes()),
        network_address: "/dns/backup.example/tcp/8080/http".parse().unwrap(),
        p2p_address: "/dns/backup.example/udp/8084".parse().unwrap(),
        primary_address: "/dns/backup.example/udp/8081".parse().unwrap(),
        worker_address: "/dns/backup.example/udp/8082".parse().unwrap(),
    };
    let request = ValidatorPromotionTargetRequest {
        plan_id: "test-promotion".to_string(),
        validator_address,
        target: target.clone(),
        proof_of_possession: Hex::encode(pop.as_ref()),
    };
    validate_promotion_target_request(&request).unwrap();

    let chain = ChainIdentifier::random();
    let draft = ValidatorPromotionDraft {
        version: VALIDATOR_PROMOTION_MANIFEST_VERSION,
        plan_id: request.plan_id,
        chain_identifier: Hex::encode(chain.as_bytes()),
        source_epoch: 9,
        activation_epoch: 10,
        validator_address,
        source_protocol_public_key: Hex::encode(source_protocol.public().as_bytes()),
        target,
        proof_of_possession: request.proof_of_possession,
    };
    let transaction = TransactionData::new_with_gas_data_and_expiration(
        build_promotion_transaction_kind(&draft).unwrap(),
        validator_address,
        GasData {
            payment: vec![],
            owner: validator_address,
            price: 1,
            budget: 1,
        },
        TransactionExpiration::ValidDuring {
            min_epoch: Some(9),
            max_epoch: Some(9),
            min_timestamp: None,
            max_timestamp: None,
            chain,
            nonce: 7,
        },
    );
    validate_prepared_promotion_transaction(&transaction, &draft, chain).unwrap();

    let mut loose = transaction;
    *loose.expiration_mut() = TransactionExpiration::Epoch(9);
    assert!(validate_prepared_promotion_transaction(&loose, &draft, chain).is_err());
}
