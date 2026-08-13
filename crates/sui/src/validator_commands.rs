// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow, bail};
use move_core_types::{ident_str, identifier::Identifier};
use mysten_common::ZipDebugEqIteratorExt;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt::{self, Debug, Display, Formatter, Write},
    fs::{self, OpenOptions},
    io::Write as _,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};
use sui_config::node::{
    VALIDATOR_PROMOTION_MANIFEST_VERSION, ValidatorPromotionEvidence, ValidatorPromotionManifest,
    ValidatorPromotionTarget,
};
use sui_genesis_builder::validator_info::GenesisValidatorInfo;
use url::{ParseError, Url};

use sui_rpc::proto::sui::rpc::v2 as proto;
use sui_rpc_api::Client;
use sui_rpc_api::client::ExecutedTransaction;
use sui_types::{
    SUI_SYSTEM_PACKAGE_ID,
    base_types::{ObjectID, ObjectRef, SuiAddress},
    crypto::{
        AuthorityPublicKey, AuthoritySignature, DEFAULT_EPOCH_ID, NetworkPublicKey, Signable,
        verify_proof_of_possession,
    },
    digests::{ChainIdentifier, TransactionDigest},
    effects::TransactionEffectsAPI,
    multiaddr::Multiaddr,
    object::Owner,
    sui_system_state::sui_system_state_inner_v1::{UnverifiedValidatorOperationCapV1, ValidatorV1},
};
use tap::tap::TapOptional;

use crate::fire_drill::get_gas_obj_ref;
use clap::*;
use colored::Colorize;
use fastcrypto::traits::ToFromBytes;
use fastcrypto::{
    encoding::{Base64, Encoding, Hex},
    traits::KeyPair,
};
use serde::Serialize;
use shared_crypto::intent::{Intent, IntentMessage, IntentScope};
use sui_bridge::metrics::BridgeMetrics;
use sui_bridge::sui_client::SuiClient as SuiBridgeClient;
use sui_bridge::sui_transaction_builder::{
    build_committee_register_transaction, build_committee_update_url_transaction,
};
use sui_keys::{
    key_derive::generate_new_key,
    keypair_file::{
        read_authority_keypair_from_file, read_keypair_from_file, read_network_keypair_from_file,
        write_authority_keypair_to_file, write_keypair_to_file,
    },
};
use sui_keys::{keypair_file::read_key, keystore::AccountKeystore};
use sui_sdk::wallet_context::WalletContext;
use sui_types::crypto::{AuthorityKeyPair, NetworkKeyPair, SignatureScheme, SuiKeyPair};
use sui_types::crypto::{
    AuthorityPublicKeyBytes, generate_proof_of_possession, get_authority_key_pair,
};
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{
    Argument, CallArg, Command, GasData, ObjectArg, Transaction, TransactionData,
    TransactionDataAPI, TransactionExpiration, TransactionKind,
};

#[path = "unit_tests/validator_tests.rs"]
#[cfg(test)]
mod validator_tests;

const DEFAULT_GAS_BUDGET: u64 = 200_000_000; // 0.2 SUI

/// Arguments related to transaction processing
#[derive(Args, Debug, Default)]
pub struct TxProcessingArgs {
    /// Instead of executing the transaction, serialize the bcs bytes of the unsigned transaction data
    /// (TransactionData) using base64 encoding, and print out the string <TX_BYTES>. The string can
    /// be used to execute transaction with `sui client execute-signed-tx --tx-bytes <TX_BYTES>`.
    #[arg(long)]
    pub serialize_unsigned_transaction: bool,
    /// Gas budget for this transaction
    #[clap(name = "gas-budget", long)]
    pub gas_budget: Option<u64>,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ValidatorPromotionTargetRequest {
    pub plan_id: String,
    pub validator_address: SuiAddress,
    pub target: ValidatorPromotionTarget,
    pub proof_of_possession: String,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ValidatorPromotionDraft {
    pub version: u64,
    pub plan_id: String,
    pub chain_identifier: String,
    pub source_epoch: u64,
    pub activation_epoch: u64,
    pub validator_address: SuiAddress,
    pub source_protocol_public_key: String,
    pub target: ValidatorPromotionTarget,
    pub proof_of_possession: String,
}

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
pub enum SuiValidatorCommand {
    #[clap(name = "make-validator-info")]
    MakeValidatorInfo {
        name: String,
        description: String,
        image_url: String,
        project_url: String,
        host_name: String,
        gas_price: u64,
    },
    #[clap(name = "become-candidate")]
    BecomeCandidate {
        #[clap(name = "validator-info-path")]
        file: PathBuf,
        #[clap(flatten)]
        tx_args: TxProcessingArgs,
    },
    #[clap(name = "join-committee")]
    JoinCommittee {
        #[clap(flatten)]
        tx_args: TxProcessingArgs,
    },
    #[clap(name = "leave-committee")]
    LeaveCommittee {
        #[clap(flatten)]
        tx_args: TxProcessingArgs,
    },
    #[clap(name = "display-metadata")]
    DisplayMetadata {
        #[clap(name = "validator-address")]
        validator_address: Option<SuiAddress>,
        #[clap(name = "json", long)]
        json: Option<bool>,
    },
    #[clap(name = "update-metadata")]
    UpdateMetadata {
        #[clap(subcommand)]
        metadata: MetadataUpdate,
        #[clap(flatten)]
        tx_args: TxProcessingArgs,
    },
    /// Export public backup metadata and create a PoP without accessing the validator account key.
    #[clap(name = "make-validator-promotion-target")]
    MakeValidatorPromotionTarget {
        #[clap(name = "plan-id", long)]
        plan_id: String,
        #[clap(name = "validator-address", long)]
        validator_address: SuiAddress,
        #[clap(name = "protocol-key-path", long)]
        protocol_key_path: PathBuf,
        #[clap(name = "network-key-path", long)]
        network_key_path: PathBuf,
        #[clap(name = "worker-key-path", long)]
        worker_key_path: PathBuf,
        #[clap(name = "network-address", long)]
        network_address: Multiaddr,
        #[clap(name = "p2p-address", long)]
        p2p_address: Multiaddr,
        #[clap(name = "primary-address", long)]
        primary_address: Multiaddr,
        #[clap(name = "worker-address", long)]
        worker_address: Multiaddr,
        /// New JSON file containing only public material. Must not already exist.
        #[clap(name = "target-path", long)]
        target_path: PathBuf,
    },
    /// Build, but never sign, the atomic next-epoch transaction for a validator promotion.
    #[clap(name = "prepare-validator-promotion")]
    PrepareValidatorPromotion {
        /// Public target metadata and proof of possession for the backup key.
        #[clap(name = "target-path", long)]
        target_path: PathBuf,
        /// New file that will bind the unsigned transaction to the source epoch and committee.
        #[clap(name = "draft-path", long)]
        draft_path: PathBuf,
        /// Gas budget for the unsigned transaction.
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
    },
    /// Verify a finalized promotion transaction and write the node authorization manifest.
    #[clap(name = "finalize-validator-promotion")]
    FinalizeValidatorPromotion {
        #[clap(name = "draft-path", long)]
        draft_path: PathBuf,
        #[clap(name = "transaction-digest", long)]
        transaction_digest: TransactionDigest,
        /// Must not already exist.
        #[clap(name = "manifest-path", long)]
        manifest_path: PathBuf,
    },
    /// Update gas price that is used to calculate Reference Gas Price
    #[clap(name = "update-gas-price")]
    UpdateGasPrice {
        /// Optional when sender is the validator itself and it holds the Cap object.
        /// Required when sender is not the validator itself.
        /// Validator's OperationCap ID can be found by using the `display-metadata` subcommand.
        #[clap(name = "operation-cap-id", long)]
        operation_cap_id: Option<ObjectID>,
        #[clap(name = "gas-price")]
        gas_price: u64,
        #[clap(flatten)]
        tx_args: TxProcessingArgs,
    },
    /// Report or un-report a validator.
    /// Report or un-report a validator.
    #[clap(name = "report-validator")]
    ReportValidator {
        /// Optional when sender is reporter validator itself and it holds the Cap object.
        /// Required when sender is not the reporter validator itself.
        /// Validator's OperationCap ID can be found by using the `display-metadata` subcommand.
        #[clap(name = "operation-cap-id", long)]
        operation_cap_id: Option<ObjectID>,
        /// The Sui Address of the validator is being reported or un-reported
        #[clap(name = "reportee-address")]
        reportee_address: SuiAddress,
        /// If true, undo an existing report.
        #[clap(name = "undo-report", long)]
        undo_report: Option<bool>,
        #[clap(flatten)]
        tx_args: TxProcessingArgs,
    },
    /// Serialize the payload that is used to generate Proof of Possession.
    /// This is useful to take the payload offline for an Authority protocol keypair to sign.
    #[clap(name = "serialize-payload-pop")]
    SerializePayloadForPoP {
        /// Authority account address encoded in hex with 0x prefix.
        #[clap(name = "account-address", long)]
        account_address: SuiAddress,
        /// Authority protocol public key encoded in hex.
        #[clap(name = "protocol-public-key", long)]
        protocol_public_key: AuthorityPublicKeyBytes,
    },
    /// Print out the serialized data of a transaction that sets the gas price quote for a validator.
    DisplayGasPriceUpdateRawTxn {
        /// Address of the transaction sender.
        #[clap(name = "sender-address", long)]
        sender_address: SuiAddress,
        /// Object ID of a validator's OperationCap, used for setting gas price and reportng validators.
        #[clap(name = "operation-cap-id", long)]
        operation_cap_id: ObjectID,
        /// Gas price to be set to.
        #[clap(name = "new-gas-price", long)]
        new_gas_price: u64,
        /// Gas budget for this transaction.
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
    },
    /// Sui native bridge committee member registration
    #[clap(name = "register-bridge-committee")]
    RegisterBridgeCommittee {
        /// Path to Bridge Authority Key file.
        #[clap(long)]
        bridge_authority_key_path: PathBuf,
        /// Bridge authority URL which clients collects action signatures from.
        #[clap(long)]
        bridge_authority_url: String,
        /// If true, only print the unsigned transaction and do not execute it.
        /// This is useful for offline signing.
        #[clap(name = "print-only", long, default_value = "false")]
        print_unsigned_transaction_only: bool,
        /// Must present if `print_unsigned_transaction_only` is true.
        #[clap(long)]
        validator_address: Option<SuiAddress>,
        /// Gas budget for this transaction.
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
    },
    /// Update sui native bridge committee node url
    UpdateBridgeCommitteeNodeUrl {
        /// New node url to be registered in the on chain bridge object.
        #[clap(long)]
        bridge_authority_url: String,
        /// If true, only print the unsigned transaction and do not execute it.
        /// This is useful for offline signing.
        #[clap(name = "print-only", long, default_value = "false")]
        print_unsigned_transaction_only: bool,
        /// Must be present if `print_unsigned_transaction_only` is true.
        #[clap(long)]
        validator_address: Option<SuiAddress>,
        /// Gas budget for this transaction.
        #[clap(name = "gas-budget", long)]
        gas_budget: Option<u64>,
    },
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum SuiValidatorCommandResponse {
    MakeValidatorInfo,
    DisplayMetadata,
    BecomeCandidate {
        response: Option<ExecutedTransaction>,
        serialized_unsigned_transaction: Option<String>,
    },
    JoinCommittee {
        response: Option<ExecutedTransaction>,
        serialized_unsigned_transaction: Option<String>,
    },
    LeaveCommittee {
        response: Option<ExecutedTransaction>,
        serialized_unsigned_transaction: Option<String>,
    },
    UpdateMetadata {
        response: Option<ExecutedTransaction>,
        serialized_unsigned_transaction: Option<String>,
    },
    MakeValidatorPromotionTarget {
        target_path: PathBuf,
        protocol_public_key: String,
    },
    PrepareValidatorPromotion {
        transaction_digest: TransactionDigest,
        serialized_unsigned_transaction: String,
        draft_path: PathBuf,
    },
    FinalizeValidatorPromotion {
        transaction_digest: TransactionDigest,
        checkpoint_sequence_number: u64,
        manifest_path: PathBuf,
    },
    UpdateGasPrice {
        response: Option<ExecutedTransaction>,
        serialized_unsigned_transaction: Option<String>,
    },
    ReportValidator {
        response: Option<ExecutedTransaction>,
        serialized_unsigned_transaction: Option<String>,
    },
    SerializedPayload(String),
    DisplayGasPriceUpdateRawTxn {
        data: TransactionData,
        serialized_data: String,
    },
    RegisterBridgeCommittee {
        execution_response: Option<ExecutedTransaction>,
        serialized_unsigned_transaction: Option<String>,
    },
    UpdateBridgeCommitteeURL {
        execution_response: Option<ExecutedTransaction>,
        serialized_unsigned_transaction: Option<String>,
    },
}

fn make_key_files(
    file_name: PathBuf,
    is_protocol_key: bool,
    key: Option<SuiKeyPair>,
) -> Result<()> {
    if file_name.exists() {
        println!("Use existing {:?} key file.", file_name);
        return Ok(());
    } else if is_protocol_key {
        let (_, keypair) = get_authority_key_pair();
        write_authority_keypair_to_file(&keypair, file_name.clone())?;
        println!("Generated new key file: {:?}.", file_name);
    } else {
        let kp = match key {
            Some(key) => {
                println!(
                    "Generated new key file {:?} based on sui.keystore file.",
                    file_name
                );
                key
            }
            None => {
                let (_, kp, _, _) = generate_new_key(SignatureScheme::ED25519, None, None)?;
                println!("Generated new key file: {:?}.", file_name);
                kp
            }
        };
        write_keypair_to_file(&kp, &file_name)?;
    }
    Ok(())
}

impl SuiValidatorCommand {
    pub async fn execute(
        self,
        context: &mut WalletContext,
    ) -> Result<SuiValidatorCommandResponse, anyhow::Error> {
        let sui_address = context.active_address()?;

        Ok(match self {
            SuiValidatorCommand::MakeValidatorInfo {
                name,
                description,
                image_url,
                project_url,
                host_name,
                gas_price,
            } => {
                let dir = std::env::current_dir()?;
                let protocol_key_file_name = dir.join("protocol.key");
                let account_key = match context.config.keystore.export(&sui_address)? {
                    SuiKeyPair::Ed25519(account_key) => SuiKeyPair::Ed25519(account_key.copy()),
                    _ => panic!(
                        "Other account key types supported yet, please use Ed25519 keys for now."
                    ),
                };
                let account_key_file_name = dir.join("account.key");
                let network_key_file_name = dir.join("network.key");
                let worker_key_file_name = dir.join("worker.key");
                make_key_files(protocol_key_file_name.clone(), true, None)?;
                make_key_files(account_key_file_name.clone(), false, Some(account_key))?;
                make_key_files(network_key_file_name.clone(), false, None)?;
                make_key_files(worker_key_file_name.clone(), false, None)?;

                let keypair: AuthorityKeyPair =
                    read_authority_keypair_from_file(protocol_key_file_name)?;
                let account_keypair: SuiKeyPair = read_keypair_from_file(account_key_file_name)?;
                let worker_keypair: NetworkKeyPair =
                    read_network_keypair_from_file(worker_key_file_name)?;
                let network_keypair: NetworkKeyPair =
                    read_network_keypair_from_file(network_key_file_name)?;
                let pop =
                    generate_proof_of_possession(&keypair, (&account_keypair.public()).into());
                let validator_info = GenesisValidatorInfo {
                    info: sui_genesis_builder::validator_info::ValidatorInfo {
                        name,
                        protocol_key: keypair.public().into(),
                        worker_key: worker_keypair.public().clone(),
                        account_address: SuiAddress::from(&account_keypair.public()),
                        network_key: network_keypair.public().clone(),
                        gas_price,
                        commission_rate: sui_config::node::DEFAULT_COMMISSION_RATE,
                        network_address: Multiaddr::try_from(format!(
                            "/dns/{}/tcp/8080/http",
                            host_name
                        ))?,
                        p2p_address: Multiaddr::try_from(format!("/dns/{}/udp/8084", host_name))?,
                        narwhal_primary_address: Multiaddr::try_from(format!(
                            "/dns/{}/udp/8081",
                            host_name
                        ))?,
                        narwhal_worker_address: Multiaddr::try_from(format!(
                            "/dns/{}/udp/8082",
                            host_name
                        ))?,
                        description,
                        image_url,
                        project_url,
                    },
                    proof_of_possession: pop,
                };
                // TODO set key files permission
                let validator_info_file_name = dir.join("validator.info");
                let validator_info_bytes = serde_yaml::to_string(&validator_info)?;
                fs::write(validator_info_file_name.clone(), validator_info_bytes)?;
                println!(
                    "Generated validator info file: {:?}.",
                    validator_info_file_name
                );
                SuiValidatorCommandResponse::MakeValidatorInfo
            }
            SuiValidatorCommand::BecomeCandidate { file, tx_args } => {
                let gas_budget = tx_args.gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let validator_info_bytes = fs::read(file)?;
                // Note: we should probably rename the struct or evolve it accordingly.
                let validator_info: GenesisValidatorInfo =
                    serde_yaml::from_slice(&validator_info_bytes)?;
                let validator = validator_info.info;

                let args = vec![
                    CallArg::Pure(
                        bcs::to_bytes(&AuthorityPublicKeyBytes::from_bytes(
                            validator.protocol_key().as_bytes(),
                        )?)
                        .unwrap(),
                    ),
                    CallArg::Pure(
                        bcs::to_bytes(&validator.network_key().as_bytes().to_vec()).unwrap(),
                    ),
                    CallArg::Pure(
                        bcs::to_bytes(&validator.worker_key().as_bytes().to_vec()).unwrap(),
                    ),
                    CallArg::Pure(
                        bcs::to_bytes(&validator_info.proof_of_possession.as_ref().to_vec())
                            .unwrap(),
                    ),
                    CallArg::Pure(
                        bcs::to_bytes(&validator.name().to_owned().into_bytes()).unwrap(),
                    ),
                    CallArg::Pure(
                        bcs::to_bytes(&validator.description.clone().into_bytes()).unwrap(),
                    ),
                    CallArg::Pure(
                        bcs::to_bytes(&validator.image_url.clone().into_bytes()).unwrap(),
                    ),
                    CallArg::Pure(
                        bcs::to_bytes(&validator.project_url.clone().into_bytes()).unwrap(),
                    ),
                    CallArg::Pure(bcs::to_bytes(validator.network_address()).unwrap()),
                    CallArg::Pure(bcs::to_bytes(validator.p2p_address()).unwrap()),
                    CallArg::Pure(bcs::to_bytes(validator.narwhal_primary_address()).unwrap()),
                    CallArg::Pure(bcs::to_bytes(validator.narwhal_worker_address()).unwrap()),
                    CallArg::Pure(bcs::to_bytes(&validator.gas_price()).unwrap()),
                    CallArg::Pure(bcs::to_bytes(&validator.commission_rate()).unwrap()),
                ];
                let (response, serialized_unsigned_transaction) = call_0x5(
                    context,
                    "request_add_validator_candidate",
                    args,
                    gas_budget,
                    tx_args.serialize_unsigned_transaction,
                )
                .await?;
                SuiValidatorCommandResponse::BecomeCandidate {
                    response,
                    serialized_unsigned_transaction,
                }
            }

            SuiValidatorCommand::JoinCommittee { tx_args } => {
                let gas_budget = tx_args.gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let (response, serialized_unsigned_transaction) = call_0x5(
                    context,
                    "request_add_validator",
                    vec![],
                    gas_budget,
                    tx_args.serialize_unsigned_transaction,
                )
                .await?;
                SuiValidatorCommandResponse::JoinCommittee {
                    response,
                    serialized_unsigned_transaction,
                }
            }

            SuiValidatorCommand::LeaveCommittee { tx_args } => {
                // Only an active validator can leave committee.
                let _status =
                    check_status(context, HashSet::from([ValidatorStatus::Active])).await?;
                let gas_budget = tx_args.gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let (response, serialized_unsigned_transaction) = call_0x5(
                    context,
                    "request_remove_validator",
                    vec![],
                    gas_budget,
                    tx_args.serialize_unsigned_transaction,
                )
                .await?;
                SuiValidatorCommandResponse::LeaveCommittee {
                    response,
                    serialized_unsigned_transaction,
                }
            }

            SuiValidatorCommand::DisplayMetadata {
                validator_address,
                json,
            } => {
                let validator_address = validator_address.unwrap_or(context.active_address()?);
                // Default display with json serialization for better UX.
                let sui_client = context.grpc_client()?;
                display_metadata(&sui_client, validator_address, json.unwrap_or(true)).await?;
                SuiValidatorCommandResponse::DisplayMetadata
            }

            SuiValidatorCommand::UpdateMetadata { metadata, tx_args } => {
                let gas_budget = tx_args.gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let (response, serialized_unsigned_transaction) = update_metadata(
                    context,
                    metadata,
                    gas_budget,
                    tx_args.serialize_unsigned_transaction,
                )
                .await?;
                SuiValidatorCommandResponse::UpdateMetadata {
                    response,
                    serialized_unsigned_transaction,
                }
            }

            SuiValidatorCommand::MakeValidatorPromotionTarget {
                plan_id,
                validator_address,
                protocol_key_path,
                network_key_path,
                worker_key_path,
                network_address,
                p2p_address,
                primary_address,
                worker_address,
                target_path,
            } => {
                let protocol = read_authority_keypair_from_file(protocol_key_path)?;
                let network = read_network_keypair_from_file(network_key_path)?;
                let worker = read_network_keypair_from_file(worker_key_path)?;
                let request = ValidatorPromotionTargetRequest {
                    plan_id,
                    validator_address,
                    target: ValidatorPromotionTarget {
                        protocol_public_key: Hex::encode(protocol.public().as_bytes()),
                        network_public_key: Hex::encode(network.public().as_bytes()),
                        worker_public_key: Hex::encode(worker.public().as_bytes()),
                        network_address,
                        p2p_address,
                        primary_address,
                        worker_address,
                    },
                    proof_of_possession: Hex::encode(
                        generate_proof_of_possession(&protocol, validator_address).as_ref(),
                    ),
                };
                validate_promotion_target_request(&request)?;
                let protocol_public_key = request.target.protocol_public_key.clone();
                write_new_json(&target_path, &request)?;
                SuiValidatorCommandResponse::MakeValidatorPromotionTarget {
                    target_path,
                    protocol_public_key,
                }
            }

            SuiValidatorCommand::PrepareValidatorPromotion {
                target_path,
                draft_path,
                gas_budget,
            } => {
                let (transaction, draft) = prepare_validator_promotion(
                    context,
                    &target_path,
                    gas_budget.unwrap_or(DEFAULT_GAS_BUDGET),
                )
                .await?;
                write_new_json(&draft_path, &draft)?;
                SuiValidatorCommandResponse::PrepareValidatorPromotion {
                    transaction_digest: transaction.digest(),
                    serialized_unsigned_transaction: Base64::encode(bcs::to_bytes(&transaction)?),
                    draft_path,
                }
            }

            SuiValidatorCommand::FinalizeValidatorPromotion {
                draft_path,
                transaction_digest,
                manifest_path,
            } => {
                let manifest =
                    finalize_validator_promotion(context, &draft_path, transaction_digest).await?;
                let checkpoint_sequence_number = manifest.evidence.checkpoint_sequence_number;
                write_new_json(&manifest_path, &manifest)?;
                SuiValidatorCommandResponse::FinalizeValidatorPromotion {
                    transaction_digest,
                    checkpoint_sequence_number,
                    manifest_path,
                }
            }

            SuiValidatorCommand::UpdateGasPrice {
                operation_cap_id,
                gas_price,
                tx_args,
            } => {
                let gas_budget = tx_args.gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let (response, serialized_unsigned_transaction) = update_gas_price(
                    context,
                    operation_cap_id,
                    gas_price,
                    gas_budget,
                    tx_args.serialize_unsigned_transaction,
                )
                .await?;
                SuiValidatorCommandResponse::UpdateGasPrice {
                    response,
                    serialized_unsigned_transaction,
                }
            }

            SuiValidatorCommand::ReportValidator {
                operation_cap_id,
                reportee_address,
                undo_report,
                tx_args,
            } => {
                let gas_budget = tx_args.gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let undo_report = undo_report.unwrap_or(false);
                let (response, serialized_unsigned_transaction) = report_validator(
                    context,
                    reportee_address,
                    operation_cap_id,
                    undo_report,
                    gas_budget,
                    tx_args.serialize_unsigned_transaction,
                )
                .await?;
                SuiValidatorCommandResponse::ReportValidator {
                    response,
                    serialized_unsigned_transaction,
                }
            }

            SuiValidatorCommand::SerializePayloadForPoP {
                account_address,
                protocol_public_key,
            } => {
                let mut msg: Vec<u8> = Vec::new();
                msg.extend_from_slice(protocol_public_key.as_bytes());
                msg.extend_from_slice(account_address.as_ref());
                let mut intent_msg_bytes = bcs::to_bytes(&IntentMessage::new(
                    Intent::sui_app(IntentScope::ProofOfPossession),
                    msg,
                ))
                .expect("Message serialization should not fail");
                DEFAULT_EPOCH_ID.write(&mut intent_msg_bytes);
                SuiValidatorCommandResponse::SerializedPayload(Base64::encode(&intent_msg_bytes))
            }

            SuiValidatorCommand::DisplayGasPriceUpdateRawTxn {
                sender_address,
                operation_cap_id,
                new_gas_price,
                gas_budget,
            } => {
                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let (_status, _summary, cap_obj_ref) =
                    get_cap_object_ref(context, Some(operation_cap_id)).await?;

                let args = vec![
                    CallArg::Object(ObjectArg::ImmOrOwnedObject(cap_obj_ref)),
                    CallArg::Pure(bcs::to_bytes(&new_gas_price).unwrap()),
                ];
                let data = construct_unsigned_0x5_txn(
                    context,
                    sender_address,
                    "request_set_gas_price",
                    args,
                    gas_budget,
                )
                .await?;
                let serialized_data = Base64::encode(bcs::to_bytes(&data)?);
                SuiValidatorCommandResponse::DisplayGasPriceUpdateRawTxn {
                    data,
                    serialized_data,
                }
            }
            SuiValidatorCommand::RegisterBridgeCommittee {
                bridge_authority_key_path,
                bridge_authority_url,
                print_unsigned_transaction_only,
                validator_address,
                gas_budget,
            } => {
                let parsed_url =
                    Url::parse(&bridge_authority_url).map_err(|e: ParseError| anyhow!(e))?;
                if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
                    anyhow::bail!(
                        "URL scheme has to be http or https: {}",
                        parsed_url.scheme()
                    );
                }
                // Read bridge keypair
                let ecdsa_keypair = match read_key(&bridge_authority_key_path, true)? {
                    SuiKeyPair::Secp256k1(key) => key,
                    _ => unreachable!("we required secp256k1 key in `read_key`"),
                };
                let address = check_address(
                    context.active_address()?,
                    validator_address,
                    print_unsigned_transaction_only,
                )?;
                // Make sure the address is a validator
                let sui_client = context.grpc_client()?;
                let active_validators = sui_client
                    .get_system_state(None)
                    .await?
                    .validators()
                    .active_validators()
                    .to_owned();
                if !active_validators
                    .into_iter()
                    .any(|s| s.address() == address.to_string())
                {
                    bail!("Address {} is not in the committee", address);
                }
                println!(
                    "Starting bridge committee registration for Sui validator: {address}, with bridge public key: {} and url: {}",
                    ecdsa_keypair.public, bridge_authority_url
                );
                let sui_rpc_url = &context.get_active_env().unwrap().rpc;
                let bridge_metrics = Arc::new(BridgeMetrics::new_for_testing());
                let bridge_client = SuiBridgeClient::new(sui_rpc_url, bridge_metrics).await?;
                let bridge = bridge_client
                    .get_mutable_bridge_object_arg_must_succeed()
                    .await;

                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let (_, gas) = context
                    .gas_for_owner_budget(address, gas_budget, Default::default())
                    .await?;

                let gas_price = context.get_reference_gas_price().await?;
                let tx_data = build_committee_register_transaction(
                    address,
                    &gas.compute_object_reference(),
                    bridge,
                    ecdsa_keypair.public().as_bytes().to_vec(),
                    &bridge_authority_url,
                    gas_price,
                    gas_budget,
                )
                .map_err(|e| anyhow!("{e:?}"))?;
                if print_unsigned_transaction_only {
                    let serialized_data = Base64::encode(bcs::to_bytes(&tx_data)?);
                    SuiValidatorCommandResponse::RegisterBridgeCommittee {
                        execution_response: None,
                        serialized_unsigned_transaction: Some(serialized_data),
                    }
                } else {
                    let tx = context.sign_transaction(&tx_data).await;
                    let response = context.execute_transaction_must_succeed(tx).await;
                    println!(
                        "Committee registration successful. Transaction digest: {}",
                        response.transaction.digest()
                    );
                    SuiValidatorCommandResponse::RegisterBridgeCommittee {
                        execution_response: Some(response),
                        serialized_unsigned_transaction: None,
                    }
                }
            }
            SuiValidatorCommand::UpdateBridgeCommitteeNodeUrl {
                bridge_authority_url,
                print_unsigned_transaction_only,
                validator_address,
                gas_budget,
            } => {
                let parsed_url =
                    Url::parse(&bridge_authority_url).map_err(|e: ParseError| anyhow!(e))?;
                if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
                    anyhow::bail!(
                        "URL scheme has to be http or https: {}",
                        parsed_url.scheme()
                    );
                }
                // Make sure the address is member of the committee
                let address = check_address(
                    context.active_address()?,
                    validator_address,
                    print_unsigned_transaction_only,
                )?;
                let sui_rpc_url = &context.get_active_env().unwrap().rpc;
                let bridge_metrics = Arc::new(BridgeMetrics::new_for_testing());
                let bridge_client = SuiBridgeClient::new(sui_rpc_url, bridge_metrics).await?;
                let committee_members = bridge_client
                    .get_bridge_summary()
                    .await
                    .map_err(|e| anyhow!("{e:?}"))?
                    .committee
                    .members;
                if !committee_members
                    .into_iter()
                    .any(|(_, m)| m.sui_address == address)
                {
                    bail!("Address {} is not in the committee", address);
                }
                println!(
                    "Updating bridge committee node URL for Sui validator: {address}, url: {}",
                    bridge_authority_url
                );

                let bridge = bridge_client
                    .get_mutable_bridge_object_arg_must_succeed()
                    .await;

                let gas_budget = gas_budget.unwrap_or(DEFAULT_GAS_BUDGET);
                let (_, gas) = context
                    .gas_for_owner_budget(address, gas_budget, Default::default())
                    .await?;

                let gas_price = context.get_reference_gas_price().await?;
                let tx_data = build_committee_update_url_transaction(
                    address,
                    &gas.compute_object_reference(),
                    bridge,
                    &bridge_authority_url,
                    gas_price,
                    gas_budget,
                )
                .map_err(|e| anyhow!("{e:?}"))?;
                if print_unsigned_transaction_only {
                    let serialized_data = Base64::encode(bcs::to_bytes(&tx_data)?);
                    SuiValidatorCommandResponse::UpdateBridgeCommitteeURL {
                        execution_response: None,
                        serialized_unsigned_transaction: Some(serialized_data),
                    }
                } else {
                    let tx = context.sign_transaction(&tx_data).await;
                    let response = context.execute_transaction_must_succeed(tx).await;
                    println!(
                        "Update Bridge validator node URL successful. Transaction digest: {}",
                        response.transaction.digest()
                    );
                    SuiValidatorCommandResponse::UpdateBridgeCommitteeURL {
                        execution_response: Some(response),
                        serialized_unsigned_transaction: None,
                    }
                }
            }
        })
    }
}

fn check_address(
    active_address: SuiAddress,
    validator_address: Option<SuiAddress>,
    print_unsigned_transaction_only: bool,
) -> Result<SuiAddress, anyhow::Error> {
    if !print_unsigned_transaction_only {
        if let Some(validator_address) = validator_address
            && validator_address != active_address
        {
            bail!(
                "`--validator-address` must be the same as the current active address: {}",
                active_address
            );
        }
        Ok(active_address)
    } else {
        validator_address
            .ok_or_else(|| anyhow!("--validator-address must be provided when `print_unsigned_transaction_only` is true"))
    }
}

async fn get_cap_object_ref(
    context: &mut WalletContext,
    operation_cap_id: Option<ObjectID>,
) -> Result<(ValidatorStatus, proto::Validator, ObjectRef)> {
    let mut sui_client = context.grpc_client()?;
    if let Some(operation_cap_id) = operation_cap_id {
        let (status, summary) =
            get_validator_summary_from_cap_id(&sui_client, operation_cap_id).await?;
        let cap_obj_ref = sui_client
            .get_object(summary.operation_cap_id().parse()?)
            .await?
            .compute_object_reference();
        Ok::<(ValidatorStatus, proto::Validator, ObjectRef), anyhow::Error>((
            status,
            summary,
            cap_obj_ref,
        ))
    } else {
        // Sender is Reporter Validator itself.
        let validator_address = context.active_address()?;
        let (status, summary) = get_validator_summary(&sui_client, validator_address)
            .await?
            .ok_or_else(|| anyhow::anyhow!("{} is not a validator.", validator_address))?;
        // TODO we should allow validator to perform this operation even though the Cap is not at hand.
        // But for now we need to make sure the cap is owned by the sender.
        let cap_object_id = summary.operation_cap_id();
        let resp = sui_client.get_object(cap_object_id.parse()?).await?;
        // Safe to unwrap as we ask with `with_owner`.
        let owner = resp.owner().to_owned();
        let cap_obj_ref = resp.compute_object_reference();
        if owner != Owner::AddressOwner(context.active_address()?) {
            anyhow::bail!(
                "OperationCap {} is not owned by the sender address {} but {:?}",
                summary.operation_cap_id(),
                validator_address,
                owner
            );
        }
        Ok((status, summary, cap_obj_ref))
    }
}

async fn update_gas_price(
    context: &mut WalletContext,
    operation_cap_id: Option<ObjectID>,
    gas_price: u64,
    gas_budget: u64,
    serialize_unsigned_transaction: bool,
) -> Result<(Option<ExecutedTransaction>, Option<String>)> {
    let (_status, _summary, cap_obj_ref) = get_cap_object_ref(context, operation_cap_id).await?;

    // TODO: Only active/pending validators can set gas price.

    let args = vec![
        CallArg::Object(ObjectArg::ImmOrOwnedObject(cap_obj_ref)),
        CallArg::Pure(bcs::to_bytes(&gas_price).unwrap()),
    ];
    call_0x5(
        context,
        "request_set_gas_price",
        args,
        gas_budget,
        serialize_unsigned_transaction,
    )
    .await
}

async fn report_validator(
    context: &mut WalletContext,
    reportee_address: SuiAddress,
    operation_cap_id: Option<ObjectID>,
    undo_report: bool,
    gas_budget: u64,
    serialize_unsigned_transaction: bool,
) -> Result<(Option<ExecutedTransaction>, Option<String>)> {
    let (status, summary, cap_obj_ref) = get_cap_object_ref(context, operation_cap_id).await?;

    let validator_address = summary.address();
    // Only active validators can report/un-report.
    if !matches!(status, ValidatorStatus::Active) {
        anyhow::bail!(
            "Only active Validator can report/un-report Validators, but {} is {:?}.",
            validator_address,
            status
        );
    }
    let args = vec![
        CallArg::Object(ObjectArg::ImmOrOwnedObject(cap_obj_ref)),
        CallArg::Pure(bcs::to_bytes(&reportee_address).unwrap()),
    ];
    let function_name = if undo_report {
        "undo_report_validator"
    } else {
        "report_validator"
    };
    call_0x5(
        context,
        function_name,
        args,
        gas_budget,
        serialize_unsigned_transaction,
    )
    .await
}

async fn get_validator_summary_from_cap_id(
    client: &Client,
    operation_cap_id: ObjectID,
) -> anyhow::Result<(ValidatorStatus, proto::Validator)> {
    let resp = client.clone().get_object(operation_cap_id).await?;
    let bcs = resp.data.try_as_move().ok_or_else(|| {
        anyhow::anyhow!(
            "Object {} does not exist or does not return bcs bytes",
            operation_cap_id
        )
    })?;
    let cap =
        bcs::from_bytes::<UnverifiedValidatorOperationCapV1>(bcs.contents()).map_err(|e| {
            anyhow::anyhow!(
                "Can't convert bcs bytes of object {} to UnverifiedValidatorOperationCapV1: {}",
                operation_cap_id,
                e,
            )
        })?;
    let validator_address = cap.authorizer_validator_address;
    let (status, summary) = get_validator_summary(client, validator_address)
        .await?
        .ok_or_else(|| anyhow::anyhow!("{} is not a validator", validator_address))?;
    if summary.operation_cap_id() != operation_cap_id.to_string() {
        anyhow::bail!(
            "Validator {}'s current operation cap id is {}",
            validator_address,
            summary.operation_cap_id()
        );
    }
    Ok((status, summary))
}

const PROMOTION_FUNCTIONS: [&str; 7] = [
    "update_validator_next_epoch_protocol_pubkey",
    "update_validator_next_epoch_network_pubkey",
    "update_validator_next_epoch_worker_pubkey",
    "update_validator_next_epoch_network_address",
    "update_validator_next_epoch_p2p_address",
    "update_validator_next_epoch_primary_address",
    "update_validator_next_epoch_worker_address",
];

async fn prepare_validator_promotion(
    context: &mut WalletContext,
    target_path: &PathBuf,
    gas_budget: u64,
) -> Result<(TransactionData, ValidatorPromotionDraft)> {
    let target: ValidatorPromotionTargetRequest = load_structured(target_path)?;
    validate_promotion_target_request(&target)?;
    let sender = context.active_address()?;
    anyhow::ensure!(
        sender == target.validator_address,
        "active client address must be the validator account in the promotion target"
    );

    let client = context.grpc_client()?;
    let system_state = client.get_system_state_summary(None).await?;
    let (status, validator) = get_validator_summary(&client, sender)
        .await?
        .context("promotion sender is not a validator")?;
    anyhow::ensure!(
        status == ValidatorStatus::Active,
        "only an active validator can prepare a promotion"
    );
    ensure_no_pending_metadata_rotation(&validator)?;

    let source_protocol = validator
        .protocol_public_key
        .as_deref()
        .context("validator protocol public key is missing")?;
    anyhow::ensure!(
        source_protocol != parse_canonical_hex(&target.target.protocol_public_key)?.as_slice(),
        "source and target protocol public keys must be distinct"
    );

    let chain = client.get_chain_identifier().await?;
    let source_epoch = system_state.epoch;
    let draft = ValidatorPromotionDraft {
        version: VALIDATOR_PROMOTION_MANIFEST_VERSION,
        plan_id: target.plan_id,
        chain_identifier: Hex::encode(chain.as_bytes()),
        source_epoch,
        activation_epoch: source_epoch.saturating_add(1),
        validator_address: sender,
        source_protocol_public_key: Hex::encode(source_protocol),
        target: target.target,
        proof_of_possession: target.proof_of_possession,
    };

    let gas = get_gas_obj_ref(sender, &client, gas_budget).await?;
    let gas_price = client.get_reference_gas_price().await?;
    let transaction = TransactionData::new_with_gas_data_and_expiration(
        build_promotion_transaction_kind(&draft)?,
        sender,
        GasData {
            payment: vec![gas],
            owner: sender,
            price: gas_price,
            budget: gas_budget,
        },
        TransactionExpiration::ValidDuring {
            min_epoch: Some(source_epoch),
            max_epoch: Some(source_epoch),
            min_timestamp: None,
            max_timestamp: None,
            chain,
            nonce: rand::random(),
        },
    );
    validate_prepared_promotion_transaction(&transaction, &draft, chain)?;
    Ok((transaction, draft))
}

async fn finalize_validator_promotion(
    context: &mut WalletContext,
    draft_path: &PathBuf,
    transaction_digest: TransactionDigest,
) -> Result<ValidatorPromotionManifest> {
    let draft: ValidatorPromotionDraft = load_structured(draft_path)?;
    anyhow::ensure!(
        draft.version == VALIDATOR_PROMOTION_MANIFEST_VERSION,
        "unsupported validator promotion draft version"
    );

    let mut client = context.grpc_client()?;
    let chain = client.get_chain_identifier().await?;
    anyhow::ensure!(
        draft.chain_identifier == Hex::encode(chain.as_bytes()),
        "promotion draft chain identifier mismatch"
    );
    let system_state = client.get_system_state_summary(None).await?;
    anyhow::ensure!(
        system_state.epoch == draft.source_epoch,
        "promotion must be finalized and installed before the source epoch ends"
    );

    let executed = client.get_transaction(&transaction_digest).await?;
    anyhow::ensure!(
        executed.transaction.digest() == transaction_digest,
        "promotion transaction digest mismatch"
    );
    anyhow::ensure!(
        executed.effects.status().is_ok(),
        "promotion transaction did not execute successfully"
    );
    validate_prepared_promotion_transaction(&executed.transaction, &draft, chain)?;
    let checkpoint_sequence_number = executed
        .checkpoint
        .context("promotion transaction is not finalized in a checkpoint")?;
    let checkpoint = client
        .get_checkpoint_summary(checkpoint_sequence_number)
        .await?;
    anyhow::ensure!(
        checkpoint.epoch() == draft.source_epoch,
        "promotion transaction finalized outside the source epoch"
    );

    let (status, validator) = get_validator_summary(&client, draft.validator_address)
        .await?
        .context("promotion validator is absent after transaction finality")?;
    anyhow::ensure!(
        status == ValidatorStatus::Active,
        "promotion validator is no longer active"
    );
    ensure_target_metadata_is_staged(&validator, &draft)?;

    Ok(ValidatorPromotionManifest {
        version: draft.version,
        plan_id: draft.plan_id,
        chain_identifier: draft.chain_identifier,
        source_epoch: draft.source_epoch,
        activation_epoch: draft.activation_epoch,
        validator_address: draft.validator_address,
        source_protocol_public_key: draft.source_protocol_public_key,
        target: draft.target,
        proof_of_possession: draft.proof_of_possession,
        evidence: ValidatorPromotionEvidence {
            transaction_digest,
            checkpoint_sequence_number,
        },
    })
}

fn validate_promotion_target_request(target: &ValidatorPromotionTargetRequest) -> Result<()> {
    anyhow::ensure!(
        !target.plan_id.is_empty()
            && target.plan_id.len() <= 128
            && target
                .plan_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "promotion plan ID must contain 1-128 ASCII letters, digits, '-' or '_'"
    );
    let protocol =
        AuthorityPublicKey::from_bytes(&parse_canonical_hex(&target.target.protocol_public_key)?)?;
    let network =
        NetworkPublicKey::from_bytes(&parse_canonical_hex(&target.target.network_public_key)?)?;
    let worker =
        NetworkPublicKey::from_bytes(&parse_canonical_hex(&target.target.worker_public_key)?)?;
    anyhow::ensure!(
        network != worker,
        "target network and worker keys must differ"
    );
    let pop = AuthoritySignature::from_bytes(&parse_canonical_hex(&target.proof_of_possession)?)?;
    verify_proof_of_possession(&pop, &protocol, target.validator_address)?;
    anyhow::ensure!(
        target.target.network_address.is_loosely_valid_tcp_addr(),
        "target network address must be a TCP address"
    );
    for (name, address) in [
        ("p2p", &target.target.p2p_address),
        ("primary", &target.target.primary_address),
        ("worker", &target.target.worker_address),
    ] {
        address
            .to_anemo_address()
            .map_err(|error| anyhow!("target {name} address must be a UDP address: {error}"))?;
    }
    Ok(())
}

fn build_promotion_transaction_kind(draft: &ValidatorPromotionDraft) -> Result<TransactionKind> {
    let mut builder = ProgrammableTransactionBuilder::new();
    for function in PROMOTION_FUNCTIONS {
        let mut arguments = vec![builder.input(CallArg::SUI_SYSTEM_MUT)?];
        for value in promotion_pure_arguments(function, draft)? {
            arguments.push(builder.input(CallArg::Pure(value))?);
        }
        builder.programmable_move_call(
            SUI_SYSTEM_PACKAGE_ID,
            Identifier::from_str("sui_system")?,
            Identifier::from_str(function)?,
            vec![],
            arguments,
        );
    }
    Ok(TransactionKind::programmable(builder.finish()))
}

fn ensure_no_pending_metadata_rotation(validator: &proto::Validator) -> Result<()> {
    for (name, current, next) in [
        (
            "protocol public key",
            validator.protocol_public_key.as_deref(),
            validator.next_epoch_protocol_public_key.as_deref(),
        ),
        (
            "proof of possession",
            validator.proof_of_possession.as_deref(),
            validator.next_epoch_proof_of_possession.as_deref(),
        ),
        (
            "network public key",
            validator.network_public_key.as_deref(),
            validator.next_epoch_network_public_key.as_deref(),
        ),
        (
            "worker public key",
            validator.worker_public_key.as_deref(),
            validator.next_epoch_worker_public_key.as_deref(),
        ),
    ] {
        anyhow::ensure!(
            current.is_some() && current == next,
            "validator already has a pending {name} change"
        );
    }
    for (name, current, next) in [
        (
            "network address",
            validator.network_address.as_deref(),
            validator.next_epoch_network_address.as_deref(),
        ),
        (
            "p2p address",
            validator.p2p_address.as_deref(),
            validator.next_epoch_p2p_address.as_deref(),
        ),
        (
            "primary address",
            validator.primary_address.as_deref(),
            validator.next_epoch_primary_address.as_deref(),
        ),
        (
            "worker address",
            validator.worker_address.as_deref(),
            validator.next_epoch_worker_address.as_deref(),
        ),
    ] {
        anyhow::ensure!(
            current.is_some() && current == next,
            "validator already has a pending {name} change"
        );
    }
    Ok(())
}

fn ensure_target_metadata_is_staged(
    validator: &proto::Validator,
    draft: &ValidatorPromotionDraft,
) -> Result<()> {
    let target = &draft.target;
    for (name, actual, expected) in [
        (
            "protocol public key",
            validator.next_epoch_protocol_public_key.as_deref(),
            parse_canonical_hex(&target.protocol_public_key)?,
        ),
        (
            "proof of possession",
            validator.next_epoch_proof_of_possession.as_deref(),
            parse_canonical_hex(&draft.proof_of_possession)?,
        ),
        (
            "network public key",
            validator.next_epoch_network_public_key.as_deref(),
            parse_canonical_hex(&target.network_public_key)?,
        ),
        (
            "worker public key",
            validator.next_epoch_worker_public_key.as_deref(),
            parse_canonical_hex(&target.worker_public_key)?,
        ),
    ] {
        anyhow::ensure!(
            actual == Some(expected.as_slice()),
            "staged validator {name} does not match the promotion target"
        );
    }
    for (name, actual, expected) in [
        (
            "network address",
            validator.next_epoch_network_address.as_deref(),
            target.network_address.to_string(),
        ),
        (
            "p2p address",
            validator.next_epoch_p2p_address.as_deref(),
            target.p2p_address.to_string(),
        ),
        (
            "primary address",
            validator.next_epoch_primary_address.as_deref(),
            target.primary_address.to_string(),
        ),
        (
            "worker address",
            validator.next_epoch_worker_address.as_deref(),
            target.worker_address.to_string(),
        ),
    ] {
        anyhow::ensure!(
            actual == Some(expected.as_str()),
            "staged validator {name} does not match the promotion target"
        );
    }
    Ok(())
}

fn validate_prepared_promotion_transaction(
    transaction: &TransactionData,
    draft: &ValidatorPromotionDraft,
    chain: ChainIdentifier,
) -> Result<()> {
    anyhow::ensure!(
        transaction.sender() == draft.validator_address,
        "promotion transaction sender mismatch"
    );
    let TransactionExpiration::ValidDuring {
        min_epoch,
        max_epoch,
        min_timestamp,
        max_timestamp,
        chain: transaction_chain,
        ..
    } = transaction.expiration()
    else {
        bail!("promotion transaction must use ValidDuring expiration");
    };
    anyhow::ensure!(
        *min_epoch == Some(draft.source_epoch)
            && *max_epoch == Some(draft.source_epoch)
            && min_timestamp.is_none()
            && max_timestamp.is_none()
            && *transaction_chain == chain,
        "promotion transaction must be bound to the exact source epoch and chain"
    );
    let TransactionKind::ProgrammableTransaction(pt) = transaction.kind() else {
        bail!("promotion transaction is not programmable");
    };
    anyhow::ensure!(
        pt.commands.len() == PROMOTION_FUNCTIONS.len(),
        "promotion transaction must contain exactly seven commands"
    );
    let mut functions = BTreeSet::new();
    for command in &pt.commands {
        let Command::MoveCall(call) = command else {
            bail!("promotion transaction contains a non-Move command");
        };
        anyhow::ensure!(
            call.package == SUI_SYSTEM_PACKAGE_ID
                && call.module.as_str() == "sui_system"
                && call.type_arguments.is_empty(),
            "promotion transaction calls outside 0x3::sui_system"
        );
        anyhow::ensure!(
            functions.insert(call.function.as_str()),
            "promotion transaction contains a duplicate command"
        );
        let expected = promotion_pure_arguments(call.function.as_str(), draft)?;
        anyhow::ensure!(
            call.arguments.len() == expected.len() + 1,
            "promotion command argument count mismatch"
        );
        anyhow::ensure!(
            resolve_promotion_input(pt, call.arguments[0])? == &CallArg::SUI_SYSTEM_MUT,
            "promotion command does not target the Sui system state"
        );
        for (argument, expected) in call.arguments[1..].iter().zip_debug_eq(expected) {
            anyhow::ensure!(
                resolve_promotion_input(pt, *argument)? == &CallArg::Pure(expected),
                "promotion command argument differs from the draft"
            );
        }
    }
    anyhow::ensure!(
        functions == PROMOTION_FUNCTIONS.into_iter().collect(),
        "promotion transaction command set is incomplete"
    );
    Ok(())
}

fn promotion_pure_arguments(
    function: &str,
    draft: &ValidatorPromotionDraft,
) -> Result<Vec<Vec<u8>>> {
    let target = &draft.target;
    Ok(match function {
        "update_validator_next_epoch_protocol_pubkey" => vec![
            bcs::to_bytes(&parse_canonical_hex(&target.protocol_public_key)?)?,
            bcs::to_bytes(&parse_canonical_hex(&draft.proof_of_possession)?)?,
        ],
        "update_validator_next_epoch_network_pubkey" => {
            vec![bcs::to_bytes(&parse_canonical_hex(
                &target.network_public_key,
            )?)?]
        }
        "update_validator_next_epoch_worker_pubkey" => {
            vec![bcs::to_bytes(&parse_canonical_hex(
                &target.worker_public_key,
            )?)?]
        }
        "update_validator_next_epoch_network_address" => {
            vec![bcs::to_bytes(&target.network_address)?]
        }
        "update_validator_next_epoch_p2p_address" => {
            vec![bcs::to_bytes(&target.p2p_address)?]
        }
        "update_validator_next_epoch_primary_address" => {
            vec![bcs::to_bytes(&target.primary_address)?]
        }
        "update_validator_next_epoch_worker_address" => {
            vec![bcs::to_bytes(&target.worker_address)?]
        }
        _ => bail!("unexpected promotion function"),
    })
}

fn resolve_promotion_input(
    transaction: &sui_types::transaction::ProgrammableTransaction,
    argument: Argument,
) -> Result<&CallArg> {
    let Argument::Input(index) = argument else {
        bail!("promotion commands may only use transaction inputs");
    };
    transaction
        .inputs
        .get(index as usize)
        .context("promotion command references a missing input")
}

fn parse_canonical_hex(value: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "key and proof values must use lowercase canonical hex"
    );
    Hex::decode(value).map_err(Into::into)
}

fn load_structured<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .or_else(|_| serde_yaml::from_slice(&bytes))
        .with_context(|| format!("failed to parse {} as JSON or YAML", path.display()))
}

fn write_new_json(path: &PathBuf, value: &impl Serialize) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

async fn construct_unsigned_0x5_txn(
    context: &mut WalletContext,
    sender: SuiAddress,
    function: &'static str,
    call_args: Vec<CallArg>,
    gas_budget: u64,
) -> anyhow::Result<TransactionData> {
    let sui_client = context.grpc_client()?;
    let mut args = vec![CallArg::SUI_SYSTEM_MUT];
    args.extend(call_args);
    let rgp = sui_client.get_reference_gas_price().await?;

    let gas_obj_ref = get_gas_obj_ref(sender, &sui_client, gas_budget).await?;
    TransactionData::new_move_call(
        sender,
        SUI_SYSTEM_PACKAGE_ID,
        ident_str!("sui_system").to_owned(),
        ident_str!(function).to_owned(),
        vec![],
        gas_obj_ref,
        args,
        gas_budget,
        rgp,
    )
}

async fn call_0x5(
    context: &mut WalletContext,
    function: &'static str,
    call_args: Vec<CallArg>,
    gas_budget: u64,
    serialize_unsigned_transaction: bool,
) -> anyhow::Result<(Option<ExecutedTransaction>, Option<String>)> {
    let sender = context.active_address()?;
    let tx_data =
        construct_unsigned_0x5_txn(context, sender, function, call_args, gas_budget).await?;
    if serialize_unsigned_transaction {
        let serialized_data = Base64::encode(bcs::to_bytes(&tx_data)?);
        return Ok((None, Some(serialized_data)));
    }
    let signature = context
        .config
        .keystore
        .sign_secure(&sender, &tx_data, Intent::sui_transaction())
        .await?;
    let transaction = Transaction::from_data(tx_data, vec![signature]);
    let response = context
        .grpc_client()?
        .execute_transaction_and_wait_for_checkpoint(&transaction)
        .await?;
    Ok((Some(response), None))
}

impl Display for SuiValidatorCommandResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut writer = String::new();
        match self {
            SuiValidatorCommandResponse::MakeValidatorInfo => {}
            SuiValidatorCommandResponse::DisplayMetadata => {}
            SuiValidatorCommandResponse::BecomeCandidate {
                response,
                serialized_unsigned_transaction,
            }
            | SuiValidatorCommandResponse::JoinCommittee {
                response,
                serialized_unsigned_transaction,
            }
            | SuiValidatorCommandResponse::LeaveCommittee {
                response,
                serialized_unsigned_transaction,
            }
            | SuiValidatorCommandResponse::UpdateMetadata {
                response,
                serialized_unsigned_transaction,
            }
            | SuiValidatorCommandResponse::UpdateGasPrice {
                response,
                serialized_unsigned_transaction,
            }
            | SuiValidatorCommandResponse::ReportValidator {
                response,
                serialized_unsigned_transaction,
            } => {
                if let Some(response) = response {
                    write!(writer, "{}", write_transaction_response(response)?)?;
                } else {
                    write!(
                        writer,
                        "Serialized transaction for signing: {:?}",
                        serialized_unsigned_transaction
                    )?;
                }
            }
            SuiValidatorCommandResponse::PrepareValidatorPromotion {
                transaction_digest,
                serialized_unsigned_transaction,
                draft_path,
            } => {
                writeln!(writer, "Promotion transaction digest: {transaction_digest}")?;
                writeln!(writer, "Promotion draft: {}", draft_path.display())?;
                write!(
                    writer,
                    "Serialized unsigned transaction: {serialized_unsigned_transaction}"
                )?;
            }
            SuiValidatorCommandResponse::MakeValidatorPromotionTarget {
                target_path,
                protocol_public_key,
            } => {
                writeln!(writer, "Promotion target: {}", target_path.display())?;
                write!(writer, "Target protocol public key: {protocol_public_key}")?;
            }
            SuiValidatorCommandResponse::FinalizeValidatorPromotion {
                transaction_digest,
                checkpoint_sequence_number,
                manifest_path,
            } => {
                writeln!(writer, "Finalized transaction: {transaction_digest}")?;
                writeln!(writer, "Checkpoint: {checkpoint_sequence_number}")?;
                write!(writer, "Promotion manifest: {}", manifest_path.display())?;
            }
            SuiValidatorCommandResponse::SerializedPayload(response) => {
                write!(writer, "Serialized payload: {}", response)?;
            }
            SuiValidatorCommandResponse::DisplayGasPriceUpdateRawTxn {
                data,
                serialized_data,
            } => {
                write!(
                    writer,
                    "Transaction: {:?}, \nSerialized transaction: {:?}",
                    data, serialized_data
                )?;
            }
            SuiValidatorCommandResponse::RegisterBridgeCommittee {
                execution_response,
                serialized_unsigned_transaction,
            }
            | SuiValidatorCommandResponse::UpdateBridgeCommitteeURL {
                execution_response,
                serialized_unsigned_transaction,
            } => {
                if let Some(response) = execution_response {
                    write!(writer, "{}", write_transaction_response(response)?)?;
                } else {
                    write!(
                        writer,
                        "Serialized transaction for signing: {:?}",
                        serialized_unsigned_transaction
                    )?;
                }
            }
        }
        write!(f, "{}", writer.trim_end_matches('\n'))
    }
}

pub fn write_transaction_response(response: &ExecutedTransaction) -> Result<String, fmt::Error> {
    // we requested with for full_content, so the following content should be available.
    let success = response.effects.status().is_ok();
    let lines = vec![
        String::from("----- Transaction Digest ----"),
        response.transaction.digest().to_string(),
        String::from("\n----- Transaction Data ----"),
        serde_json::to_string_pretty(&response.transaction).unwrap(),
        String::from("----- Transaction Effects ----"),
        serde_json::to_string_pretty(&response.effects).unwrap(),
    ];
    let mut writer = String::new();
    for line in lines {
        let colorized_line = if success { line.green() } else { line.red() };
        writeln!(writer, "{}", colorized_line)?;
    }
    Ok(writer)
}

impl Debug for SuiValidatorCommandResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let string = serde_json::to_string_pretty(self);
        let s = match string {
            Ok(s) => s,
            Err(err) => format!("{err}").red().to_string(),
        };
        write!(f, "{}", s)
    }
}

impl SuiValidatorCommandResponse {
    pub fn print(&self, pretty: bool) {
        match self {
            // Don't print empty responses
            SuiValidatorCommandResponse::MakeValidatorInfo
            | SuiValidatorCommandResponse::DisplayMetadata => {}
            other => {
                let line = if pretty {
                    format!("{other}")
                } else {
                    format!("{:?}", other)
                };
                // Log line by line
                for line in line.lines() {
                    println!("{line}");
                }
            }
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    Pending,
}

pub async fn get_validator_summary(
    client: &Client,
    validator_address: SuiAddress,
) -> anyhow::Result<Option<(ValidatorStatus, proto::Validator)>> {
    let system_state = client.get_system_state(None).await?;
    let mut status = None;
    let mut active_validators = system_state
        .validators()
        .active_validators()
        .iter()
        .map(|s| (s.address().to_owned(), s))
        .collect::<BTreeMap<_, _>>();
    let validator_info = if active_validators.contains_key(&validator_address.to_string()) {
        status = Some(ValidatorStatus::Active);
        Some(
            active_validators
                .remove(&validator_address.to_string())
                .unwrap()
                .to_owned(),
        )
    } else {
        // Check panding validators
        get_pending_candidate_summary(
            validator_address,
            client,
            system_state
                .validators()
                .pending_active_validators()
                .id()
                .parse()
                .unwrap(),
        )
        .await?
        .tap_some(|_s| status = Some(ValidatorStatus::Pending))

        // TODO also check candidate and inactive valdiators
    };
    if validator_info.is_none() {
        return Ok(None);
    }
    // status is safe unwrap because it has to be Some when the code recahes here
    // validator_info is safe to unwrap because of the above check
    Ok(Some((status.unwrap(), validator_info.unwrap())))
}

async fn display_metadata(
    client: &Client,
    validator_address: SuiAddress,
    json: bool,
) -> anyhow::Result<()> {
    match get_validator_summary(client, validator_address).await? {
        None => println!(
            "{} is not an active or pending Validator.",
            validator_address
        ),
        Some((status, info)) => {
            println!("{}'s valdiator status: {:?}", validator_address, status);
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("{:#?}", info);
            }
        }
    }
    Ok(())
}

async fn get_pending_candidate_summary(
    validator_address: SuiAddress,
    sui_client: &Client,
    pending_active_validators_id: ObjectID,
) -> anyhow::Result<Option<proto::Validator>> {
    let pending_validators = sui_client
        .get_dynamic_fields(pending_active_validators_id, None, None)
        .await?;
    for resp in pending_validators.dynamic_fields() {
        // We always expect an objectId from the response as one of data/error should be included.
        let object_id = resp.field_id();
        let field = resp.value().deserialize::<ValidatorV1>().map_err(|e| {
            anyhow::anyhow!(
                "Can't convert bcs bytes of object {} to ValidatorV1: {}",
                object_id,
                e,
            )
        })?;
        if field.verified_metadata().sui_address == validator_address {
            return Ok(Some(field.into()));
        }
    }
    Ok(None)
}

#[derive(Subcommand)]
#[clap(rename_all = "kebab-case")]
pub enum MetadataUpdate {
    /// Update name. Effectuate immediately.
    Name { name: String },
    /// Update description. Effectuate immediately.
    Description { description: String },
    /// Update Image URL. Effectuate immediately.
    ImageUrl { image_url: String },
    /// Update Project URL. Effectuate immediately.
    ProjectUrl { project_url: String },
    /// Update Network Address. Effectuate from next epoch.
    NetworkAddress { network_address: Multiaddr },
    /// Update Primary Address. Effectuate from next epoch.
    PrimaryAddress { primary_address: Multiaddr },
    /// Update Worker Address. Effectuate from next epoch.
    WorkerAddress { worker_address: Multiaddr },
    /// Update P2P Address. Effectuate from next epoch.
    P2pAddress { p2p_address: Multiaddr },
    /// Update Network Public Key. Effectuate from next epoch.
    NetworkPubKey {
        #[clap(name = "network-key-path")]
        file: PathBuf,
    },
    /// Update Worker Public Key. Effectuate from next epoch.
    WorkerPubKey {
        #[clap(name = "worker-key-path")]
        file: PathBuf,
    },
    /// Update Protocol Public Key and Proof and Possession. Effectuate from next epoch.
    ProtocolPubKey {
        #[clap(name = "protocol-key-path")]
        file: PathBuf,
    },
}

async fn update_metadata(
    context: &mut WalletContext,
    metadata: MetadataUpdate,
    gas_budget: u64,
    serialize_unsigned_transaction: bool,
) -> anyhow::Result<(Option<ExecutedTransaction>, Option<String>)> {
    use ValidatorStatus::*;
    match metadata {
        MetadataUpdate::Name { name } => {
            let args = vec![CallArg::Pure(bcs::to_bytes(&name.into_bytes()).unwrap())];
            call_0x5(
                context,
                "update_validator_name",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::Description { description } => {
            let args = vec![CallArg::Pure(
                bcs::to_bytes(&description.into_bytes()).unwrap(),
            )];
            call_0x5(
                context,
                "update_validator_description",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::ImageUrl { image_url } => {
            let args = vec![CallArg::Pure(
                bcs::to_bytes(&image_url.into_bytes()).unwrap(),
            )];
            call_0x5(
                context,
                "update_validator_image_url",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::ProjectUrl { project_url } => {
            let args = vec![CallArg::Pure(
                bcs::to_bytes(&project_url.into_bytes()).unwrap(),
            )];
            call_0x5(
                context,
                "update_validator_project_url",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::NetworkAddress { network_address } => {
            // Check the network address to be in TCP.
            if !network_address.is_loosely_valid_tcp_addr() {
                bail!("Network address must be a TCP address");
            }
            let _status = check_status(context, HashSet::from([Pending, Active])).await?;
            let args = vec![CallArg::Pure(bcs::to_bytes(&network_address).unwrap())];
            call_0x5(
                context,
                "update_validator_next_epoch_network_address",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::PrimaryAddress { primary_address } => {
            primary_address.to_anemo_address().map_err(|_| {
                anyhow!("Invalid primary address, it must look like `/[ip4,ip6,dns]/.../udp/port`")
            })?;
            let _status = check_status(context, HashSet::from([Pending, Active])).await?;
            let args = vec![CallArg::Pure(bcs::to_bytes(&primary_address).unwrap())];
            call_0x5(
                context,
                "update_validator_next_epoch_primary_address",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::WorkerAddress { worker_address } => {
            worker_address.to_anemo_address().map_err(|_| {
                anyhow!("Invalid worker address, it must look like `/[ip4,ip6,dns]/.../udp/port`")
            })?;
            // Only an active validator can leave committee.
            let _status = check_status(context, HashSet::from([Pending, Active])).await?;
            let args = vec![CallArg::Pure(bcs::to_bytes(&worker_address).unwrap())];
            call_0x5(
                context,
                "update_validator_next_epoch_worker_address",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::P2pAddress { p2p_address } => {
            p2p_address.to_anemo_address().map_err(|_| {
                anyhow!("Invalid p2p address, it must look like `/[ip4,ip6,dns]/.../udp/port`")
            })?;
            let _status = check_status(context, HashSet::from([Pending, Active])).await?;
            let args = vec![CallArg::Pure(bcs::to_bytes(&p2p_address).unwrap())];
            call_0x5(
                context,
                "update_validator_next_epoch_p2p_address",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::NetworkPubKey { file } => {
            let _status = check_status(context, HashSet::from([Pending, Active])).await?;
            let network_pub_key: NetworkPublicKey =
                read_network_keypair_from_file(file)?.public().clone();
            let args = vec![CallArg::Pure(
                bcs::to_bytes(&network_pub_key.as_bytes().to_vec()).unwrap(),
            )];
            call_0x5(
                context,
                "update_validator_next_epoch_network_pubkey",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::WorkerPubKey { file } => {
            let _status = check_status(context, HashSet::from([Pending, Active])).await?;
            let worker_pub_key: NetworkPublicKey =
                read_network_keypair_from_file(file)?.public().clone();
            let args = vec![CallArg::Pure(
                bcs::to_bytes(&worker_pub_key.as_bytes().to_vec()).unwrap(),
            )];
            call_0x5(
                context,
                "update_validator_next_epoch_worker_pubkey",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
        MetadataUpdate::ProtocolPubKey { file } => {
            let _status = check_status(context, HashSet::from([Pending, Active])).await?;
            let sui_address = context.active_address()?;
            let protocol_key_pair: AuthorityKeyPair = read_authority_keypair_from_file(file)?;
            let protocol_pub_key: AuthorityPublicKey = protocol_key_pair.public().clone();
            let pop = generate_proof_of_possession(&protocol_key_pair, sui_address);
            let args = vec![
                CallArg::Pure(
                    bcs::to_bytes(&AuthorityPublicKeyBytes::from_bytes(
                        protocol_pub_key.as_bytes(),
                    )?)
                    .unwrap(),
                ),
                CallArg::Pure(bcs::to_bytes(&pop.as_ref().to_vec()).unwrap()),
            ];
            call_0x5(
                context,
                "update_validator_next_epoch_protocol_pubkey",
                args,
                gas_budget,
                serialize_unsigned_transaction,
            )
            .await
        }
    }
}

async fn check_status(
    context: &mut WalletContext,
    allowed_status: HashSet<ValidatorStatus>,
) -> Result<ValidatorStatus> {
    let sui_client = context.grpc_client()?;
    let validator_address = context.active_address()?;
    let summary = get_validator_summary(&sui_client, validator_address).await?;
    if summary.is_none() {
        bail!("{validator_address} is not a Validator.");
    }
    let (status, _summary) = summary.unwrap();
    if allowed_status.contains(&status) {
        return Ok(status);
    }
    bail!(
        "Validator {validator_address} is {:?}, this operation is not supported in this tool or prohibited.",
        status
    )
}
