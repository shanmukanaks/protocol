use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::Address;
use bitcoin_data_engine::BitcoinDataEngine;
use bitcoin_light_client_core::{
    hasher::Keccak256Hasher, ChainTransition, ProvenLeaf, VerifiedBlock,
};
use bitcoincore_rpc_async::bitcoin::hashes::Hash;
use bitcoincore_rpc_async::bitcoin::BlockHash;
use data_engine::engine::ContractDataEngine;
use rift_sdk::{
    bitcoin_utils::AsyncBitcoinClient, get_retarget_height_from_block_height,
    proof_generator::RiftProofGenerator, WebsocketWalletProvider,
};
use sol_bindings::{RiftExchange, Types::BlockProofParams};
use tokio::{
    sync::{watch, Mutex, RwLockReadGuard},
    task::JoinSet,
    time::sleep,
};
use tracing::{error, info, info_span, warn, Instrument};

use crate::swap_watchtower::build_chain_transition_for_light_client_update;
use crate::txn_broadcast::{PreflightCheck, TransactionBroadcaster};

pub struct ForkWatchtower;

impl ForkWatchtower {
    pub fn run(
        rift_exchange_address: Address,
        transaction_broadcaster: Arc<TransactionBroadcaster>,
        evm_rpc: Arc<WebsocketWalletProvider>,
        btc_rpc: Arc<AsyncBitcoinClient>,
        contract_data_engine: Arc<ContractDataEngine>,
        bitcoin_data_engine: Arc<BitcoinDataEngine>,
        bitcoin_concurrency_limit: usize,
        proof_generator: Arc<RiftProofGenerator>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) {
        let poll_interval = Duration::from_secs(60);

        let currently_processing = Arc::new(Mutex::new(false));

        join_set.spawn(
            async move {
                info!("starting Fork Watchtower");

                let mut block_subscription = bitcoin_data_engine.subscribe_to_new_blocks();

                loop {
                    tokio::select! {
                        Ok(new_leaf) = block_subscription.recv() => {
                            info!("new bitcoin block detected: height={}, hash={}",
                                  new_leaf.height, hex::encode(new_leaf.block_hash));
                        }
                        _ = sleep(poll_interval) => {
                            info!("performing fork check");
                        }
                    }
                    if currently_processing.lock().await.clone() {
                        info!("already processing a fork, skipping check");
                        continue;
                    }

                    match detect_fork(&bitcoin_data_engine, &contract_data_engine).await {
                        Ok(fork_detected) => {
                            if fork_detected {
                                info!("fork detected processing");

                                *currently_processing.lock().await = true;

                                match process_fork(
                                    &rift_exchange_address,
                                    &transaction_broadcaster,
                                    &evm_rpc,
                                    &btc_rpc,
                                    &contract_data_engine,
                                    &bitcoin_data_engine,
                                    bitcoin_concurrency_limit,
                                    &proof_generator,
                                )
                                .await
                                {
                                    Ok(_) => info!("fork processing completed successfully"),
                                    Err(e) => error!("error processing fork: {}", e),
                                }

                                *currently_processing.lock().await = false;
                            }
                        }
                        Err(e) => error!("error detecting fork: {}", e),
                    }
                }

                #[allow(unreachable_code)]
                Ok(())
            }
            .instrument(info_span!("fork watchtower")),
        );
    }
}

async fn detect_fork(
    bitcoin_data_engine: &Arc<BitcoinDataEngine>,
    contract_data_engine: &Arc<ContractDataEngine>,
) -> eyre::Result<bool> {
    let bde_root = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_root()
        .await?;
    let cde_root = contract_data_engine.get_mmr_root().await?;

    if bde_root != cde_root {
        let bde_height = bitcoin_data_engine
            .indexed_mmr
            .read()
            .await
            .get_leaf_count()
            .await? as u32;
        let cde_height = contract_data_engine.get_leaf_count().await? as u32;

        info!(
            "potential fork detected: BDE height={}, CDE height={}",
            bde_height, cde_height
        );
        info!(
            "BDE root: {}, CDE root: {}",
            hex::encode(bde_root),
            hex::encode(cde_root)
        );

        let common_height = std::cmp::min(bde_height, cde_height).saturating_sub(1);

        if common_height > 0 {
            let bde_leaf = bitcoin_data_engine
                .indexed_mmr
                .read()
                .await
                .get_leaf_by_leaf_index(common_height as usize)
                .await?;

            let cde_leaf = contract_data_engine
                .checkpointed_block_tree
                .read()
                .await
                .get_leaf_by_leaf_index(common_height as usize)
                .await?;

            if let (Some(bde_leaf), Some(cde_leaf)) = (bde_leaf, cde_leaf) {
                let bde_hash = bde_leaf.hash::<Keccak256Hasher>();
                let cde_hash = cde_leaf.hash::<Keccak256Hasher>();

                if bde_hash != cde_hash {
                    info!(
                        "fork confirmed at height {}: BDE hash={}, CDE hash={}",
                        common_height,
                        hex::encode(bde_hash),
                        hex::encode(cde_hash)
                    );
                    return Ok(true);
                }
            }
        }

        info!("MMR roots differ but cant confirm fork point");
        return Ok(true);
    }
    Ok(false)
}

async fn process_fork(
    rift_exchange_address: &Address,
    transaction_broadcaster: &Arc<TransactionBroadcaster>,
    evm_rpc: &Arc<WebsocketWalletProvider>,
    btc_rpc: &Arc<AsyncBitcoinClient>,
    contract_data_engine: &Arc<ContractDataEngine>,
    bitcoin_data_engine: &Arc<BitcoinDataEngine>,
    bitcoin_concurrency_limit: usize,
    proof_generator: &Arc<RiftProofGenerator>,
) -> eyre::Result<()> {
    info!("building chain transition for light client update");

    let chain_transition = {
        let bitcoin_mmr = bitcoin_data_engine.indexed_mmr.read().await;
        let light_client_mmr = contract_data_engine.checkpointed_block_tree.read().await;

        build_chain_transition_for_light_client_update(
            btc_rpc.clone(),
            &bitcoin_mmr,
            &light_client_mmr,
            bitcoin_concurrency_limit,
        )
        .await?
    };

    info!("chain transition built, generating proof");

    let rift_program_input = rift_core::giga::RiftProgramInput::builder()
        .proof_type(rift_core::giga::RustProofType::LightClientOnly)
        .light_client_input(chain_transition.clone())
        .build()
        .map_err(|e| eyre::eyre!("failed to build rift program input: {}", e))?;

    let (public_values, auxiliary_data) = rift_program_input.get_auxiliary_light_client_data();

    info!("genning ZK proof");

    let proof = proof_generator
        .prove(&rift_program_input)
        .await
        .map_err(|e| eyre::eyre!("Failed to generate proof: {}", e))?;

    info!("proof genned: {:?}", proof);

    let block_proof_params = BlockProofParams {
        priorMmrRoot: public_values.previousMmrRoot,
        newMmrRoot: public_values.newMmrRoot,
        tipBlockLeaf: public_values.tipBlockLeaf,
        compressedBlockLeaves: auxiliary_data.compressed_leaves.into(),
    };

    let proof_bytes = match proof.proof {
        Some(proof) => proof.bytes(),
        None => {
            warn!("no proof used for light client update, assuming mock proof");
            vec![]
        }
    };

    let rift_exchange = RiftExchange::new(*rift_exchange_address, evm_rpc.clone());

    let update_call = rift_exchange.updateLightClient(block_proof_params, proof_bytes.into());
    let calldata = update_call.calldata().to_owned();
    let transaction_request = update_call.into_transaction_request();

    info!("submitting light client update transaction");

    let tx_result = transaction_broadcaster
        .broadcast_transaction(calldata, transaction_request, PreflightCheck::Simulate)
        .await?;

    info!("light client update transaction result: {:?}", tx_result);

    if tx_result.is_success() {
        info!("light client update successful");
    } else if tx_result.is_revert() {
        warn!("light client update reverted: {:?}", tx_result);
    } else {
        error!("light client update failed: {:?}", tx_result);
    }

    Ok(())
}
