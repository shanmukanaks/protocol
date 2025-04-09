use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::Address;
use alloy::sol_types::SolValue;
use bitcoin_data_engine::BitcoinDataEngine;
use bitcoin_light_client_core::{
    hasher::Keccak256Hasher, leaves::BlockLeaf, ChainTransition, ProvenLeaf, VerifiedBlock,
};
use crypto_bigint::U256;
use data_engine::engine::ContractDataEngine;
use bitcoin::key::rand::{self, Rng};
use rift_core::giga::RustProofType;
use rift_sdk::{
    bitcoin_utils::AsyncBitcoinClient, proof_generator::RiftProofGenerator, WebsocketWalletProvider,
};
use sol_bindings::{
    RiftExchange, 
    Types::{BlockProofParams, LightClientPublicInput},
};
use tokio::{
    sync::{watch, Mutex},
    task::JoinSet,
    time::sleep,
};
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::swap_watchtower::build_chain_transition_for_light_client_update;
use crate::txn_broadcast::{PreflightCheck, TransactionBroadcaster, TransactionExecutionResult};

pub struct ForkWatchtowerConfig {
    pub poll_interval: Duration,
    pub max_attempts: u32,
    pub base_retry_delay_ms: u64,
    pub max_retry_delay_ms: u64,
    pub retry_jitter_ms: u64,
    pub proof_regen_attempts: u32,
}

impl Default for ForkWatchtowerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            max_attempts: 5,
            base_retry_delay_ms: 1000,
            max_retry_delay_ms: 60000,
            retry_jitter_ms: 500,
            proof_regen_attempts: 3,
        }
    }
}

#[derive(Debug, Clone)]
enum ForkType {
    MissingBlocks {
        lc_tip_height: u32,
        bde_tip_height: u32,
    },
    Reorganization {
        lc_tip_height: u32,
        bde_tip_height: u32,
        lc_tip_chainwork: U256,
        bde_tip_chainwork: U256,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum RevertErrorType {
    ProofVerificationFailure,
    SimulationFailure,
    NonceError,
    GasError,
    SlippageError,
    FrontrunningProtection,
    InvariantViolation,
    UnknownRevert,
    NetworkError,
    TransientError,
}

struct RetryStrategy {
    should_retry: bool,
    should_regenerate_proof: bool,
    delay_ms: u64,
    backoff_multiplier: f64,
    max_attempts: u32,
    error_message: String,
}

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
        info!("starting Fork Watchtower");
        let config = ForkWatchtowerConfig::default();
        let currently_processing = Arc::new(Mutex::new(false));
        let (mmr_root_tx, mmr_root_rx) = watch::channel([0u8; 32]);
        let cde_clone = contract_data_engine.clone();
        let root_sender = mmr_root_tx.clone();
        
        join_set.spawn(async move {
            let mut last_root = [0u8; 32];
            
            loop {
                match cde_clone.get_mmr_root().await {
                    Ok(new_root) => {
                        if new_root != last_root {
                            info!("LC MMR root changed: {}", hex::encode(new_root));
                            last_root = new_root;
                            let _ = root_sender.send(new_root);
                        }
                    },
                    Err(e) => error!("err getting MMR root: {}", e),
                }
                
                sleep(Duration::from_secs(10)).await;
            }
            
            #[allow(unreachable_code)]
            Ok(())
        });

        join_set.spawn(
            async move {
                let mut rx = mmr_root_rx;
                
                match contract_data_engine.get_mmr_root().await {
                    Ok(root) => { let _ = mmr_root_tx.send(root); },
                    Err(e) => error!("err getting initial MMR root: {}", e),
                }
                
                info!("Fork watchtower started");
                
                loop {
                    tokio::select! {
                        result = rx.changed() => {
                            if result.is_ok() {
                                let mmr_root = *rx.borrow();
                                info!("lc state changed MMR root: {}", 
                                    hex::encode(mmr_root));
                            } else {
                                error!("watch channel err: {:?}", result.err());
                            }
                        }
                        _ = sleep(config.poll_interval) => {
                            debug!("interval fork check");
                        }
                    }
                    
                    let is_processing = {
                        let guard = currently_processing.lock().await;
                        *guard
                    };
                    
                    if is_processing {
                        debug!("already processing a fork, skipping check");
                        continue;
                    }

                    match detect_fork(&bitcoin_data_engine, &contract_data_engine).await {
                        Ok(Some(fork_type)) => {
                            info!("fork detected processing: {:?}", fork_type);
                            
                            {
                                let mut guard = currently_processing.lock().await;
                                *guard = true;
                            }

                            match process_fork(
                                &rift_exchange_address,
                                &transaction_broadcaster,
                                &evm_rpc,
                                &btc_rpc,
                                &contract_data_engine,
                                &bitcoin_data_engine,
                                bitcoin_concurrency_limit,
                                &proof_generator,
                                &config,
                                fork_type,
                            )
                            .await
                            {
                                Ok(_) => info!("fork processing completed successfully"),
                                Err(e) => error!("error processing fork: {}", e),
                            }

                            {
                                let mut guard = currently_processing.lock().await;
                                *guard = false;
                            }
                        },
                        Ok(None) => {
                            debug!("no fork detected");
                        },
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
) -> eyre::Result<Option<ForkType>> {
    let lc_tip_height = contract_data_engine.get_leaf_count().await?;
    if lc_tip_height == 0 {
        return Ok(None);
    }
    
    let lc_tip_height = (lc_tip_height - 1) as u32;
    
    if lc_tip_height == 0 {
        debug!("LC: no fork possible");
        return Ok(None);
    }
    
    let lc_tip_leaf = contract_data_engine
        .checkpointed_block_tree
        .read()
        .await
        .get_leaf_by_leaf_index(lc_tip_height as usize)
        .await?
        .ok_or_else(|| eyre::eyre!("err getting LC tip leaf"))?;
    
    let bde_leaf_count = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_count()
        .await?;
    
    if bde_leaf_count == 0 {
        debug!("BDE: no fork possible");
        return Ok(None);
    }
    
    let bde_tip_height = (bde_leaf_count - 1) as u32;
    let bde_tip_leaf = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_by_leaf_index(bde_tip_height as usize)
        .await?
        .ok_or_else(|| eyre::eyre!("err getting BDE tip leaf"))?;
    
    let lc_tip_hash = lc_tip_leaf.hash::<Keccak256Hasher>();
    let bde_tip_hash = bde_tip_leaf.hash::<Keccak256Hasher>();
    
    if lc_tip_hash == bde_tip_hash {
        debug!("LC tip hash == BDE tip hash no fork");
        return Ok(None);
    }
    
    let lc_tip_chainwork = lc_tip_leaf.chainwork_as_u256();
    let bde_tip_chainwork = bde_tip_leaf.chainwork_as_u256();
    
    if lc_tip_chainwork == bde_tip_chainwork {
        info!("LC tip chainwork == BDE tip chainwork, favor existing chain");
        return Ok(None);
    }
    
    if lc_tip_chainwork > bde_tip_chainwork {
        warn!(
            "LC tip chainwork > BDE tip chainwork, ({} > {}), wait for BDE to update",
            lc_tip_chainwork, bde_tip_chainwork
        );
        return Ok(None);
    }
    
    let lc_tip_in_bde = bitcoin_data_engine
        .indexed_mmr
        .read()
        .await
        .get_leaf_by_leaf_hash(&lc_tip_hash)
        .await?;
    
    if lc_tip_in_bde.is_some() {
        info!(
            "LC tip (height={}) is in BDE chain but not the tip (height={}), missing newer blocks",
            lc_tip_height, bde_tip_height
        );
        return Ok(Some(ForkType::MissingBlocks {
            lc_tip_height,
            bde_tip_height,
        }));
    }
    
    info!(
        "LC tip (height={}, chainwork={}) is not in BDE chain (height={}, chainwork={}), reorg",
        lc_tip_height, lc_tip_chainwork, bde_tip_height, bde_tip_chainwork
    );
    
    return Ok(Some(ForkType::Reorganization {
        lc_tip_height,
        bde_tip_height,
        lc_tip_chainwork,
        bde_tip_chainwork,
    }));
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
    config: &ForkWatchtowerConfig,
    fork_type: ForkType,
) -> eyre::Result<()> {
    info!("processing fork of type: {:?}", fork_type);
    
    let start_time = Instant::now();
    
    struct RetryContext {
        attempt: u32,
        proof_regenerations: u32,
        chain_transition: Option<ChainTransition>,
        block_proof_params: Option<BlockProofParams>,
        last_error: Option<String>,
        last_error_type: Option<RevertErrorType>,
        proof_bytes: Vec<u8>,
        public_values: Option<LightClientPublicInput>,
    }
    
    let mut ctx = RetryContext {
        attempt: 0,
        proof_regenerations: 0,
        chain_transition: None,
        block_proof_params: None,
        last_error: None,
        last_error_type: None,
        proof_bytes: vec![],
        public_values: None,
    };
    
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
    
    ctx.chain_transition = Some(chain_transition.clone());
    
    while ctx.attempt < config.max_attempts {
        ctx.attempt += 1;
        info!("fork resolve attempt {}/{}", ctx.attempt, config.max_attempts);
        
        if ctx.proof_regenerations == 0 || ctx.last_error_type == Some(RevertErrorType::ProofVerificationFailure) {
            if ctx.proof_regenerations > 0 {
                info!("regen proof after verification failure, attempt {}/{}", 
                      ctx.proof_regenerations, config.proof_regen_attempts);
                
                let updated_chain_transition = {
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
                
                ctx.chain_transition = Some(updated_chain_transition.clone());
            }
            
            if ctx.proof_regenerations >= config.proof_regen_attempts {
                return Err(eyre::eyre!("err to gen a valid proof after {} attempts", ctx.proof_regenerations));
            }
            
            ctx.proof_regenerations += 1;
            
            let chain_transition = ctx.chain_transition.clone().unwrap();
            
            let rift_program_input = rift_core::giga::RiftProgramInput::builder()
                .proof_type(RustProofType::LightClientOnly)
                .light_client_input(chain_transition.clone())
                .build()
                .map_err(|e| eyre::eyre!("err to build rift program input: {}", e))?;

            let (public_values, auxiliary_data) = rift_program_input.get_auxiliary_light_client_data();
            ctx.public_values = Some(public_values.clone());

            info!("genning ZK proof (attempt {}/{})", ctx.proof_regenerations, config.proof_regen_attempts);
            let proof_start = Instant::now();
            
            let proof = proof_generator
                .prove(&rift_program_input)
                .await
                .map_err(|e| eyre::eyre!("err to gen proof: {}", e))?;

            let proof_duration = proof_start.elapsed();
            info!("Proof genned in {:?}", proof_duration);

            ctx.block_proof_params = Some(BlockProofParams {
                priorMmrRoot: public_values.previousMmrRoot,
                newMmrRoot: public_values.newMmrRoot,
                tipBlockLeaf: public_values.tipBlockLeaf,
                compressedBlockLeaves: auxiliary_data.compressed_leaves.into(),
            });

            ctx.proof_bytes = match proof.proof {
                Some(proof) => proof.bytes(),
                None => {
                    warn!("no proof used for LC update");
                    vec![]
                }
            };
        }
        
        let rift_exchange = RiftExchange::new(*rift_exchange_address, evm_rpc.clone());
        let block_proof_params = ctx.block_proof_params.clone().unwrap();

        let update_call = rift_exchange.updateLightClient(block_proof_params, ctx.proof_bytes.clone().into());
        let calldata = update_call.calldata().to_owned();
        let transaction_request = update_call.into_transaction_request();

        info!("trying to update light client (attempt {}/{})", ctx.attempt, config.max_attempts);
        
        let tx_result = transaction_broadcaster
            .broadcast_transaction(calldata.clone(), transaction_request.clone(), PreflightCheck::Simulate)
            .await?;

        match tx_result {
            TransactionExecutionResult::Success(receipt) => {
                let elapsed = start_time.elapsed();
                info!("LC update worked after {} attempts in {:?} txn hash: {}", 
                     ctx.attempt, elapsed, receipt.transaction_hash);
                
                info!("wait for cde to sync the update");
                let expected_mmr_root: [u8; 32] = ctx.public_values.as_ref().unwrap().newMmrRoot.into();
                
                for i in 1..=15 {
                    match contract_data_engine.get_mmr_root().await {
                        Ok(current_root) => {
                            if current_root == expected_mmr_root {
                                info!("cde synced the update");
                                break;
                            }
                            if i == 15 {
                                warn!("cde did not sync in time");
                            }
                        },
                        Err(e) => {
                            warn!("err checking CDE update status: {}", e);
                        }
                    }
                    sleep(Duration::from_secs(2)).await;
                }
                
                debug!("final MMR root: {:?}", ctx.public_values.as_ref().unwrap().newMmrRoot);
                
                return Ok(());
            },
            TransactionExecutionResult::Revert(revert_info) => {
                let (error_type, strategy) = classify_revert_error(&revert_info);
                ctx.last_error_type = Some(error_type.clone());
                ctx.last_error = Some(revert_info.error_payload.message.to_string());
                
                match error_type {
                    RevertErrorType::ProofVerificationFailure => {
                        error!("LC update failed due to proof verification: {}", revert_info.error_payload.message);
                        
                        if ctx.proof_regenerations < config.proof_regen_attempts {
                            warn!("attempt to regen proof in next iter");
                            sleep(Duration::from_millis(calculate_backoff_with_jitter(
                                config.base_retry_delay_ms / 2, 
                                ctx.attempt, 
                                1.5, 
                                config.max_retry_delay_ms,
                                config.retry_jitter_ms
                            ))).await;
                            continue;
                        } else {
                            return Err(eyre::eyre!("proof verification failed after regen attempts: {}", 
                                                  revert_info.error_payload.message));
                        }
                    },
                    RevertErrorType::NonceError => {
                        warn!("txns revert due to nonce issue, retry: {}", revert_info.error_payload.message);
                        sleep(Duration::from_millis(calculate_backoff_with_jitter(
                            500, 
                            ctx.attempt, 
                            1.2, 
                            config.max_retry_delay_ms,
                            config.retry_jitter_ms
                        ))).await;
                        continue;
                    },
                    RevertErrorType::GasError => {
                        warn!("txns revert due to gas issue, retry with higher gas: {}", 
                              revert_info.error_payload.message);
                        sleep(Duration::from_millis(calculate_backoff_with_jitter(
                            config.base_retry_delay_ms, 
                            ctx.attempt, 
                            1.5, 
                            config.max_retry_delay_ms,
                            config.retry_jitter_ms
                        ))).await;
                        continue;
                    },
                    RevertErrorType::InvariantViolation => {
                        error!("invariant violation: {}", revert_info.error_payload.message);
                        return Err(eyre::eyre!("invariant violation: {}", revert_info.error_payload.message));
                    },
                    RevertErrorType::FrontrunningProtection | 
                    RevertErrorType::SlippageError => {
                        warn!("chain state changed, rebuild chain transition: {}", revert_info.error_payload.message);
                        ctx.last_error_type = Some(RevertErrorType::ProofVerificationFailure);
                        sleep(Duration::from_millis(calculate_backoff_with_jitter(
                            config.base_retry_delay_ms, 
                            ctx.attempt, 
                            2.0, 
                            config.max_retry_delay_ms,
                            config.retry_jitter_ms
                        ))).await;
                        continue;
                    },
                    _ => {
                        warn!("LC update reverted because: {}", revert_info.error_payload.message);
                        sleep(Duration::from_millis(calculate_backoff_with_jitter(
                            config.base_retry_delay_ms, 
                            ctx.attempt, 
                            2.0, 
                            config.max_retry_delay_ms,
                            config.retry_jitter_ms
                        ))).await;
                        continue;
                    }
                }
            },
            TransactionExecutionResult::InvalidRequest(error) => {
                error!("invalid txns req: {}", error);
                return Err(eyre::eyre!("invalid txns req: {}", error));
            },
            TransactionExecutionResult::UnknownError(error) => {
                warn!("unknown err during txn: {}", error);
                ctx.last_error = Some(error.clone());
                ctx.last_error_type = Some(RevertErrorType::NetworkError);
                
                sleep(Duration::from_millis(calculate_backoff_with_jitter(
                    config.base_retry_delay_ms * 2, 
                    ctx.attempt, 
                    2.5, 
                    config.max_retry_delay_ms * 2,
                    config.retry_jitter_ms
                ))).await;
                continue;
            }
        }
    }
    
    Err(eyre::eyre!("err updating LC after {} attempts, last error: {}", 
                  config.max_attempts, ctx.last_error.unwrap_or_else(|| "unknown error".to_string())))
}

fn classify_revert_error(revert_info: &crate::txn_broadcast::RevertInfo) -> (RevertErrorType, RetryStrategy) {
    if let Some(decoded_error) = revert_info.error_payload
        .as_decoded_error::<RiftExchange::RiftExchangeErrors>(false) 
    {
        match decoded_error {
            // InvalidLeavesCommitment
            // InvalidConfirmationBlockInclusionProof
            // RootWasNotUpdated
            RiftExchange::RiftExchangeErrors::InvalidBlockInclusionProof(_) |
            RiftExchange::RiftExchangeErrors::InvalidSwapBlockInclusionProof(_) => {
                return (
                    RevertErrorType::ProofVerificationFailure,
                    RetryStrategy {
                        should_retry: true,
                        should_regenerate_proof: true,
                        delay_ms: 1000,
                        backoff_multiplier: 1.5,
                        max_attempts: 3,
                        error_message: format!("invalid proof verification: {:?}", decoded_error),
                    }
                );
            },
            RiftExchange::RiftExchangeErrors::ChainworkTooLow(_) => {
                return (
                    RevertErrorType::InvariantViolation,
                    RetryStrategy {
                        should_retry: false,
                        should_regenerate_proof: false,
                        delay_ms: 0,
                        backoff_multiplier: 0.0,
                        max_attempts: 0,
                        error_message: format!("invariant violation: {:?}", decoded_error),
                    }
                );
            },
            RiftExchange::RiftExchangeErrors::NotEnoughConfirmationBlocks(_) |
            RiftExchange::RiftExchangeErrors::NotEnoughConfirmations(_) => {
                return (
                    RevertErrorType::InvariantViolation,
                    RetryStrategy {
                        should_retry: false,
                        should_regenerate_proof: false,
                        delay_ms: 0,
                        backoff_multiplier: 0.0,
                        max_attempts: 0,
                        error_message: format!("not enough confirmation blocks: {:?}", decoded_error),
                    }
                );
            },
            _ => {
            }
        }
    }
    
    let error_message = revert_info.error_payload.message.to_lowercase();
    
    if error_message.contains("invalid proof") || 
       error_message.contains("verification failed") || 
       error_message.contains("inclusion proof") {
        (
            RevertErrorType::ProofVerificationFailure,
            RetryStrategy {
                should_retry: true,
                should_regenerate_proof: true,
                delay_ms: 1000,
                backoff_multiplier: 1.5,
                max_attempts: 3,
                error_message: error_message.to_string(),
            }
        )
    } else if error_message.contains("nonce") {
        (
            RevertErrorType::NonceError,
            RetryStrategy {
                should_retry: true,
                should_regenerate_proof: false,
                delay_ms: 500,
                backoff_multiplier: 1.2,
                max_attempts: 5,
                error_message: error_message.to_string(),
            }
        )
    } else if error_message.contains("gas") {
        (
            RevertErrorType::GasError,
            RetryStrategy {
                should_retry: true,
                should_regenerate_proof: false,
                delay_ms: 1000,
                backoff_multiplier: 1.5,
                max_attempts: 4,
                error_message: error_message.to_string(),
            }
        )
    } else if error_message.contains("slippage") {
        (
            RevertErrorType::SlippageError,
            RetryStrategy {
                should_retry: true,
                should_regenerate_proof: true,
                delay_ms: 2000,
                backoff_multiplier: 2.0,
                max_attempts: 3,
                error_message: error_message.to_string(),
            }
        )
    } else if error_message.contains("invariant") || error_message.contains("assertion") {
        (
            RevertErrorType::InvariantViolation,
            RetryStrategy {
                should_retry: false,
                should_regenerate_proof: false,
                delay_ms: 0,
                backoff_multiplier: 0.0,
                max_attempts: 0,
                error_message: error_message.to_string(),
            }
        )
    } else {
        (
            RevertErrorType::UnknownRevert,
            RetryStrategy {
                should_retry: true,
                should_regenerate_proof: false,
                delay_ms: 2000,
                backoff_multiplier: 2.0,
                max_attempts: 3,
                error_message: error_message.to_string(),
            }
        )
    }
}

fn calculate_backoff_with_jitter(
    base_delay_ms: u64,
    attempt: u32,
    multiplier: f64,
    max_delay_ms: u64,
    jitter_ms: u64,
) -> u64 {
    let exponential_delay = (base_delay_ms as f64 * multiplier.powi(attempt as i32 - 1)) as u64;
    let capped_delay = exponential_delay.min(max_delay_ms);
    
    if jitter_ms > 0 {
        let jitter = rand::thread_rng().gen_range(0..=jitter_ms);
        capped_delay.saturating_add(jitter)
    } else {
        capped_delay
    }
}