// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.27;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

import {Constants} from "./libraries/Constants.sol";
import {Errors} from "./libraries/Errors.sol";
import {Types} from "./libraries/Types.sol";
import {Events} from "./libraries/Events.sol";
import {CommitmentVerificationLib} from "./libraries/CommitmentVerificationLib.sol";
import {MarketLib} from "./libraries/MarketLib.sol";
import {BitcoinLightClient} from "./BitcoinLightClient.sol";

// TODO: Make unnecessary public functions internal, setup interfaces for light client and exchange
// all pure functions should be behind a library in a seperate file
/**
 * @title RiftExchange
 * @author alpinevm <https://github.com/alpinevm>
 * @author spacegod <https://github.com/bruidbarrett>
 * @notice A decentralized exchange for cross-chain Bitcoin to ERC20 swaps
 * @dev Uses a Bitcoin light client and zero-knowledge proofs for verification
 */
contract RiftExchange is BitcoinLightClient, Ownable {
    // --------- IMMUTABLES --------- //
    IERC20 public immutable DEPOSIT_TOKEN;
    uint8 public immutable TOKEN_DECIMALS;
    bytes32 public immutable CIRCUIT_VERIFICATION_KEY;
    ISP1Verifier public immutable VERIFIER_CONTRACT;
    address public immutable FEE_ROUTER_ADDRESS;

    // --------- STATE --------- //
    bytes32[] public vaultCommitments;
    bytes32[] public swapCommitments;
    uint256 public accumulatedFeeBalance;

    //--------- CONSTRUCTOR ---------//
    constructor(
        address _initialOwner,
        bytes32 _mmrRoot,
        Types.BlockLeaf memory _initialCheckpointLeaf,
        address _depositToken,
        bytes32 _circuitVerificationKey,
        address _verifierContract,
        address _feeRouterAddress
    ) Ownable(_initialOwner) BitcoinLightClient(_mmrRoot, _initialCheckpointLeaf) {
        DEPOSIT_TOKEN = IERC20(_depositToken);
        TOKEN_DECIMALS = IERC20Metadata(_depositToken).decimals();
        CIRCUIT_VERIFICATION_KEY = _circuitVerificationKey;
        VERIFIER_CONTRACT = ISP1Verifier(_verifierContract);
        FEE_ROUTER_ADDRESS = _feeRouterAddress;
    }

    //--------- WRITE FUNCTIONS ---------//
    /// @notice Sends accumulated protocol fees to the fee router contract
    /// @dev Reverts if there are no fees to pay or if the transfer fails
    function payoutToFeeRouter() public {
        if (accumulatedFeeBalance == 0) revert Errors.NoFeeToPay();
        accumulatedFeeBalance = 0;
        if (!DEPOSIT_TOKEN.transfer(FEE_ROUTER_ADDRESS, accumulatedFeeBalance)) revert Errors.TransferFailed();
    }

    /// @notice Deposits new liquidity into a new vault
    /// @param specifiedPayoutAddress Address to receive swap proceeds
    /// @param initialDepositAmount Amount of ERC20 tokens to deposit including fee
    /// @param expectedSats Expected BTC output in satoshis
    /// @param btcPayoutScriptPubKey Bitcoin script for receiving BTC
    /// @param depositSalt User generated salt for vault nonce
    function depositLiquidity(
        address specifiedPayoutAddress,
        uint256 initialDepositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        bytes32 depositSalt
    ) public {
        // [0] create deposit liquidity request
        (Types.DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(
            specifiedPayoutAddress,
            initialDepositAmount,
            expectedSats,
            btcPayoutScriptPubKey,
            vaultCommitments.length,
            depositSalt
        );

        // [1] add deposit hash to vault commitments
        vaultCommitments.push(depositHash);

        // [2] finalize deposit
        _finalizeDeposit(vault);
    }

    /// @notice Deposits new liquidity by overwriting an existing empty vault
    /// @param overwriteVault Existing empty vault to overwrite
    /// @dev Identical to depositLiquidity, but allows for overwriting an existing empty vault
    function depositLiquidityWithOverwrite(
        address specifiedPayoutAddress,
        uint256 initialDepositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        bytes32 depositSalt,
        Types.DepositVault calldata overwriteVault
    ) public {
        // [0] create deposit liquidity request
        (Types.DepositVault memory vault, bytes32 depositHash) = _prepareDeposit(
            specifiedPayoutAddress,
            initialDepositAmount,
            expectedSats,
            btcPayoutScriptPubKey,
            overwriteVault.vaultIndex,
            depositSalt
        );

        // [1] ensure passed vault is real and overwritable
        CommitmentVerificationLib.validateDepositVaultCommitment(overwriteVault, vaultCommitments);
        if (overwriteVault.depositAmount != 0) revert Errors.DepositVaultNotOverwritable();

        // [2] overwrite deposit vault
        vaultCommitments[overwriteVault.vaultIndex] = depositHash;

        // [3] finalize deposit
        _finalizeDeposit(vault);
    }

    /// @notice Checks invariants and creates new deposit vault struct
    /// @dev Validates deposit amounts and creates vault structure
    /// @return Tuple of the new vault and its commitment hash
    function _prepareDeposit(
        address specifiedPayoutAddress,
        uint256 initialDepositAmount,
        uint64 expectedSats,
        bytes22 btcPayoutScriptPubKey,
        uint256 depositVaultIndex,
        bytes32 depositSalt
    ) internal view returns (Types.DepositVault memory, bytes32) {
        // [0] ensure deposit amount is greater than min protocol fee
        if (initialDepositAmount < Constants.MIN_DEPOSIT_AMOUNT) revert Errors.DepositAmountTooLow();

        // [1] ensure expected sat output is above minimum to prevent dust errors
        if (expectedSats < Constants.MIN_OUTPUT_SATS) revert Errors.SatOutputTooLow();

        // [2] ensure scriptPubKey is valid
        if (!CommitmentVerificationLib.validateP2WPKHScriptPubKey(btcPayoutScriptPubKey))
            revert Errors.InvalidScriptPubKey();

        uint256 depositFee = MarketLib.calculateFeeFromAmount(initialDepositAmount);

        Types.DepositVault memory vault = Types.DepositVault({
            vaultIndex: depositVaultIndex,
            depositTimestamp: uint64(block.timestamp),
            depositAmount: initialDepositAmount - depositFee,
            depositFee: depositFee,
            expectedSats: expectedSats,
            btcPayoutScriptPubKey: btcPayoutScriptPubKey,
            specifiedPayoutAddress: specifiedPayoutAddress,
            ownerAddress: msg.sender,
            /// @dev Nonce prevents replay attacks by combining:
            /// 1. depositSalt - LP-provided entropy, unknown before deposit
            /// 2. depositVaultIndex - prevents same-block collisions
            /// 3. chainId - prevents cross-chain collisions
            /// While a random salt from the LP would be sufficient for security,
            /// including the vault index and chain ID ensures protocol safety even if
            /// an LP uses a predictable salt. LPs are incentivized to use random salts
            /// to protect their own liquidity.
            nonce: EfficientHashLib.hash(depositSalt, bytes32(depositVaultIndex), bytes32(uint256(block.chainid)))
        });
        return (vault, CommitmentVerificationLib.hashDepositVault(vault));
    }

    /// @notice Completes deposit by emitting event and transferring tokens
    function _finalizeDeposit(Types.DepositVault memory vault) internal {
        emit Events.VaultUpdated(vault);
        if (!DEPOSIT_TOKEN.transferFrom(msg.sender, address(this), vault.depositAmount + vault.depositFee))
            revert Errors.TransferFailed();
    }

    /// @notice Withdraws liquidity from a deposit vault after the lockup period
    /// @param vault The deposit vault to withdraw from
    /// @dev Anyone can call, reverts if vault doesn't exist, is empty, or still in lockup period
    function withdrawLiquidity(Types.DepositVault calldata vault) public {
        // [0] validate deposit vault exists
        CommitmentVerificationLib.validateDepositVaultCommitment(vault, vaultCommitments);

        // [1] ensure deposit amount is non-zero
        if (vault.depositAmount == 0) revert Errors.EmptyDepositVault();

        // [2] ensure the deposit vault is not time locked
        if (block.timestamp < vault.depositTimestamp + Constants.DEPOSIT_LOCKUP_PERIOD)
            revert Errors.DepositStillLocked();

        // [3] update deposit vault commitment
        Types.DepositVault memory updatedVault = vault;
        updatedVault.depositAmount = 0;
        updatedVault.depositFee = 0;
        bytes32 updatedVaultHash = CommitmentVerificationLib.hashDepositVault(updatedVault);
        vaultCommitments[vault.vaultIndex] = updatedVaultHash;

        // [4] transfer funds to vault owner
        emit Events.VaultUpdated(updatedVault);
        if (!DEPOSIT_TOKEN.transfer(vault.ownerAddress, vault.depositAmount)) {
            revert Errors.TransferFailed();
        }
    }

    /// @notice Internal function to prepare and validate a new swap
    /// @return swap The prepared swap struct
    /// @return updatedSwapHash The hash of the prepared swap
    function _validateSwap(
        uint256 swapIndex,
        bytes32 proposedBlockHash,
        uint64 proposedBlockHeight,
        uint256 proposedBlockCumulativeChainwork,
        Types.DepositVault[] calldata vaults,
        address specifiedPayoutAddress,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        uint256 totalSwapFee,
        uint256 totalSwapAmount,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves
    ) internal returns (Types.ProposedSwap memory swap, bytes32 updatedSwapHash) {
        // [0] create deposit vault & compressed leaves commitments
        bytes32 aggregateVaultCommitment = CommitmentVerificationLib.validateDepositVaultCommitments(
            vaults,
            vaultCommitments
        );
        bytes32 compressedLeavesCommitment = EfficientHashLib.hash(compressedBlockLeaves);

        // [1] craft public inputs and verify proof
        bytes memory publicInputs = abi.encode(
            Types.SwapProofPublicInputs({
                proposedBlockHash: proposedBlockHash,
                aggregateVaultCommitment: aggregateVaultCommitment,
                previousMmrRoot: priorMmrRoot,
                newMmrRoot: newMmrRoot,
                compressedLeavesCommitment: compressedLeavesCommitment,
                proposedBlockCumulativeChainwork: proposedBlockCumulativeChainwork,
                specifiedPayoutAddress: specifiedPayoutAddress,
                proposedBlockHeight: proposedBlockHeight,
                confirmationBlocks: Constants.MIN_CONFIRMATION_BLOCKS,
                totalSwapFee: totalSwapFee,
                totalSwapAmount: totalSwapAmount
            })
        );

        VERIFIER_CONTRACT.verifyProof(CIRCUIT_VERIFICATION_KEY, publicInputs, proof);
        updateRoot(priorMmrRoot, newMmrRoot);

        // [2] create the new swap
        swap = Types.ProposedSwap({
            swapIndex: swapIndex,
            aggregateVaultCommitment: aggregateVaultCommitment,
            proposedBlockLeaf: Types.BlockLeaf({
                blockHash: proposedBlockHash,
                height: proposedBlockHeight,
                cumulativeChainwork: proposedBlockCumulativeChainwork
            }),
            liquidityUnlockTimestamp: uint64(block.timestamp + Constants.CHALLENGE_PERIOD),
            specifiedPayoutAddress: specifiedPayoutAddress,
            totalSwapFee: totalSwapFee,
            totalSwapAmount: totalSwapAmount,
            state: Types.SwapState.Proved
        });

        updatedSwapHash = CommitmentVerificationLib.hashSwap(swap);
    }

    /// @notice Submits a new swap proof and adds it to swapCommitments
    /// @param proposedBlockHash Hash of the Bitcoin block containing the swap
    /// @param proposedBlockHeight Height of the Bitcoin block
    /// @param proposedBlockCumulativeChainwork Cumulative chainwork up to this block
    /// @param vaults Array of deposit vaults being used in the swap
    /// @param specifiedPayoutAddress Address to receive the swap proceeds
    /// @param priorMmrRoot Previous MMR root used to generate this swap proof
    /// @param newMmrRoot Updated MMR root at least incluing up to the confirmation block
    /// @param proof ZK proof validating the swap
    /// @param compressedBlockLeaves Compressed block data for MMR Data Availability
    function submitSwapProof(
        bytes32 proposedBlockHash,
        uint64 proposedBlockHeight,
        uint256 proposedBlockCumulativeChainwork,
        Types.DepositVault[] calldata vaults,
        address specifiedPayoutAddress,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        uint256 totalSwapFee,
        uint256 totalSwapAmount,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves
    ) public {
        // [0] validate swap proof
        (Types.ProposedSwap memory swap, bytes32 updatedSwapHash) = _validateSwap(
            swapCommitments.length,
            proposedBlockHash,
            proposedBlockHeight,
            proposedBlockCumulativeChainwork,
            vaults,
            specifiedPayoutAddress,
            priorMmrRoot,
            newMmrRoot,
            totalSwapFee,
            totalSwapAmount,
            proof,
            compressedBlockLeaves
        );

        // [1] update swap commitments with updated swap hash
        swapCommitments.push(updatedSwapHash);
        emit Events.SwapUpdated(swap);
    }

    /// @notice Same as submitSwapProof but overwrites an existing completed swap commitment
    /// @param overwriteSwap Existing completed swap to overwrite
    /// @dev All other parameters are identical to submitSwapProof
    function submitSwapProofWithOverwrite(
        bytes32 proposedBlockHash,
        uint64 proposedBlockHeight,
        uint256 proposedBlockCumulativeChainwork,
        Types.DepositVault[] calldata vaults,
        address specifiedPayoutAddress,
        bytes32 priorMmrRoot,
        bytes32 newMmrRoot,
        uint256 totalSwapFee,
        uint256 totalSwapAmount,
        bytes calldata proof,
        bytes calldata compressedBlockLeaves,
        Types.ProposedSwap calldata overwriteSwap
    ) public {
        // [0] validate overwrite swap exists and is completed
        CommitmentVerificationLib.validateSwapCommitment(overwriteSwap, swapCommitments);
        if (overwriteSwap.state != Types.SwapState.Completed) revert Errors.CannotOverwriteOnGoingSwap();

        // [1] validate swap proof
        (Types.ProposedSwap memory swap, bytes32 updatedSwapHash) = _validateSwap(
            overwriteSwap.swapIndex,
            proposedBlockHash,
            proposedBlockHeight,
            proposedBlockCumulativeChainwork,
            vaults,
            specifiedPayoutAddress,
            priorMmrRoot,
            newMmrRoot,
            totalSwapFee,
            totalSwapAmount,
            proof,
            compressedBlockLeaves
        );

        // [2] update swap commitments with updated swap hash
        swapCommitments[overwriteSwap.swapIndex] = updatedSwapHash;
        emit Events.SwapUpdated(swap);
    }

    function releaseLiquidity(
        Types.ProposedSwap calldata swap,
        bytes32[] calldata bitcoinBlockInclusionProof,
        Types.DepositVault[] calldata utilizedVaults
    ) public {
        // [0] validate swap exists
        CommitmentVerificationLib.validateSwapCommitment(swap, swapCommitments);

        // [1] validate swap has been proved
        if (swap.state != Types.SwapState.Proved) {
            revert Errors.SwapNotProved();
        }

        // [2] ensure challenge period has passed since proof submission
        if (block.timestamp < swap.liquidityUnlockTimestamp) {
            revert Errors.StillInChallengePeriod();
        }

        // [3] ensure swap block is still part of longest chain
        if (!proveBlockInclusion(swap.proposedBlockLeaf, bitcoinBlockInclusionProof))
            revert Errors.InvalidBlockInclusionProof();

        // [4] ensure all utilized vaults hash to the aggregate vault commitment
        bytes32 aggregateVaultCommitmentHash = CommitmentVerificationLib.validateDepositVaultCommitments(
            utilizedVaults,
            vaultCommitments
        );
        if (aggregateVaultCommitmentHash != swap.aggregateVaultCommitment) revert Errors.InvalidVaultCommitment();

        // [5] empty deposit amounts for all associated deposit vaults
        for (uint256 i = 0; i < utilizedVaults.length; i++) {
            Types.DepositVault memory updatedVault = utilizedVaults[i];
            updatedVault.depositAmount = 0;
            updatedVault.depositFee = 0;
            vaultCommitments[updatedVault.vaultIndex] = CommitmentVerificationLib.hashDepositVault(updatedVault);
        }

        // [6] update completed swap hash
        Types.ProposedSwap memory updatedSwap = swap;
        updatedSwap.state = Types.SwapState.Completed;
        bytes32 updatedSwapHash = CommitmentVerificationLib.hashSwap(updatedSwap);
        swapCommitments[swap.swapIndex] = updatedSwapHash;

        // [7] add protocol fee to accumulated fee balance
        accumulatedFeeBalance += swap.totalSwapFee;

        // [8] emit swap updated
        emit Events.SwapUpdated(updatedSwap);

        // [9] release funds to buyers ETH payout address
        if (!DEPOSIT_TOKEN.transfer(swap.specifiedPayoutAddress, swap.totalSwapAmount)) revert Errors.TransferFailed();
    }

    //--------- READ FUNCTIONS ---------//

    function getVaultCommitmentsLength() public view returns (uint256) {
        return vaultCommitments.length;
    }

    function getSwapCommitmentsLength() public view returns (uint256) {
        return swapCommitments.length;
    }

    function getVaultCommitment(uint256 vaultIndex) public view returns (bytes32) {
        return vaultCommitments[vaultIndex];
    }

    function getSwapCommitment(uint256 swapIndex) public view returns (bytes32) {
        return swapCommitments[swapIndex];
    }
}
