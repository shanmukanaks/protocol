// SPDX-License-Identifier: Unlicensed
pragma solidity =0.8.28;

import {Types} from "./Types.sol";
import {Constants} from "./Constants.sol";
import {Errors} from "./Errors.sol";

import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";

library VaultLib {
    function hashDepositVault(Types.DepositVault memory vault) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(vault));
    }

    function hashSwap(Types.ProposedSwap memory swap) internal pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(swap));
    }

    function validateDepositVaultCommitment(
        Types.DepositVault calldata vault,
        bytes32[] storage vaultCommitments
    ) internal view returns (bytes32) {
        bytes32 vaultHash = hashDepositVault(vault);
        if (vaultHash != vaultCommitments[vault.vaultIndex]) {
            revert Errors.DepositVaultDoesNotExist();
        }
        return vaultHash;
    }

    function validateSwapCommitment(
        Types.ProposedSwap calldata swap,
        bytes32[] storage swapCommitments
    ) internal view returns (bytes32) {
        bytes32 swapHash = hashSwap(swap);
        if (swapHash != swapCommitments[swap.swapIndex]) {
            revert Errors.SwapDoesNotExist();
        }
        return swapHash;
    }

    function calculateSwapTotals(
        Types.DepositVault memory vault
    ) internal pure returns (uint256 totalSwapOutput, uint256 totalSwapFee) {
        uint256 makerDepositAmount = vault.depositAmount;
        // depositFee is the same for both maker and taker
        totalSwapFee = vault.depositFee * 2;
        totalSwapOutput = makerDepositAmount - vault.depositFee; // makerDepositAmount already has the maker fee removed
    }
}
