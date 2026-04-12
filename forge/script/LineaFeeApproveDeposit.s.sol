// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {StdCheats} from "forge-std/StdCheats.sol";

/// @dev Linea mainnet MultiSignFeeRegistry (deposit uses `transferFrom` → approve fee token first).
address constant LINEA_FEE_REGISTRY = 0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3;

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IFeeRegistry {
    struct FeeConfig {
        address feeToken;
        uint256 freeNonceAllocation;
        uint256 feePerNonce;
        uint256 minimumDeposit;
        bytes32 chainType;
    }

    function keyGenFeeConfig(address keyGen) external view returns (FeeConfig memory);

    function deposit(address keyGenAddress, uint256 amount) external;
}

/// @notice Two txs: `approve(feeRegistry, amount)` on the fee ERC20, then `deposit(mpc, amount)` on the registry.
/// @dev Set env `DEPOSIT_AMOUNT_WEI` (uint256) and `MPC_ADDRESS` (KeyGen ethereum address). Run with the same address as `--sender`.
///      Optional: `FORGE_LINEA_FEE_SIMULATE=true` mints fee-token balance via `deal` on a fork so simulation succeeds when building `run-latest.json` (no effect on-chain).
contract LineaFeeApproveDeposit is Script, StdCheats {
    function run() external {
        uint256 amount = vm.envUint("DEPOSIT_AMOUNT_WEI");
        address mpc = vm.envAddress("MPC_ADDRESS");

        IFeeRegistry.FeeConfig memory cfg = IFeeRegistry(LINEA_FEE_REGISTRY).keyGenFeeConfig(mpc);
        require(cfg.feeToken != address(0), "LineaFeeApproveDeposit: keyGen not registered");

        if (vm.envOr("FORGE_LINEA_FEE_SIMULATE", false)) {
            deal(cfg.feeToken, mpc, amount);
        }

        vm.startBroadcast(mpc);
        IERC20Approve(cfg.feeToken).approve(LINEA_FEE_REGISTRY, amount);
        IFeeRegistry(LINEA_FEE_REGISTRY).deposit(mpc, amount);
        vm.stopBroadcast();
    }
}
