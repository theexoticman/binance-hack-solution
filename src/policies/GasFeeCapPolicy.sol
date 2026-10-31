// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC165 } from "forge-std/interfaces/IERC165.sol";
import {
    IPolicy,
    IUserOpPolicy,
    ConfigId,
    PackedUserOperation,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "../interfaces/ISessionPolicy.sol";

/**
 * @title GasFeeCapPolicy (user-op policy, companion to SmartSessions' SimpleGasPolicy)
 * @notice Makes SimpleGasPolicy's wei budget a hard bound on the ETH the Safe can spend on gas.
 *
 * The EntryPoint v0.7 takes `prefund = (verificationGasLimit + callGasLimit + preVerificationGas)
 * * maxFeePerGas` from the account and never charges more than that prefund. SimpleGasPolicy counts
 * `(same gas limits) * gasPrice`, where `gasPrice = min(maxFeePerGas, maxPriorityFeePerGas +
 * basefee)`. When `maxFeePerGas` is above that price, the two diverge:
 *  - the Safe pays a prefund larger than what was counted (excess is parked in the Safe's
 *    EntryPoint deposit: with priority fee 0 this moved 42.5 ETH while counting 0), and
 *  - EntryPoint overhead outside the gas limits can be charged above the counted cost.
 *
 * This policy requires `maxFeePerGas == maxPriorityFeePerGas`, the fee mode in which the EntryPoint
 * uses `maxFeePerGas` as the price. Then counted cost == prefund >= charge for every operation.
 * It also caps the fee per gas, so the budget cannot be spent in a single operation at an
 * arbitrary price.
 *
 * initData: `abi.encodePacked(uint128 maxFeePerGas)`.
 */
contract GasFeeCapPolicy is IUserOpPolicy {
    struct Config {
        bool initialized;
        uint128 maxFeePerGas;
    }

    // config[configId][multiplexer][account]
    mapping(ConfigId => mapping(address => mapping(address => Config))) internal $config;

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        if (initData.length != 16) revert PolicyNotInitialized(configId, msg.sender, account);
        $config[configId][msg.sender][account] =
            Config({ initialized: true, maxFeePerGas: uint128(bytes16(initData[0:16])) });
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata userOp)
        external
        view
        returns (uint256)
    {
        Config memory c = $config[id][msg.sender][userOp.sender];
        if (!c.initialized) revert PolicyNotInitialized(id, msg.sender, userOp.sender);
        uint256 maxPriorityFeePerGas = uint128(bytes16(userOp.gasFees));
        uint256 maxFeePerGas = uint128(uint256(userOp.gasFees));
        if (maxFeePerGas != maxPriorityFeePerGas || maxFeePerGas > c.maxFeePerGas) return VALIDATION_FAILED;
        return VALIDATION_SUCCESS;
    }

    function getConfig(ConfigId id, address multiplexer, address account)
        external
        view
        returns (Config memory)
    {
        return $config[id][multiplexer][account];
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IPolicy).interfaceId
            || interfaceId == type(IUserOpPolicy).interfaceId;
    }
}
