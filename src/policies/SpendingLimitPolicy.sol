// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ConfigId } from "../interfaces/ISessionPolicy.sol";
import { SessionPolicyBase } from "./SessionPolicyBase.sol";
import { TransferLib } from "../libraries/TransferLib.sol";

/**
 * @title SpendingLimitPolicy (Control 2)
 * @notice Per-asset amount controls for a session:
 *          - `maxPerTx`      maximum amount of a single transfer (native value or ERC-20 amount)
 *          - `maxPerPeriod`  aggregate amount over a fixed, aligned time window of `period` seconds
 *                            (e.g. 86400 = UTC day). All transfers of the session count, including
 *                            every element of a batch and every userOp of a bundle.
 *         Assets without a configured limit are rejected (fail-closed).
 *
 * Accounting model (read docs/THREAT_MODEL.md, "Stateful accounting"):
 *  - Usage is recorded during ERC-4337 *validation*, exactly when the operation is authorised.
 *    A later revert of the execution phase does not refund it: the policy may over-count, it can
 *    never under-count. To make that rare, the policy refuses transfers the account cannot cover.
 *  - Usage is NOT reset by re-configuration: raising a limit never refunds what was already spent
 *    in the current window.
 *  - Uses `block.timestamp` during validation. That is banned by ERC-7562 for the *public* 4337
 *    mempool (OP-011), so operations must be submitted by the operator's own bundler. This is a
 *    mempool-compatibility constraint only; on-chain enforcement does not depend on the bundler.
 *
 * initData: `abi.encode(AssetLimit[])`. Re-initialising replaces the whole set of limits.
 */
contract SpendingLimitPolicy is SessionPolicyBase {
    struct AssetLimit {
        address asset; // address(0) = native token
        uint128 maxPerTx;
        uint128 maxPerPeriod;
        uint48 period;
    }

    struct Limit {
        uint128 maxPerTx;
        uint128 maxPerPeriod;
        uint48 period;
    }

    struct Usage {
        uint128 spent;
        uint48 windowEnd;
    }

    event SpendRecorded(
        ConfigId indexed id,
        address indexed account,
        address indexed asset,
        uint256 amount,
        uint256 spentInWindow
    );

    error InvalidLimit(address asset);
    error NoLimits();

    // limits[configId][multiplexer][epoch][asset][account]
    mapping(
        ConfigId => mapping(address => mapping(uint256 => mapping(address => mapping(address => Limit))))
    ) internal $limits;
    // usage[configId][multiplexer][asset][account] - deliberately not epoch-scoped.
    mapping(ConfigId => mapping(address => mapping(address => mapping(address => Usage)))) internal $usage;

    function getLimit(ConfigId id, address multiplexer, address account, address asset)
        external
        view
        returns (Limit memory)
    {
        return $limits[id][multiplexer][$epoch[id][multiplexer][account]][asset][account];
    }

    /// @notice Amount spent in the window that is current at `block.timestamp`.
    function spentInCurrentWindow(ConfigId id, address multiplexer, address account, address asset)
        external
        view
        returns (uint256)
    {
        Usage memory u = $usage[id][multiplexer][asset][account];
        return block.timestamp >= u.windowEnd ? 0 : u.spent;
    }

    function _configure(
        ConfigId id,
        address multiplexer,
        address account,
        uint256 epoch,
        bytes calldata initData
    ) internal override {
        AssetLimit[] memory limits = abi.decode(initData, (AssetLimit[]));
        if (limits.length == 0) revert NoLimits();
        for (uint256 i; i < limits.length; i++) {
            AssetLimit memory l = limits[i];
            if (l.period == 0 || l.maxPerTx == 0 || l.maxPerTx > l.maxPerPeriod) {
                revert InvalidLimit(l.asset);
            }
            $limits[id][multiplexer][epoch][l.asset][account] =
                Limit({ maxPerTx: l.maxPerTx, maxPerPeriod: l.maxPerPeriod, period: l.period });
        }
    }

    function _check(
        ConfigId id,
        address multiplexer,
        address account,
        uint256 epoch,
        address target,
        uint256 value,
        bytes calldata data
    ) internal override returns (bool) {
        TransferLib.Transfer memory t = TransferLib.decode(target, value, data);
        if (t.kind == TransferLib.Kind.UNSUPPORTED) return false;

        Limit memory limit = $limits[id][multiplexer][epoch][t.asset][account];
        if (limit.period == 0) return false; // asset not configured for this session
        if (t.amount > limit.maxPerTx) return false;

        Usage memory u = $usage[id][multiplexer][t.asset][account];
        if (block.timestamp >= u.windowEnd) {
            u.spent = 0;
            u.windowEnd = uint48(block.timestamp - (block.timestamp % limit.period) + limit.period);
        }
        uint256 newSpent = uint256(u.spent) + t.amount;
        if (newSpent > limit.maxPerPeriod) return false;
        if (!_hasBalance(account, t)) return false;

        // Safe cast: newSpent <= maxPerPeriod <= type(uint128).max
        // forge-lint: disable-next-line(unsafe-typecast)
        $usage[id][multiplexer][t.asset][account] =
            Usage({ spent: uint128(newSpent), windowEnd: u.windowEnd });
        emit SpendRecorded(id, account, t.asset, t.amount, newSpent);
        return true;
    }

    /// @dev Best-effort guard against recording usage for a transfer that is bound to revert.
    function _hasBalance(address account, TransferLib.Transfer memory t) internal view returns (bool) {
        if (t.kind == TransferLib.Kind.NATIVE_TRANSFER) return account.balance >= t.amount;
        (bool ok, bytes memory ret) =
            t.asset.staticcall(abi.encodeWithSignature("balanceOf(address)", account));
        return ok && ret.length >= 32 && abi.decode(ret, (uint256)) >= t.amount;
    }
}
