// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    ISafePolicy,
    ISafePolicyEngine,
    PolicyOperation,
    AccessSelectorLib
} from "../../interfaces/ISafePolicy.sol";

/// @dev Safe7579's `Execution` struct (erc7579 reference implementation), declared locally.
struct Execution7579 {
    address target;
    uint256 value;
    bytes callData;
}

/// @dev `BatchedExecUtil.execute(Execution[])` from Safe7579's `DCUtil.sol`.
interface IBatchedExecUtil {
    function execute(Execution7579[] calldata executions) external;
}

/**
 * @title Safe7579BatchPolicy
 * @notice Safe Policy Engine policy that applies the Safe's policies to every element of a
 *         Safe7579 batch - the 7579 counterpart of upstream `MultiSendPolicy`.
 *
 * Safe7579 v1.0.0 executes an ERC-7579 batch (`execute` with CALLTYPE_BATCH) as ONE module
 * transaction: `Safe.execTransactionFromModule(UTIL, 0, BatchedExecUtil.execute(executions),
 * DELEGATECALL)`. Inside that delegatecall, each element is a plain `CALL` made by the Safe itself,
 * which never passes through `execTransactionFromModule` again, so the module guard sees only the
 * outer delegatecall. Without this policy the engine must either deny all 7579 batches or allow the
 * delegatecall wholesale; the latter lets any batch element - including a self-call to
 * `Safe.addOwnerWithThreshold` - run with no policy check at all.
 *
 * Configure it ONLY on `(UTIL, IBatchedExecUtil.execute.selector, DELEGATECALL)`, where UTIL is the
 * `Safe7579DCUtil` deployed by the Safe7579 adapter's constructor. Each element is checked as a CALL
 * (that is what `BatchedExecUtil._execute` performs); a nested batch is a CALL to UTIL, which has no
 * policy and is denied. Elements are decoded with the strict ABI decoder; anything it rejects is denied.
 *
 * Like `MultiSendPolicy`, every element is checked before any of them runs, against pre-batch state.
 */
contract Safe7579BatchPolicy is ISafePolicy {
    using AccessSelectorLib for uint256;

    error InvalidBatch();

    function checkTransaction(
        address safe,
        address,
        uint256 value,
        bytes calldata data,
        PolicyOperation operation,
        address,
        bytes calldata,
        uint256
    ) external returns (bytes4) {
        require(
            operation == PolicyOperation.DELEGATECALL && value == 0 && data.length >= 4
                && bytes4(data) == IBatchedExecUtil.execute.selector,
            InvalidBatch()
        );
        Execution7579[] memory executions = abi.decode(data[4:], (Execution7579[]));
        require(executions.length != 0, InvalidBatch());

        for (uint256 i; i < executions.length; i++) {
            ISafePolicyEngine(msg.sender)
                .checkTransaction(
                    safe,
                    executions[i].target,
                    executions[i].value,
                    executions[i].callData,
                    PolicyOperation.CALL,
                    ""
                );
        }
        return ISafePolicy.checkTransaction.selector;
    }

    function configure(address, uint256 access, bytes memory data) external pure returns (bool) {
        return access.selector() == IBatchedExecUtil.execute.selector
            && access.operation() == PolicyOperation.DELEGATECALL && data.length == 0;
    }
}
