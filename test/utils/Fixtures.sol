// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @notice An "intermediate contract": forwards whatever it receives to an arbitrary address.
contract Forwarder {
    function forward(address payable to) external payable {
        (bool ok,) = to.call{ value: address(this).balance }("");
        require(ok);
    }
}

/// @notice A whitelisted destination whose execution always fails.
contract RevertingReceiver {
    receive() external payable {
        revert("RevertingReceiver");
    }
}

/// @notice A whitelisted destination that re-enters the EntryPoint with a pre-signed operation.
contract ReentrantReceiver {
    IEntryPoint internal immutable entryPoint;
    PackedUserOperation[] internal pending;
    bytes public reentryError;
    bool public reentrySucceeded;

    constructor(IEntryPoint ep) {
        entryPoint = ep;
    }

    function arm(PackedUserOperation calldata op) external {
        pending.push(op);
    }

    receive() external payable {
        if (pending.length == 0) return;
        PackedUserOperation[] memory ops = pending;
        delete pending;
        try entryPoint.handleOps(ops, payable(address(this))) {
            reentrySucceeded = true;
        } catch (bytes memory err) {
            reentryError = err;
        }
    }
}
