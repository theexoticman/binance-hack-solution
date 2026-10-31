// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

interface ISafeLike {
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool);
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool);
    function addOwnerWithThreshold(address owner, uint256 threshold) external;
    function enableModule(address module) external;
    function setGuard(address guard) external;
}

interface IERC7579Like {
    function execute(bytes32 mode, bytes calldata executionCalldata) external;
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        returns (bytes[] memory);
    function installModule(uint256 moduleType, address module, bytes calldata initData) external;
}

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IPolicyLike {
    function initializeWithMultiplexer(address account, bytes32 configId, bytes calldata initData) external;
}

/**
 * @title MaliciousDelegation
 * @notice DELIBERATELY MALICIOUS. Test/demo fixture only - never deploy to a real network.
 *
 * An attacker who has stolen the session key signs an EIP-7702 authorization that sets the
 * session EOA's code to this contract. Every function below runs *as the session EOA*
 * (address(this) == session key address) and tries a different way of taking the Safe's funds or
 * authority. `drainAll` tries everything at once and reports each outcome as an event.
 *
 * Note what this contract can NOT do: change the Safe's code, the Safe's owners, or any other
 * account's delegation. EIP-7702 only lets a key holder change the code of *their own* EOA.
 */
contract MaliciousDelegation {
    /// @dev ERC-7579 mode: single call, default exec type.
    bytes32 internal constant MODE_SINGLE = bytes32(0);
    bytes4 internal constant ERC1271_MAGIC = 0x1626ba7e;

    event AttackAttempt(string route, bool success, bytes returnData);

    /*//////////////////////////////////////////////////////////////
                    SIGNATURE FORGERY (ERC-1271 HIJACK)
    //////////////////////////////////////////////////////////////*/

    /// @notice Claims every hash is signed by this EOA. Any validator that consults ERC-1271 for a
    ///         signer with code (e.g. Safe-style `v == 0` contract signatures) will now accept
    ///         *anyone's* signature on behalf of the session key.
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return ERC1271_MAGIC;
    }

    /*//////////////////////////////////////////////////////////////
                      DIRECT ATTACKS ON THE SAFE
    //////////////////////////////////////////////////////////////*/

    /// @notice Pretend to be an enabled Safe module.
    function drainViaModule(address safe, address to, uint256 value, bytes calldata data) external {
        ISafeLike(safe).execTransactionFromModule(to, value, data, 0);
    }

    /// @notice Pretend to be enough owners using "approved by msg.sender" (v = 1) signatures.
    function drainViaExecTransaction(address safe, address to, uint256 value, bytes calldata data) external {
        bytes memory oneSig = abi.encodePacked(bytes32(uint256(uint160(address(this)))), bytes32(0), uint8(1));
        bytes memory sigs = abi.encodePacked(oneSig, oneSig, oneSig, oneSig, oneSig);
        ISafeLike(safe).execTransaction(to, value, data, 0, 0, 0, 0, address(0), payable(address(0)), sigs);
    }

    /// @notice Call the Safe7579 `execute` entrypoint through the Safe's fallback handler.
    function drainVia7579Execute(address safe, address to, uint256 value, bytes calldata data) external {
        IERC7579Like(safe).execute(MODE_SINGLE, abi.encodePacked(to, value, data));
    }

    /// @notice Pretend to be an installed ERC-7579 executor module.
    function drainVia7579Executor(address safe, address to, uint256 value, bytes calldata data) external {
        IERC7579Like(safe).executeFromExecutor(MODE_SINGLE, abi.encodePacked(to, value, data));
    }

    /// @notice Pull ERC-20s with `transferFrom` (would need an allowance the Safe never gave).
    function drainViaTransferFrom(address token, address safe, address to) external {
        IERC20Like(token).transferFrom(safe, to, IERC20Like(token).balanceOf(safe));
    }

    /// @notice Make the attacker a Safe owner with threshold 1.
    function escalateAddOwner(address safe, address newOwner) external {
        ISafeLike(safe).addOwnerWithThreshold(newOwner, 1);
    }

    /// @notice Enable this EOA as an unrestricted Safe module.
    function escalateEnableModule(address safe) external {
        ISafeLike(safe).enableModule(address(this));
    }

    /// @notice Install this EOA as an ERC-7579 executor via the adapter.
    function escalateInstallExecutor(address safe) external {
        IERC7579Like(safe).installModule(2, address(this), "");
    }

    /// @notice Overwrite a policy's configuration by calling it directly, claiming to configure
    ///         the Safe. Policies namespace state by msg.sender, so this only writes to the
    ///         attacker's own namespace.
    function overwritePolicy(address policy, address account, bytes32 configId, bytes calldata initData)
        external
    {
        IPolicyLike(policy).initializeWithMultiplexer(account, configId, initData);
    }

    /// @notice Act as the ERC-4337 bundler (msg.sender == tx.origin == session EOA with code).
    function bundle(IEntryPoint entryPoint, PackedUserOperation[] calldata ops) external {
        entryPoint.handleOps(ops, payable(address(this)));
    }

    /*//////////////////////////////////////////////////////////////
                              ALL AT ONCE
    //////////////////////////////////////////////////////////////*/

    /// @notice Tries every direct route; returns how many succeeded. Expected: 0.
    function drainAll(address safe, address token, address attacker) external returns (uint256 successes) {
        uint256 ethBal = safe.balance;
        bytes memory tokenTransfer =
            abi.encodeWithSignature("transfer(address,uint256)", attacker, IERC20Like(token).balanceOf(safe));

        successes += _try(
            "safe.execTransactionFromModule(ETH)",
            abi.encodeCall(this.drainViaModule, (safe, attacker, ethBal, ""))
        );
        successes += _try(
            "safe.execTransactionFromModule(ERC20)",
            abi.encodeCall(this.drainViaModule, (safe, token, 0, tokenTransfer))
        );
        successes += _try(
            "safe.execTransaction(v=1 sigs)",
            abi.encodeCall(this.drainViaExecTransaction, (safe, attacker, ethBal, ""))
        );
        successes += _try(
            "safe7579.execute", abi.encodeCall(this.drainVia7579Execute, (safe, attacker, ethBal, ""))
        );
        successes += _try(
            "safe7579.executeFromExecutor",
            abi.encodeCall(this.drainVia7579Executor, (safe, attacker, ethBal, ""))
        );
        successes += _try(
            "token.transferFrom", abi.encodeCall(this.drainViaTransferFrom, (token, safe, attacker))
        );
        successes += _try(
            "safe.addOwnerWithThreshold", abi.encodeCall(this.escalateAddOwner, (safe, attacker))
        );
        successes += _try("safe.enableModule", abi.encodeCall(this.escalateEnableModule, (safe)));
        successes += _try(
            "safe7579.installModule(executor)", abi.encodeCall(this.escalateInstallExecutor, (safe))
        );
    }

    function _try(string memory route, bytes memory call) internal returns (uint256) {
        (bool ok, bytes memory ret) = address(this).call(call);
        emit AttackAttempt(route, ok, ret);
        return ok ? 1 : 0;
    }

    receive() external payable { }
}
