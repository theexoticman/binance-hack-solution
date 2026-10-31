// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ISafe7579 } from "safe7579/ISafe7579.sol";
import { ModuleInit, RegistryInit } from "safe7579/DataTypes.sol";
import { IERC7484 } from "safe7579/interfaces/IERC7484.sol";
import {
    Session,
    PolicyData,
    ActionData,
    ERC7739Context,
    FALLBACK_TARGET_FLAG,
    FALLBACK_TARGET_SELECTOR_FLAG
} from "smartsessions/DataTypes.sol";
import { ISessionValidator } from "smartsessions/interfaces/ISessionValidator.sol";

import { FunctionWhitelistPolicy } from "../../src/policies/FunctionWhitelistPolicy.sol";
import { SpendingLimitPolicy } from "../../src/policies/SpendingLimitPolicy.sol";

/**
 * @notice Calldata builders shared by the deploy script and the tests. Nothing here is deployed;
 *         it only shows, in one place, exactly what leadership signs.
 */
library SessionSetup {
    struct Policies {
        address timeFrame; // SmartSessions TimeFramePolicy (reused, userOp policy)
        address gas; // SmartSessions SimpleGasPolicy (reused, userOp policy)
        address gasFeeCap; // GasFeeCapPolicy (this repo, userOp policy)
        address functionWhitelist;
        address addressWhitelist;
        address spendingLimit;
    }

    struct SessionParams {
        ISessionValidator validator; // OwnableValidator (reused)
        address signer; // session key
        bytes32 salt;
        uint48 validUntil;
        uint128 gasUnitsLimit; // lifetime cap on gas units the session may consume
        uint128 gasCostLimit; // lifetime cap (wei) on worst-case gas cost paid by the Safe
        uint128 maxFeePerGas; // per-op fee cap; also forces maxFeePerGas == maxPriorityFeePerGas
        bool allowNativeTransfers;
        FunctionWhitelistPolicy.Permission[] permissions;
        address[] recipients;
        SpendingLimitPolicy.AssetLimit[] limits;
    }

    /**
     * @notice Payload for ONE leadership transaction (DELEGATECALL into MultiSendCallOnly) that
     *         turns a plain Safe into a Safe7579 account whose only ERC-7579 validator is
     *         SmartSession. No executors, no hooks, no 7579 fallback handlers.
     */
    function attachSafe7579(address safe, address safe7579, address smartSession)
        internal
        pure
        returns (bytes memory multiSendTransactions)
    {
        ModuleInit[] memory validators = new ModuleInit[](1);
        validators[0] = ModuleInit({ module: smartSession, initData: "" });
        ModuleInit[] memory none = new ModuleInit[](0);

        bytes memory enableModule = abi.encodeWithSignature("enableModule(address)", safe7579);
        bytes memory setFallback = abi.encodeWithSignature("setFallbackHandler(address)", safe7579);
        // Reaches Safe7579 through the fallback handler set in the previous call; the adapter sees
        // the Safe calling itself, which satisfies `onlyEntryPointOrSelf`.
        bytes memory init = abi.encodeCall(
            ISafe7579.initializeAccount,
            (
                validators,
                none,
                none,
                none,
                RegistryInit({ registry: IERC7484(address(0)), attesters: new address[](0), threshold: 0 })
            )
        );

        multiSendTransactions = abi.encodePacked(
            _multiSendTx(safe, enableModule), _multiSendTx(safe, setFallback), _multiSendTx(safe, init)
        );
    }

    /**
     * @notice A SmartSessions `Session` that routes EVERY execution through the catch-all
     *         (fallback) action, where all three custom policies must pass. Using one action keeps
     *         one ConfigId per session, so SpendingLimitPolicy tracks a true per-session aggregate.
     */
    function exchangeSession(SessionParams memory p, Policies memory pol)
        internal
        pure
        returns (Session memory s)
    {
        address[] memory signers = new address[](1);
        signers[0] = p.signer;

        PolicyData[] memory userOpPolicies = new PolicyData[](3);
        // TimeFramePolicy initData: bytes12 = uint48 validUntil || uint48 validAfter
        userOpPolicies[0] =
            PolicyData({ policy: pol.timeFrame, initData: abi.encodePacked(p.validUntil, uint48(0)) });
        // SimpleGasPolicy initData: uint128 gasLimit || uint128 costLimit. Without it, a compromised
        // key could make the Safe pay arbitrary gas fees to an attacker-run bundler.
        userOpPolicies[1] =
            PolicyData({ policy: pol.gas, initData: abi.encodePacked(p.gasUnitsLimit, p.gasCostLimit) });
        // GasFeeCapPolicy initData: uint128 maxFeePerGas. Required for SimpleGasPolicy's wei budget to
        // bound what the EntryPoint actually takes from the Safe (see GasFeeCapPolicy).
        userOpPolicies[2] = PolicyData({ policy: pol.gasFeeCap, initData: abi.encodePacked(p.maxFeePerGas) });

        PolicyData[] memory actionPolicies = new PolicyData[](3);
        actionPolicies[0] = PolicyData({
            policy: pol.functionWhitelist, initData: abi.encode(p.allowNativeTransfers, p.permissions)
        });
        actionPolicies[1] = PolicyData({ policy: pol.addressWhitelist, initData: abi.encode(p.recipients) });
        actionPolicies[2] = PolicyData({ policy: pol.spendingLimit, initData: abi.encode(p.limits) });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG,
            actionTarget: FALLBACK_TARGET_FLAG,
            actionPolicies: actionPolicies
        });

        s.sessionValidator = p.validator;
        s.sessionValidatorInitData = abi.encode(uint256(1), signers); // OwnableValidator: 1-of-[signer]
        s.salt = p.salt;
        s.userOpPolicies = userOpPolicies;
        // No ERC-1271 / ERC-7739 permissions: the session can never sign messages for the Safe.
        s.erc7739Policies.allowedERC7739Content = new ERC7739Context[](0);
        s.erc7739Policies.erc1271Policies = new PolicyData[](0);
        s.actions = actions;
        s.permitERC4337Paymaster = false;
    }

    function _multiSendTx(address to, bytes memory data) private pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, uint256(0), data.length, data);
    }
}
