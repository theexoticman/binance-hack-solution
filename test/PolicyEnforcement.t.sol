// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Vm } from "forge-std/Vm.sol";
import { SessionTestBase } from "./utils/SessionTestBase.sol";
import { MockERC20 } from "./utils/MockERC20.sol";
import { Forwarder, RevertingReceiver, ReentrantReceiver } from "./utils/Fixtures.sol";
import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import {
    ModeLib,
    ModeCode,
    ModePayload,
    CALLTYPE_SINGLE,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    MODE_DEFAULT
} from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { IAccountExecute } from "account-abstraction/interfaces/IAccountExecute.sol";
import { SessionSetup } from "script/lib/SessionSetup.sol";
import { Session, PermissionId, PolicyData } from "smartsessions/DataTypes.sol";
import { FunctionWhitelistPolicy } from "src/policies/FunctionWhitelistPolicy.sol";
import { SpendingLimitPolicy } from "src/policies/SpendingLimitPolicy.sol";
import { AddressWhitelistPolicy } from "src/policies/AddressWhitelistPolicy.sol";

/**
 * Test C - attempts to bypass policy enforcement with the *legitimate* session key.
 * Every rejection is proven to come from SmartSession validation (exact reason) and from the real
 * EntryPoint path; balances are checked afterwards.
 */
contract PolicyEnforcementTest is SessionTestBase {
    function _assertNoFundsMoved() internal view {
        assertEq(address(safe).balance, SAFE_ETH, "ETH moved");
        assertEq(usdc.balanceOf(address(safe)), SAFE_USDC, "USDC moved");
        assertEq(attacker.balance, 0);
        assertEq(usdc.balanceOf(attacker), 0);
    }

    /*//////////////////////////////////////////////////////////////
                        CONTROL 1: BENEFICIARIES
    //////////////////////////////////////////////////////////////*/

    function test_C_ethToNonWhitelistedRecipient() public {
        _assertRejectedInValidation(
            _sessionOp(_singleCall(attacker, 1 ether, "")), _policyViolation(address(addressPolicy))
        );
        _assertNoFundsMoved();
    }

    /// @dev Target (the token) is whitelisted; the beneficiary inside calldata is not.
    function test_C_erc20ToNonWhitelistedRecipient() public {
        _assertRejectedInValidation(
            _sessionOp(_usdcTransfer(attacker, 1e6)), _policyViolation(address(addressPolicy))
        );
        _assertNoFundsMoved();
    }

    function test_C_nonWhitelistedToken() public {
        MockERC20 other = new MockERC20();
        other.mint(address(safe), 1e6);
        bytes memory call = _singleCall(address(other), 0, abi.encodeCall(other.transfer, (alice, 1e6)));
        _assertRejectedInValidation(_sessionOp(call), _policyViolation(address(functionPolicy)));
        assertEq(other.balanceOf(address(safe)), 1e6);
    }

    /// @dev Even if leadership whitelists an intermediate contract's function by mistake, value can
    ///      only flow through direct transfers to whitelisted beneficiaries.
    function test_C_intermediateContractCannotLaunderBeneficiary() public {
        Forwarder fwd = new Forwarder();
        FunctionWhitelistPolicy.Permission[] memory p = new FunctionWhitelistPolicy.Permission[](2);
        p[0] = FunctionWhitelistPolicy.Permission({ target: address(usdc), selector: usdc.transfer.selector });
        p[1] = FunctionWhitelistPolicy.Permission({
            target: address(fwd), selector: Forwarder.forward.selector
        });
        _reconfigure(address(functionPolicy), abi.encode(true, p));

        bytes memory call =
            _singleCall(address(fwd), 0, abi.encodeCall(Forwarder.forward, (payable(attacker))));
        _assertRejectedInValidation(_sessionOp(call), _policyViolation(address(addressPolicy)));
        _assertNoFundsMoved();
    }

    /*//////////////////////////////////////////////////////////////
                          CONTROL 2: AMOUNTS
    //////////////////////////////////////////////////////////////*/

    function test_C_ethAbovePerTxLimit() public {
        _assertRejectedInValidation(
            _sessionOp(_singleCall(alice, ETH_PER_TX + 1, "")), _policyViolation(address(spendingPolicy))
        );
        _assertNoFundsMoved();
    }

    function test_C_erc20AbovePerTxLimit() public {
        _assertRejectedInValidation(
            _sessionOp(_usdcTransfer(alice, USDC_PER_TX + 1)), _policyViolation(address(spendingPolicy))
        );
        _assertNoFundsMoved();
    }

    function test_C_aggregateLimitAcrossUserOps() public {
        for (uint256 i; i < 5; i++) {
            _submit(_sessionOp(_singleCall(alice, 1 ether, "")));
        }
        _assertRejectedInValidation(
            _sessionOp(_singleCall(bob, 1 wei, "")), _policyViolation(address(spendingPolicy))
        );
        assertEq(alice.balance, 5 ether);
        assertEq(bob.balance, 0);
    }

    /// @dev Six 1-ETH transfers in ONE batch: each element passes per-tx, the sum exceeds 5 ETH/day.
    function test_C_aggregateLimitWithinOneBatch() public {
        Execution[] memory execs = new Execution[](6);
        for (uint256 i; i < 6; i++) {
            execs[i] = Execution({ target: alice, value: 1 ether, callData: "" });
        }
        _assertRejectedInValidation(_sessionOp(_batchCall(execs)), _policyViolation(address(spendingPolicy)));
        _assertNoFundsMoved();
        assertEq(
            spendingPolicy.spentInCurrentWindow(
                actionConfigId, address(smartSession), address(safe), address(0)
            ),
            0
        );
    }

    /// @dev Two ops in one bundle share the same budget (validation runs sequentially).
    function test_C_aggregateLimitWithinOneBundle() public {
        for (uint256 i; i < 4; i++) {
            _submit(_sessionOp(_singleCall(alice, 1 ether, ""))); // 4 ETH spent
        }
        PackedUserOperation memory op1 = _sessionOp(_singleCall(alice, 1 ether, "")); // nonce n   -> 5 ETH, ok
        PackedUserOperation memory op2 = _userOp(_singleCall(bob, 1 ether, ""));
        op2.nonce = op1.nonce + 1; //                         nonce n+1 -> 6 ETH, over budget
        op2 = _signAs(op2, sessionKeyPk, permissionId);

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = op1;
        ops[1] = op2;
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                1,
                "AA23 reverted",
                abi.encodeWithSignature("ExecutionFailed()")
            )
        );
        entryPoint.handleOps(ops, bundler);
        assertEq(alice.balance, 4 ether);
    }

    function test_C_insufficientBalanceIsRejectedNotCounted() public {
        _execLeadership(makeAddr("coldWallet"), SAFE_ETH - 0.5 ether, "", Enum.Operation.Call);
        _assertRejectedInValidation(
            _sessionOp(_singleCall(alice, 1 ether, "")), _policyViolation(address(spendingPolicy))
        );
        assertEq(
            spendingPolicy.spentInCurrentWindow(
                actionConfigId, address(smartSession), address(safe), address(0)
            ),
            0
        );
    }

    /// @dev Documented accounting model: usage is recorded at validation. If the *execution* of an
    ///      authorised transfer reverts, the budget stays consumed (over-count, never under-count).
    function test_C_failedExecutionConsumesBudget_failSafe() public {
        RevertingReceiver bad = new RevertingReceiver();
        address[] memory r = new address[](2);
        r[0] = alice;
        r[1] = address(bad);
        _reconfigure(address(addressPolicy), abi.encode(r));

        vm.recordLogs();
        _submit(_sessionOp(_singleCall(address(bad), 1 ether, "")));
        assertFalse(_lastUserOpSucceeded(), "execution should have reverted");
        assertEq(address(safe).balance, SAFE_ETH, "nothing left the Safe");
        assertEq(
            spendingPolicy.spentInCurrentWindow(
                actionConfigId, address(smartSession), address(safe), address(0)
            ),
            1 ether,
            "budget consumed although execution failed"
        );
    }

    /// @dev A whitelisted recipient re-enters the EntryPoint during execution: rejected by the
    ///      EntryPoint's reentrancy guard, and the budget is only charged for the outer op.
    function test_C_reentrancyFromRecipientIsRejected() public {
        ReentrantReceiver rr = new ReentrantReceiver(entryPoint);
        address[] memory r = new address[](1);
        r[0] = address(rr);
        _reconfigure(address(addressPolicy), abi.encode(r));

        PackedUserOperation memory outer = _sessionOp(_singleCall(address(rr), 1 ether, ""));
        PackedUserOperation memory inner = _userOp(_singleCall(address(rr), 1 ether, ""));
        inner.nonce = outer.nonce + 1;
        rr.arm(_signAs(inner, sessionKeyPk, permissionId));

        _submit(outer);

        assertFalse(rr.reentrySucceeded());
        assertEq(rr.reentryError(), abi.encodeWithSignature("ReentrancyGuardReentrantCall()"));
        assertEq(address(rr).balance, 1 ether);
        assertEq(
            spendingPolicy.spentInCurrentWindow(
                actionConfigId, address(smartSession), address(safe), address(0)
            ),
            1 ether
        );
    }

    /*//////////////////////////////////////////////////////////////
                    GAS FEES: the non-obvious outflow
    //////////////////////////////////////////////////////////////*/

    /// @dev An ERC-4337 account pays its own gas. A compromised key can sign a cheap, in-policy op
    ///      with an absurd fee and preVerificationGas, bundle it itself, and collect the fee as
    ///      beneficiary. Shown here WITHOUT SimpleGasPolicy, to prove the vector is real.
    function test_C_gasFeeExtraction_withoutGasPolicy_bypassesSpendingLimits() public {
        Session memory s = _exchangeSession(sessionKey, bytes32(uint256(99)), _defaultRecipients());
        PolicyData[] memory onlyExpiry = new PolicyData[](1);
        onlyExpiry[0] = s.userOpPolicies[0]; // TimeFramePolicy only - no gas policy
        s.userOpPolicies = onlyExpiry;
        PermissionId noGasCap = _enableSession(s);

        PackedUserOperation memory op = _feeExtractionOp();
        op = _signAs(op, sessionKeyPk, noGasCap);
        entryPoint.handleOps(_ops(op), payable(attacker));

        emit log_named_decimal_uint("ETH extracted as gas fees in ONE op", attacker.balance, 18);
        assertGt(
            attacker.balance, ETH_PER_DAY, "attacker-bundler extracted more than the daily ETH limit in fees"
        );
        assertEq(alice.balance, 1 wei, "the op itself was a harmless, in-policy transfer");
    }

    /// @dev The default session carries SimpleGasPolicy (reused from SmartSessions): the same
    ///      operation is rejected because its worst-case cost exceeds the session's gas budget.
    function test_C_gasFeeExtraction_blockedBySimpleGasPolicy() public {
        PackedUserOperation memory op = _signAs(_feeExtractionOp(), sessionKeyPk, permissionId);
        _assertRejectedInValidation(op, _policyViolation(address(gasPolicy)));
        assertEq(attacker.balance, 0);
        assertEq(address(safe).balance, SAFE_ETH);
    }

    function _feeExtractionOp() internal view returns (PackedUserOperation memory op) {
        op = _userOp(_singleCall(alice, 1 wei, ""));
        op.accountGasLimits = bytes32(abi.encodePacked(uint128(600_000), uint128(200_000)));
        op.preVerificationGas = 4_000_000; // charged in full, whatever is actually used
        uint128 feePerGas = 10_000 gwei; // prefund 4.8M gas * 1e13 = 48 ETH, affordable for the Safe
        op.gasFees = bytes32(abi.encodePacked(feePerGas, feePerGas));
    }

    function test_C_paymasterNotPermitted() public {
        PackedUserOperation memory op = _userOp(_singleCall(alice, 1 ether, ""));
        op.paymasterAndData = abi.encodePacked(address(0xbeef), uint128(100_000), uint128(100_000));
        op = _signAs(op, sessionKeyPk, permissionId);
        _assertRejectedInValidation(
            op, abi.encodeWithSignature("PaymasterValidationNotEnabled(bytes32)", permissionId)
        );
    }

    /*//////////////////////////////////////////////////////////////
                    CONTROL 3: OPERATIONS / CALLDATA
    //////////////////////////////////////////////////////////////*/

    function test_C_erc20Approve() public {
        bytes memory call =
            _singleCall(address(usdc), 0, abi.encodeCall(usdc.approve, (attacker, type(uint256).max)));
        _assertRejectedInValidation(_sessionOp(call), _policyViolation(address(functionPolicy)));
        assertEq(usdc.allowance(address(safe), attacker), 0);
    }

    function test_C_erc20TransferFrom() public {
        bytes memory call =
            _singleCall(address(usdc), 0, abi.encodeCall(usdc.transferFrom, (address(safe), attacker, 1e6)));
        _assertRejectedInValidation(_sessionOp(call), _policyViolation(address(functionPolicy)));
    }

    /// @dev Selector is whitelisted, but the calldata is not a canonical transfer: the beneficiary
    ///      check is fail-closed on anything it cannot decode exactly.
    function test_C_transferWithTrailingCalldata() public {
        bytes memory data = abi.encodePacked(
            abi.encodeCall(usdc.transfer, (alice, 1e6)), bytes32(uint256(uint160(attacker)))
        );
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(usdc), 0, data)), _policyViolation(address(addressPolicy))
        );
    }

    function test_C_transferWithDirtyAddressBits() public {
        bytes memory data =
            abi.encodeWithSelector(usdc.transfer.selector, (uint256(0xdead) << 160) | uint160(alice), 1e6);
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(usdc), 0, data)), _policyViolation(address(addressPolicy))
        );
    }

    function test_C_erc20TransferCarryingEth() public {
        bytes memory call = _singleCall(address(usdc), 1 ether, abi.encodeCall(usdc.transfer, (alice, 1e6)));
        _assertRejectedInValidation(_sessionOp(call), _policyViolation(address(functionPolicy)));
    }

    function test_C_shortCalldataHittingFallback() public {
        _assertRejectedInValidation(
            _sessionOp(_singleCall(alice, 1 ether, hex"aabbcc")), _policyViolation(address(functionPolicy))
        );
    }

    /// @dev Plain ETH "transfers" to the Safe itself or to SmartSession hit their receive/fallback
    ///      logic; FunctionWhitelist bans both targets even though native transfers are allowed.
    function test_C_nativeCallToAccountOrMultiplexer() public {
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(safe), 1 ether, "")), _policyViolation(address(functionPolicy))
        );
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(smartSession), 0, "")),
            abi.encodeWithSignature("NoPoliciesSet(bytes32)", permissionId)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION HARDENING
    //////////////////////////////////////////////////////////////*/

    function test_C_config_functionPolicyRejectsDangerousEntries() public {
        FunctionWhitelistPolicy.Permission[] memory p = new FunctionWhitelistPolicy.Permission[](1);

        p[0] = FunctionWhitelistPolicy.Permission({ target: address(safe), selector: bytes4(0x0d582f13) });
        vm.expectRevert(
            abi.encodeWithSelector(FunctionWhitelistPolicy.ForbiddenTarget.selector, address(safe))
        );
        functionPolicy.initializeWithMultiplexer(address(safe), actionConfigId, abi.encode(true, p));

        p[0] = FunctionWhitelistPolicy.Permission({ target: address(this), selector: bytes4(0x0d582f13) });
        vm.expectRevert(
            abi.encodeWithSelector(FunctionWhitelistPolicy.ForbiddenTarget.selector, address(this))
        );
        functionPolicy.initializeWithMultiplexer(address(safe), actionConfigId, abi.encode(true, p)); // this == multiplexer

        p[0] = FunctionWhitelistPolicy.Permission({ target: address(usdc), selector: usdc.approve.selector });
        vm.expectRevert(
            abi.encodeWithSelector(FunctionWhitelistPolicy.ForbiddenSelector.selector, usdc.approve.selector)
        );
        functionPolicy.initializeWithMultiplexer(address(safe), actionConfigId, abi.encode(true, p));
    }

    function test_C_config_addressPolicyRejectsInvalidRecipients() public {
        address[] memory r = new address[](1);
        r[0] = address(safe);
        vm.expectRevert(
            abi.encodeWithSelector(AddressWhitelistPolicy.InvalidRecipient.selector, address(safe))
        );
        addressPolicy.initializeWithMultiplexer(address(safe), actionConfigId, abi.encode(r));

        vm.expectRevert(AddressWhitelistPolicy.EmptyWhitelist.selector);
        addressPolicy.initializeWithMultiplexer(address(safe), actionConfigId, abi.encode(new address[](0)));
    }

    function test_C_config_spendingPolicyRejectsInvalidLimits() public {
        SpendingLimitPolicy.AssetLimit[] memory l = new SpendingLimitPolicy.AssetLimit[](1);
        l[0] = SpendingLimitPolicy.AssetLimit({
            asset: address(0), maxPerTx: 2 ether, maxPerPeriod: 1 ether, period: 1 days
        });
        vm.expectRevert(abi.encodeWithSelector(SpendingLimitPolicy.InvalidLimit.selector, address(0)));
        spendingPolicy.initializeWithMultiplexer(address(safe), actionConfigId, abi.encode(l));

        l[0].maxPerPeriod = 2 ether;
        l[0].period = 0;
        vm.expectRevert(abi.encodeWithSelector(SpendingLimitPolicy.InvalidLimit.selector, address(0)));
        spendingPolicy.initializeWithMultiplexer(address(safe), actionConfigId, abi.encode(l));
    }

    /// @dev A policy that was never configured for a namespace fails closed.
    function test_C_uninitialisedPolicyFailsClosed() public {
        vm.expectRevert(
            abi.encodeWithSignature(
                "PolicyNotInitialized(bytes32,address,address)", actionConfigId, address(this), address(safe)
            )
        );
        addressPolicy.checkAction(actionConfigId, address(safe), alice, 1 ether, "");
    }

    /*//////////////////////////////////////////////////////////////
                 EXECUTION MODES, NESTING AND BATCHING
    //////////////////////////////////////////////////////////////*/

    function test_C_delegatecallMode() public {
        ModeCode mode =
            ModeLib.encode(CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0));
        bytes memory call = abi.encodeCall(
            IERC7579Account.execute,
            (mode, abi.encodePacked(address(usdc), abi.encodeCall(usdc.transfer, (attacker, 1e6))))
        );
        _assertRejectedInValidation(
            _sessionOp(call), abi.encodeWithSignature("UnsupportedCallType(bytes1)", bytes1(0xff))
        );
        _assertNoFundsMoved();
    }

    function test_C_tryExecMode() public {
        ModeCode mode = ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(0));
        bytes memory call =
            abi.encodeCall(IERC7579Account.execute, (mode, ExecutionLib.encodeSingle(alice, 1 ether, "")));
        _assertRejectedInValidation(_sessionOp(call), abi.encodeWithSignature("UnsupportedExecutionType()"));
    }

    function test_C_executeUserOpSelector() public {
        bytes memory call =
            abi.encodePacked(IAccountExecute.executeUserOp.selector, _singleCall(attacker, 1 ether, ""));
        _assertRejectedInValidation(_sessionOp(call), abi.encodeWithSignature("UnsupportedExecutionType()"));
    }

    /// @dev execute(Safe, execute(token.transfer(attacker))) - nested self-execution.
    function test_C_nestedSelfExecute() public {
        bytes memory inner = _usdcTransfer(attacker, 1e6);
        _assertRejectedInValidation(
            _sessionOp(_singleCall(address(safe), 0, inner)), abi.encodeWithSignature("InvalidSelfCall()")
        );
    }

    function test_C_batchSmugglingOneBadCall() public {
        Execution[] memory execs = new Execution[](3);
        execs[0] = Execution({ target: alice, value: 1 ether, callData: "" });
        execs[1] = Execution({
            target: address(usdc), value: 0, callData: abi.encodeCall(usdc.transfer, (attacker, 1e6))
        });
        execs[2] = Execution({ target: bob, value: 1 ether, callData: "" });
        _assertRejectedInValidation(_sessionOp(_batchCall(execs)), _policyViolation(address(addressPolicy)));
        _assertNoFundsMoved();
    }

    function test_C_batchContainingNestedExecute() public {
        Execution[] memory execs = new Execution[](2);
        execs[0] = Execution({ target: alice, value: 1 ether, callData: "" });
        execs[1] =
            Execution({ target: address(safe), value: 0, callData: _singleCall(attacker, 1 ether, "") });
        _assertRejectedInValidation(
            _sessionOp(_batchCall(execs)), abi.encodeWithSignature("InvalidSelfCall()")
        );
    }

    function test_C_emptyBatch() public {
        _assertRejectedInValidation(
            _sessionOp(_batchCall(new Execution[](0))), abi.encodeWithSignature("NoExecutionsInBatch()")
        );
    }

    /*//////////////////////////////////////////////////////////////
               REPLAY, EXPIRY, REVOCATION, DOMAIN SEPARATION
    //////////////////////////////////////////////////////////////*/

    function test_C_replayConsumedOperation() public {
        PackedUserOperation memory op = _sessionOp(_singleCall(alice, 1 ether, ""));
        _submit(op);
        _assertRejectedByEntryPoint(op, "AA25 invalid account nonce");
        assertEq(alice.balance, 1 ether);
    }

    function test_C_expiredSession() public {
        vm.warp(block.timestamp + SESSION_DURATION + 1);
        _assertRejectedByEntryPoint(_sessionOp(_singleCall(alice, 1 ether, "")), "AA22 expired or not due");
        assertEq(alice.balance, 0);
    }

    function test_C_revokedSession() public {
        PackedUserOperation memory signedBeforeRevocation = _sessionOp(_singleCall(alice, 1 ether, ""));
        _execLeadership(
            address(smartSession),
            abi.encodeWithSignature("removeSession(bytes32)", permissionId),
            Enum.Operation.Call
        );
        _assertRejectedInValidation(
            signedBeforeRevocation, abi.encodeWithSignature("InvalidPermissionId(bytes32)", permissionId)
        );
    }

    function test_C_wrongSigner() public {
        (, uint256 randomPk) = makeAddrAndKey("random");
        _assertRejectedByEntryPoint(
            _signAs(_userOp(_singleCall(alice, 1 ether, "")), randomPk, permissionId), "AA24 signature error"
        );
    }

    /// @dev The userOp hash commits to chainId: a signature from another chain is invalid here.
    function test_C_crossChainReplay() public {
        PackedUserOperation memory op = _userOp(_singleCall(alice, 1 ether, ""));
        uint256 home = block.chainid;
        vm.chainId(56);
        op = _signAs(op, sessionKeyPk, permissionId);
        vm.chainId(home);
        _assertRejectedByEntryPoint(op, "AA24 signature error");
    }

    /// @dev The same session key holds no permission on a different Safe.
    function test_C_crossAccountReplay() public {
        Safe other = _deploySafe2();
        PackedUserOperation memory op = _userOp(_singleCall(alice, 1 ether, ""));
        op.sender = address(other);
        op.nonce = entryPoint.getNonce(address(other), uint192(bytes24(bytes20(address(smartSession)))));
        op = _signAs(op, sessionKeyPk, permissionId);

        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        vm.prank(address(other));
        vm.expectRevert(abi.encodeWithSignature("InvalidPermissionId(bytes32)", permissionId));
        smartSession.validateUserOp(op, userOpHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("ExecutionFailed()")
            )
        );
        entryPoint.handleOps(_ops(op), bundler);
        assertEq(address(other).balance, 10 ether);
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _deploySafe2() internal returns (Safe other) {
        Safe main = safe;
        bytes memory setup = abi.encodeCall(
            Safe.setup, (owners, THRESHOLD, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        other = Safe(payable(address(safeFactory.createProxyWithNonce(address(safeSingleton), setup, 1))));
        vm.deal(address(other), 10 ether);
        safe = other;
        _execLeadership(
            address(multiSend),
            abi.encodeWithSignature(
                "multiSend(bytes)",
                SessionSetup.attachSafe7579(address(other), address(safe7579), address(smartSession))
            ),
            Enum.Operation.DelegateCall
        );
        safe = main;
    }

    function _lastUserOpSucceeded() internal returns (bool success) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] == IEntryPoint.UserOperationEvent.selector) {
                (, success,,) = abi.decode(logs[i - 1].data, (uint256, bool, uint256, uint256));
                return success;
            }
        }
        revert("no UserOperationEvent");
    }
}
