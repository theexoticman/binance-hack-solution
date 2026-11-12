// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { OperatorKeyBase, ISafe150, PolicyConfig } from "./OperatorKeyBase.sol";
import { MultiSendCallOnly } from "@safe-global/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";

// Zodiac Roles v2.1.1 (gnosisguild/zodiac-modifier-roles @ 218a516, LGPL-3.0-only) and Zodiac core 3.4.1
import { Roles } from "zodiac-roles/Roles.sol";
import { MultiSendUnwrapper } from "zodiac-roles/adapters/MultiSendUnwrapper.sol";
import { ExecutionOptions } from "zodiac-roles/Types.sol";
import { Enum as ZodiacEnum } from "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import { ModuleProxyFactory } from "@gnosis.pm/zodiac/contracts/factory/ModuleProxyFactory.sol";
import { OperatorKeySetup } from "script/lib/OperatorKeySetup.sol";

/**
 * @notice Architecture A:  Operator EOA -> Zodiac Roles -> Safe -> Safe Policy Engine -> execution
 *
 *   Roles (one minimal proxy per Safe, owner = avatar = target = the Safe) is the Safe's ONLY module.
 *   Role OPERATOR:
 *     USDC.transfer(to, amount)   to ∈ {alice, bob}, amount < 1000e6 + 1, amount within allowance
 *                                 OPERATOR_DAILY (3000e6, refilled to 3000e6 every day)
 *                                 ExecutionOptions.None: no ETH value, no delegatecall
 *   MultiSendCallOnly is registered with Roles' MultiSendUnwrapper, so a batch is authorized element
 *   by element (and then re-checked element by element by the Policy Engine's MultiSendPolicy).
 *
 *   The operator key signs the Roles EIP-712 module-tx digest; a relayer submits it
 *   (zodiac `moduleOnly`: calldata || salt || r,s,v). Direct EOA submission also works (see tests).
 */
abstract contract ZodiacRolesHarness is OperatorKeyBase {
    bytes32 internal constant ROLE = keccak256("OPERATOR");
    bytes32 internal constant ALLOWANCE = keccak256("OPERATOR_DAILY");

    Roles internal rolesMastercopy;
    ModuleProxyFactory internal moduleFactory;
    MultiSendUnwrapper internal unwrapper;
    Roles internal roles;
    uint256 internal saltNonce;

    /// @dev EIP-2470 SingletonFactory. Roles' WriteOnce (SSTORE2) deploys every scope config through it,
    ///      so it is a hard deployment prerequisite. Runtime code taken from the EIP's presigned
    ///      deployment transaction (the same one upstream's test setup broadcasts).
    address internal constant EIP2470_FACTORY = 0xce0042B868300000d44A59004Da54A005ffdcf9f;
    bytes internal constant EIP2470_RUNTIME =
        hex"6080604052348015600f57600080fd5b506004361060285760003560e01c80634af63f0214602d575b600080fd5b60cf60048036036040811015604157600080fd5b810190602081018135640100000000811115605b57600080fd5b820183602082011115606c57600080fd5b80359060200191846001830284011164010000000083111715608d57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250929550509135925060eb915050565b604080516001600160a01b039092168252519081900360200190f35b6000818351602085016000f5939250505056fea26469706673582212206b44f8a82cb6b156bfcc3dc6aadd6df4eefd204bc928a4397fd15dacf6d5320564736f6c63430006020033";

    function _deployArchitecture() internal virtual override {
        if (EIP2470_FACTORY.code.length == 0) vm.etch(EIP2470_FACTORY, EIP2470_RUNTIME);
        // Singletons (one per chain; canonical deployments exist for v2.1.0).
        rolesMastercopy = new Roles(address(0xdead), address(0xdead), address(0xdead));
        moduleFactory = new ModuleProxyFactory();
        unwrapper = new MultiSendUnwrapper();
        // Per Safe: a minimal proxy, initialized for this Safe.
        roles = Roles(
            moduleFactory.deployModule(
                address(rolesMastercopy),
                abi.encodeCall(Roles.setUp, (abi.encode(address(safe), address(safe), address(safe)))),
                0
            )
        );
    }

    function _rolesParams() internal view returns (OperatorKeySetup.RolesParams memory p) {
        address[] memory recipients = new address[](2);
        recipients[0] = alice;
        recipients[1] = bob;
        p = OperatorKeySetup.RolesParams({
            safe: address(safe),
            roles: address(roles),
            multiSend: address(multiSend),
            unwrapper: address(unwrapper),
            token: address(usdc),
            recipients: recipients,
            maxPerTx: MAX_PER_TX,
            maxPerDay: MAX_PER_DAY,
            role: ROLE,
            allowanceKey: ALLOWANCE
        });
    }

    /// @dev ONE owner transaction (before the guards exist) attaches and configures Roles.
    function _attachArchitecture() internal virtual override {
        _ownerExecOrFail(
            address(multiSend),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (OperatorKeySetup.rolesAttach(_rolesParams()))),
            1
        );
    }

    function _registerInitialOperator(address op) internal virtual override {
        Exec memory r = _registerOperatorTx(op);
        _ownerExecOrFail(r.to, r.value, r.data, r.operation);
    }

    function _architecturePolicies() internal view virtual override returns (PolicyConfig[] memory) {
        return OperatorKeySetup.rolesPolicies(address(roles), ownerOnlyPolicy);
    }

    function _operatorModule() internal view virtual override returns (address) {
        return address(roles);
    }

    /// @dev Calldata the operator authorizes: `execTransactionWithRole(..., ROLE, shouldRevert=true)`.
    function _rolesPayload(Exec memory e) internal pure returns (bytes memory) {
        return abi.encodeCall(
            Roles.execTransactionWithRole,
            (e.to, e.value, e.data, ZodiacEnum.Operation(e.operation), ROLE, true)
        );
    }

    /// @dev Operator signs the EIP-712 module-tx digest (KMS-compatible); anyone can relay it.
    function _signedRolesCall(Key memory k, Exec memory e) internal returns (bytes memory) {
        bytes memory payload = _rolesPayload(e);
        bytes32 salt = bytes32(++saltNonce);
        bytes32 digest = roles.moduleTxHash(payload, salt);
        return abi.encodePacked(payload, salt, _signDigest(k, digest));
    }

    function _operatorExec(Key memory k, Exec memory e)
        internal
        virtual
        override
        returns (bool ok, bytes memory reason)
    {
        bytes memory signedCall = _signedRolesCall(k, e);
        vm.prank(relayer);
        (ok, reason) = address(roles).call(signedCall);
    }

    function _operatorBatch(Key memory k, Exec[] memory es)
        internal
        virtual
        override
        returns (bool ok, bytes memory reason)
    {
        return _operatorExec(k, _multiSendExec(es));
    }

    function _batchAsModuleTx(Exec[] memory es) internal view virtual override returns (Exec memory) {
        return _multiSendExec(es); // Roles forwards the MultiSend delegatecall unchanged
    }

    function _registerOperatorTx(address op) internal virtual override returns (Exec memory) {
        return Exec(address(roles), 0, OperatorKeySetup.rolesAssign(op, ROLE, true), 0);
    }

    function _revokeOperatorTx(address op) internal virtual override returns (Exec memory) {
        return Exec(address(roles), 0, OperatorKeySetup.rolesAssign(op, ROLE, false), 0);
    }

    function _openOperatorLayer(Key memory, address target, uint8) internal virtual override returns (bool) {
        // Calls to (MultiSend, multiSend) are always routed through the registered unwrapper, which
        // only accepts DELEGATECALL batches and checks every element - target clearance cannot open it.
        if (target == address(multiSend)) return false;
        // Roles can express "anything on target": Clearance.Target with ExecutionOptions.Both.
        vm.prank(address(safe));
        roles.allowTarget(ROLE, target, ExecutionOptions.Both);
        return true;
    }

    function _archState() internal view virtual override returns (bytes32) {
        (address[] memory mods,) = roles.getModulesPaginated(SENTINEL, 20);
        (uint128 refill, uint128 maxRefill, uint64 period, uint128 balance, uint64 ts) =
            roles.allowances(ALLOWANCE);
        return keccak256(
            abi.encode(
                mods, roles.owner(), roles.avatar(), roles.target(), refill, maxRefill, period, balance, ts
            )
        );
    }
}
