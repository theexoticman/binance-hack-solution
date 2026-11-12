// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ISafePolicy, PolicyOperation, AccessSelectorLib } from "../../interfaces/ISafePolicy.sol";

/**
 * @title OwnerOnlyPolicy
 * @notice Safe Policy Engine policy: allows the access selector only on the owner-transaction path
 *         (`Safe.execTransaction`, checked against the Safe's normal threshold), never from a module.
 *
 * Used for the administrative calls of an operator framework - Roles `assignRoles`, SmartSessions
 * `enableSessions`/`removeSession`, `Safe.disableModule` - so that a module (Zodiac Roles, Safe7579),
 * whatever it has been configured to allow, can never reach them. Upstream has no equivalent:
 * `AllowPolicy` also admits module transactions, and `CoSignerPolicy`/`IncreasedThresholdPolicy`
 * add requirements on top of the owner path.
 *
 * `module` is the only trustworthy authorization indicator the engine provides (it is held in
 * engine state, not taken from the caller), so it is the only input read here. Stateless.
 */
contract OwnerOnlyPolicy is ISafePolicy {
    using AccessSelectorLib for uint256;

    error ModuleTransactionDenied(address module);

    function checkTransaction(
        address,
        address,
        uint256,
        bytes calldata,
        PolicyOperation,
        address module,
        bytes calldata,
        uint256
    ) external pure returns (bytes4) {
        require(module == address(0), ModuleTransactionDenied(module));
        return ISafePolicy.checkTransaction.selector;
    }

    /// @dev Only for CALL access selectors; there is nothing to configure.
    function configure(address, uint256 access, bytes memory data) external pure returns (bool) {
        return access.operation() == PolicyOperation.CALL && data.length == 0;
    }
}
