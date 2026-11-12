// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @notice MIT declarations, ABI-identical to the Safe Policy Engine interfaces
 *         (safe-research/policy-engine `IPolicy`, `IPolicyEngine`, `Operation`, `AccessSelector`),
 *         so that the sentinel policies compile no LGPL source. The sentinel keeps its own copy so it
 *         shares no source with the rest of the repository. Selectors are identical because
 *         `AccessSelector.T` is a user-defined value type over `uint256` and `Operation` is a
 *         two-member enum, both encoded as their underlying types.
 */
enum PolicyOperation {
    CALL,
    DELEGATECALL
}

interface ISafePolicy {
    /// @return magicValue `ISafePolicy.checkTransaction.selector` to allow; anything else (or a revert) denies.
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        PolicyOperation operation,
        address module,
        bytes calldata context,
        uint256 access
    ) external returns (bytes4 magicValue);

    function configure(address safe, uint256 access, bytes memory data) external returns (bool success);
}

interface ISafePolicyEngine {
    /// @dev Only callable while the engine is checking `safe`; used by policies that recurse.
    function checkTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        PolicyOperation operation,
        bytes memory context
    ) external returns (address);
}

/// @dev Mirror of the upstream AccessSelector layout: `ssss o ... tttt` (selector, operation, target).
library AccessSelectorLib {
    function selector(uint256 access) internal pure returns (bytes4) {
        return bytes4(bytes32(access));
    }

    function target(uint256 access) internal pure returns (address) {
        return address(uint160(access));
    }

    function operation(uint256 access) internal pure returns (PolicyOperation) {
        return PolicyOperation((access >> 216) & 1);
    }
}
