// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title TransferLib
 * @notice Strict, allocation-free decoder that classifies a single ERC-7579 execution
 *         `(target, value, data)` as one of the asset movements this template understands.
 *
 * Anything that is not *exactly* one of the shapes below is classified as `UNSUPPORTED`, and
 * every policy in this repository treats `UNSUPPORTED` as a hard failure (fail-closed).
 *
 *   NATIVE_TRANSFER  data.length == 0                       asset = address(0)  beneficiary = target
 *   ERC20_TRANSFER   data == transfer(address,uint256)      asset = target      beneficiary = to
 *                    with exactly 68 bytes, clean address
 *                    padding and value == 0
 *
 * The distinction between `target` (the contract being called) and `beneficiary` (the address
 * that ends up controlling the asset) is the whole point of this library: an ERC-20 transfer is
 * a call to the *token*, but the value goes to the address encoded in calldata.
 */
library TransferLib {
    enum Kind {
        UNSUPPORTED,
        NATIVE_TRANSFER,
        ERC20_TRANSFER
    }

    struct Transfer {
        Kind kind;
        address asset; // address(0) for the native token
        address beneficiary;
        uint256 amount;
    }

    /// @dev `IERC20.transfer(address,uint256)`
    bytes4 internal constant ERC20_TRANSFER_SELECTOR = 0xa9059cbb;

    address internal constant NATIVE_ASSET = address(0);

    function decode(address target, uint256 value, bytes calldata data)
        internal
        pure
        returns (Transfer memory t)
    {
        if (data.length == 0) {
            return
                Transfer({
                    kind: Kind.NATIVE_TRANSFER, asset: NATIVE_ASSET, beneficiary: target, amount: value
                });
        }

        // Exactly selector + 2 words. Rejects trailing bytes, short calldata and any other selector.
        if (data.length != 68 || bytes4(data[0:4]) != ERC20_TRANSFER_SELECTOR) return t;
        // ERC-20 transfers must not carry native value: it would be an untracked second asset flow.
        if (value != 0) return t;

        uint256 rawTo = uint256(bytes32(data[4:36]));
        // Dirty upper bits would be silently truncated by some tokens and not by others.
        if (rawTo >> 160 != 0) return t;

        // forge-lint: disable-next-item(unsafe-typecast) upper 96 bits verified zero above
        t = Transfer({
            kind: Kind.ERC20_TRANSFER,
            asset: target,
            beneficiary: address(uint160(rawTo)),
            amount: uint256(bytes32(data[36:68]))
        });
    }
}
