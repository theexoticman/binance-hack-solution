// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice 6-decimal ERC-20 with open minting and holder-initiated burning (test fixture).
///         `burn` gives the authorized contract a destructive function the operator must not reach.
contract TestToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) { }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
}

/// @notice A contract the operator is not authorized to call. Records every call it receives.
contract UnauthorizedTarget {
    uint256 public calls;

    function poke(uint256) external payable {
        calls++;
    }
}

/// @notice Delegatecall payload: run in the Safe's context it would send all ETH to `to`.
contract Drainer {
    function drain(address payable to) external {
        (bool ok,) = to.call{ value: address(this).balance }("");
        require(ok);
    }
}
