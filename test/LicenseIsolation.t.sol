// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { IPolicy, IActionPolicy, IUserOpPolicy } from "src/interfaces/ISessionPolicy.sol";
import {
    IPolicy as UpstreamIPolicy,
    IActionPolicy as UpstreamIActionPolicy,
    IUserOpPolicy as UpstreamIUserOpPolicy
} from "smartsessions/interfaces/IPolicy.sol";

/**
 * src/ does not import SmartSessions or ERC-4337 sources (they are AGPL/LGPL/GPL); it declares the
 * policy ABI itself. This test (which may import them - tests are not deployed) proves the MIT
 * declarations are ABI-identical: SmartSession checks these ERC-165 ids when a policy is enabled
 * (ConfigLib.requirePolicyType) and decodes these errors and events.
 * script/check-licenses.sh verifies that no copyleft source is compiled into the src/ contracts.
 */
contract LicenseIsolationTest is Test {
    function test_L_interfaceIdsMatchUpstream() public pure {
        assertEq(type(IPolicy).interfaceId, type(UpstreamIPolicy).interfaceId);
        assertEq(type(IActionPolicy).interfaceId, type(UpstreamIActionPolicy).interfaceId);
        assertEq(type(IUserOpPolicy).interfaceId, type(UpstreamIUserOpPolicy).interfaceId);
    }

    function test_L_errorAndEventSignaturesMatchUpstream() public pure {
        assertEq(IPolicy.PolicyNotInitialized.selector, UpstreamIPolicy.PolicyNotInitialized.selector);
        assertEq(IPolicy.PolicySet.selector, UpstreamIPolicy.PolicySet.selector);
    }
}
