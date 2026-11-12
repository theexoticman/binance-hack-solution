// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.30;

// Compiles Safenet's SentinelOracle (lib/safenet @ c355af1, GPL-3.0-only) with its upstream settings
// (viaIR, 1M runs; see foundry.toml). Tests deploy it with `vm.deployCode` and talk to it through a
// local interface, so no MIT test file imports its implementation.
import { SentinelOracle } from "lib/safenet/contracts/src/SentinelOracle.sol";
