// SPDX-License-Identifier: MIT
pragma solidity =0.8.30;

// Compiles the upstream Safe Policy Engine contracts the sentinel Safe uses, with their upstream
// settings (viaIR, 10M runs; see foundry.toml). Sentinel tests deploy them with `vm.deployCode`, so
// test code never imports their implementation. Kept separate from test/utils/PolicyEngineArtifacts.sol
// so the sentinel shares no file with the operator-key comparison.
import { SafePolicyGuard } from "policy-engine/SafePolicyGuard.sol";
import { AllowPolicy } from "policy-engine/policies/AllowPolicy.sol";
import { ERC20TransferPolicy } from "policy-engine/policies/ERC20TransferPolicy.sol";
import { IncreasedThresholdPolicy } from "policy-engine/policies/IncreasedThresholdPolicy.sol";
