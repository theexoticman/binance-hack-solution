// SPDX-License-Identifier: MIT
pragma solidity =0.8.30;

// Compiles the upstream Safe Policy Engine contracts with their upstream settings (viaIR, 10M runs;
// see foundry.toml). Tests deploy them with `vm.deployCode` so that test code, which is compiled
// without viaIR, never has to import their implementation.
import { SafePolicyGuard } from "policy-engine/SafePolicyGuard.sol";
import { AllowedModulePolicy } from "policy-engine/policies/AllowedModulePolicy.sol";
import { ERC20TransferPolicy } from "policy-engine/policies/ERC20TransferPolicy.sol";
import { MultiSendPolicy } from "policy-engine/policies/MultiSendPolicy.sol";
import { NativeTransferPolicy } from "policy-engine/policies/NativeTransferPolicy.sol";
import { IncreasedThresholdPolicy } from "policy-engine/policies/IncreasedThresholdPolicy.sol";
