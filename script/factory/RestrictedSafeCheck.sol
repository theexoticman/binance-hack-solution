// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { RestrictedSafePlan } from "./RestrictedSafePlan.sol";
import { RestrictedSafeSetup } from "../../src/factory/RestrictedSafeSetup.sol";

interface ISafeView {
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);
}

interface IRolesView {
    function owner() external view returns (address);
    function avatar() external view returns (address);
    function target() external view returns (address);
}

interface IPolicyGuardView {
    function getPolicy(address safe, address to, bytes calldata data, uint8 operation)
        external
        view
        returns (uint256 access, address policy);
}

/**
 * @notice Reads a deployed restricted Safe back from the chain and fails unless it is exactly what the
 *         plan describes: owners, threshold, Roles as the only module, owned by the Safe, the engine as
 *         both guards, every admin and mandate entry, and nothing on the most sensitive Safe functions.
 */
library RestrictedSafeCheck {
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant MODULE_GUARD_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    bytes32 internal constant FALLBACK_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    function check(
        RestrictedSafePlan.Config memory c,
        RestrictedSafePlan.Infra memory infra,
        RestrictedSafePlan.Deployment memory d
    ) internal view {
        require(d.safe.code.length > 0, "Safe not deployed");
        ISafeView safe = ISafeView(d.safe);

        address[] memory owners = safe.getOwners();
        require(owners.length == c.owners.length, "owner count");
        for (uint256 i; i < c.owners.length; i++) {
            bool found;
            for (uint256 j; j < owners.length; j++) {
                if (owners[j] == c.owners[i]) found = true;
            }
            require(found, "owner missing");
        }
        require(safe.getThreshold() == c.threshold, "threshold");

        (address[] memory modules,) = safe.getModulesPaginated(address(0x1), 10);
        require(modules.length == 1 && modules[0] == d.roles, "Roles must be the only module");
        require(_slot(safe, GUARD_SLOT) == infra.guard, "transaction guard");
        require(_slot(safe, MODULE_GUARD_SLOT) == infra.guard, "module guard");
        require(_slot(safe, FALLBACK_SLOT) == infra.fallbackHandler, "fallback handler");

        IRolesView roles = IRolesView(d.roles);
        require(
            roles.owner() == d.safe && roles.avatar() == d.safe && roles.target() == d.safe,
            "Roles must be owned by the Safe and act on it"
        );

        IPolicyGuardView guard = IPolicyGuardView(infra.guard);
        RestrictedSafeSetup.EngineEntry[] memory admin =
            RestrictedSafeSetup(infra.setup).adminEntries(d.safe, d.roles, d.setup);
        _expectEntries(guard, d.safe, admin);
        _expectEntries(guard, d.safe, d.setup.entries);

        // Default-deny on what matters most: no entry, and no fallback entry, for these.
        bytes4[7] memory denied = [
            bytes4(keccak256("addOwnerWithThreshold(address,uint256)")),
            bytes4(keccak256("removeOwner(address,address,uint256)")),
            bytes4(keccak256("changeThreshold(uint256)")),
            bytes4(keccak256("enableModule(address)")),
            bytes4(keccak256("setGuard(address)")),
            bytes4(keccak256("setModuleGuard(address)")),
            bytes4(keccak256("setFallbackHandler(address)"))
        ];
        for (uint256 i; i < denied.length; i++) {
            (, address p) = guard.getPolicy(d.safe, d.safe, abi.encodePacked(denied[i]), 0);
            require(p == address(0), "a Safe admin function has a Policy Engine entry");
        }
        for (uint8 op; op < 2; op++) {
            (, address p) = guard.getPolicy(d.safe, address(0xdead), abi.encodePacked(bytes4(0xdeadbeef)), op);
            require(p == address(0), "the Policy Engine has a fallback entry");
        }
    }

    function _expectEntries(IPolicyGuardView guard, address safe, RestrictedSafeSetup.EngineEntry[] memory e)
        private
        view
    {
        for (uint256 i; i < e.length; i++) {
            (, address p) =
                guard.getPolicy(safe, e[i].target, abi.encodePacked(e[i].selector), e[i].operation);
            require(p == e[i].policy, "Policy Engine entry missing or different");
        }
    }

    function _slot(ISafeView safe, bytes32 slot) private view returns (address) {
        return address(uint160(uint256(bytes32(safe.getStorageAt(uint256(slot), 1)))));
    }
}
