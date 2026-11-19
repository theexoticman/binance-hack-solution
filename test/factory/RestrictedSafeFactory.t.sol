// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import { RestrictedSafeSetup } from "src/factory/RestrictedSafeSetup.sol";
import { RestrictedSafePlan } from "script/factory/RestrictedSafePlan.sol";
import { RestrictedSafeInfra } from "script/factory/RestrictedSafeInfra.sol";
import { RestrictedSafeJson } from "script/factory/RestrictedSafeJson.sol";
import { RestrictedSafeCheck } from "script/factory/RestrictedSafeCheck.sol";
import { DeployRestrictedSafe } from "script/factory/DeployRestrictedSafe.s.sol";

contract FactoryToken is ERC20 {
    constructor() ERC20("USD Coin", "USDC") { }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract Pinger {
    uint256 public last;

    function ping(uint256 v) external payable {
        last = v;
    }

    function pong() external { }

    function other() external { }
}

interface ISafe {
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce
    ) external view returns (bytes32);
    function nonce() external view returns (uint256);
    function getThreshold() external view returns (uint256);
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool);
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
}

interface ISafeFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address);
}

interface IModuleFactory {
    function deployModule(address masterCopy, bytes memory initializer, uint256 saltNonce)
        external
        returns (address);
}

interface IRoles {
    function execTransactionWithRole(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes32 roleKey,
        bool shouldRevert
    ) external returns (bool);
    function assignRoles(address module, bytes32[] calldata roleKeys, bool[] calldata memberOf) external;
    function allowTarget(bytes32 roleKey, address targetAddress, uint8 options) external;
}

interface IGuard {
    function requestConfiguration(bytes32 root) external;
    function applyConfiguration(RestrictedSafeSetup.EngineEntry[] calldata configurations) external;
}

/**
 * @notice The restricted-Safe factory end to end: config file -> one transaction -> a Safe whose keys can
 *         do exactly their mandate, whose Roles module cannot exceed the Policy Engine floor, and whose
 *         owners keep administration.
 *
 * The config built in `_config()` is the same as test/factory/fixtures/local.json, so the JSON path and
 * the struct path are checked to produce the identical Safe.
 */
contract RestrictedSafeFactoryTest is Test {
    string internal constant FIXTURE = "test/factory/fixtures/local.json";

    // Fixture addresses (see local.json)
    address internal constant USDC = 0x1000000000000000000000000000000000000001;
    address internal constant PINGER = 0x1000000000000000000000000000000000000002;
    address internal constant ALICE = 0x00000000000000000000000000000000000A11cE;
    address internal constant BOB = 0x0000000000000000000000000000000000000B0b;
    address internal constant CAROL = 0x00000000000000000000000000000000000cA201;
    address internal constant VAULT = 0x000000000000000000000000000000000000fA17;
    address internal constant TREASURY = 0x0000000000000000000000000000000000007EA5;

    bytes32 internal constant PAYOUTS = bytes32("PAYOUTS");
    bytes32 internal constant TREASURY_ROLE = bytes32("TREASURY");

    uint256[] internal ownerKeys = [1, 2, 3];
    address internal payoutKey = vm.addr(4);
    address internal treasuryKey = vm.addr(5);
    address internal attacker = makeAddr("attacker");

    RestrictedSafePlan.Infra internal infra;
    address internal safe;
    address internal roles;

    function setUp() public {
        deployCodeTo("RestrictedSafeFactory.t.sol:FactoryToken", USDC);
        deployCodeTo("RestrictedSafeFactory.t.sol:Pinger", PINGER);
        vm.warp(1_750_000_000);

        RestrictedSafePlan.Config memory c = _config();
        infra = RestrictedSafeInfra.resolve(_noOverrides(), c.engineDelay, c.engineExpiry);
        RestrictedSafeInfra.ensure(infra, c.engineDelay, c.engineExpiry);
        RestrictedSafePlan.Deployment memory d = RestrictedSafePlan.plan(c, infra);
        safe = ISafeFactory(infra.safeProxyFactory)
            .createProxyWithNonce(infra.safeSingleton, d.initializer, c.saltNonce);
        roles = d.roles;
        FactoryToken(USDC).mint(safe, 100_000e6);
        vm.deal(safe, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIG -> ONE TRANSACTION
    //////////////////////////////////////////////////////////////*/

    function test_deploy_stateMatchesConfig() public view {
        RestrictedSafePlan.Deployment memory d = _d();
        assertEq(safe, d.safe, "predicted address");
        RestrictedSafeCheck.check(_config(), infra, d);
    }

    /// @dev The shared contracts' addresses follow from their bytecode only. They are listed in
    ///      safe-factory/README.md; if this fails, the bytecode changed and the docs must change with it.
    function test_infra_addressesArePinned() public view {
        assertEq(infra.setup, 0x31f444546E8A30261eb3Cb0dAe15805f38Bb911D, "RestrictedSafeSetup");
        assertEq(infra.guard, 0xA0bC7f48b28204987F8dCf3Bd4CFaB724812d71B, "SafePolicyGuard(1 day, 7 days)");
        assertEq(infra.rolesMastercopy, 0x8b80f6Bb5922C4940FEa26fdcD1C73Bc39E9De83, "Roles mastercopy");
        assertEq(infra.allowPolicy, 0x9bB8973490cB62C98Cf5DE06252b82f3A0F6A1f0, "AllowPolicy");
        assertEq(infra.erc20TransferPolicy, 0xaB47a79ebE0D3cb60175A3a2e1c9AF983689a1E3, "ERC20TransferPolicy");
        assertEq(infra.approveCapPolicy, 0xa178267aC8D3FE564E2D238D075EE414344f1391, "ERC20ApproveCapPolicy");
        assertEq(infra.ownerOnlyPolicy, 0x46896Ba7558B78A272B1fFf7B01b314EE0893Ca1, "OwnerOnlyPolicy");
        assertEq(
            infra.increasedThresholdPolicy,
            0xF8Cf5706D7c24e8D7c0f64f5aE409e797BB3eD07,
            "IncreasedThresholdPolicy"
        );
    }

    function test_json_producesTheSameSafe() public view {
        RestrictedSafeJson.File memory f = RestrictedSafeJson.parse(vm.readFile(FIXTURE));
        assertEq(f.name, "factory-test");
        RestrictedSafePlan.Deployment memory fromJson = RestrictedSafePlan.plan(f.config, infra);
        assertEq(fromJson.initializer, _d().initializer, "initializer");
        assertEq(fromJson.safe, safe, "address");
    }

    function test_script_deploysChecksAndIsIdempotent() public {
        // setUp already created the fixture's Safe: the script must recognise and check it
        DeployRestrictedSafe script = new DeployRestrictedSafe();
        RestrictedSafePlan.Deployment memory again = script.deploy(FIXTURE);
        assertEq(again.safe, safe);
        string memory record = vm.readFile("deployments/restricted-safes/31337-factory-test.json");
        assertEq(vm.parseJsonAddress(record, ".safe"), safe);
        assertEq(vm.parseJsonAddress(record, ".roles"), roles);
    }

    function test_script_deploysAFreshSafe() public {
        // a different salt is a different Safe; the script deploys and checks it
        vm.setEnv("CONFIG", FIXTURE);
        string memory json = vm.readFile(FIXTURE);
        json = vm.replace(json, '"saltNonce": 7', '"saltNonce": 8');
        RestrictedSafeJson.File memory f = RestrictedSafeJson.parse(json);
        RestrictedSafePlan.Deployment memory fresh = RestrictedSafePlan.plan(f.config, infra);
        assertEq(fresh.safe.code.length, 0);
        address created = ISafeFactory(infra.safeProxyFactory)
            .createProxyWithNonce(infra.safeSingleton, fresh.initializer, f.config.saltNonce);
        assertEq(created, fresh.safe);
        RestrictedSafeCheck.check(f.config, infra, fresh);
    }

    function test_deploy_anyoneCanSendIt_sameAddress() public {
        RestrictedSafePlan.Config memory c = _config();
        c.saltNonce = 99;
        RestrictedSafePlan.Deployment memory p = RestrictedSafePlan.plan(c, infra);
        vm.prank(attacker); // the sender gets no rights and does not change the address
        address created =
            ISafeFactory(infra.safeProxyFactory).createProxyWithNonce(infra.safeSingleton, p.initializer, 99);
        assertEq(created, p.safe);
        RestrictedSafeCheck.check(c, infra, p);
    }

    function test_deploy_frontRunRolesProxyIsHarmless() public {
        RestrictedSafePlan.Config memory c = _config();
        c.saltNonce = 100;
        RestrictedSafePlan.Deployment memory p = RestrictedSafePlan.plan(c, infra);
        // someone deploys the Roles proxy first, with the only initializer that yields that address
        vm.prank(attacker);
        IModuleFactory(infra.moduleProxyFactory)
            .deployModule(
                infra.rolesMastercopy,
                abi.encodeWithSignature("setUp(bytes)", abi.encode(p.safe, p.safe, p.safe)),
                0
            );
        assertGt(p.roles.code.length, 0);
        ISafeFactory(infra.safeProxyFactory).createProxyWithNonce(infra.safeSingleton, p.initializer, 100);
        RestrictedSafeCheck.check(c, infra, p);
    }

    /*//////////////////////////////////////////////////////////////
                         THE KEYS: EXACTLY THEIR MANDATE
    //////////////////////////////////////////////////////////////*/

    function test_key_transfersWithinLimits() public {
        _keyOk(payoutKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1000e6));
        _keyOk(payoutKey, PAYOUTS, USDC, 0, _transfer(BOB, 1000e6));
        _keyOk(payoutKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1000e6));
        assertEq(ERC20(USDC).balanceOf(ALICE), 2000e6);
        assertEq(ERC20(USDC).balanceOf(BOB), 1000e6);
    }

    function test_key_blockedOutsideLimits() public {
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, _transfer(attacker, 1), 0, "recipient");
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1000e6 + 1), 0, "per-tx cap");
        _keyDenied(
            payoutKey,
            PAYOUTS,
            USDC,
            0,
            abi.encodeCall(ERC20.transferFrom, (safe, attacker, 1)),
            0,
            "transferFrom"
        );
        // daily allowance: 3000 per day
        for (uint256 i; i < 3; i++) {
            _keyOk(payoutKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1000e6));
        }
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1), 0, "allowance spent");
        vm.warp(block.timestamp + 1 days);
        _keyOk(payoutKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1000e6));
    }

    function test_key_approveWithinCapOnly() public {
        _keyOk(payoutKey, PAYOUTS, USDC, 0, abi.encodeCall(ERC20.approve, (VAULT, 500.5e6)));
        assertEq(ERC20(USDC).allowance(safe, VAULT), 500.5e6);
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, abi.encodeCall(ERC20.approve, (VAULT, 500.5e6 + 1)), 0, "cap");
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, abi.encodeCall(ERC20.approve, (attacker, 1)), 0, "spender");
    }

    function test_key_callsOnlyListedFunctions_noValue_noDelegatecall() public {
        _keyOk(payoutKey, PAYOUTS, PINGER, 0, abi.encodeCall(Pinger.ping, (42)));
        assertEq(Pinger(PINGER).last(), 42);
        _keyOk(payoutKey, PAYOUTS, PINGER, 0, abi.encodeCall(Pinger.pong, ()));
        _keyDenied(payoutKey, PAYOUTS, PINGER, 0, abi.encodeCall(Pinger.other, ()), 0, "unlisted function");
        _keyDenied(payoutKey, PAYOUTS, PINGER, 1, abi.encodeCall(Pinger.ping, (1)), 0, "ETH value");
        _keyDenied(payoutKey, PAYOUTS, PINGER, 0, abi.encodeCall(Pinger.ping, (1)), 1, "delegatecall");
        _keyDenied(payoutKey, PAYOUTS, attacker, 1 ether, "", 0, "send ETH");
    }

    function test_key_cannotAdministerAnything() public {
        bytes32[] memory r = new bytes32[](1);
        r[0] = PAYOUTS;
        bool[] memory m = new bool[](1);
        m[0] = true;
        _keyDenied(
            payoutKey,
            PAYOUTS,
            roles,
            0,
            abi.encodeCall(IRoles.assignRoles, (attacker, r, m)),
            0,
            "assignRoles"
        );
        _keyDenied(
            payoutKey,
            PAYOUTS,
            safe,
            0,
            abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", attacker, 1),
            0,
            "addOwner"
        );
        _keyDenied(
            payoutKey,
            PAYOUTS,
            safe,
            0,
            abi.encodeWithSignature("setGuard(address)", address(0)),
            0,
            "setGuard"
        );
    }

    function test_roles_areIsolatedFromEachOther() public {
        // the engine entry for USDC.transfer is the union {alice, bob, carol, treasury};
        // each role is still held to its own recipients by Roles
        _keyOk(treasuryKey, TREASURY_ROLE, USDC, 0, _transfer(CAROL, 50_000e6)); // no cap on this role
        _keyDenied(treasuryKey, TREASURY_ROLE, USDC, 0, _transfer(ALICE, 1), 0, "treasury -> alice");
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, _transfer(CAROL, 1), 0, "payouts -> carol");
        _keyDenied(treasuryKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1), 0, "not a member of PAYOUTS");
        _keyDenied(attacker, PAYOUTS, USDC, 0, _transfer(ALICE, 1), 0, "not a member");
    }

    /*//////////////////////////////////////////////////////////////
                 THE FLOOR: A COMPROMISED ROLES MODULE
    //////////////////////////////////////////////////////////////*/

    function test_floor_compromisedModuleIsBoundedByTheEngine() public {
        // Roles itself asks the Safe directly: only the Policy Engine stands between
        _moduleDenied(USDC, 0, _transfer(attacker, 1), 0, "transfer to attacker");
        _moduleDenied(USDC, 0, abi.encodeCall(ERC20.approve, (attacker, 1)), 0, "approve attacker");
        _moduleDenied(USDC, 0, abi.encodeCall(ERC20.approve, (VAULT, 500.5e6 + 1)), 0, "approve above cap");
        _moduleDenied(PINGER, 0, abi.encodeCall(Pinger.other, ()), 0, "unlisted function");
        _moduleDenied(attacker, 1 ether, "", 0, "send ETH");
        _moduleDenied(safe, 0, abi.encodeWithSignature("enableModule(address)", attacker), 0, "enableModule");
        _moduleDenied(safe, 0, abi.encodeWithSignature("changeThreshold(uint256)", 1), 0, "changeThreshold");
        _moduleDenied(
            safe,
            0,
            abi.encodeWithSignature("disableModule(address,address)", address(1), roles),
            0,
            "disableModule"
        );
        _moduleDenied(PINGER, 0, abi.encodeCall(Pinger.ping, (1)), 1, "delegatecall");
        bytes32[] memory r = new bytes32[](1);
        r[0] = PAYOUTS;
        bool[] memory m = new bool[](1);
        m[0] = true;
        _moduleDenied(roles, 0, abi.encodeCall(IRoles.assignRoles, (attacker, r, m)), 0, "assignRoles");
    }

    function test_floor_misconfiguredRolesStillBounded() public {
        // owners cannot even widen a role to a whole target: allowTarget has no engine entry
        _ownerDenied(roles, abi.encodeCall(IRoles.allowTarget, (PAYOUTS, USDC, 3)), "allowTarget");
        // simulate Roles opened up anyway (bypassing the guard): the engine floor still holds
        vm.prank(safe);
        IRoles(roles).allowTarget(PAYOUTS, USDC, 3);
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, _transfer(attacker, 1), 0, "opened Roles, attacker");
        _keyDenied(
            payoutKey,
            PAYOUTS,
            USDC,
            0,
            abi.encodeCall(ERC20.approve, (attacker, 1)),
            0,
            "opened Roles, approve"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          OWNERS KEEP CONTROL
    //////////////////////////////////////////////////////////////*/

    function test_owners_rotateKeyInstantly() public {
        address newKey = makeAddr("newKey");
        bytes32[] memory r = new bytes32[](1);
        r[0] = PAYOUTS;
        bool[] memory yes = new bool[](1);
        yes[0] = true;
        bool[] memory no = new bool[](1);
        _ownerOk(roles, abi.encodeCall(IRoles.assignRoles, (newKey, r, yes)));
        _ownerOk(roles, abi.encodeCall(IRoles.assignRoles, (payoutKey, r, no)));
        _keyOk(newKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1));
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1), 0, "revoked key");
    }

    function test_owners_killSwitchDetachesRoles() public {
        _ownerOk(safe, abi.encodeWithSignature("disableModule(address,address)", address(1), roles));
        _keyDenied(payoutKey, PAYOUTS, USDC, 0, _transfer(ALICE, 1), 0, "after kill switch");
    }

    function test_owners_withdrawToTreasuryOnly() public {
        _ownerOk(USDC, _transfer(TREASURY, 90_000e6));
        assertEq(ERC20(USDC).balanceOf(TREASURY), 90_000e6);
        _ownerDenied(USDC, _transfer(attacker, 1), "owners to attacker");
    }

    function test_owners_otherChangesGoThroughTheEngineDelay() public {
        _ownerDenied(safe, abi.encodeWithSignature("changeThreshold(uint256)", 3), "immediately");
        RestrictedSafeSetup.EngineEntry[] memory e = new RestrictedSafeSetup.EngineEntry[](1);
        e[0] = RestrictedSafeSetup.EngineEntry(
            safe, bytes4(keccak256("changeThreshold(uint256)")), 0, infra.ownerOnlyPolicy, ""
        );
        _ownerOk(infra.guard, abi.encodeCall(IGuard.requestConfiguration, (keccak256(abi.encode(e)))));
        _ownerDenied(infra.guard, abi.encodeCall(IGuard.applyConfiguration, (e)), "before the delay");
        vm.warp(block.timestamp + 1 days);
        _ownerOk(infra.guard, abi.encodeCall(IGuard.applyConfiguration, (e)));
        _ownerOk(safe, abi.encodeWithSignature("changeThreshold(uint256)", 3));
        assertEq(ISafe(safe).getThreshold(), 3);
    }

    /*//////////////////////////////////////////////////////////////
                    THE SETUP CONTRACT'S OWN INVARIANTS
    //////////////////////////////////////////////////////////////*/

    function test_setup_onlyAsDelegatecall() public {
        RestrictedSafeSetup.Setup memory s = _d().setup;
        vm.expectRevert(RestrictedSafeSetup.OnlyDelegateCall.selector);
        RestrictedSafeSetup(infra.setup).setUp(s);
    }

    function test_setup_onlyDuringSafeSetup() public {
        // a plain 1-of-1 Safe whose owner later delegatecalls the setup contract
        address[] memory o = new address[](1);
        o[0] = vm.addr(1);
        address plain = ISafeFactory(infra.safeProxyFactory)
            .createProxyWithNonce(
                infra.safeSingleton,
                abi.encodeCall(
                    ISafe.setup,
                    (o, 1, address(0), "", infra.fallbackHandler, address(0), 0, payable(address(0)))
                ),
                1
            );
        bytes memory data = abi.encodeCall(RestrictedSafeSetup.setUp, (_d().setup));
        bytes32 h =
            ISafe(plain).getTransactionHash(infra.setup, 0, data, 1, 0, 0, 0, address(0), address(0), 0);
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(1, h);
        vm.expectRevert(RestrictedSafeSetup.OnlyDuringSafeSetup.selector); // Safe 1.5.0 bubbles the reason
        ISafe(plain)
            .execTransaction(
                infra.setup, 0, data, 1, 0, 0, 0, address(0), payable(address(0)), abi.encodePacked(rr, s, v)
            );
    }

    /// @dev The Safe and its Roles module cannot appear in their own setup data (the Safe address is a hash
    ///      of it), so the setup contract's checks for those two are defence in depth. The guard, the zero
    ///      address and a fallback entry (target 0) can be named, and are rejected.
    function test_setup_rejectsEntriesOnTheGuardOrZero() public {
        address[2] memory targets = [address(0), infra.guard];
        for (uint256 i; i < targets.length; i++) {
            RestrictedSafeSetup.Setup memory s = _d().setup;
            RestrictedSafeSetup.EngineEntry[] memory e = new RestrictedSafeSetup.EngineEntry[](1);
            e[0] = RestrictedSafeSetup.EngineEntry(targets[i], bytes4(0x12345678), 0, infra.allowPolicy, "");
            s.entries = e;
            _expectSetupRevert(s, 200 + i);
        }
    }

    function test_setup_rejectsDelegatecallEntries() public {
        RestrictedSafeSetup.Setup memory s = _d().setup;
        RestrictedSafeSetup.EngineEntry[] memory e = new RestrictedSafeSetup.EngineEntry[](1);
        e[0] = RestrictedSafeSetup.EngineEntry(PINGER, bytes4(0x12345678), 1, infra.allowPolicy, "");
        s.entries = e;
        _expectSetupRevert(s, 210);
    }

    function test_setup_rejectsWideOrValueRolesCalls() public {
        bytes[3] memory bad = [
            abi.encodeCall(IRoles.allowTarget, (PAYOUTS, PINGER, 0)), // whole target
            abi.encodeWithSignature(
                "allowFunction(bytes32,address,bytes4,uint8)", PAYOUTS, PINGER, Pinger.other.selector, 1
            ), // ETH value
            abi.encodeWithSignature("setDefaultRole(address,bytes32)", payoutKey, PAYOUTS) // not a permission call
        ];
        for (uint256 i; i < bad.length; i++) {
            RestrictedSafeSetup.Setup memory s = _d().setup;
            bytes[] memory calls = new bytes[](1);
            calls[0] = bad[i];
            s.rolesCalls = calls;
            _expectSetupRevert(s, 220 + i);
        }
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIG VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_config_rejectsMistakes() public {
        PlanCaller caller = new PlanCaller();
        RestrictedSafePlan.Config memory c;

        c = _config();
        c.owners[1] = c.owners[0];
        _expectPlanRevert(caller, c, "duplicate owner");

        c = _config();
        c.roles[0].permissions[0].counterparties[1] = 0x2222222222222222222222222222222222222222;
        _expectPlanRevert(
            caller, c, "placeholder address (0x1111...-style) in the config: replace it before deploying"
        );

        c = _config();
        c.threshold = 4;
        _expectPlanRevert(caller, c, "threshold must be 1..owners");

        c = _config();
        c.roles[0].members[0] = c.owners[0];
        _expectPlanRevert(caller, c, "an operational key must not be a Safe owner");

        c = _config();
        c.roles[0].permissions[2].selectors[0] = ERC20.transfer.selector;
        _expectPlanRevert(
            caller, c, "use a transfer or approve permission for token movements (role PAYOUTS)"
        );

        c = _config();
        c.roles[1].permissions[0].target = PINGER;
        c.roles[1].permissions[0].kind = RestrictedSafePlan.Kind.Call;
        c.roles[1].permissions[0].selectors = new bytes4[](1);
        c.roles[1].permissions[0].selectors[0] = Pinger.ping.selector;
        c.roles[1].members = c.roles[0].members;
        c.roles[1].name = "PAYOUTS";
        _expectPlanRevert(caller, c, "duplicate role: PAYOUTS");

        c = _config();
        c.roles[0].permissions[1].maxAmount = 0;
        _expectPlanRevert(caller, c, "approve needs a maxAmount (and at most 2^248 - 1) (role PAYOUTS)");

        c = _config();
        c.roles[0].permissions[0].period = 0;
        _expectPlanRevert(caller, c, "maxPerPeriod needs a period (role PAYOUTS)");
    }

    function test_config_rejectsOverlappingPermissionsInOneRole() public {
        PlanCaller caller = new PlanCaller();
        RestrictedSafePlan.Config memory c = _config();
        RestrictedSafePlan.Permission[] memory p = new RestrictedSafePlan.Permission[](2);
        p[0] = c.roles[1].permissions[0];
        p[1] = c.roles[1].permissions[0];
        c.roles[1].permissions = p;
        _expectPlanRevert(
            caller,
            c,
            "role TREASURY: two permissions cover the same function on the same target; merge them into one"
        );
    }

    function test_parseUnits() public pure {
        assertEq(RestrictedSafeJson.parseUnits("800", 6), 800e6);
        assertEq(RestrictedSafeJson.parseUnits("0.4", 6), 0.4e6);
        assertEq(RestrictedSafeJson.parseUnits("500.5", 6), 500.5e6);
        assertEq(RestrictedSafeJson.parseUnits("1", 18), 1e18);
        assertEq(RestrictedSafeJson.parseUnits("0.000001", 6), 1);
    }

    function test_parseUnits_rejectsTooManyDecimals() public {
        PlanCaller caller = new PlanCaller();
        vm.expectRevert(bytes("more decimals than the token has: 0.0000001"));
        caller.parseUnits("0.0000001", 6);
        vm.expectRevert(bytes("invalid amount (digits and one '.'): 1e6"));
        caller.parseUnits("1e6", 6);
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Same content as test/factory/fixtures/local.json.
    function _config() internal view returns (RestrictedSafePlan.Config memory c) {
        c.owners = new address[](3);
        for (uint256 i; i < 3; i++) {
            c.owners[i] = vm.addr(ownerKeys[i]);
        }
        c.threshold = 2;
        c.saltNonce = 7;
        c.engineDelay = 1 days;
        c.engineExpiry = 7 days;
        c.ownerSwapMaxAbsent = 1;

        c.roles = new RestrictedSafePlan.Role[](2);
        RestrictedSafePlan.Permission[] memory p = new RestrictedSafePlan.Permission[](3);
        p[0].kind = RestrictedSafePlan.Kind.Transfer;
        p[0].target = USDC;
        p[0].counterparties = _list(ALICE, BOB);
        p[0].maxAmount = 1000e6;
        p[0].maxPerPeriod = 3000e6;
        p[0].period = 1 days;
        p[1].kind = RestrictedSafePlan.Kind.Approve;
        p[1].target = USDC;
        p[1].counterparties = _list(VAULT);
        p[1].maxAmount = 500.5e6;
        p[2].kind = RestrictedSafePlan.Kind.Call;
        p[2].target = PINGER;
        p[2].selectors = new bytes4[](2);
        p[2].selectors[0] = Pinger.ping.selector;
        p[2].selectors[1] = Pinger.pong.selector;
        c.roles[0] = RestrictedSafePlan.Role("PAYOUTS", bytes32(0), _list(payoutKey), p);

        RestrictedSafePlan.Permission[] memory t = new RestrictedSafePlan.Permission[](1);
        t[0].kind = RestrictedSafePlan.Kind.Transfer;
        t[0].target = USDC;
        t[0].counterparties = _list(CAROL);
        c.roles[1] = RestrictedSafePlan.Role("TREASURY", bytes32(0), _list(treasuryKey), t);

        c.ownerWithdrawals = new RestrictedSafePlan.Withdrawal[](1);
        c.ownerWithdrawals[0] = RestrictedSafePlan.Withdrawal(USDC, _list(TREASURY));
    }

    function _d() internal view returns (RestrictedSafePlan.Deployment memory) {
        return RestrictedSafePlan.plan(_config(), infra);
    }

    function _noOverrides() internal pure returns (RestrictedSafeInfra.Overrides memory o) { }

    function _transfer(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeCall(ERC20.transfer, (to, amount));
    }

    function _keyOk(address key, bytes32 role, address to, uint256 value, bytes memory data) internal {
        vm.prank(key);
        IRoles(roles).execTransactionWithRole(to, value, data, 0, role, true);
    }

    function _keyDenied(
        address key,
        bytes32 role,
        address to,
        uint256 value,
        bytes memory data,
        uint8 op,
        string memory label
    ) internal {
        uint256 balance = ERC20(USDC).balanceOf(safe);
        vm.prank(key);
        (bool ok,) =
            roles.call(abi.encodeCall(IRoles.execTransactionWithRole, (to, value, data, op, role, true)));
        assertFalse(ok, label);
        assertEq(ERC20(USDC).balanceOf(safe), balance, label);
    }

    function _moduleDenied(address to, uint256 value, bytes memory data, uint8 op, string memory label)
        internal
    {
        vm.prank(roles);
        (bool ok, bytes memory ret) =
            safe.call(abi.encodeCall(ISafe.execTransactionFromModule, (to, value, data, op)));
        assertTrue(!ok || !abi.decode(ret, (bool)), label);
    }

    function _ownerExec(address to, bytes memory data) internal returns (bool ok) {
        bytes32 h = ISafe(safe)
            .getTransactionHash(to, 0, data, 0, 0, 0, 0, address(0), address(0), ISafe(safe).nonce());
        uint256[] memory keys = _sortedOwnerKeys();
        bytes memory sigs;
        for (uint256 i; i < 2; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            sigs = abi.encodePacked(sigs, r, s, v);
        }
        (ok,) = safe.call(
            abi.encodeCall(
                ISafe.execTransaction, (to, 0, data, 0, 0, 0, 0, address(0), payable(address(0)), sigs)
            )
        );
    }

    function _ownerOk(address to, bytes memory data) internal {
        assertTrue(_ownerExec(to, data), "owner transaction failed");
    }

    function _ownerDenied(address to, bytes memory data, string memory label) internal {
        assertFalse(_ownerExec(to, data), label);
    }

    function _sortedOwnerKeys() internal view returns (uint256[] memory keys) {
        keys = ownerKeys;
        for (uint256 i; i < keys.length; i++) {
            for (uint256 j = i + 1; j < keys.length; j++) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
    }

    function _initializer(RestrictedSafeSetup.Setup memory s) internal view returns (bytes memory) {
        return abi.encodeCall(
            ISafe.setup,
            (
                _config().owners,
                2,
                infra.setup,
                abi.encodeCall(RestrictedSafeSetup.setUp, (s)),
                infra.fallbackHandler,
                address(0),
                0,
                payable(address(0))
            )
        );
    }

    function _expectSetupRevert(RestrictedSafeSetup.Setup memory s, uint256 salt) internal {
        (bool ok,) = infra.safeProxyFactory
            .call(
                abi.encodeCall(
                    ISafeFactory.createProxyWithNonce, (infra.safeSingleton, _initializer(s), salt)
                )
            );
        assertFalse(ok, "Safe with a forbidden setup was created");
    }

    function _expectPlanRevert(PlanCaller caller, RestrictedSafePlan.Config memory c, string memory reason)
        internal
    {
        vm.expectRevert(bytes(reason));
        caller.plan(c, infra);
    }

    function _list(address a) internal pure returns (address[] memory l) {
        l = new address[](1);
        l[0] = a;
    }

    function _list(address a, address b) internal pure returns (address[] memory l) {
        l = new address[](2);
        l[0] = a;
        l[1] = b;
    }
}

/// @dev External wrapper so that `vm.expectRevert` can catch library reverts.
contract PlanCaller {
    function plan(RestrictedSafePlan.Config memory c, RestrictedSafePlan.Infra memory i)
        external
        view
        returns (RestrictedSafePlan.Deployment memory)
    {
        return RestrictedSafePlan.plan(c, i);
    }

    function parseUnits(string memory a, uint8 dec) external pure returns (uint256) {
        return RestrictedSafeJson.parseUnits(a, dec);
    }
}

/// @notice The shipped example configs deploy, once their placeholders are replaced; as shipped, they are refused.
contract RestrictedSafeExamplesTest is Test {
    address internal constant USDC_ETHEREUM = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant USDCE_GNOSIS = 0x2a22f9c3b484c3629090FeED35F17Ff8F88f76F0;
    bytes32 internal constant SENTINEL_KEY = keccak256("SENTINEL");

    function setUp() public {
        deployCodeTo("RestrictedSafeFactory.t.sol:FactoryToken", USDC_ETHEREUM);
        deployCodeTo("RestrictedSafeFactory.t.sol:FactoryToken", USDCE_GNOSIS);
    }

    function test_examples_deployOnceFilledIn() public {
        string[2] memory examples =
            ["safe-factory/examples/payouts.json", "safe-factory/examples/safenet-sentinel.json"];
        for (uint256 i; i < examples.length; i++) {
            RestrictedSafeJson.File memory f = RestrictedSafeJson.parse(_filledIn(vm.readFile(examples[i])));
            RestrictedSafePlan.Infra memory infra =
                RestrictedSafeInfra.resolve(f.overrides, f.config.engineDelay, f.config.engineExpiry);
            RestrictedSafeInfra.ensure(infra, f.config.engineDelay, f.config.engineExpiry);
            RestrictedSafePlan.Deployment memory d = RestrictedSafePlan.plan(f.config, infra);
            ISafeFactory(infra.safeProxyFactory).createProxyWithNonce(infra.safeSingleton, d.initializer, 0);
            RestrictedSafeCheck.check(f.config, infra, d);
        }
    }

    function test_examples_sentinelMatchesSentinelSetup() public {
        RestrictedSafeJson.File memory f =
            RestrictedSafeJson.parse(_filledIn(vm.readFile("safe-factory/examples/safenet-sentinel.json")));
        assertEq(f.config.roles[0].key, SENTINEL_KEY, "same role key as SentinelSetup.ROLE");
        RestrictedSafePlan.Permission memory approve = f.config.roles[0].permissions[0];
        assertEq(approve.maxAmount, 800e6, "one bond: 0.40 USDC.e x 2000");
        bytes4[] memory sels = f.config.roles[0].permissions[1].selectors;
        assertEq(sels.length, 5);
        assertEq(sels[0], bytes4(keccak256("commit(bytes32,bytes32)")));
        assertEq(sels[1], bytes4(keccak256("reveal(bytes32,bool,bytes32,string)")));
        assertEq(sels[2], bytes4(keccak256("finalize(bytes32)")));
        assertEq(sels[3], bytes4(keccak256("claim(bytes32)")));
        assertEq(sels[4], bytes4(keccak256("timeoutArbitration(bytes32)")));
    }

    function test_examples_asShippedAreRefused() public {
        PlanCaller caller = new PlanCaller();
        RestrictedSafeJson.File memory f =
            RestrictedSafeJson.parse(vm.readFile("safe-factory/examples/payouts.json"));
        RestrictedSafePlan.Infra memory infra =
            RestrictedSafeInfra.resolve(f.overrides, f.config.engineDelay, f.config.engineExpiry);
        RestrictedSafeInfra.ensure(infra, f.config.engineDelay, f.config.engineExpiry);
        vm.expectRevert(
            bytes("placeholder address (0x1111...-style) in the config: replace it before deploying")
        );
        caller.plan(f.config, infra);
    }

    function _filledIn(string memory json) internal returns (string memory) {
        for (uint256 n = 1; n <= 7; n++) {
            string memory hexDigit = vm.toString(n);
            bytes memory placeholder = new bytes(40);
            for (uint256 k; k < 40; k++) {
                placeholder[k] = bytes(hexDigit)[0];
            }
            json = vm.replace(
                json,
                string.concat("0x", string(placeholder)),
                vm.toString(makeAddr(string.concat("party", hexDigit)))
            );
        }
        return json;
    }
}
