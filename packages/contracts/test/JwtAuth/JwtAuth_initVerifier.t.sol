// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import {JwtAuthTestBase} from "./JwtAuthBase.t.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {JwtAuth} from "../../src/JwtAuth.sol";

contract JwtAuthTest_initVerifier is JwtAuthTestBase {
    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    function testRevert_initVerifier_OwnableUnauthorizedAccount() public {
        vm.startPrank(vm.addr(2));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                vm.addr(2)
            )
        );
        jwtAuth.initVerifier(address(verifier));
        vm.stopPrank();
    }

    function testRevert_initVerifier_InvalidJwtRegistryAddress() public {
        vm.startPrank(deployer);
        vm.expectRevert("invalid verifier address");
        jwtAuth.initVerifier(address(0));
        vm.stopPrank();
    }

    function testRevert_initVerifier_AlreadyInitialized() public {
        vm.startPrank(deployer);
        vm.expectEmit(true, true, false, false);
        emit JwtAuth.VerifierUpdated(address(verifier));
        jwtAuth.initVerifier(address(verifier));
        vm.expectRevert("verifier already initialized");
        jwtAuth.initVerifier(address(verifier));
        vm.stopPrank();
    }

    function test_initVerifier() public {
        vm.startPrank(deployer);
        vm.expectEmit(true, true, false, false);
        emit JwtAuth.VerifierUpdated(address(verifier));
        jwtAuth.initVerifier(address(verifier));
        vm.stopPrank();
    }
}
