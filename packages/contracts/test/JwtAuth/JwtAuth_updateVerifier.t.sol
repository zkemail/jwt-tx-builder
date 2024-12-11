// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import {JwtAuthTestBase} from "./JwtAuthBase.t.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {JwtAuth} from "../../src/JwtAuth.sol";

contract JwtAuthTest_updateVerifier is JwtAuthTestBase {
    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    function testRevert_updateVerifier_OwnableUnauthorizedAccount() public {
        vm.startPrank(vm.addr(2));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                vm.addr(2)
            )
        );
        jwtAuth.updateVerifier(address(verifier));
        vm.stopPrank();
    }

    function testRevert_updateVerifier_InvalidJwtRegistryAddress() public {
        vm.startPrank(deployer);
        vm.expectRevert("invalid verifier address");
        jwtAuth.updateVerifier(address(0));
        vm.stopPrank();
    }

    function test_updateVerifier() public {
        vm.startPrank(deployer);
        vm.expectEmit(true, true, false, false);
        emit JwtAuth.VerifierUpdated(address(verifier));
        jwtAuth.updateVerifier(address(verifier));
        vm.stopPrank();
    }
}
