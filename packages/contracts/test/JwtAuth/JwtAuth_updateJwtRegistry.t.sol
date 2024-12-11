// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import {JwtAuthTestBase} from "./JwtAuthBase.t.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {JwtAuth} from "../../src/JwtAuth.sol";

contract JwtAuthTest_updateJwtRegistry is JwtAuthTestBase {
    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    function testRevert_updateJwtRegistry_OwnableUnauthorizedAccount() public {
        vm.startPrank(vm.addr(2));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                vm.addr(2)
            )
        );
        jwtAuth.updateJwtRegistry(address(jwtRegistry));
        vm.stopPrank();
    }

    function testRevert_updateJwtRegistry_InvalidJwtRegistryAddress() public {
        vm.startPrank(deployer);
        vm.expectRevert("invalid jwt registry address");
        jwtAuth.updateJwtRegistry(address(0));
        vm.stopPrank();
    }

    function test_updateJwtRegistry() public {
        vm.startPrank(deployer);
        vm.expectEmit(true, true, false, false);
        emit JwtAuth.JwtRegistryUpdated(address(jwtRegistry));
        jwtAuth.updateJwtRegistry(address(jwtRegistry));
        vm.stopPrank();
    }
}
