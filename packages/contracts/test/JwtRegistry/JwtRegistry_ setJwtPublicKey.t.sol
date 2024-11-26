// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import {JwtRegistryTestBase} from "./JwtRegistryBase.t.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract JwtRegistryTest_setJwtPublicKey is JwtRegistryTestBase {
    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    function testRevert_setJwtPublicKey_publicKeyHashIsAlreadySet() public {
        vm.startPrank(deployer);
        string memory domainName = "https://example.com|12345";
        vm.expectRevert(bytes("publicKeyHash is already set"));
        jwtRegistry.setJwtPublicKey(domainName, publicKeyHash);
        vm.stopPrank();
    }

    function testRevert_setJwtPublicKey_publicKeyHashIsRevoked() public {
        vm.startPrank(deployer);
        string memory domainName = "https://example.com|12345";
        jwtRegistry.revokeDKIMPublicKeyHash(domainName, publicKeyHash);
        vm.expectRevert(bytes("publicKeyHash is revoked"));
        jwtRegistry.setJwtPublicKey(domainName, publicKeyHash);
        vm.stopPrank();
    }

    function testRevert_setJwtPublicKey_OwnableUnauthorizedAccount() public {
        vm.startPrank(vm.addr(2));
        string memory domainName = "https://example.com|12345";
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                vm.addr(2)
            )
        );
        jwtRegistry.setJwtPublicKey(domainName, publicKeyHash);
        vm.stopPrank();
    }

    function test_setJwtPublicKey() public {
        vm.startPrank(deployer);
        string memory domainName = "https://example.xyz|12345";
        jwtRegistry.setJwtPublicKey(domainName, publicKeyHash);
        assertEq(jwtRegistry.whitelistedClients("client-id-12345"), true);
        vm.stopPrank();
    }
}
