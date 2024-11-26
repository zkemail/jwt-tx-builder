// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import {JwtRegistryTestBase} from "./JwtRegistryBase.t.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract JwtRegistryTest_revokeDKIMPublicKeyHash is JwtRegistryTestBase {
    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    function testRevert_revokeDKIMPublicKeyHash_invalidDomainName() public {
        vm.startPrank(deployer);
        string memory domainName = "";
        vm.expectRevert(bytes("Invalid domain name"));
        jwtRegistry.revokeDKIMPublicKeyHash(domainName, publicKeyHash);
        vm.stopPrank();
    }

    function testRevert_revokeDKIMPublicKeyHash_invalidPublicKeyHash() public {
        vm.startPrank(deployer);
        string memory domainName = "12345|https://example.com";
        vm.expectRevert(bytes("Invalid public key hash"));
        jwtRegistry.revokeDKIMPublicKeyHash(domainName, bytes32(0));
        vm.stopPrank();
    }

    function testRevert_revokeDKIMPublicKeyHash_publicKeyHashIsNotSet() public {
        vm.startPrank(deployer);
        string memory domainName = "54321|https://example.com";
        vm.expectRevert(bytes("publicKeyHash is not set"));
        jwtRegistry.revokeDKIMPublicKeyHash(domainName, publicKeyHash);
        vm.stopPrank();
    }

    function testRevert_revokeDKIMPublicKeyHash_OwnableUnauthorizedAccount()
        public
    {
        vm.startPrank(vm.addr(2));
        string memory domainName = "54321|https://example.com";
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                vm.addr(2)
            )
        );
        jwtRegistry.revokeDKIMPublicKeyHash(domainName, publicKeyHash);
        vm.stopPrank();
    }

    function test_revokeDKIMPublicKeyHash() public {
        vm.startPrank(deployer);
        string memory domainName = "12345|https://example.com";
        jwtRegistry.revokeDKIMPublicKeyHash(domainName, publicKeyHash);
        // revokeDKIMPublicKeyHash does not set azp to false
        assertEq(jwtRegistry.whitelistedClients("client-id-12345"), true);
        vm.stopPrank();
    }
}
