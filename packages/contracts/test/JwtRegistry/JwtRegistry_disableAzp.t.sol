// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import {JwtRegistryTestBase} from "./JwtRegistryBase.t.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract JwtRegistryTest_disableAzp is JwtRegistryTestBase {
    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    // function testRevert_disableAzp_invalidDomainNameFormat() public {
    //     vm.startPrank(deployer);
    //     string memory invalidDomainName = "12345|https://example.com";
    //     vm.expectRevert(bytes("Invalid kid|iss|azp strings"));
    //     jwtRegistry.disableAzp(invalidDomainName);
    //     vm.stopPrank();
    // }

    // function testRevert_disableAzp_tooManyParts() public {
    //     vm.startPrank(deployer);
    //     string
    //         memory invalidDomainName = "12345|https://example.com|extra";
    //     vm.expectRevert(bytes("Invalid kid|iss strings"));
    //     jwtRegistry.disableAzp(invalidDomainName);
    //     vm.stopPrank();
    // }

    function testRevert_disableAzp_emptyString() public {
        vm.startPrank(deployer);
        string memory azp = "";
        vm.expectRevert(bytes("Invalid azp string"));
        jwtRegistry.disableAzp(azp);
        vm.stopPrank();
    }

    function testRevert_disableAzp_OwnableUnauthorizedAccount() public {
        vm.startPrank(vm.addr(2));
        string memory azp = "client-id-12345";
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                vm.addr(2)
            )
        );
        jwtRegistry.disableAzp(azp);
        vm.stopPrank();
    }

    function test_disableAzp() public {
        vm.startPrank(deployer);
        string memory azp = "client-id-12345";

        // Verify that client-id-12345 is whitelisted
        assertTrue(
            jwtRegistry.whitelistedClients("client-id-12345"),
            "Client should be whitelisted initially"
        );

        // Call disableAzp
        jwtRegistry.disableAzp(azp);

        // Verify that client-id-12345 is no longer whitelisted
        assertFalse(
            jwtRegistry.whitelistedClients("client-id-12345"),
            "Client should not be whitelisted after disableAzp"
        );
        vm.stopPrank();
    }
}
