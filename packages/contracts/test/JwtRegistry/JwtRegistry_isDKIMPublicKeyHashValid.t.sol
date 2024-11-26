// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {JwtRegistryTestBase} from "./JwtRegistryBase.t.sol";

contract JwtRegistryTest_isJwtPublicKeyHashValid is JwtRegistryTestBase {
    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    function testFail_isJwtPublicKeyHashValid_invalidKid() public {
        string memory domainName = "54321|https://example.com";
        bool res = jwtRegistry.isJwtPublicKeyHashValid(
            domainName,
            publicKeyHash
        );
        assertEq(res, true);
    }

    function testFail_isDKIMPublicKeyHashValid_invalidIss() public {
        string memory domainName = "12345|https://example.xyz";
        bool res = jwtRegistry.isJwtPublicKeyHashValid(
            domainName,
            publicKeyHash
        );
        assertEq(res, true);
    }

    // function testFail_isDKIMPublicKeyHashValid_invalidAzp() public {
    //     string memory domainName = "12345|https://example.com";
    //     bool res = jwtRegistry.isJwtPublicKeyHashValid(
    //         domainName,
    //         publicKeyHash
    //     );
    //     assertEq(res, true);
    // }

    function test_isDKIMPublicKeyHashValid() public {
        string memory domainName = "12345|https://example.com";
        bool res = jwtRegistry.isJwtPublicKeyHashValid(
            domainName,
            publicKeyHash
        );
        assertEq(res, true);
    }
}
