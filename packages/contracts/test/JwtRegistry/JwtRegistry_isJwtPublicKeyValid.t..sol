// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {JwtRegistryTestBase} from "./JwtRegistryBase.t.sol";

contract JwtRegistryTest_isJwtPublicKeyValid is JwtRegistryTestBase {
    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    function testFail_isJwtPublicKeyValid_invalidKid() public {
        string memory domainName = "54321|https://example.com";
        bool res = jwtRegistry.isJwtPublicKeyValid(domainName, publicKeyHash);
        assertEq(res, true);
    }

    function testFail_isJwtPublicKeyValid_invalidIss() public {
        string memory domainName = "12345|https://example.xyz";
        bool res = jwtRegistry.isJwtPublicKeyValid(domainName, publicKeyHash);
        assertEq(res, true);
    }

    // function testFail_isJwtPublicKeyValid_invalidAzp() public {
    //     string memory domainName = "12345|https://example.com|client-id-54321";
    //     bool res = jwtRegistry.isJwtPublicKeyValid(domainName, publicKeyHash);
    //     assertEq(res, true);
    // }

    function test_isJwtPublicKeyValid() public {
        string memory domainName = "12345|https://example.com";
        bool res = jwtRegistry.isJwtPublicKeyValid(domainName, publicKeyHash);
        assertEq(res, true);
    }
}
