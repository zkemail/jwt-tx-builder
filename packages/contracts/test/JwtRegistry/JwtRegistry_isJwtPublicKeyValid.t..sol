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
        string memory domainName = "https://example.com|54321";
        bool res = jwtRegistry.isJwtPublicKeyValid(domainName, publicKeyHash);
        assertEq(res, true);
    }

    function testFail_isJwtPublicKeyValid_invalidIss() public {
        string memory domainName = "https://example.xyz|12345";
        bool res = jwtRegistry.isJwtPublicKeyValid(domainName, publicKeyHash);
        assertEq(res, true);
    }

    function test_isJwtPublicKeyValid() public {
        string memory domainName = "https://example.com|12345";
        bool res = jwtRegistry.isJwtPublicKeyValid(domainName, publicKeyHash);
        assertEq(res, true);
    }
}
