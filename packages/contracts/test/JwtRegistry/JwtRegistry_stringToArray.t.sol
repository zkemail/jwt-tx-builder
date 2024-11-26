// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {JwtRegistryTestBase} from "./JwtRegistryBase.t.sol";
import {StringToArrayUtils} from "../../src/utils/StringToArrayUtils.sol";

contract JwtRegistryTest_stringToArray is JwtRegistryTestBase {
    using StringToArrayUtils for string;

    constructor() {}

    function setUp() public override {
        super.setUp();
    }

    function test_stringToArray() public {
        string memory domainName = "12345|https://example.com";
        string[] memory points = domainName.stringToArray();
        assertEq(points[0], "12345");
        assertEq(points[1], "https://example.com");
    }
}
