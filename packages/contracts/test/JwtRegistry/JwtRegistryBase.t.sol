// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {JwtRegistry} from "../../src/utils/JwtRegistry.sol";
import {JwtRegistryTestBase} from "./JwtRegistryBase.t.sol";

contract JwtRegistryTestBase is Test {
    bytes32 publicKeyHash =
        0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
    string issKidString = "https://example.com|12345";
    string azpString = "client-id-12345";
    
    JwtRegistry jwtRegistry;

    address deployer = vm.addr(1);

    constructor() {}

    function setUp() public virtual {
        // Create jwt registry
        vm.startPrank(deployer);
        jwtRegistry = new JwtRegistry(deployer);

        // TODO Call ChainLink Function, currently it's not implemented yet
        // jwtRegistry.updateJwtRegistry();
        jwtRegistry.setJwtPublicKey(issKidString, publicKeyHash);
        jwtRegistry.whitelistAzp(azpString);
        vm.stopPrank();

        bool isRegistered = jwtRegistry.isJwtPublicKeyHashValid(
            issKidString,
            publicKeyHash
        );
        assertTrue(isRegistered, "JWT Public Key Hash should be registered");
        isRegistered = jwtRegistry.isJwtPublicKeyValid(
            issKidString,
            publicKeyHash
        );
        assertTrue(isRegistered, "JWT Public Key Hash should be registered");
    }
}
