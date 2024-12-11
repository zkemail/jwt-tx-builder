// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {JwtRegistry} from "../../src/utils/JwtRegistry.sol";
import {JwtAuth} from "../../src/JwtAuth.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {JwtProof, JwtVerifier} from "../../src/utils/JwtVerifier.sol";
import {JwtGroth16Verifier} from "../../src/utils/JwtGroth16Verifier.sol";

contract JwtAuthTestBase is Test {
    bytes32 publicKeyHash =
        0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
    string issKidString = "https://example.com|12345";
    string azpString = "client-id-12345";

    address deployer = vm.addr(1);
    bytes32 accountSalt =
        0x2c3abbf3d1171bfefee99c13bf9c47f1e8447576afd89096652a34f27b297971;
    bytes32 jwtNullifier =
        0x00a83fce3d4b1c9ef0f600644c1ecc6c8115b57b1596e0e3295e2c5105fbfd8a;
    bytes mockProof = abi.encodePacked(bytes1(0x01));

    JwtRegistry jwtRegistry;
    JwtAuth jwtAuth;
    JwtVerifier verifier;

    constructor() {}

    function setUp() public virtual {
        JwtAuth authImpl = new JwtAuth();
        ERC1967Proxy authProxy = new ERC1967Proxy(
            address(authImpl),
            abi.encodeCall(authImpl.initialize, (deployer))
        );
        jwtAuth = JwtAuth(address(authProxy));

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

        JwtVerifier verifierImpl = new JwtVerifier();
        JwtGroth16Verifier groth16Verifier = new JwtGroth16Verifier();
        ERC1967Proxy verifierProxy = new ERC1967Proxy(
            address(verifierImpl),
            abi.encodeCall(
                verifierImpl.initialize,
                (deployer, address(groth16Verifier))
            )
        );
        verifier = JwtVerifier(address(verifierProxy));

        vm.stopPrank();
    }
}
