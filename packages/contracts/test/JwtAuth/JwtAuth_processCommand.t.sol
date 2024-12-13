// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import {JwtAuthTestBase} from "./JwtAuthBase.t.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {JwtAuth} from "../../src/JwtAuth.sol";
import {IVerifier} from "../../src/interfaces/IVerifier.sol";

contract JwtAuthTest_processCommand is JwtAuthTestBase {
    uint[2] mockpA;
    uint[2][2] mockpB;
    uint[2] mockpC;
    uint[] mockPubSignals;
    uint[] mockExtraInput;

    constructor() {}

    function setUp() public override {
        super.setUp();

        vm.startPrank(deployer);
        // jwtAuth.initJwtRegistry(address(jwtRegistry));
        jwtAuth.initVerifier(address(verifier));
        jwtAuth.initJwtAuthGroth16Verifier(address(groth16Verifier));
        jwtRegistry.updateJwtVerifier(address(verifier));
        vm.stopPrank();

        // jwtProof = JwtProof({
        //     domainName: "random.website.com|5aaff47c21d06e266cce395b2145c7c6d4730ea5",
        //     azp: "demo-client-id",
        //     publicKeyHash: publicKeyHash,
        //     timestamp: 1694989812,
        //     maskedCommand: "Send 1 ETH to 0x0000000000000000000000000000000000000020",
        //     jwtNullifier: jwtNullifier,
        //     accountSalt: accountSalt,
        //     isCodeExist: true,
        //     proof: mockProof
        // });
    }

    // function testRevert_processCommand_NotJwtAuth() public {
    //     vm.startPrank(deployer);
    //     jwtRegistry.updateJwtVerifier(deployer);
    //     vm.expectRevert("only jwtAuth");
    //     jwtAuth.processCommand(mockpA, mockpB, mockpC, mockPubSignals, mockExtraInput);
    //     vm.stopPrank();
    // }

    // function testRevert_authJwt_InvalidPublicKeyHash() public {
    //     vm.startPrank(deployer);
    //     vm.expectRevert("Invalid public key hash");
    //     jwtAuth.processCommand(mockpA, mockpB, mockpC, mockPubSignals, mockExtraInput);
    //     vm.stopPrank();
    // }

    // function testRevert_authJwt_AzpIsNotWhitelisted() public {
    //     vm.startPrank(deployer);
    //     jwtProof.domainName = "https://example.com|12345";
    //     vm.expectRevert("azp is not whitelisted");
    //     jwtAuth.authJwt(jwtProof);
    //     vm.stopPrank();
    // }

    // function testRevert_authJwt_InvalidJwtProof() public {
    //     vm.startPrank(deployer);
    //     jwtProof.domainName = "https://example.com|12345";
    //     jwtProof.azp = "client-id-12345";
    //     vm.mockCall(
    //         address(verifier),
    //         abi.encodeWithSelector(IVerifier.verifyJwtProof.selector, jwtProof),
    //         abi.encode(false)
    //     );
    //     vm.expectRevert("invalid jwt proof");
    //     jwtAuth.authJwt(jwtProof);
    //     vm.stopPrank();
    // }

    // function test_authJwt() public {
    //     vm.startPrank(deployer);
    //     vm.mockCall(
    //         address(verifier),
    //         abi.encodeWithSelector(IVerifier.verifyJwtProof.selector, jwtProof),
    //         abi.encode(true)
    //     );
    //     vm.expectEmit(true, true, false, false);
    //     emit JwtAuth.JwtAuthed(
    //         jwtProof.jwtNullifier,
    //         jwtProof.isCodeExist,
    //         jwtProof.domainName,
    //         jwtProof.azp
    //     );
    //     jwtAuth.authJwt(jwtProof);
    //     vm.stopPrank();
    // }
}