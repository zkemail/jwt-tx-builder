// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {JwtRegistry} from "../../src/utils/JwtRegistry.sol";
import {JwtProof, JwtVerifier} from "../../src/utils/JwtVerifier.sol";
import {JwtGroth16Verifier} from "../../src/utils/JwtGroth16Verifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {HexUtils} from "../../src/utils/HexUtils.sol";

contract JwtVerifierTest_verifyjwtProof is Test {
    using Strings for *;
    using HexUtils for bytes32;

    JwtVerifier verifier;

    address deployer = vm.addr(1);

    constructor() {}

    function setUp() public {
        bytes32 publicKeyHash =
            0x026fe6cf02399716650c42f1b9aaa9d71f2383392e217314198dfeb7208325d7;
        string memory issKidString = "random.website.com|5aaff47c21d06e266cce395b2145c7c6d4730ea5";
        string memory azpString = "demo-client-id";

        vm.startPrank(deployer);
        JwtRegistry jwtRegistry = new JwtRegistry(deployer);
        jwtRegistry.setJwtPublicKey(issKidString, publicKeyHash);
        jwtRegistry.whitelistAzp(azpString);

        // Check if the publicKeyHash is registered
        require(
            jwtRegistry.isJwtPublicKeyValid(issKidString, publicKeyHash),
            "JWT Public Key Hash should be registered"
        );

        JwtVerifier verifierImpl = new JwtVerifier();
        JwtGroth16Verifier groth16Verifier = new JwtGroth16Verifier();
        ERC1967Proxy verifierProxy = new ERC1967Proxy(
            address(verifierImpl),
            abi.encodeCall(
                verifierImpl.initialize,
                (msg.sender, address(groth16Verifier), address(jwtRegistry))
            )
        );
        verifier = JwtVerifier(address(verifierProxy));
        vm.stopPrank();
    }

    function test_verifyjwtProof() public {
        bytes32 accountCode = 0x1162ebff40918afe5305e68396f0283eb675901d0387f97d21928d423aaa0b54;

        // Verify the jwt proof
        string[] memory inputGenerationInput = new string[](2);
        inputGenerationInput[0] = string.concat(
            vm.projectRoot(),
            "/test/bin/generate.sh"
        );
        inputGenerationInput[1] = uint256(accountCode).toHexString(32);
        vm.ffi(inputGenerationInput);

        string memory publicInputFile = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/build_integration/public.json"
            )
        );
        string[] memory pubSignals = abi.decode(
            vm.parseJson(publicInputFile),
            (string[])
        );

        // kid -> pubSignals[0]
        bytes32 kid = bytes32(vm.parseUint(pubSignals[0]));
        string memory kidString = kid.bytes32ToHexString();
        // iss -> pubSignals[1] - pubSignals[2]
        string memory iss = "random.website.com";
        // publicKeyHash -> pubSignals[3]
        bytes32 publicKeyHash = bytes32(vm.parseUint(pubSignals[3]));
        // nullifier -> pubSignals[4]
        bytes32 jwtNullifier = bytes32(vm.parseUint(pubSignals[4]));
        // timestamp -> pubSignals[5]
        uint timeStamp = vm.parseUint(pubSignals[5]);
        // maskedCommand -> pubSignals[6] - pubSignals[25]
        string memory maskedCommand = "Send 0.12 ETH to 0x1234";
        // accountSalt -> pubSignals[26]
        bytes32 accountSalt = bytes32(vm.parseUint(pubSignals[26]));
        // azp -> pubSignals[27] - pubSignals[29]
        string memory azp = "demo-client-id";
        // isCodeExist -> pubSignals[30]
        bool isCodeExist = vm.parseUint(pubSignals[30]) == 1;

        JwtProof memory jwtProof;

        jwtProof.domainName = string(
            abi.encodePacked(iss, "|", kidString)
        );
        jwtProof.azp = azp;
        jwtProof.publicKeyHash = publicKeyHash;
        jwtProof.timestamp = timeStamp;
        jwtProof.maskedCommand = maskedCommand;
        jwtProof.jwtNullifier = jwtNullifier;
        jwtProof.accountSalt = accountSalt;
        jwtProof.isCodeExist = isCodeExist;
        jwtProof.proof = proofToBytes(
            string.concat(
                vm.projectRoot(),
                "/test/build_integration/proof.json"
            )
        );

        require(verifier.verifyJwtProof(jwtProof) == true, "verify failed");
    }

    function proofToBytes(
        string memory proofPath
    ) internal view returns (bytes memory) {
        string memory proofFile = vm.readFile(proofPath);
        string[] memory pi_a = abi.decode(
            vm.parseJson(proofFile, ".pi_a"),
            (string[])
        );
        uint256[2] memory pA = [vm.parseUint(pi_a[0]), vm.parseUint(pi_a[1])];
        string[][] memory pi_b = abi.decode(
            vm.parseJson(proofFile, ".pi_b"),
            (string[][])
        );
        uint256[2][2] memory pB = [
            [vm.parseUint(pi_b[0][1]), vm.parseUint(pi_b[0][0])],
            [vm.parseUint(pi_b[1][1]), vm.parseUint(pi_b[1][0])]
        ];
        string[] memory pi_c = abi.decode(
            vm.parseJson(proofFile, ".pi_c"),
            (string[])
        );
        uint256[2] memory pC = [vm.parseUint(pi_c[0]), vm.parseUint(pi_c[1])];
        bytes memory proof = abi.encode(pA, pB, pC);
        return proof;
    }
}
