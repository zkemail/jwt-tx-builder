// script/Deploy.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Script.sol";
import "../src/utils/JwtRegistry.sol";
import "../src/utils/JwtVerifier.sol";
import "../src/utils/JwtGroth16Verifier.sol";
import "../src/JwtAuth.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// 1. `source .env`
// 2. `forge script script/Deploy_jwtAuth.s.sol:DeployScript --rpc-url $RPC_URL --verify --etherscan-api-key $ETHERSCAN_API_KEY --broadcast -vvvv`
contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        bytes32 salt = keccak256(abi.encodePacked(vm.envString("DEPLOY_SALT")));
        address initialOwner = deployer;

        vm.startBroadcast(deployerPrivateKey);

        // Deploy the contract using CREATE2
        JwtRegistry jwtRegistry = new JwtRegistry{salt: salt}(deployer);

        console.log("JwtRegistry deployed to:", address(jwtRegistry));

        JwtVerifier jwtVerifierImpl = new JwtVerifier();
        console.log(
            "JWTVerifier implementation deployed at: %s",
            address(jwtVerifierImpl)
        );
        JwtGroth16Verifier groth16Verifier = new JwtGroth16Verifier();
        ERC1967Proxy jwtVerifierProxy = new ERC1967Proxy{salt: salt}(
            address(jwtVerifierImpl),
            abi.encodeCall(
                jwtVerifierImpl.initialize,
                (initialOwner, address(groth16Verifier))
            )
        );

        JwtVerifier verifier = JwtVerifier(address(jwtVerifierProxy));
        console.log("JWTVerifier proxy deployed to:", address(verifier));

        JwtAuth authImpl = new JwtAuth();
        ERC1967Proxy authProxy = new ERC1967Proxy(
            address(authImpl),
            abi.encodeCall(authImpl.initialize, (deployer))
        );
        JwtAuth jwtAuth = JwtAuth(address(authProxy));
        console.log("JwtAuth proxy deployed to:", address(jwtAuth));

        jwtAuth.initJwtRegistry(address(jwtRegistry));
        console.log("JwtRegistry address has been set in JwtAuth");
        jwtAuth.initVerifier(address(verifier));
        console.log("JwtVerifier address has been set in JwtAuth");
        jwtRegistry.updateJwtAuth(address(jwtAuth));
        console.log("JwtAuth address has been updated in JwtRegistry");

        vm.stopBroadcast();
    }
}