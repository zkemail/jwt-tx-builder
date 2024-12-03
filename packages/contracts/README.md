# JWT Contracts

This directory contains verifier contracts for handling JSON Web Tokens(JWTs) proofs. 

## Contracts Overview

### JWTRegistry

- **Purpose**: The `JWTRegistry` contract is used to store and manage JWTs. It keeps track of all issued tokens and their statuses.
- **Usage**: In another project, you can use this contract to verify if a JWT is valid and to check its status (active, revoked, etc.).

### JWTVerifier

- **Purpose**: The `JWTVerifier` contract is responsible for verifying the authenticity of JWTs. It checks the proof and ensures the token is valid.
- **Usage**: Use this contract in your project to verify JWTs proof before granting access to protected resources.

## Build

To build the project, run the following command:

```
yarn build
```

## Unit Tests

To run unit tests, use the following command:

```
yarn test:unit
```

## Integration Tests

To run integration tests, use the following command:

```
yarn test:integration
```

## Deployment

To deploy, run the following commands:

```
foundryup
source .env
forge script script/Deploy_jwtRegistry.s.sol:DeployScript --rpc-url $RPC_URL --broadcast --verify -vvvv --sender $ETH_FROM
```

## How to Use in Another Project

1. **Installation**: First, install the package using yarn. Run the following command in your project directory:

   ```
   yarn add @zk-email/jwt-tx-builder-contracts 
   ```

2. **Integration**: 

   - **Foundry**: Add the following line to remappings.txt:

   ```text
   @zk-email/jwt-tx-builder-contracts=../../node_modules/@zk-email/jwt-tx-builder-contracts/src
   ```

   - **Solidity**: Import the contracts in your Solidity files using the following syntax:

     ```solidity
     // Import necessary contracts for JWT verification
     import {JwtVerifier} from "@zk-email/jwt-tx-builder-contracts/utils/JwtVerifier.sol";
     import {JwtGroth16Verifier} from "@zk-email/jwt-tx-builder-contracts/utils/JwtGroth16Verifier.sol";
     import {JwtRegistry} from "@zk-email/jwt-tx-builder-contracts/utils/JwtRegistry.sol";
     ```

     You can use the imported contracts as follows:

     ```solidity
     IVerifier jwtVerifier;
     JwtRegistry jwtRegistry;

     // Create jwt registry and set DKIM public key hash
     jwtRegistry = new JwtRegistry(deployer);
     jwtRegistry.setDKIMPublicKeyHash(
         "12345|https://example.com|client-id-12345",
         publicKeyHash
     );

     // Create JwtVerifier and initialize with proxy
     {
         JwtVerifier verifierImpl = new JwtVerifier();
         console.log(
             "JwtVerifier implementation deployed at: %s",
             address(verifierImpl)
         );
         JwtGroth16Verifier groth16Verifier = new JwtGroth16Verifier();
         ERC1967Proxy verifierProxy = new ERC1967Proxy(
             address(verifierImpl),
             abi.encodeCall(
                 verifierImpl.initialize,
                 (msg.sender, address(groth16Verifier))
             )
         );
         jwtVerifier = IVerifier(address(verifierProxy));
     }
     ```

## Sample Deployed Addresses

Here are some example addresses where the contracts have been deployed on Base Sepolia test network:

- **JWTRegistry**: `0x60Dd906E3D1d827d23Bd393aa3224fb38cac1A11`
- **JWTVerifier Implementation**: `0x020FD65080C114AB55Cdeb018db197f3A8751B7F`
- **JWTVerifier Proxy**: `0xD3863Ad6AD48e3dEc3736d335967b4117f64ce49`

## Troubleshooting

If you encounter a `CreateCollision` error, it means the salt in your `.env` file is already used. Try using a different salt value.

```
Error:
script failed: <empty revert data>
```

This error indicates a problem with the deployment script. Check your environment variables and try again.
