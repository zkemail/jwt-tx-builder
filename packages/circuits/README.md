# @zk-email/jwt-tx-builder-circuits

The `circuits` package exports the circom circuits needed for building on ZK-JWT.

All circuits in this package are libraries that can be imported to your circom project (i.e this package does not contain a `main` circuit).

## Installation

```bash
yarn add @zk-email/jwt-tx-builder-circuits
```

## JWT Auth Circuit

The [JWT Auth](./jwt-auth.circom) circuit is the core circuit for verifying JWT signatures and actions using the JWT Auth protocol.

### Usage

Import to your circuit file like below.

```circom
include "@zk-email/jwt-tx-builder-circuits/jwt-auth.circom";
```

-   Parameters:
    -   `n`: Number of bits per chunk the RSA key is split into. Recommended to be 121.
    -   `k`: Number of chunks the RSA key is split into. Recommended to be 17.
    -   `maxMessageLength`: Maximum length of the JWT message (header + payload).
    -   `maxB64HeaderLength`: Maximum length of the base64 encoded header.
    -   `maxB64PayloadLength`: Maximum length of the base64 encoded payload.
    -   `maxAzpLength`: Maximum length of the "azp" (authorized party) claim.
    -   `maxCommandLength`: Maximum length of the "command" claim.

> Note: We use these values for n and k because their product (n \* k) needs to be more than 2048 (RSA constraint) and n has to be less than half of 255 to fit in a circom signal.

-   Inputs:

    -   `message`: The JWT message (header + payload).
    -   `messageLength`: Actual length of the message signed in the JWT.
    -   `pubkey`: The RSA public key split into k chunks of n bits each.
    -   `signature`: The RSA signature split into k chunks of n bits each.
    -   `accountCode`: The account code. (Used in the context of a `jwt-wallet` to identify the smart wallet)
    -   `codeIndex`: The index of the "account code" in the "command".
    -   `periodIndex`: The index of the period in the JWT message.
    -   `jwtKidStartIndex`: The index of the "kid" in the JWT header.
    -   `issKeyStartIndex`: The index of the "iss" key in the JWT payload.
    -   `issLength`: The length of the "iss" claim in the JWT payload.
    -   `iatKeyStartIndex`: The index of the "iat" key in the JWT payload.
    -   `azpKeyStartIndex`: The index of the "azp" (authorized party) key in the JWT payload.
    -   `azpLength`: The length of the "azp" (authorized party) claim in the JWT payload.
    -   `emailKeyStartIndex`: The index of the "email" key in the JWT payload.
    -   `emailLength`: The length of the "email" claim in the JWT payload.
    -   `nonceKeyStartIndex`: The index of the "nonce" key in the JWT payload.
    -   `commandLength`: The length of the "command" claim in the "nonce" key in the JWT payload.
    -   `emailDomainIndex`: The index of the domain in the email.
    -   `emailDomainLength`: The length of the domain in the email.

-   Outputs:
    -   `kid`: The "kid" (key ID) claim in the JWT header.
    -   `iss`: The "iss" (issuer) claim in the JWT payload.
    -   `publicKeyHash`: The SHA256 hash of the RSA public key.
    -   `jwtNullifier`: The unique nullifier for the JWT.
    -   `timestamp`: The "iat" (issued at) claim in the JWT payload.
    -   `maskedCommand`: The "command" claim in the JWT payload with the "accountCode" masked and receiving email address masked.
    -   `accountSalt`: The "accountSalt" claim in the JWT payload.
    -   `azp`: The "azp" (authorized party) claim in the JWT payload.
    -   `domainName`: The domain name extracted from the email.
    -   `isCodeExist`: Whether the "accountCode" exists in the "command" claim.
