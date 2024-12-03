# @zk-email/jwt-tx-builder-helpers

The @zk-email/jwt-tx-builder-helpers package provides utility functions for JWT verification and cryptographic operations. It includes functions for handling RSA signatures, public keys, JWT messages, and hashes.

## Installation

```bash
yarn add @zk-email/jwt-tx-builder-helpers
```

### input-generators.ts

The [input-generators.ts](./src/input-generators.ts) file provides functions for generating inputs to the JWT Auth circuit. It includes utilities for JWT verification, input generation, and handling anonymous domains.

#### Key Interfaces:

```typescript
export interface RSAPublicKey {
    n: string; // Base64-encoded modulus
    e: number; // Public exponent
}

export interface JWTInputGenerationArgs {
    maxMessageLength?: number;
    verifyAnonymousDomains?: boolean;
    anonymousDomainsTreeHeight?: number;
    anonymousDomainsTreeRoot?: bigint;
    emailDomainPath?: bigint[];
    emailDomainPathHelper?: number[];
}
```

#### Main Function:

```typescript
async function generateJWTVerifierInputs(
    rawJWT: string,
    publicKey: RSAPublicKey,
    accountCode: bigint,
    params: JWTInputGenerationArgs = {}
);
```

## Testing

To test the input generator, you can run the following command:

```bash
yarn test
```
