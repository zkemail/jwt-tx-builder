import {
    generateJWTVerifierInputs,
    generateJWTAuthenticatorInputs,
    generateJWTAuthenticatorWithAnonDomainsInputs,
    RSAPublicKey,
} from "../src/input-generators";
import { generateJWT } from "../src/jwt";
import { InvalidInputError, JWTVerificationError } from "../src/errors";

describe("JWT Input Generators", () => {
    let validJWT: string;
    let validPublicKey: RSAPublicKey;
    let validAccountCode: bigint;

    beforeAll(() => {
        const header = {
            alg: "RS256",
            typ: "JWT",
            kid: "test-key-id",
        };
        const payload = {
            iss: "https://example.com",
            iat: Math.floor(Date.now() / 1000),
            azp: "client-123",
            email: "user@example.com",
            nonce: "Send 0.1 ETH to alice@example.com code 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        };

        const { rawJWT, publicKey } = generateJWT(header, payload);
        validJWT = rawJWT;
        validPublicKey = publicKey;
        validAccountCode = BigInt(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    });

    describe("generateJWTVerifierInputs", () => {
        it("should generate valid base inputs for JWT verification", async () => {
            const result = await generateJWTVerifierInputs(
                validJWT,
                validPublicKey
            );

            expect(result).toBeDefined();
            expect(result.message).toBeInstanceOf(Array);
            expect(result.messageLength).toBeDefined();
            expect(result.pubkey).toBeInstanceOf(Array);
            expect(result.signature).toBeInstanceOf(Array);
            expect(result.periodIndex).toBeDefined();
        });

        it("should throw InvalidInputError for empty JWT", async () => {
            await expect(
                generateJWTVerifierInputs("", validPublicKey)
            ).rejects.toThrow(InvalidInputError);
        });

        it("should throw InvalidInputError for non-string JWT", async () => {
            await expect(
                generateJWTVerifierInputs(123 as any, validPublicKey)
            ).rejects.toThrow(InvalidInputError);
        });

        it("should throw JWTVerificationError for invalid signature", async () => {
            const tamperedJWT = validJWT.slice(0, -5) + "XXXXX";
            await expect(
                generateJWTVerifierInputs(tamperedJWT, validPublicKey)
            ).rejects.toThrow(JWTVerificationError);
        });
    });

    describe("generateJWTAuthenticatorInputs", () => {
        it("should generate valid inputs for JWT authentication", async () => {
            const result = await generateJWTAuthenticatorInputs(
                validJWT,
                validPublicKey,
                validAccountCode
            );

            // Base verifier checks
            expect(result.message).toBeInstanceOf(Array);
            expect(result.messageLength).toBeDefined();
            expect(result.pubkey).toBeInstanceOf(Array);
            expect(result.signature).toBeInstanceOf(Array);

            // Authenticator-specific checks
            expect(result.accountCode).toBe(validAccountCode);
            expect(result.codeIndex).toBeDefined();
            expect(result.jwtKidStartIndex).toBeDefined();
            expect(result.issKeyStartIndex).toBeDefined();
            expect(result.issLength).toBeDefined();
            expect(result.iatKeyStartIndex).toBeDefined();
            expect(result.azpKeyStartIndex).toBeDefined();
            expect(result.azpLength).toBeDefined();
            expect(result.emailKeyStartIndex).toBeDefined();
            expect(result.emailLength).toBeDefined();
            expect(result.nonceKeyStartIndex).toBeDefined();
            expect(result.commandLength).toBeDefined();
            expect(result.emailDomainIndex).toBeDefined();
            expect(result.emailDomainLength).toBeDefined();
        });

        it("should throw InvalidInputError for invalid public key", async () => {
            const invalidPublicKey = { n: "invalid", e: "invalid" } as any;
            await expect(
                generateJWTAuthenticatorInputs(
                    validJWT,
                    invalidPublicKey,
                    validAccountCode
                )
            ).rejects.toThrow(InvalidInputError);
        });

        it("should handle maximum message length", async () => {
            const result = await generateJWTAuthenticatorInputs(
                validJWT,
                validPublicKey,
                validAccountCode,
                { maxMessageLength: 1000 }
            );
            expect(parseInt(result.messageLength)).toBeLessThanOrEqual(1000);
        });
    });

    describe("generateJWTAuthenticatorWithAnonDomainsInputs", () => {
        it("should generate valid inputs with anonymous domains", async () => {
            const result = await generateJWTAuthenticatorWithAnonDomainsInputs(
                validJWT,
                validPublicKey,
                validAccountCode,
                {
                    anonymousDomainsTreeHeight: 2,
                    anonymousDomainsTreeRoot: BigInt(
                        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                    ),
                    emailDomainPath: [
                        BigInt(
                            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        ),
                    ],
                    emailDomainPathHelper: [0],
                }
            );

            // Check authenticator inputs
            expect(result.accountCode).toBe(validAccountCode);
            expect(result.emailDomainIndex).toBeDefined();
            expect(result.emailDomainLength).toBeDefined();

            // Check anonymous domain specific inputs
            expect(result.anonymousDomainsTreeRoot).toBeDefined();
            expect(result.emailDomainPath).toBeInstanceOf(Array);
            expect(result.emailDomainPathHelper).toBeInstanceOf(Array);
        });

        it("should throw error when missing anonymous domain params", async () => {
            await expect(
                generateJWTAuthenticatorWithAnonDomainsInputs(
                    validJWT,
                    validPublicKey,
                    validAccountCode,
                    {}
                )
            ).rejects.toThrow(InvalidInputError);
        });
    });
});
