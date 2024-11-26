import fs from "fs";
import path from "path";
import { wasm as wasm_tester } from "circom_tester";
const relayerUtils = require("@zk-email/relayer-utils");
import {
    generateJWTAuthenticatorInputs,
    generateJWTAuthenticatorWithAnonDomainsInputs,
    generateJWTVerifierInputs,
    RSAPublicKey,
} from "../../helpers/src/input-generators";
import { generateJWT } from "../../helpers/src/jwt";
import { splitJWT } from "../../helpers/src/utils";
import {
    createMerkleTree,
    MerkleTree,
    poseidonModular,
} from "../../helpers/src/merkle-tree";

describe("JWT Verifier Circuit", () => {
    jest.setTimeout(10 * 60 * 1000); // 10 minutes
    let circuit: any;
    let header: any;
    let payload: any;

    beforeAll(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "./test-circuits/jwt-verifier-test.circom"),
            {
                recompile: true,
                include: path.join(__dirname, "../../../node_modules"),
                output: path.join(__dirname, "./compiled-test-circuits"),
            }
        );

        header = {
            alg: "RS256",
            typ: "JWT",
            kid: "5aaff47c21d06e266cce395b2145c7c6d4730ea5",
        };

        payload = {
            iat: 1694989812,
            iss: "accounts.google.com",
        };
    });

    it("should verify a basic JWT", async () => {
        const { rawJWT, publicKey } = generateJWT(header, payload);

        const verifierInputs = await generateJWTVerifierInputs(
            rawJWT,
            publicKey,
            {
                maxMessageLength: 1024,
            }
        );

        const witness = await circuit.calculateWitness(verifierInputs);
        await circuit.checkConstraints(witness);

        // Verify public key hash
        const expectedPubKeyHash = relayerUtils.publicKeyHash(
            "0x" + Buffer.from(publicKey.n, "base64").toString("hex")
        );
        expect(BigInt(expectedPubKeyHash)).toEqual(witness[1]);
    });
});

describe("JWT Authenticator Circuit", () => {
    jest.setTimeout(10 * 60 * 1000); // 10 minutes

    let circuit: any;
    let header: any;
    let payload: any;
    let accountCode: bigint;
    let timestamp: number;
    let issuer: string;
    let azp: string;
    let email: string;
    let kid: bigint;

    beforeAll(async () => {
        circuit = await wasm_tester(
            path.join(
                __dirname,
                "./test-circuits/jwt-auth-test.circom"
            ),
            {
                recompile: true,
                include: path.join(__dirname, "../../../node_modules"),
                output: path.join(__dirname, "./compiled-test-circuits"),
            }
        );

        accountCode = await relayerUtils.genAccountCode();

        kid = BigInt("0x5aaff47c21d06e266cce395b2145c7c6d4730ea5");
        issuer = "random.website.com";
        timestamp = 1694989812;
        azp = "demo-client-id";
        email = "dummy@gmail.com";

        header = {
            alg: "RS256",
            typ: "JWT",
            kid: kid.toString(16),
        };

        payload = {
            email,
            iat: timestamp,
            azp,
            iss: issuer,
        };
    });

    it("Verify a jwt whose command has an email address", async () => {
        const { rawJWT, publicKey } = generateJWT(header, {
            ...payload,
            nonce: "Send 0.1 ETH to alice@gmail.com",
        });

        const jwtVerifierInputs = await generateJWTAuthenticatorInputs(
            rawJWT,
            publicKey,
            accountCode,
            {
                maxMessageLength: 1024,
            }
        );

        const witness = await circuit.calculateWitness(jwtVerifierInputs);
        await circuit.checkConstraints(witness);

        // kid
        expect(BigInt(kid)).toEqual(witness[1]);

        // issuer
        const paddedIssuer = relayerUtils.padString(issuer, 32);
        const issuerFields = relayerUtils.bytes2Fields(paddedIssuer);
        for (let i = 0; i < issuerFields.length; i++) {
            expect(BigInt(issuerFields[i])).toEqual(witness[1 + 1 + i]);
        }

        // publicKeyHash
        const expectedPubKeyHash = relayerUtils.publicKeyHash(
            "0x" + Buffer.from(publicKey.n, "base64").toString("hex")
        );
        expect(BigInt(expectedPubKeyHash)).toEqual(
            witness[1 + 1 + issuerFields.length]
        );

        // jwtNullifier
        const [, , signature] = splitJWT(rawJWT);
        const expectedJwtNullifier = relayerUtils.emailNullifier(
            "0x" + Buffer.from(signature, "base64").toString("hex")
        );
        expect(BigInt(expectedJwtNullifier)).toEqual(
            witness[1 + 1 + issuerFields.length + 1]
        );

        // timestamp
        expect(timestamp).toEqual(
            parseInt(witness[1 + 1 + issuerFields.length + 2])
        );

        // maskedCommand
        const maskedCommand = "Send 0.1 ETH to ";
        const paddedMaskedCommand = relayerUtils.padString(maskedCommand, 605);
        const maskedCommandFields =
            relayerUtils.bytes2Fields(paddedMaskedCommand);
        for (let i = 0; i < maskedCommandFields.length; ++i) {
            expect(BigInt(maskedCommandFields[i])).toEqual(
                witness[1 + 1 + issuerFields.length + 3 + i]
            );
        }

        // accountSalt
        const accountSalt = relayerUtils.accountSalt(email, accountCode);
        expect(BigInt(accountSalt)).toEqual(
            witness[
                1 + 1 + issuerFields.length + 3 + maskedCommandFields.length
            ]
        );

        // azp
        const paddedAzp = relayerUtils.padString(azp, 72);
        const azpFields = relayerUtils.bytes2Fields(paddedAzp);
        for (let i = 0; i < azpFields.length; i++) {
            expect(BigInt(azpFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        i
                ]
            );
        }

        // domainName
        const paddedDomain = relayerUtils.padString("gmail.com", 255);
        const expectedDomainFields = relayerUtils.bytes2Fields(paddedDomain);
        for (let i = 0; i < expectedDomainFields.length; i++) {
            expect(BigInt(expectedDomainFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        azpFields.length +
                        i
                ]
            );
        }

        // isCodeExist
        expect(0n).toEqual(
            witness[
                1 +
                    1 +
                    issuerFields.length +
                    3 +
                    maskedCommandFields.length +
                    1 +
                    azpFields.length +
                    expectedDomainFields.length
            ]
        );
    });

    it("Verify a jwt whose command does not have an email address", async () => {
        const { rawJWT, publicKey } = generateJWT(header, {
            ...payload,
            nonce: "Swap 1 ETH to DAI",
        });

        const jwtVerifierInputs = await generateJWTAuthenticatorInputs(
            rawJWT,
            publicKey,
            accountCode,
            {
                maxMessageLength: 1024,
            }
        );

        const witness = await circuit.calculateWitness(jwtVerifierInputs);
        await circuit.checkConstraints(witness);

        // kid
        expect(BigInt(kid)).toEqual(witness[1]);

        // issuer
        const paddedIssuer = relayerUtils.padString(issuer, 32);
        const issuerFields = relayerUtils.bytes2Fields(paddedIssuer);
        for (let i = 0; i < issuerFields.length; i++) {
            expect(BigInt(issuerFields[i])).toEqual(witness[1 + 1 + i]);
        }

        // publicKeyHash
        const expectedPubKeyHash = relayerUtils.publicKeyHash(
            "0x" + Buffer.from(publicKey.n, "base64").toString("hex")
        );
        expect(BigInt(expectedPubKeyHash)).toEqual(
            witness[1 + 1 + issuerFields.length]
        );

        // jwtNullifier
        const [, , signature] = splitJWT(rawJWT);
        const expectedJwtNullifier = relayerUtils.emailNullifier(
            "0x" + Buffer.from(signature, "base64").toString("hex")
        );
        expect(BigInt(expectedJwtNullifier)).toEqual(
            witness[1 + 1 + issuerFields.length + 1]
        );

        // timestamp
        expect(timestamp).toEqual(
            parseInt(witness[1 + 1 + issuerFields.length + 2])
        );

        // maskedCommand
        const maskedCommand = "Swap 1 ETH to DAI";
        const paddedMaskedCommand = relayerUtils.padString(maskedCommand, 605);
        const maskedCommandFields =
            relayerUtils.bytes2Fields(paddedMaskedCommand);
        for (let i = 0; i < maskedCommandFields.length; ++i) {
            expect(BigInt(maskedCommandFields[i])).toEqual(
                witness[1 + 1 + issuerFields.length + 3 + i]
            );
        }

        // accountSalt
        const accountSalt = relayerUtils.accountSalt(email, accountCode);
        expect(BigInt(accountSalt)).toEqual(
            witness[
                1 + 1 + issuerFields.length + 3 + maskedCommandFields.length
            ]
        );

        // azp
        const paddedAzp = relayerUtils.padString(azp, 72);
        const azpFields = relayerUtils.bytes2Fields(paddedAzp);
        for (let i = 0; i < azpFields.length; i++) {
            expect(BigInt(azpFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        i
                ]
            );
        }

        // domainName
        const paddedDomain = relayerUtils.padString("gmail.com", 255);
        const expectedDomainFields = relayerUtils.bytes2Fields(paddedDomain);
        for (let i = 0; i < expectedDomainFields.length; i++) {
            expect(BigInt(expectedDomainFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        azpFields.length +
                        i
                ]
            );
        }

        // isCodeExist
        expect(0n).toEqual(
            witness[
                1 +
                    1 +
                    issuerFields.length +
                    3 +
                    maskedCommandFields.length +
                    1 +
                    azpFields.length +
                    expectedDomainFields.length
            ]
        );
    });

    it("Verify a jwt whose command has an email address and an invitation code", async () => {
        const { rawJWT, publicKey } = generateJWT(header, {
            ...payload,
            nonce: `Send 0.12 ETH to alice@gmail.com code ${accountCode
                .toString(16)
                .slice(2)}`,
        });

        const jwtVerifierInputs = await generateJWTAuthenticatorInputs(
            rawJWT,
            publicKey,
            accountCode,
            {
                maxMessageLength: 1024,
            }
        );

        const witness = await circuit.calculateWitness(jwtVerifierInputs);
        await circuit.checkConstraints(witness);

        // kid
        expect(BigInt(kid)).toEqual(witness[1]);

        // issuer
        const paddedIssuer = relayerUtils.padString(issuer, 32);
        const issuerFields = relayerUtils.bytes2Fields(paddedIssuer);
        for (let i = 0; i < issuerFields.length; i++) {
            expect(BigInt(issuerFields[i])).toEqual(witness[1 + 1 + i]);
        }

        // publicKeyHash
        const expectedPubKeyHash = relayerUtils.publicKeyHash(
            "0x" + Buffer.from(publicKey.n, "base64").toString("hex")
        );
        expect(BigInt(expectedPubKeyHash)).toEqual(
            witness[1 + 1 + issuerFields.length]
        );

        // jwtNullifier
        const [, , signature] = splitJWT(rawJWT);
        const expectedJwtNullifier = relayerUtils.emailNullifier(
            "0x" + Buffer.from(signature, "base64").toString("hex")
        );
        expect(BigInt(expectedJwtNullifier)).toEqual(
            witness[1 + 1 + issuerFields.length + 1]
        );

        // timestamp
        expect(timestamp).toEqual(
            parseInt(witness[1 + 1 + issuerFields.length + 2])
        );

        // maskedCommand
        const maskedCommand = "Send 0.12 ETH to ";
        const paddedMaskedCommand = relayerUtils.padString(maskedCommand, 605);
        const maskedCommandFields =
            relayerUtils.bytes2Fields(paddedMaskedCommand);
        for (let i = 0; i < maskedCommandFields.length; ++i) {
            expect(BigInt(maskedCommandFields[i])).toEqual(
                witness[1 + 1 + issuerFields.length + 3 + i]
            );
        }

        // accountSalt
        const accountSalt = relayerUtils.accountSalt(email, accountCode);
        expect(BigInt(accountSalt)).toEqual(
            witness[
                1 + 1 + issuerFields.length + 3 + maskedCommandFields.length
            ]
        );

        // azp
        const paddedAzp = relayerUtils.padString(azp, 72);
        const azpFields = relayerUtils.bytes2Fields(paddedAzp);
        for (let i = 0; i < azpFields.length; i++) {
            expect(BigInt(azpFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        i
                ]
            );
        }

        // domainName
        const paddedDomain = relayerUtils.padString("gmail.com", 255);
        const expectedDomainFields = relayerUtils.bytes2Fields(paddedDomain);
        for (let i = 0; i < expectedDomainFields.length; i++) {
            expect(BigInt(expectedDomainFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        azpFields.length +
                        i
                ]
            );
        }

        // isCodeExist
        expect(1n).toEqual(
            witness[
                1 +
                    1 +
                    issuerFields.length +
                    3 +
                    maskedCommandFields.length +
                    1 +
                    azpFields.length +
                    expectedDomainFields.length
            ]
        );
    });

    it("Verify a jwt whose command has an invitation code", async () => {
        const { rawJWT, publicKey } = generateJWT(header, {
            ...payload,
            nonce: `Re: Accept guardian request for 0x04884491560f38342C56E26BDD0fEAbb68E2d2FC code ${accountCode
                .toString(16)
                .slice(2)}`,
        });

        const jwtVerifierInputs = await generateJWTAuthenticatorInputs(
            rawJWT,
            publicKey,
            accountCode,
            {
                maxMessageLength: 1024,
            }
        );

        const witness = await circuit.calculateWitness(jwtVerifierInputs);
        await circuit.checkConstraints(witness);

        // kid
        expect(BigInt(kid)).toEqual(witness[1]);

        // issuer
        const paddedIssuer = relayerUtils.padString(issuer, 32);
        const issuerFields = relayerUtils.bytes2Fields(paddedIssuer);
        for (let i = 0; i < issuerFields.length; i++) {
            expect(BigInt(issuerFields[i])).toEqual(witness[1 + 1 + i]);
        }

        // publicKeyHash
        const expectedPubKeyHash = relayerUtils.publicKeyHash(
            "0x" + Buffer.from(publicKey.n, "base64").toString("hex")
        );
        expect(BigInt(expectedPubKeyHash)).toEqual(
            witness[1 + 1 + issuerFields.length]
        );

        // jwtNullifier
        const [, , signature] = splitJWT(rawJWT);
        const expectedJwtNullifier = relayerUtils.emailNullifier(
            "0x" + Buffer.from(signature, "base64").toString("hex")
        );
        expect(BigInt(expectedJwtNullifier)).toEqual(
            witness[1 + 1 + issuerFields.length + 1]
        );

        // timestamp
        expect(timestamp).toEqual(
            parseInt(witness[1 + 1 + issuerFields.length + 2])
        );

        // maskedCommand
        const maskedCommand =
            "Re: Accept guardian request for 0x04884491560f38342C56E26BDD0fEAbb68E2d2FC";
        const paddedMaskedCommand = relayerUtils.padString(maskedCommand, 605);
        const maskedCommandFields =
            relayerUtils.bytes2Fields(paddedMaskedCommand);
        for (let i = 0; i < maskedCommandFields.length; ++i) {
            expect(BigInt(maskedCommandFields[i])).toEqual(
                witness[1 + 1 + issuerFields.length + 3 + i]
            );
        }

        // accountSalt
        const accountSalt = relayerUtils.accountSalt(email, accountCode);
        expect(BigInt(accountSalt)).toEqual(
            witness[
                1 + 1 + issuerFields.length + 3 + maskedCommandFields.length
            ]
        );

        // azp
        const paddedAzp = relayerUtils.padString(azp, 72);
        const azpFields = relayerUtils.bytes2Fields(paddedAzp);
        for (let i = 0; i < azpFields.length; i++) {
            expect(BigInt(azpFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        i
                ]
            );
        }

        // domainName
        const paddedDomain = relayerUtils.padString("gmail.com", 255);
        const expectedDomainFields = relayerUtils.bytes2Fields(paddedDomain);
        for (let i = 0; i < expectedDomainFields.length; i++) {
            expect(BigInt(expectedDomainFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        azpFields.length +
                        i
                ]
            );
        }

        // isCodeExist
        expect(1n).toEqual(
            witness[
                1 +
                    1 +
                    issuerFields.length +
                    3 +
                    maskedCommandFields.length +
                    1 +
                    azpFields.length +
                    expectedDomainFields.length
            ]
        );
    });

    // @Note - Needs an actual Google Sign-In JWT to run
    it.skip("Verify a real Google Sign-In JWT", async () => {
        const googleSignInData = JSON.parse(
            fs.readFileSync(
                path.join(__dirname, "test-jwts/google-sign-in.json"),
                "utf8"
            )
        );
        const rawJWT = googleSignInData.idToken;
        const publicKey: RSAPublicKey = {
            e: 65537,
            n: googleSignInData.publicKeys.keys[1].n,
        };

        const jwtVerifierInputs = await generateJWTAuthenticatorInputs(
            rawJWT,
            publicKey,
            accountCode,
            {
                maxMessageLength: 1024,
            }
        );

        const witness = await circuit.calculateWitness(jwtVerifierInputs);
        await circuit.checkConstraints(witness);

        const [header, payload, signature] = splitJWT(rawJWT);
        const decodedPayload = JSON.parse(
            Buffer.from(payload, "base64").toString()
        );

        // kid
        const expectedKid = BigInt(
            "0x" + googleSignInData.publicKeys.keys[1].kid
        );
        expect(expectedKid).toEqual(witness[1]);

        // issuer
        const paddedIssuer = relayerUtils.padString(decodedPayload.iss, 32);
        const issuerFields = relayerUtils.bytes2Fields(paddedIssuer);
        for (let i = 0; i < issuerFields.length; i++) {
            expect(BigInt(issuerFields[i])).toEqual(witness[1 + 1 + i]);
        }

        // publicKeyHash
        const expectedPubKeyHash = relayerUtils.publicKeyHash(
            "0x" + Buffer.from(publicKey.n, "base64").toString("hex")
        );
        expect(BigInt(expectedPubKeyHash)).toEqual(
            witness[1 + 1 + issuerFields.length]
        );

        // jwtNullifier
        const expectedJwtNullifier = relayerUtils.emailNullifier(
            "0x" + Buffer.from(signature, "base64").toString("hex")
        );
        expect(BigInt(expectedJwtNullifier)).toEqual(
            witness[1 + 1 + issuerFields.length + 1]
        );

        // timestamp
        expect(decodedPayload.iat).toEqual(
            parseInt(witness[1 + 1 + issuerFields.length + 2])
        );

        // maskedCommand (in this case, there's no command, so it should be empty)
        const maskedCommand = "Swap 1 ETH to DAI";
        const paddedMaskedCommand = relayerUtils.padString(maskedCommand, 605);
        const maskedCommandFields =
            relayerUtils.bytes2Fields(paddedMaskedCommand);
        for (let i = 0; i < maskedCommandFields.length; ++i) {
            expect(BigInt(maskedCommandFields[i])).toEqual(
                witness[1 + 1 + issuerFields.length + 3 + i]
            );
        }

        // accountSalt
        const accountSalt = relayerUtils.accountSalt(
            decodedPayload.email,
            accountCode
        );
        expect(BigInt(accountSalt)).toEqual(
            witness[
                1 + 1 + issuerFields.length + 3 + maskedCommandFields.length
            ]
        );

        // azp
        const paddedAzp = relayerUtils.padString(decodedPayload.azp, 72);
        const azpFields = relayerUtils.bytes2Fields(paddedAzp);
        for (let i = 0; i < azpFields.length; i++) {
            expect(BigInt(azpFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        i
                ]
            );
        }

        // domainName
        const paddedDomain = relayerUtils.padString("gmail.com", 255);
        const expectedDomainFields = relayerUtils.bytes2Fields(paddedDomain);
        for (let i = 0; i < expectedDomainFields.length; i++) {
            expect(BigInt(expectedDomainFields[i])).toEqual(
                witness[
                    1 +
                        1 +
                        issuerFields.length +
                        3 +
                        maskedCommandFields.length +
                        1 +
                        azpFields.length +
                        i
                ]
            );
        }

        // isCodeExist (should be 0 as there's no invitation code in this JWT)
        expect(0n).toEqual(
            witness[
                1 +
                    1 +
                    issuerFields.length +
                    3 +
                    maskedCommandFields.length +
                    1 +
                    azpFields.length +
                    expectedDomainFields.length
            ]
        );
    });
});

describe("Anonymous Email Domains", () => {
    let circuit: any;
    let header: any;
    let accountCode: bigint;
    let kid: bigint;
    let anonymousDomainsTree: MerkleTree;
    const domains = [
        "anonymous.relay",
        "protonmail.com",
        "tutanota.com",
        "gmail.com",
    ];

    async function createAnonymousDomainsTree(
        domains: string[],
        height: number
    ) {
        const paddedDomains = domains.map(
            (domain) => relayerUtils.padString(domain, 255) // DOMAIN_MAX_BYTES
        );
        const domainFields = paddedDomains.map((paddedDomain) =>
            relayerUtils.bytes2Fields(paddedDomain)
        );
        const domainLeaves = await Promise.all(
            domainFields.map((field) => poseidonModular(field))
        );
        return createMerkleTree(height, domainLeaves);
    }

    beforeAll(async () => {
        circuit = await wasm_tester(
            path.join(
                __dirname,
                "./test-circuits/jwt-auth-with-anon-email-domains-test.circom"
            ),
            {
                recompile: true,
                include: path.join(__dirname, "../../../node_modules"),
                output: path.join(__dirname, "./compiled-test-circuits"),
            }
        );

        accountCode = await relayerUtils.genAccountCode();
        kid = BigInt("0x5aaff47c21d06e266cce395b2145c7c6d4730ea5");

        header = {
            alg: "RS256",
            typ: "JWT",
            kid: kid.toString(16),
        };

        anonymousDomainsTree = await createAnonymousDomainsTree(domains, 2);
    });

    it("should support anonymous domains", async () => {
        const email = "user@gmail.com";
        const timestamp = Math.floor(Date.now() / 1000);

        const payload = {
            email,
            iat: timestamp,
            azp: "demo-client-id",
            iss: "accounts.google.com",
            nonce: "Send 0.1 ETH to recipient@gmail.com",
        };

        const { rawJWT, publicKey } = generateJWT(header, payload);

        const emailDomainProof = anonymousDomainsTree.getProof(
            domains.indexOf("gmail.com")
        );

        const jwtVerifierInputs =
            await generateJWTAuthenticatorWithAnonDomainsInputs(
                rawJWT,
                publicKey,
                accountCode,
                {
                    maxMessageLength: 1024,
                    verifyAnonymousDomains: true,
                    anonymousDomainsTreeHeight: 4,
                    anonymousDomainsTreeRoot: anonymousDomainsTree.getRoot(),
                    emailDomainPath: emailDomainProof.proof,
                    emailDomainPathHelper: emailDomainProof.pathIndices,
                }
            );

        const witness = await circuit.calculateWitness(jwtVerifierInputs);
        await circuit.checkConstraints(witness);
        expect(witness[41]).toEqual(anonymousDomainsTree.getRoot());
    });
});
