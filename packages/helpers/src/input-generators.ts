/**
 * @module input-generators
 * @description Generates circuit inputs for JWT verification with optional anonymous domain support
 */

import {
    Uint8ArrayToCharArray,
    toCircomBigIntBytes,
    sha256Pad,
} from "@zk-email/helpers";
import { verifyJWT } from "./jwt";
import { base64ToBigInt, splitJWT } from "./utils";
import { MAX_JWT_PADDED_BYTES } from "./constants";
import { InvalidInputError, JWTVerificationError } from "./errors";

/** RSA public key interface */
export interface RSAPublicKey {
    /** Base64-encoded modulus */
    n: string;
    /** Public exponent */
    e: number;
}

/** Input generation configuration options */
export interface JWTInputGenerationArgs {
    /** Max length of the JWT message including padding */
    maxMessageLength?: number;
    /** Enable anonymous domain verification */
    verifyAnonymousDomains?: boolean;
    /** Height of the Merkle tree for anonymous domains */
    anonymousDomainsTreeHeight?: number;
    /** Root of the Merkle tree for anonymous domains */
    anonymousDomainsTreeRoot?: bigint;
    /** Merkle proof path for the email domain */
    emailDomainPath?: bigint[];
    /** Helper values for the Merkle proof */
    emailDomainPathHelper?: number[];
}

/** Base JWT verifier inputs interface */
export interface JWTVerifierInputs {
    message: string[];
    messageLength: string;
    pubkey: string[];
    signature: string[];
    periodIndex: string;
}

/** JWT authenticator inputs interface */
export interface JWTAuthenticatorInputs extends JWTVerifierInputs {
    accountCode: bigint;
    codeIndex: string;
    jwtKidStartIndex: string;
    issKeyStartIndex: string;
    issLength: string;
    iatKeyStartIndex: string;
    azpKeyStartIndex: string;
    azpLength: string;
    emailKeyStartIndex: string;
    emailLength: string;
    nonceKeyStartIndex: string;
    commandLength: string;
    emailDomainIndex: string;
    emailDomainLength: number;
}

/** Anonymous domain authenticator inputs interface */
export interface JWTAuthenticatorWithAnonDomainsInputs
    extends JWTAuthenticatorInputs {
    anonymousDomainsTreeRoot: string;
    emailDomainPath: string[];
    emailDomainPathHelper: string[];
}

/**
 * Finds the index of an account code within a nonce string
 * @param nonce - The nonce string to search in
 * @param accountCode - The account code to find
 * @returns The index of the code or 0 if not found
 */
function findCodeIndex(nonce: string | undefined, accountCode: bigint): number {
    if (!nonce) return 0;
    const index = nonce.indexOf(accountCode.toString(16).slice(2));
    return index >= 0 ? index : 0;
}

/**
 * Extracts domain and its index from an email address
 * @param email - Email address to parse
 * @returns Object containing domain and its index
 * @throws Error if email format is invalid
 */
function getDomainFromEmail(email: string): { domain: string; index: number } {
    const match = email.match(/@(.+)$/);
    if (!match) {
        throw new Error(`Invalid email format: ${email}`);
    }
    return {
        domain: match[1],
        index: match.index! + 1,
    };
}

// Helper functions (implement these based on the extracted functionality)
function validateInputs(rawJWT: string, publicKey: RSAPublicKey): void {
    if (!rawJWT || typeof rawJWT !== "string") {
        throw new InvalidInputError("Invalid JWT: Must be a non-empty string");
    }
    if (
        !publicKey ||
        typeof publicKey.n !== "string" ||
        typeof publicKey.e !== "number"
    ) {
        throw new InvalidInputError("Invalid public key");
    }
}

async function verifyJWTSignature(
    rawJWT: string,
    publicKey: RSAPublicKey
): Promise<void> {
    try {
        const isVerified = await verifyJWT(rawJWT, publicKey);
        if (!isVerified) {
            throw new JWTVerificationError(
                "JWT verification failed: Invalid signature"
            );
        }
    } catch (error: any) {
        throw new JWTVerificationError(
            `JWT verification failed: ${error.message}`
        );
    }
}

function prepareMessage(
    headerString: string,
    payloadString: string,
    params: JWTInputGenerationArgs
): [Uint8Array, number] {
    const message = Buffer.from(`${headerString}.${payloadString}`);
    return sha256Pad(message, params.maxMessageLength || MAX_JWT_PADDED_BYTES);
}

function decodeJWT(
    headerString: string,
    payloadString: string
): { header: string; payload: string; parsedPayload: any } {
    const header = Buffer.from(headerString, "base64").toString("utf-8");
    const payload = Buffer.from(payloadString, "base64").toString("utf-8");
    try {
        const parsedPayload = JSON.parse(payload);
        return { header, payload, parsedPayload };
    } catch (error) {
        throw new InvalidInputError("Invalid JWT payload: Not a valid JSON");
    }
}

function validateAnonymousDomainParams(params: JWTInputGenerationArgs): void {
    if (
        !params.anonymousDomainsTreeRoot ||
        !params.emailDomainPath ||
        !params.emailDomainPathHelper
    ) {
        throw new InvalidInputError(
            "Anonymous domains tree root, email domain path, and email domain path helper are required when verifyAnonymousDomains is true"
        );
    }
}

/**
 * Finds all required indices in JWT header and payload
 */
function findJWTIndices(header: string, payload: string) {
    return {
        jwtKidStartIndex: header.indexOf('"kid":').toString(),
        issKeyStartIndex: payload.indexOf('"iss":').toString(),
        iatKeyStartIndex: payload.indexOf('"iat":').toString(),
        azpKeyStartIndex: payload.indexOf('"azp":').toString(),
        emailKeyStartIndex: payload.indexOf('"email":').toString(),
        nonceKeyStartIndex: payload.indexOf('"nonce":').toString(),
    };
}

/**
 * Calculates lengths of required JWT payload fields
 */
function calculateLengths(parsedPayload: any) {
    return {
        issLength: (parsedPayload.iss?.length ?? 0).toString(),
        azpLength: (parsedPayload.azp?.length ?? 0).toString(),
        emailLength: (parsedPayload.email?.length ?? 0).toString(),
        commandLength: (parsedPayload.nonce?.length ?? 0).toString(),
    };
}

function handleError(error: any): never {
    if (
        error instanceof JWTVerificationError ||
        error instanceof InvalidInputError
    ) {
        throw error;
    }
    throw new Error(
        `Unexpected error in generateJWTVerifierInputs: ${error.message}`
    );
}

/**
 * Generates base JWT verifier circuit inputs
 */
export async function generateJWTVerifierInputs(
    rawJWT: string,
    publicKey: RSAPublicKey,
    params: JWTInputGenerationArgs = {}
): Promise<JWTVerifierInputs> {
    try {
        validateInputs(rawJWT, publicKey);
        const [headerString, payloadString, signatureString] = splitJWT(rawJWT);
        await verifyJWTSignature(rawJWT, publicKey);

        const periodIndex = rawJWT.indexOf(".");
        const [messagePadded, messagePaddedLen] = prepareMessage(
            headerString,
            payloadString,
            params
        );

        return {
            message: Uint8ArrayToCharArray(messagePadded),
            messageLength: messagePaddedLen.toString(),
            pubkey: toCircomBigIntBytes(base64ToBigInt(publicKey.n)),
            signature: toCircomBigIntBytes(base64ToBigInt(signatureString)),
            periodIndex: periodIndex.toString(),
        };
    } catch (error: any) {
        handleError(error);
    }
}

/**
 * Generates JWT authenticator circuit inputs
 */
export async function generateJWTAuthenticatorInputs(
    rawJWT: string,
    publicKey: RSAPublicKey,
    accountCode: bigint,
    params: JWTInputGenerationArgs = {}
): Promise<JWTAuthenticatorInputs> {
    try {
        const baseInputs = await generateJWTVerifierInputs(
            rawJWT,
            publicKey,
            params
        );
        const [headerString, payloadString] = splitJWT(rawJWT);
        const { header, payload, parsedPayload } = decodeJWT(
            headerString,
            payloadString
        );

        const indices = findJWTIndices(header, payload);
        const lengths = calculateLengths(parsedPayload);
        const { domain, index } = getDomainFromEmail(parsedPayload.email);
        const codeIndex = findCodeIndex(parsedPayload.nonce, accountCode);

        return {
            ...baseInputs,
            accountCode,
            codeIndex: codeIndex.toString(),
            ...indices,
            ...lengths,
            emailDomainIndex: index.toString(),
            emailDomainLength: domain.length,
        };
    } catch (error: any) {
        handleError(error);
    }
}

/**
 * Generates JWT authenticator circuit inputs with anonymous domain support
 */
export async function generateJWTAuthenticatorWithAnonDomainsInputs(
    rawJWT: string,
    publicKey: RSAPublicKey,
    accountCode: bigint,
    params: JWTInputGenerationArgs
): Promise<JWTAuthenticatorWithAnonDomainsInputs> {
    validateAnonymousDomainParams(params);
    const baseInputs = await generateJWTAuthenticatorInputs(
        rawJWT,
        publicKey,
        accountCode,
        params
    );

    return {
        ...baseInputs,
        anonymousDomainsTreeRoot: params.anonymousDomainsTreeRoot!.toString(),
        emailDomainPath:
            params.emailDomainPath?.map((path) => path.toString()) || [],
        emailDomainPathHelper:
            params.emailDomainPathHelper?.map((helper) => helper.toString()) ||
            [],
    };
}
