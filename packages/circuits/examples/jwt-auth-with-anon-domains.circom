pragma circom 2.1.6;

include "@zk-email/ether-email-auth-circom/src/utils/bytes2ints.circom";

include "./jwt-auth.circom";
include "../helpers/auth.circom";
include "../utils/constants.circom";

template JWTAuthWithAnonymousDomains(
    n,
    k, 
    maxMessageLength, 
    maxB64HeaderLength, 
    maxB64PayloadLength, 
    maxAzpLength, 
    maxCommandLength,
    anonymousDomainsTreeHeight
) {
    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input pubkey[k]; // RSA public key split into k chunks
    signal input signature[k]; // RSA signature split into k chunks

    signal input accountCode;
    signal input codeIndex; // Index of the "invitation code" in the "command"

    signal input periodIndex; // Index of the period in the JWT message

    signal input jwtKidStartIndex; // Index of the "kid" in the JWT header

    signal input issKeyStartIndex; // Index of the "iss" key in the JWT payload
    signal input issLength; // Length of the "iss" in the JWT payload
    signal input iatKeyStartIndex; // Index of the "iat" key in the JWT payload
    signal input azpKeyStartIndex; // Index of the "azp" (Authorized party) key in the JWT payload
    signal input azpLength; // Length of the "azp" (Authorized party) in the JWT payload
    signal input emailKeyStartIndex; // Index of the "email" key in the JWT payload
    signal input emailLength; // Length of the "email" in the JWT payload
    signal input nonceKeyStartIndex; // Index of the "nonce" key in the JWT payload
    signal input commandLength; // Length of the "command" in the "nonce" key in the JWT payload
    signal input emailDomainIndex; // Index of the domain in the email
    signal input emailDomainLength; // Length of the domain in the email

    signal input anonymousDomainsTreeRoot; // Root of the Merkle tree for the email domains (Public)
    signal input emailDomainPath[anonymousDomainsTreeHeight]; // Path in the Merkle tree for the email domain
    signal input emailDomainPathHelper[anonymousDomainsTreeHeight]; // Helper for the path in the Merkle tree for the email domain

    var commandFieldLength = compute_ints_size(maxCommandLength);
    var azpFieldLength = compute_ints_size(maxAzpLength);
    var issLen = ISSUER_MAX_BYTES();
    var issFieldLength = compute_ints_size(issLen);
    var maxDomainLength = DOMAIN_MAX_BYTES();
    var maxDomainFieldLength = compute_ints_size(maxDomainLength);

    signal output kid;
    signal output iss[issFieldLength];
    signal output publicKeyHash;
    signal output jwtNullifier;
    signal output timestamp;
    signal output maskedCommand[commandFieldLength];
    signal output accountSalt;
    signal output azp[azpFieldLength];
    signal output domainName[maxDomainFieldLength];
    signal output isCodeExist;

    component jwtAuth = JWTAuth(n, k, maxMessageLength, maxB64HeaderLength, maxB64PayloadLength, maxAzpLength, maxCommandLength);
    jwtAuth.message <== message;
    jwtAuth.messageLength <== messageLength;
    jwtAuth.pubkey <== pubkey;
    jwtAuth.signature <== signature;
    jwtAuth.accountCode <== accountCode;
    jwtAuth.codeIndex <== codeIndex;
    jwtAuth.periodIndex <== periodIndex;
    jwtAuth.jwtKidStartIndex <== jwtKidStartIndex;
    jwtAuth.issKeyStartIndex <== issKeyStartIndex;
    jwtAuth.issLength <== issLength;
    jwtAuth.iatKeyStartIndex <== iatKeyStartIndex;
    jwtAuth.azpKeyStartIndex <== azpKeyStartIndex;
    jwtAuth.azpLength <== azpLength;
    jwtAuth.emailKeyStartIndex <== emailKeyStartIndex;
    jwtAuth.emailLength <== emailLength;
    jwtAuth.nonceKeyStartIndex <== nonceKeyStartIndex;
    jwtAuth.commandLength <== commandLength;
    jwtAuth.emailDomainIndex <== emailDomainIndex;
    jwtAuth.emailDomainLength <== emailDomainLength;

    kid <== jwtAuth.kid;
    iss <== jwtAuth.iss;
    publicKeyHash <== jwtAuth.publicKeyHash;
    jwtNullifier <== jwtAuth.jwtNullifier;
    timestamp <== jwtAuth.timestamp;
    maskedCommand <== jwtAuth.maskedCommand;
    accountSalt <== jwtAuth.accountSalt;
    azp <== jwtAuth.azp;
    domainName <== jwtAuth.domainName;
    isCodeExist <== jwtAuth.isCodeExist;

    component verifyAnonymousDomain = VerifyAnonymousDomain(maxDomainFieldLength, anonymousDomainsTreeHeight);
    verifyAnonymousDomain.domainName <== domainName;
    verifyAnonymousDomain.anonymousDomainsTreeRoot <== anonymousDomainsTreeRoot;
    verifyAnonymousDomain.emailDomainPath <== emailDomainPath;
    verifyAnonymousDomain.emailDomainPathHelper <== emailDomainPathHelper;
    verifyAnonymousDomain.isDomainIncluded === 1;
}