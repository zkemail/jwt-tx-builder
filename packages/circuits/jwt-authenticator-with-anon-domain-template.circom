pragma circom 2.1.6;

include "@zk-email/circuits/utils/hash.circom";

include "./jwt-authenticator-template.circom";
include "./utils/merkle-tree.circom";

template JWTAuthenticatorWithAnonymousDomain(
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

    signal input jwtTypStartIndex; // Index of the "typ" in the JWT header
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

    component jwtAuthenticator = JWTAuthenticator(n, k, maxMessageLength, maxB64HeaderLength, maxB64PayloadLength, maxAzpLength, maxCommandLength);
    jwtAuthenticator.message <== message;
    jwtAuthenticator.messageLength <== messageLength;
    jwtAuthenticator.pubkey <== pubkey;
    jwtAuthenticator.signature <== signature;
    jwtAuthenticator.accountCode <== accountCode;
    jwtAuthenticator.codeIndex <== codeIndex;
    jwtAuthenticator.periodIndex <== periodIndex;
    jwtAuthenticator.jwtTypStartIndex <== jwtTypStartIndex;
    jwtAuthenticator.jwtKidStartIndex <== jwtKidStartIndex;
    jwtAuthenticator.issKeyStartIndex <== issKeyStartIndex;
    jwtAuthenticator.issLength <== issLength;
    jwtAuthenticator.iatKeyStartIndex <== iatKeyStartIndex;
    jwtAuthenticator.azpKeyStartIndex <== azpKeyStartIndex;
    jwtAuthenticator.azpLength <== azpLength;
    jwtAuthenticator.emailKeyStartIndex <== emailKeyStartIndex;
    jwtAuthenticator.emailLength <== emailLength;
    jwtAuthenticator.nonceKeyStartIndex <== nonceKeyStartIndex;
    jwtAuthenticator.commandLength <== commandLength;
    jwtAuthenticator.emailDomainIndex <== emailDomainIndex;
    jwtAuthenticator.emailDomainLength <== emailDomainLength;

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

    kid <== jwtAuthenticator.kid;
    iss <== jwtAuthenticator.iss;
    publicKeyHash <== jwtAuthenticator.publicKeyHash;
    jwtNullifier <== jwtAuthenticator.jwtNullifier;
    timestamp <== jwtAuthenticator.timestamp;
    maskedCommand <== jwtAuthenticator.maskedCommand;
    accountSalt <== jwtAuthenticator.accountSalt;
    azp <== jwtAuthenticator.azp;
    isCodeExist <== jwtAuthenticator.isCodeExist;

    // Generate the leaf of the Merkle tree for the email domain
    component domainHasher = PoseidonModular(maxDomainFieldLength);
    for (var i = 0; i < maxDomainFieldLength; i++) {
        domainHasher.in[i] <== jwtAuthenticator.domainName[i];
    }
    signal domainLeaf <== domainHasher.out;

    // Verify the email domain is in the Merkle tree
    component treeVerifier = MerkleTreeVerifier(anonymousDomainsTreeHeight);
    for (var i = 0; i < anonymousDomainsTreeHeight; i++) {
        treeVerifier.proof[i] <== emailDomainPath[i];
        treeVerifier.proofHelper[i] <== emailDomainPathHelper[i];
    }
    treeVerifier.root <== anonymousDomainsTreeRoot;
    treeVerifier.leaf <== domainLeaf;
    treeVerifier.isValid === 1;
}