pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/helpers/reveal-substring.circom";
include "@zk-email/ether-email-auth-circom/src/utils/bytes2ints.circom";

include "../jwt-verifier.circom";
include "../utils/constants.circom";
include "../utils/hex2int.circom";
include "../helpers/auth.circom";
include "../helpers/fields.circom";

template TeleportNFTRedeem(
    n,
    k, 
    maxMessageLength, 
    maxB64HeaderLength, 
    maxB64PayloadLength, 
    maxAzpLength, 
    maxCommandLength
) {
    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input pubkey[k]; // RSA public key split into k chunks
    signal input signature[k]; // RSA signature split into k chunks
    signal input periodIndex; // Index of the period in the JWT message
    signal input jwtKidStartIndex; // Index of the "kid" in the JWT header
    signal input issKeyStartIndex; // Index of the "iss" key in the JWT payload
    signal input issLength; // Length of the "iss" in the JWT payload
    signal input azpKeyStartIndex; // Index of the "azp" (Authorized party) key in the JWT payload
    signal input azpLength; // Length of the "azp" (Authorized party) in the JWT payload
    signal input subKeyStartIndex; // Index of the "sub" key in the JWT payload
    signal input emailKeyStartIndex; // Index of the "email" key in the JWT payload
    signal input emailLength; // Length of the "email" in the JWT payload
    signal input nonceKeyStartIndex; // Index of the "nonce" key in the JWT payload
    signal input commandLength; // Length of the "command" in the "nonce" key in the JWT payload
    signal input emailDomainIndex; // Index of the domain in the email
    signal input emailDomainLength; // Length of the domain in the email

    assert(maxMessageLength % 64 == 0);
    assert(n * k > 2048); // to support 2048 bit RSA
    assert(n < (255 \ 2)); // for multiplication to fit in the field (255 bits)

    // Ensure maxB64HeaderLength and maxB64PayloadLength are multiples of 4
    // Base64 encoding always produces output in multiples of 4 characters
    assert(maxB64HeaderLength % 4 == 0); 
    assert(maxB64PayloadLength % 4 == 0); 

    var commandFieldLength = compute_ints_size(maxCommandLength);
    var azpFieldLength = compute_ints_size(maxAzpLength);
    var issLen = ISSUER_MAX_BYTES();
    var issFieldLength = compute_ints_size(issLen);
    var maxEmailLength = EMAIL_ADDR_MAX_BYTES();
    var maxDomainLength = DOMAIN_MAX_BYTES();
    var maxDomainFieldLength = compute_ints_size(maxDomainLength);

    signal output publicKeyHash;
    signal output iss[issFieldLength];
    signal output kid;
    signal output azp[azpFieldLength];
    signal output emailNullifier;
    signal output domainName[maxDomainFieldLength];
    signal output command[commandFieldLength];

    component jwtVerifier = JWTVerifier(n, k, maxMessageLength, maxB64HeaderLength, maxB64PayloadLength);
    jwtVerifier.message <== message;
    jwtVerifier.messageLength <== messageLength;
    jwtVerifier.pubkey <== pubkey;
    jwtVerifier.signature <== signature;
    jwtVerifier.periodIndex <== periodIndex;

    publicKeyHash <== jwtVerifier.publicKeyHash;

    var maxHeaderLength = (maxB64HeaderLength * 3) \ 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) \ 4;

    signal header[maxHeaderLength] <== jwtVerifier.header;
    signal payload[maxPayloadLength] <== jwtVerifier.payload;

    // Verify if the key `kid` in the header is unique
    // Reveal the kid in the header
    component extractKid = ExtractKid(maxHeaderLength);
    extractKid.header <== header;
    extractKid.jwtKidStartIndex <== jwtKidStartIndex;
    kid <== extractKid.kid;

    // Verify if the key `iss` in the payload is unique
    // Reveal the iss in the payload
    component extractIssuer = ExtractIssuer(maxPayloadLength);
    extractIssuer.payload <== payload;
    extractIssuer.issKeyStartIndex <== issKeyStartIndex;
    extractIssuer.issLength <== issLength;
    iss <== extractIssuer.iss;

    // Verify if the key `azp` in the payload is unique
    // Reveal the azp in the payload
    component extractAzp = ExtractAzp(maxPayloadLength, maxAzpLength);
    extractAzp.payload <== payload;
    extractAzp.azpKeyStartIndex <== azpKeyStartIndex;
    extractAzp.azpLength <== azpLength;
    azp <== extractAzp.azp;

    // Verify if the key `sub` in the payload is unique
    // Reveal the sub in the payload
    component extractSub = ExtractSub(maxPayloadLength);
    extractSub.payload <== payload;
    extractSub.subKeyStartIndex <== subKeyStartIndex;
    signal sub <== extractSub.sub;

    // Hash the sub to create the email nullifier
    emailNullifier <== Poseidon(1)([sub]);

    // Verify if the key `email` in the payload is unique
    // Reveal the email in the payload
    component extractEmail = ExtractEmail(maxPayloadLength, maxEmailLength);
    extractEmail.payload <== payload;
    extractEmail.emailKeyStartIndex <== emailKeyStartIndex;
    extractEmail.emailLength <== emailLength;
    signal email[maxEmailLength] <== extractEmail.email;

    // Extract the domain from the email
    component extractDomainFromEmail = ExtractDomainFromEmail(maxEmailLength, maxDomainLength);
    extractDomainFromEmail.email <== email;
    extractDomainFromEmail.emailDomainIndex <== emailDomainIndex;
    extractDomainFromEmail.emailDomainLength <== emailDomainLength;
    domainName <== extractDomainFromEmail.domainName;

    // Verify if the key `nonce` in the payload is unique
    // Reveal the command in the nonce
    component extractCommand = ExtractCommand(maxPayloadLength, maxCommandLength);
    extractCommand.payload <== payload;
    extractCommand.nonceKeyStartIndex <== nonceKeyStartIndex;
    extractCommand.commandLength <== commandLength;
    signal commandBytes[maxCommandLength] <== extractCommand.command;
    command <== Bytes2Ints(maxCommandLength)(commandBytes);
}

component main = TeleportNFTRedeem(121, 17, 1024, 128, 896, 72, 280);
