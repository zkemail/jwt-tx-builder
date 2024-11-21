pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/utils/constants.circom";
include "@zk-email/circuits/utils/regex.circom";
include "@zk-email/circuits/helpers/reveal-substring.circom";
include "@zk-email/ether-email-auth-circom/src/utils/bytes2ints.circom";
include "@zk-email/ether-email-auth-circom/src/utils/digit2int.circom";
include "@zk-email/ether-email-auth-circom/src/utils/hash_sign.circom";
include "@zk-email/ether-email-auth-circom/src/utils/account_salt.circom";
include "@zk-email/ether-email-auth-circom/src/regexes/invitation_code_with_prefix_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/email_addr_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/email_domain_regex.circom";

include "./utils/constants.circom";
include "./utils/hex2int.circom";

include "./jwt-verifier-template.circom";

template JWTAuthenticator(
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

    /// Calculate the JWT nullifier
    var k2ChunkedSize = k >> 1;
    if(k % 2 == 1) {
        k2ChunkedSize += 1;
    }
    signal signHash;
    signal signInts[k2ChunkedSize];
    (signHash, signInts) <== HashSign(n,k)(signature);
    jwtNullifier <== Poseidon(1)([signHash]);

    // Verify if the typ in the header is "JWT"
    var typLength = JWT_TYP_LENGTH();
    var typ[typLength] = JWT_TYP();
    signal typMatch[typLength] <== RevealSubstring(maxHeaderLength, typLength, 1)(header, jwtTypStartIndex, typLength);
    for (var i = 0; i < typLength; i++) {
        typMatch[i] === typ[i];
    }

    // Verify if the key `kid` in the header is unique
    var kidKeyLength = JWT_KID_KEY_LENGTH();
    var kidKey[kidKeyLength] = JWT_KID_KEY();
    signal kidKeyMatch[kidKeyLength] <== RevealSubstring(maxHeaderLength, kidKeyLength, 1)(header, jwtKidStartIndex, kidKeyLength);
    for (var i = 0; i < kidKeyLength; i++) {
        kidKeyMatch[i] === kidKey[i];
    }

    // Reveal the kid in the header
    signal kidStartIndex <== jwtKidStartIndex + kidKeyLength + 1;
    var kidLength = JWT_KID_LENGTH();
    signal kidBytes[kidLength] <== RevealSubstring(maxHeaderLength, kidLength, 0)(header, kidStartIndex, kidLength);
    kid <== Hex2FieldModular(kidLength)(kidBytes);

    // Verify if the key `iss` in the payload is unique
    var issKeyLength = ISS_KEY_LENGTH();
    var issKey[issKeyLength] = ISS_KEY();
    signal issKeyMatch[issKeyLength] <== RevealSubstring(maxPayloadLength, issKeyLength, 1)(payload, issKeyStartIndex, issKeyLength);
    for (var i = 0; i < issKeyLength; i++) {
        issKeyMatch[i] === issKey[i];
    }   

    // Reveal the iss in the payload
    signal issStartIndex <== issKeyStartIndex + issKeyLength + 1;
    signal issMatch[issLen] <== RevealSubstring(maxPayloadLength, issLen, 0)(payload, issStartIndex, issLength);
    iss <== Bytes2Ints(issLen)(issMatch);

    // Verify if the key `iat` in the payload is unique
    var iatKeyLength = IAT_KEY_LENGTH();
    var iatKey[iatKeyLength] = IAT_KEY();
    signal iatKeyMatch[iatKeyLength] <== RevealSubstring(maxPayloadLength, iatKeyLength, 1)(payload, iatKeyStartIndex, iatKeyLength);
    for (var i = 0; i < iatKeyLength; i++) {
        iatKeyMatch[i] === iatKey[i];
    }

    // Reveal the iat in the payload
    var iatLength = TIMESTAMP_LENGTH();
    signal iatStartIndex <== iatKeyStartIndex + iatKeyLength;
    signal iatMatch[iatLength] <== RevealSubstring(maxPayloadLength, iatLength, 0)(payload, iatStartIndex, iatLength);
    timestamp <== Digit2Int(iatLength)(iatMatch);

    // Verify if the key `azp` in the payload is unique
    var azpKeyLength = AZP_KEY_LENGTH();
    var azpKey[azpKeyLength] = AZP_KEY();
    signal azpKeyMatch[azpKeyLength] <== RevealSubstring(maxPayloadLength, azpKeyLength, 1)(payload, azpKeyStartIndex, azpKeyLength);
    for (var i = 0; i < azpKeyLength; i++) {
        azpKeyMatch[i] === azpKey[i];
    }

    // Reveal the azp in the payload
    signal azpStartIndex <== azpKeyStartIndex + azpKeyLength + 1;
    signal azpMatch[maxAzpLength] <== RevealSubstring(maxPayloadLength, maxAzpLength, 0)(payload, azpStartIndex, azpLength);
    azp <== Bytes2Ints(maxAzpLength)(azpMatch);

    // Verify if the key `email` in the payload is unique
    var emailKeyLength = EMAIL_KEY_LENGTH();
    var emailKey[emailKeyLength] = EMAIL_KEY();
    signal emailKeyMatch[emailKeyLength] <== RevealSubstring(maxPayloadLength, emailKeyLength, 1)(payload, emailKeyStartIndex, emailKeyLength);
    for (var i = 0; i < emailKeyLength; i++) {
        emailKeyMatch[i] === emailKey[i];
    }

    // Reveal the email in the payload
    var maxEmailLength = EMAIL_ADDR_MAX_BYTES();
    signal emailStartIndex <== emailKeyStartIndex + emailKeyLength + 1;
    signal email[maxEmailLength] <== RevealSubstring(maxPayloadLength, maxEmailLength, 0)(payload, emailStartIndex, emailLength);

    // Extract the domain from the email
    signal domainNameBytes[maxDomainLength] <== RevealSubstring(maxEmailLength, maxDomainLength, 0)(email, emailDomainIndex, emailDomainLength);
    domainName <== Bytes2Ints(maxDomainLength)(domainNameBytes);

    // Calculate account salt using email
    var numEmailInts = compute_ints_size(maxEmailLength);
    signal emailInts[numEmailInts] <== Bytes2Ints(maxEmailLength)(email);
    accountSalt <== AccountSalt(numEmailInts)(emailInts, accountCode);

    // Verify if the key `nonce` in the payload is unique
    var nonceKeyLength = NONCE_LENGTH();
    var nonceKey[nonceKeyLength] = NONCE();
    signal nonceKeyMatch[nonceKeyLength] <== RevealSubstring(maxPayloadLength, nonceKeyLength, 1)(payload, nonceKeyStartIndex, nonceKeyLength);
    for (var i = 0; i < nonceKeyLength; i++) {
        nonceKeyMatch[i] === nonceKey[i];
    }

    // Reveal the command in the nonce
    signal commandStartIndex <== nonceKeyStartIndex + nonceKeyLength + 1;
    signal command[maxCommandLength] <== RevealSubstring(maxPayloadLength, maxCommandLength, 0)(payload, commandStartIndex, commandLength);

    // Check if the command in the nonce has a valid invitation code and remove the prefix if it exists
    signal prefixedCodeRegexOut, prefixedCodeRegexReveal[maxCommandLength];
    (prefixedCodeRegexOut, prefixedCodeRegexReveal) <== InvitationCodeWithPrefixRegex(maxCommandLength)(command);
    isCodeExist <== prefixedCodeRegexOut;
    signal removedCode[maxCommandLength];
    for(var i = 0; i < maxCommandLength; i++) {
        removedCode[i] <== isCodeExist * prefixedCodeRegexReveal[i];
    }

    // Check if the command in the nonce has a valid email address and remove the email address if it exists
    signal emailAddrRegexOut, emailAddrRegexReveal[maxCommandLength];
    (emailAddrRegexOut, emailAddrRegexReveal) <== EmailAddrRegex(maxCommandLength)(command);
    signal isEmailAddrExist <== emailAddrRegexOut;
    signal removedEmailAddr[maxCommandLength];
    for(var i = 0; i < maxCommandLength; i++) {
        removedEmailAddr[i] <== isEmailAddrExist * emailAddrRegexReveal[i];
    }

    // Mask the command with the code and email address
    signal maskedCommandBytes[maxCommandLength];
    for(var i = 0; i < maxCommandLength; i++) {
        maskedCommandBytes[i] <== command[i] - removedCode[i] - removedEmailAddr[i];
    }
    maskedCommand <== Bytes2Ints(maxCommandLength)(maskedCommandBytes);

    // Extract the invitation code from the command
    var invitationCodeLen = INVITATION_CODE_LENGTH();
    assert(invitationCodeLen < maxCommandLength);
    signal revealedCode[invitationCodeLen] <== RevealSubstring(maxCommandLength, invitationCodeLen, 0)(command, codeIndex, invitationCodeLen);
    signal invitationCodeHex[invitationCodeLen];
    for (var i = 0; i < invitationCodeLen; i++) {
        invitationCodeHex[i] <== isCodeExist * revealedCode[i] + (1 - isCodeExist) * 48;
    }

    // Verify the invitation code is equal to the account code
    signal embeddedAccountCode <== Hex2FieldModular(invitationCodeLen)(invitationCodeHex);
    isCodeExist * (embeddedAccountCode - accountCode) === 0;
}