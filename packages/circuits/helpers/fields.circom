pragma circom 2.1.6;

include "@zk-email/circuits/helpers/reveal-substring.circom";
include "@zk-email/ether-email-auth-circom/src/utils/bytes2ints.circom";
include "@zk-email/ether-email-auth-circom/src/utils/digit2int.circom";

include "../utils/constants.circom";

/// @title ExtractKid
/// @notice Extracts and validates the 'kid' (Key ID) from JWT header
/// @param maxHeaderLength Maximum length of JWT header
/// @input header[maxHeaderLength] JWT header bytes
/// @input jwtKidStartIndex Starting index of 'kid' field
/// @output kid Key ID converted to field element
template ExtractKid(maxHeaderLength) {
    signal input header[maxHeaderLength];
    signal input jwtKidStartIndex;

    signal output kid;

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
}

/// @title ExtractIssuer
/// @notice Extracts and validates the 'iss' (Issuer) from JWT payload
/// @param maxPayloadLength Maximum length of JWT payload
/// @input payload[maxPayloadLength] JWT payload bytes
/// @input issKeyStartIndex Starting index of 'iss' field
/// @input issLength Length of issuer value
/// @output iss[compute_ints_size(ISSUER_MAX_BYTES())] Issuer as array of field elements
template ExtractIssuer(maxPayloadLength) {
    signal input payload[maxPayloadLength];
    signal input issKeyStartIndex;
    signal input issLength;

    signal output iss[compute_ints_size(ISSUER_MAX_BYTES())];

    // Verify if the key `iss` in the payload is unique
    var issKeyLength = ISS_KEY_LENGTH();
    var issKey[issKeyLength] = ISS_KEY();
    signal issKeyMatch[issKeyLength] <== RevealSubstring(maxPayloadLength, issKeyLength, 1)(payload, issKeyStartIndex, issKeyLength);
    for (var i = 0; i < issKeyLength; i++) {
        issKeyMatch[i] === issKey[i];
    }   

    // Reveal the iss in the payload
    signal issStartIndex <== issKeyStartIndex + issKeyLength + 1;
    signal issMatch[ISSUER_MAX_BYTES()] <== RevealSubstring(maxPayloadLength, ISSUER_MAX_BYTES(), 0)(payload, issStartIndex, issLength);
    iss <== Bytes2Ints(ISSUER_MAX_BYTES())(issMatch);
}

/// @title ExtractTimestamp
/// @notice Extracts and validates the 'iat' (Issued At) timestamp
/// @param maxPayloadLength Maximum length of JWT payload
/// @input payload[maxPayloadLength] JWT payload bytes
/// @input iatKeyStartIndex Starting index of 'iat' field
/// @output timestamp Unix timestamp as field element
template ExtractTimestamp(maxPayloadLength) {
    signal input payload[maxPayloadLength];
    signal input iatKeyStartIndex;

    signal output timestamp;

    // Verify if the key `iat` in the payload is unique
    var iatKeyLength = IAT_KEY_LENGTH();
    var iatKey[iatKeyLength] = IAT_KEY();
    signal iatKeyMatch[iatKeyLength] <== RevealSubstring(maxPayloadLength, iatKeyLength, 1)(payload, iatKeyStartIndex, iatKeyLength);
    for (var i = 0; i < iatKeyLength; i++) {
        iatKeyMatch[i] === iatKey[i];
    }

    // Reveal and convert the timestamp
    var iatLength = TIMESTAMP_LENGTH();
    signal iatStartIndex <== iatKeyStartIndex + iatKeyLength;
    signal iatMatch[iatLength] <== RevealSubstring(maxPayloadLength, iatLength, 0)(payload, iatStartIndex, iatLength);
    timestamp <== Digit2Int(iatLength)(iatMatch);
}

/// @title ExtractAzp
/// @notice Extracts and validates the 'azp' (Authorized Party)
/// @param maxPayloadLength Maximum length of JWT payload
/// @param maxAzpLength Maximum length of authorized party string
/// @input payload[maxPayloadLength] JWT payload bytes
/// @input azpKeyStartIndex Starting index of 'azp' field
/// @input azpLength Length of azp value
/// @output azp[compute_ints_size(maxAzpLength)] Authorized party as array of field elements
template ExtractAzp(maxPayloadLength, maxAzpLength) {
    signal input payload[maxPayloadLength];
    signal input azpKeyStartIndex;
    signal input azpLength;

    signal output azp[compute_ints_size(maxAzpLength)];

    // Verify if the key `azp` in the payload is unique
    var azpKeyLength = AZP_KEY_LENGTH();
    var azpKey[azpKeyLength] = AZP_KEY();
    signal azpKeyMatch[azpKeyLength] <== RevealSubstring(maxPayloadLength, azpKeyLength, 1)(payload, azpKeyStartIndex, azpKeyLength);
    for (var i = 0; i < azpKeyLength; i++) {
        azpKeyMatch[i] === azpKey[i];
    }

    // Reveal the azp
    signal azpStartIndex <== azpKeyStartIndex + azpKeyLength + 1;
    signal azpMatch[maxAzpLength] <== RevealSubstring(maxPayloadLength, maxAzpLength, 0)(payload, azpStartIndex, azpLength);
    azp <== Bytes2Ints(maxAzpLength)(azpMatch);
}

/// @title ExtractEmail
/// @notice Extracts and validates the email field
/// @param maxPayloadLength Maximum length of JWT payload
/// @param maxEmailLength Maximum length of email string
/// @input payload[maxPayloadLength] JWT payload bytes
/// @input emailKeyStartIndex Starting index of email field
/// @input emailLength Length of email value
/// @output email[maxEmailLength] Email address bytes
template ExtractEmail(maxPayloadLength, maxEmailLength) {
    signal input payload[maxPayloadLength];
    signal input emailKeyStartIndex;
    signal input emailLength;

    signal output email[maxEmailLength];

    // Verify email key
    var emailKeyLength = EMAIL_KEY_LENGTH();
    var emailKey[emailKeyLength] = EMAIL_KEY();
    signal emailKeyMatch[emailKeyLength] <== RevealSubstring(maxPayloadLength, emailKeyLength, 1)(payload, emailKeyStartIndex, emailKeyLength);
    for (var i = 0; i < emailKeyLength; i++) {
        emailKeyMatch[i] === emailKey[i];
    }

    // Extract email
    signal emailStartIndex <== emailKeyStartIndex + emailKeyLength + 1;
    email <== RevealSubstring(maxPayloadLength, maxEmailLength, 0)(payload, emailStartIndex, emailLength);
}

/// @title ExtractDomainFromEmail
/// @notice Extracts domain part from email address
/// @param maxEmailLength Maximum length of email string
/// @param maxDomainLength Maximum length of domain string
/// @input email[maxEmailLength] Email address bytes
/// @input emailDomainIndex Starting index of domain in email
/// @input emailDomainLength Length of domain
/// @output domainName[compute_ints_size(maxDomainLength)] Domain as array of field elements
template ExtractDomainFromEmail(maxEmailLength, maxDomainLength) {
    signal input email[maxEmailLength];
    signal input emailDomainIndex;
    signal input emailDomainLength;

    signal output domainName[compute_ints_size(maxDomainLength)];
    
    // Extract domain bytes from email
    signal domainNameBytes[maxDomainLength] <== RevealSubstring(maxEmailLength, maxDomainLength, 0)(
        email, 
        emailDomainIndex, 
        emailDomainLength
    );

    // Convert domain bytes to ints
    domainName <== Bytes2Ints(maxDomainLength)(domainNameBytes);
}

/// @title ExtractCommand
/// @notice Extracts and validates command from nonce field
/// @param maxPayloadLength Maximum length of JWT payload
/// @param maxCommandLength Maximum length of command string
/// @input payload[maxPayloadLength] JWT payload bytes
/// @input nonceKeyStartIndex Starting index of nonce field
/// @input commandLength Length of command value
/// @output command[maxCommandLength] Command bytes
template ExtractCommand(maxPayloadLength, maxCommandLength) {
    signal input payload[maxPayloadLength];
    signal input nonceKeyStartIndex;
    signal input commandLength;

    signal output command[maxCommandLength];

    // Verify nonce key
    var nonceKeyLength = NONCE_LENGTH();
    var nonceKey[nonceKeyLength] = NONCE();
    signal nonceKeyMatch[nonceKeyLength] <== RevealSubstring(maxPayloadLength, nonceKeyLength, 1)(payload, nonceKeyStartIndex, nonceKeyLength);
    for (var i = 0; i < nonceKeyLength; i++) {
        nonceKeyMatch[i] === nonceKey[i];
    }

    // Extract command
    signal commandStartIndex <== nonceKeyStartIndex + nonceKeyLength + 1;
    command <== RevealSubstring(maxPayloadLength, maxCommandLength, 0)(payload, commandStartIndex, commandLength);
}

/// @title ExtractSub
/// @notice Extracts and validates the 'sub' field from JWT payload.
///         The 'sub' field identifies an unique user.
/// @param maxPayloadLength Maximum length of JWT payload
/// @input payload[maxPayloadLength] JWT payload bytes
/// @input subKeyStartIndex Starting index of 'sub' field
/// @output sub Sub as field element
template ExtractSub(maxPayloadLength) {
    signal input payload[maxPayloadLength];
    signal input subKeyStartIndex;

    signal output sub;

    // Verify if the key `sub` in the payload is unique
    var subKeyLength = SUB_KEY_LENGTH();
    var subKey[subKeyLength] = SUB_KEY();
    signal subKeyMatch[subKeyLength] <== RevealSubstring(maxPayloadLength, subKeyLength, 1)(payload, subKeyStartIndex, subKeyLength);
    for (var i = 0; i < subKeyLength; i++) {
        subKeyMatch[i] === subKey[i];
    }

    // Reveal the sub
    signal subStartIndex <== subKeyStartIndex + SUB_KEY_LENGTH() + 1;
    signal subMatch[SUB_VALUE_LENGTH()] <== RevealSubstring(maxPayloadLength, SUB_VALUE_LENGTH(), 0)(payload, subStartIndex, SUB_VALUE_LENGTH());
    sub <== Digit2Int(SUB_VALUE_LENGTH())(subMatch);
}

