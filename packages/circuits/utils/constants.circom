pragma circom 2.1.6;

function JWT_TYP_LENGTH() {
    // len("typ": "JWT")
    return 11;
}

function JWT_KID_KEY_LENGTH() {
    // len("kid":)
    return 6;
}

// KID is 20 bytes long
function JWT_KID_LENGTH() {
    return 40;
}

function AZP_KEY_LENGTH() {
    // len("azp":)
    return 6;
}

function NONCE_LENGTH() {
    // len("nonce":)
    return 8;
}

function ISS_KEY_LENGTH() {
    // len("iss":)
    return 6;
}

function SUB_KEY_LENGTH() {
    // len("sub":)
    return 6;
}

// TODO: Assign a proper value to this
function ISSUER_MAX_BYTES() {
    return 32;
}

function IAT_KEY_LENGTH() {
    // len("iat":)
    return 6;
}

function EMAIL_KEY_LENGTH() {
    // len("email":)
    return 8;
}

function TIMESTAMP_LENGTH() {
    return 10;
}

function INVITATION_CODE_LENGTH() {
    return 64;
}

function SUB_VALUE_LENGTH() {
    // length of the "sub" field in JWT which identifies an unique user
    return 21;
}

function JWT_TYP() {
    // "typ":"JWT"
    return [34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34];
}

function JWT_KID_KEY() {
    // "kid":
    return [34, 107, 105, 100, 34, 58];
}

function AZP_KEY() {
    // "azp":
    return [34, 97, 122, 112, 34, 58];
}

function NONCE() {
    // "nonce":
    return [34, 110, 111, 110, 99, 101, 34, 58];
}

function ISS_KEY() {
    // "iss":
    return [34, 105, 115, 115, 34, 58];
}

function IAT_KEY() {
    // "iat":
    return [34, 105, 97, 116, 34, 58];
}

function EMAIL_KEY() {
    // "email":
    return [34, 101, 109, 97, 105, 108, 34, 58];
}

function SUB_KEY() {
    // "sub":
    return [34, 115, 117, 98, 34, 58];
}
