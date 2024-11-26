pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/utils/hash.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/base64.circom";
include "./utils/bytes.circom";
include "./utils/array.circom";

/// @title JWTVerifier
/// @notice Verifies JWT signatures and extracts header/payload components
/// @dev This template verifies RSA-SHA256 signed JWTs and decodes Base64 encoded components.
///      It works by:
///      1. Verifying message length and padding
///      2. Computing SHA256 hash of `header.payload`
///      3. Verifying RSA signature against public key
///      4. Extracting and decoding Base64 header/payload
///      5. Computing public key hash for external reference
/// @param n RSA chunk size in bits (n < 127 for field arithmetic)
/// @param k Number of RSA chunks (n*k > 2048 for RSA-2048)
/// @param maxMessageLength Maximum JWT string length (must be multiple of 64 for SHA256)
/// @param maxB64HeaderLength Maximum Base64 header length (must be multiple of 4)
/// @param maxB64PayloadLength Maximum Base64 payload length (must be multiple of 4)
/// @input message[maxMessageLength] JWT string (header.payload)
/// @input messageLength Actual length of JWT string
/// @input pubkey[k] RSA public key in k chunks
/// @input signature[k] RSA signature in k chunks
/// @input periodIndex Location of period separating header.payload
/// @output publicKeyHash Poseidon hash of public key
/// @output header[maxHeaderLength] Decoded JWT header
/// @output payload[maxPayloadLength] Decoded JWT payload
template JWTVerifier(
    n,
    k,
    maxMessageLength,
    maxB64HeaderLength,
    maxB64PayloadLength
) {
    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input pubkey[k]; // RSA public key split into k chunks
    signal input signature[k]; // RSA signature split into k chunks
    signal input periodIndex; // Index of the period in the JWT message

    var maxHeaderLength = (maxB64HeaderLength * 3) \ 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) \ 4;

    signal output publicKeyHash;
    signal output header[maxHeaderLength];
    signal output payload[maxPayloadLength];

    // Assert message length fits in ceil(log2(maxMessageLength))
    component n2bMessageLength = Num2Bits(log2Ceil(maxMessageLength));
    n2bMessageLength.in <== messageLength;

    // Assert message data after messageLength are zeros
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // Calculate SHA256 hash of the JWT message
    signal sha[256] <== Sha256Bytes(maxMessageLength)(message, messageLength);

    // Pack SHA output bytes to int[] for RSA input message
    var rsaMessageSize = (256 + n) \ n; // Adjust based on RSA chunk size
    component rsaMessage[rsaMessageSize];
    for (var i = 0; i < rsaMessageSize; i++) {
        rsaMessage[i] = Bits2Num(n);
    }
    for (var i = 0; i < 256; i++) {
        rsaMessage[i \ n].in[i % n] <== sha[255 - i];
    }
    for (var i = 256; i < n * rsaMessageSize; i++) {
        rsaMessage[i \ n].in[i % n] <== 0;
    }

    // Verify RSA signature
    component rsaVerifier = RSAVerifier65537(n, k);
    for (var i = 0; i < rsaMessageSize; i++) {
        rsaVerifier.message[i] <== rsaMessage[i].out;
    }
    for (var i = rsaMessageSize; i < k; i++) {
        rsaVerifier.message[i] <== 0;
    }
    rsaVerifier.modulus <== pubkey;
    rsaVerifier.signature <== signature;

    // Calculate the pubkey hash
    publicKeyHash <== PoseidonLarge(n, k)(pubkey);

    // Assert that period exists at periodIndex
    signal period <== ItemAtIndex(maxMessageLength)(message, periodIndex);
    period === 46;

    // Assert that period is unique
    signal periodCount <== CountCharOccurrences(maxMessageLength)(message, 46);
    periodCount === 1;

    // Find the real message length
    signal realMessageLength <== FindRealMessageLength(maxMessageLength)(message);

    // Calculate the length of the Base64 encoded header and payload
    signal b64HeaderLength <== periodIndex;
    signal b64PayloadLength <== realMessageLength - b64HeaderLength - 1;

    // Extract the Base64 encoded header and payload from the message
    signal b64Header[maxB64HeaderLength] <== SelectSubArrayBase64(maxMessageLength, maxB64HeaderLength)(message, 0, b64HeaderLength);
    signal b64Payload[maxB64PayloadLength] <== SelectSubArrayBase64(maxMessageLength, maxB64PayloadLength)(message, b64HeaderLength + 1, b64PayloadLength);

    // Decode the Base64 encoded header and payload
    header <== Base64Decode(maxHeaderLength)(b64Header);
    payload <== Base64Decode(maxPayloadLength)(b64Payload);
}