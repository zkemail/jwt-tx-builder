// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

struct JwtProof {
    string domainName; // it contains iss and kid with the delimiter |
    string azp; // The azp string
    bytes32 publicKeyHash; // Hash of the public key used in jwt
    uint timestamp; // Timestamp of the jwt
    string maskedCommand; // Masked command of the jwt
    bytes32 jwtNullifier; // Nullifier of the jwt to prevent its reuse.
    bytes32 accountSalt; // Create2 salt of the account
    bool isCodeExist; // Check if the account code is exist
    bytes proof; // ZK proof of jwt
}

interface IVerifier {
    /**
     * @notice Verifies the provided jwt proof.
     * @param proof The jwt proof to be verified.
     * @return bool indicating whether the proof is valid.
     */
    function verifyJwtProof(JwtProof memory proof) external returns (bool);

    /**
     * @notice Returns a constant value representing command bytes.
     * @return uint256 The constant value of command bytes.
     */
    function getCommandBytes() external pure returns (uint256);
}
