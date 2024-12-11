// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {JwtRegistry} from "./utils/JwtRegistry.sol";
import {IVerifier, JwtProof} from "./interfaces/IVerifier.sol";

/// @title JWT Auth
/// @notice TODO
/// @dev TODO
contract JwtAuth is OwnableUpgradeable, UUPSUpgradeable {
    /// An instance of the JWT registry contract.
    JwtRegistry internal jwtRegistry;
    /// An instance of the Verifier contract.
    IVerifier internal verifier;
    /// A mapping of the hash of the authorized message associated with its `jwtNullifier`.
    mapping(bytes32 => bool) public usedNullifiers;

    event JwtRegistryUpdated(address indexed jwtRegistry);
    event VerifierUpdated(address indexed verifier);
    event JwtAuthed(
        bytes32 indexed jwtNullifier,
        bool isCodeExist,
        string indexed domainName,
        string indexed azp
    );

    constructor() {}

    /// @notice Initialize the contract with an initial owner and an account salt.
    /// @param _initialOwner The address of the initial owner.
    function initialize(
        address _initialOwner
    ) public initializer {
        __Ownable_init(_initialOwner);
    }

    /// @notice Initializes the address of the JWT registry contract.
    /// @param _jwtRegistryAddr The address of the JWT registry contract.
    function initJwtRegistry(address _jwtRegistryAddr) public onlyOwner {
        require(_jwtRegistryAddr != address(0), "invalid jwt registry address");
        require(
            address(jwtRegistry) == address(0),
            "jwt registry already initialized"
        );
        jwtRegistry = JwtRegistry(_jwtRegistryAddr);
        emit JwtRegistryUpdated(_jwtRegistryAddr);
    }

    /// @notice Initializes the address of the verifier contract.
    /// @param _verifierAddr The address of the verifier contract.
    function initVerifier(address _verifierAddr) public onlyOwner {
        require(_verifierAddr != address(0), "invalid verifier address");
        require(
            address(verifier) == address(0),
            "verifier already initialized"
        );
        verifier = IVerifier(_verifierAddr);
        emit VerifierUpdated(_verifierAddr);
    }

    /// @notice Updates the address of the JWT registry contract.
    /// @param _jwtRegistryAddr The new address of the JWT registry contract.
    function updateJwtRegistry(address _jwtRegistryAddr) public onlyOwner {
        require(_jwtRegistryAddr != address(0), "invalid jwt registry address");
        jwtRegistry = JwtRegistry(_jwtRegistryAddr);
        emit JwtRegistryUpdated(_jwtRegistryAddr);
    }

    /// @notice Updates the address of the verifier contract.
    /// @param _verifierAddr The new address of the verifier contract.
    function updateVerifier(address _verifierAddr) public onlyOwner {
        require(_verifierAddr != address(0), "invalid verifier address");
        verifier = IVerifier(_verifierAddr);
        emit VerifierUpdated(_verifierAddr);
    }

    function authJwt(JwtProof memory proof) public onlyOwner {

        // Check JwtRegistry,
        // if it returns false, then call updateJwtRegistry,
        // and then try isJwtPublicKeyValid again.
        if (
            !jwtRegistry.isJwtPublicKeyValid(
                proof.domainName,
                proof.publicKeyHash
            )
        ) {
            jwtRegistry.updateJwtRegistry();
            require(
                jwtRegistry.isJwtPublicKeyValid(
                    proof.domainName,
                    proof.publicKeyHash
                ),
                "Invalid public key hash"
            );
        }
        // Check if azp is in whitelist
        require(
            jwtRegistry.isAzpWhitelisted(proof.azp),
            "azp is not whitelisted"
        );

        require(verifier.verifyJwtProof(proof) == true, "invalid jwt proof");

        usedNullifiers[proof.jwtNullifier] = true;

        emit JwtAuthed(
            proof.jwtNullifier,
            proof.isCodeExist,
            proof.domainName,
            proof.azp
        );
    }

    /// @notice Upgrade the implementation of the proxy.
    /// @param newImplementation Address of the new implementation.
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}
}
