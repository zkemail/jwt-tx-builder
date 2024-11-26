// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "@zk-email/contracts/DKIMRegistry.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {strings} from "solidity-stringutils/src/strings.sol";
import {StringToArrayUtils} from "./StringToArrayUtils.sol";

/// @title JWT Registry
/// @notice TODO
/// @dev TODO
contract JwtRegistry is Ownable {
    using strings for *;
    using StringToArrayUtils for string;

    DKIMRegistry public dkimRegistry;

    // Check if azp is registered
    mapping(string => bool) public whitelistedClients;

    constructor(address _owner) Ownable(_owner) {
        dkimRegistry = new DKIMRegistry(address(this));
    }

    /// @notice Checks if a public key hash is valid and not revoked for a given kis and iss.
    /// @param domainName The domain name contains kid and iss fields.
    /// @param publicKeyHash The public key hash to validate.
    /// @return bool Returns true if the public key hash is valid and not revoked, false otherwise.
    function isJwtPublicKeyHashValid(
        string memory domainName,
        bytes32 publicKeyHash
    ) public view returns (bool) {
        string[] memory parts = domainName.stringToArray();
        string memory kidAndIss = string(abi.encode(parts[0], "|", parts[1]));
        return
            dkimRegistry.isDKIMPublicKeyHashValid(kidAndIss, publicKeyHash);
    }

    function isAzpWhitelisted(
        string memory azp
    ) public view returns (bool) {
        return whitelistedClients[azp];
    }

    /// @notice Validates a JWT public key hash
    /// @dev This function is just a wrapper for isDKIMPublicKeyHashValid
    /// @param domainName The domain name containing kid, iss, and azp fields
    /// @param publicKeyHash The public key hash to validate
    /// @return bool Returns true if the public key hash is valid, false otherwise
    function isJwtPublicKeyValid(
        string memory domainName,
        bytes32 publicKeyHash
    ) public view returns (bool) {
        return this.isJwtPublicKeyHashValid(domainName, publicKeyHash);
    }

    /// @notice Sets a public key hash for a `kis|iss` string  after validating the provided signature.
    /// @param domainName The domain name contains kis, iss and azp fields.
    /// @param publicKeyHash The public key hash to set.
    /// @dev This function requires that the public key hash is not already set or revoked.
    function setJwtPublicKey(
        string memory domainName,
        string memory azp,
        bytes32 publicKeyHash
    ) public onlyOwner {
        require(bytes(domainName).length != 0, "Invalid domain name");
        require(publicKeyHash != bytes32(0), "Invalid public key hash");
        string[] memory parts = domainName.stringToArray();
        string memory kidAndIss = string(abi.encode(parts[0], "|", parts[1]));
        require(
            isJwtPublicKeyHashValid(domainName, publicKeyHash) == false,
            "publicKeyHash is already set"
        );
        require(
            dkimRegistry.revokedDKIMPublicKeyHashes(publicKeyHash) == false,
            "publicKeyHash is revoked"
        );

        dkimRegistry.setDKIMPublicKeyHash(kidAndIss, publicKeyHash);
        // Register azp
        whitelistedClients[azp] = true;
    }

    /// @notice Revokes a public key hash for `kis|iss` string after validating the provided signature.
    /// @param domainName The domain name contains kis, iss and azp fields.
    /// @param publicKeyHash The public key hash to revoke.
    /// @dev This function requires that the public key hash is currently set and not already revoked.
    function revokeDKIMPublicKeyHash(
        string memory domainName,
        bytes32 publicKeyHash
    ) public onlyOwner {
        require(bytes(domainName).length != 0, "Invalid domain name");
        require(publicKeyHash != bytes32(0), "Invalid public key hash");
        require(
            isJwtPublicKeyHashValid(domainName, publicKeyHash) == true,
            "publicKeyHash is not set"
        );
        require(
            dkimRegistry.revokedDKIMPublicKeyHashes(publicKeyHash) == false,
            "publicKeyHash is already revoked"
        );

        dkimRegistry.revokeDKIMPublicKeyHash(publicKeyHash);
    }

    /// @notice Disables the azp (authorized party) associated with the given domain name
    /// @param domainName The domain name containing kis, iss, and azp fields
    /// @dev This function removes the azp from the whitelisted clients
    function disableAzp(string memory domainName) public onlyOwner {
        string[] memory parts = domainName.stringToArray();
        string memory azp = parts[2];
        whitelistedClients[azp] = false;
    }
}
