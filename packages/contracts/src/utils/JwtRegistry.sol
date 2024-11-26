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
        string memory issAndKid = string(abi.encodePacked(parts[0], "|", parts[1]));
        return
            dkimRegistry.isDKIMPublicKeyHashValid(issAndKid, publicKeyHash);
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

    function updateJwtRegistry() public onlyOwner {
        // TODO Call ChainLink Function
        // TODO Receive kid, iss, publicKeyHash

        // Example implementation, we implement ChainLink Function later
        for(uint i = 0; i < 1; i++) {
            string memory issAndKid = "https://example.com|12345";
            bytes32 publicKeyHash = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
            if(isJwtPublicKeyHashValid(issAndKid, publicKeyHash)){
                continue;
            }
            if(dkimRegistry.revokedDKIMPublicKeyHashes(publicKeyHash)){
                continue;
            }
            dkimRegistry.setDKIMPublicKeyHash(issAndKid, publicKeyHash);    
        }
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

    function isAzpWhitelisted(
        string memory azp
    ) public view returns (bool) {
        return whitelistedClients[azp];
    }

    function whitelistAzp(
        string memory azp
    ) public onlyOwner(){
        whitelistedClients[azp] = true;
    }

    /// @notice Disables the azp (authorized party) associated with the given domain name
    /// @param azp The azp string
    /// @dev This function removes the azp from the whitelisted clients
    function disableAzp(string memory azp) public onlyOwner {
        require(bytes(azp).length != 0, "Invalid azp string");
        whitelistedClients[azp] = false;
    }
}
