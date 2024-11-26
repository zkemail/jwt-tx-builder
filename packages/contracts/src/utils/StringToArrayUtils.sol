// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {strings} from "solidity-stringutils/src/strings.sol";

library StringToArrayUtils {
    using strings for *;

    /// @notice Converts a string containing three parts separated by '|' into an array of strings
    /// @param _strings The input string to be split
    /// @return An array of three strings, representing kid and iss
    /// @dev This function is used to parse the domainName parameter in other functions
    /// @dev Requires the input string to contain exactly two '|' characters
    function stringToArray(
        string memory _strings
    ) internal pure returns (string[] memory) {
        strings.slice memory slicee = _strings.toSlice();
        strings.slice memory delim = "|".toSlice();
        string[] memory parts = new string[](slicee.count(delim) + 1);
        for (uint i = 0; i < parts.length; i++) {
            parts[i] = slicee.split(delim).toString();
        }
        require(parts.length == 2, "Invalid kid|iss strings");
        return parts;
    }
}
