// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title CIDValidatorLib - Library for validating IPFS CIDs (v0 and v1 with base16, base32, base58)
library CIDValidatorLib {
    /// @notice Validates if a string is a valid IPFS CID
    /// @param cid The CID to validate
    /// @return True if the CID is valid, false otherwise
    function isValidCID(string memory cid) internal pure returns (bool) {
        bytes memory cidBytes = bytes(cid);
        uint256 length = cidBytes.length;

        // Require minimum length of 2 characters
        if (length < 2) return false;

        bytes1 first = cidBytes[0];
        bytes1 second = cidBytes[1];

        // CIDv0: base58btc, starts with "Qm" and length 46
        if (first == 0x51 && second == 0x6d) {
            // "Q" and "m"
            if (length != 46) return false;

            for (uint256 i = 0; i < length;) {
                bytes1 char = cidBytes[i];
                if (
                    // 1-9
                    // A-H
                    // J-N
                    // P-Z
                    // a-k
                    !(
                        (char >= 0x31 && char <= 0x39) || (char >= 0x41 && char <= 0x48)
                            || (char >= 0x4A && char <= 0x4E) || (char >= 0x50 && char <= 0x5A)
                            || (char >= 0x61 && char <= 0x6B) || (char >= 0x6D && char <= 0x7A)
                    ) // m-z (excluding 'l')
                ) {
                    return false;
                }
                unchecked {
                    ++i;
                }
            }
            return true;
        }

        // CIDv1: multibase prefix "b" followed by encoding type
        if (first == 0x62) {
            // "b"
            if (length < 4) return false;

            // CIDv1 base16: "bf..."
            if (second == 0x66) {
                for (uint256 i = 2; i < length;) {
                    bytes1 char = cidBytes[i];
                    if (
                        // 0-9
                        // a-f
                        !(
                            (char >= 0x30 && char <= 0x39) || (char >= 0x61 && char <= 0x66)
                                || (char >= 0x41 && char <= 0x46)
                        ) // A-F
                    ) {
                        return false;
                    }
                    unchecked {
                        ++i;
                    }
                }
                return true;
            }

            // CIDv1 base58btc: "bz..."
            if (second == 0x7a) {
                // "z"
                for (uint256 i = 2; i < length;) {
                    bytes1 char = cidBytes[i];
                    if (
                        // 1-9
                        // A-H
                        // J-N
                        // P-Z
                        // a-k
                        !(
                            (char >= 0x31 && char <= 0x39) || (char >= 0x41 && char <= 0x48)
                                || (char >= 0x4A && char <= 0x4E) || (char >= 0x50 && char <= 0x5A)
                                || (char >= 0x61 && char <= 0x6B) || (char >= 0x6D && char <= 0x7A)
                        ) // m-z
                    ) {
                        return false;
                    }
                    unchecked {
                        ++i;
                    }
                }
                return true;
            }

            // CIDv1 base32: "ba..." or "bc...", excluding "bf" and "bz"
            if (second >= 0x61 && second <= 0x7a && second != 0x66 && second != 0x7a) {
                for (uint256 i = 2; i < length;) {
                    bytes1 char = cidBytes[i];
                    if (
                        // A-Z
                        // a-z
                        // 2-7
                        !(
                            (char >= 0x41 && char <= 0x5A) || (char >= 0x61 && char <= 0x7A)
                                || (char >= 0x32 && char <= 0x37) || char == 0x3D
                        ) // '=' padding
                    ) {
                        return false;
                    }
                    unchecked {
                        ++i;
                    }
                }
                return true;
            }
        }

        return false;
    }
}
