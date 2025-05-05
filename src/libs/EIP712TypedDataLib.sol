// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title EIP712TypedDataLib - Stateless helper for EIP-712 typed data hashing
library EIP712TypedDataLib {
    /// @notice Hashes typed data per EIP-712 using domain separator
    /// @param domainSeparator The domain separator
    /// @param structHash The keccak256 struct hash of the typed data
    /// @return digest The final EIP-712 message digest
    function hashTypedDataV4(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
