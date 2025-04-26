// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title VaultTypehashLib - Library for hashing vault types
library VaultTypehashLib {
    bytes32 internal constant METADATA_SIGNATURE_TYPEHASH =
        keccak256("MetadataHash(string metadata,uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 internal constant METADATA_ARRAY_SIGNATURE_TYPEHASH =
        keccak256("MetadataArrayHash(string[] metadata,uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 internal constant PERMISSION_GRANT_TYPEHASH =
        keccak256("PermissionGrant(address to,uint256 tokenId,uint8 permission,uint256 nonce,uint256 deadline)");
}
