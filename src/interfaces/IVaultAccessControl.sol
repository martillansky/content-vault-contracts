// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title IVaultAccessControl - Minimal interface for Vault permission and access management
interface IVaultAccessControl {
    function mintVaultAccess(address to, uint256 tokenId) external;
    function burnVaultAccess(address from, uint256 tokenId) external;
    function getVaultBalance(address user, uint256 tokenId) external view returns (uint256);
}
