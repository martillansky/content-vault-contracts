// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

interface IVaultPermissions {
    // Events
    event PermissionUpgraded(address indexed user, uint256 indexed tokenId);
    event VaultAccessRevoked(address indexed to, uint256 indexed tokenId);

    function setPermissionNone(uint256 tokenId, address user) external;
    function setPermissionRead(uint256 tokenId, address user) external;
    function setPermissionWrite(uint256 tokenId, address user) external;
    function getPermissionRead() external pure returns (uint8);
    function getPermissionWrite() external pure returns (uint8);
    function getPermissionNone() external pure returns (uint8);
    function isPermissionVaultRead(uint256 tokenId, address user) external view returns (bool);
    function isPermissionVaultWrite(uint256 tokenId, address user) external view returns (bool);
    function hasGrantedPermission(uint256 tokenId, address user) external view returns (bool);
}
