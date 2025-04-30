// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {IVaultErrors} from "./interfaces/IVaultErrors.sol";
import {IVaultPermissions} from "./interfaces/IVaultPermissions.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {VaultPermissionsLib} from "./libs/VaultPermissionsLib.sol";

abstract contract VaultPermissions is IVaultErrors, IVaultPermissions, ERC1155 {
    // Address of the ProposalVaultManager contract
    address public proposalVaultManager;

    // Mapping of vaults: tokenId -> address
    mapping(uint256 => address) public vaultOwner;

    // Mapping of permissions: tokenId -> address -> permission
    mapping(uint256 => mapping(address => uint8)) public permissions;

    // ----------------------------- //
    //        Modifiers              //
    // ----------------------------- //

    modifier onlyProposalVaultManager() {
        if (msg.sender != proposalVaultManager) {
            revert NotProposalVaultManager();
        }
        _;
    }

    // ----------------------------- //
    //        Functions              //
    // ----------------------------- //

    /// @notice Returns the read permission
    /// @return The read permission
    function getPermissionRead() external pure returns (uint8) {
        return VaultPermissionsLib.PERMISSION_READ;
    }

    /// @notice Returns the write permission
    /// @return The write permission
    function getPermissionWrite() external pure returns (uint8) {
        return VaultPermissionsLib.PERMISSION_WRITE;
    }

    /// @notice Returns the none permission
    /// @return The none permission
    function getPermissionNone() external pure returns (uint8) {
        return VaultPermissionsLib.PERMISSION_NONE;
    }

    /// @notice Returns true if the user has read permission for the vault
    /// @param tokenId The vault identifier
    /// @param user The address of the user
    /// @return True if the user has read permission, false otherwise
    function isPermissionVaultRead(uint256 tokenId, address user) external view returns (bool) {
        return permissions[tokenId][user] == VaultPermissionsLib.PERMISSION_READ;
    }

    /// @notice Returns true if the user has write permission for the vault
    /// @param tokenId The vault identifier
    /// @param user The address of the user
    /// @return True if the user has write permission, false otherwise
    function isPermissionVaultWrite(uint256 tokenId, address user) external view returns (bool) {
        return permissions[tokenId][user] == VaultPermissionsLib.PERMISSION_WRITE;
    }

    /// @notice Returns true if the user has granted permission for the vault
    /// @param tokenId The vault identifier
    /// @param user The address of the user
    /// @return True if the user has granted permission, false otherwise
    function hasGrantedPermission(uint256 tokenId, address user) external view returns (bool) {
        return permissions[tokenId][user] != VaultPermissionsLib.PERMISSION_NONE;
    }

    /// @notice Sets the none permission for a user
    /// @param tokenId The vault identifier
    /// @param user The address of the user
    /// @custom:error NotProposalVaultManager if the caller is not the proposal vault manager
    function setPermissionNone(uint256 tokenId, address user) external onlyProposalVaultManager {
        permissions[tokenId][user] = VaultPermissionsLib.PERMISSION_NONE;
    }

    /// @notice Sets the read permission for a user
    /// @param tokenId The vault identifier
    /// @param user The address of the user
    /// @custom:error NotProposalVaultManager if the caller is not the proposal vault manager
    function setPermissionRead(uint256 tokenId, address user) external onlyProposalVaultManager {
        permissions[tokenId][user] = VaultPermissionsLib.PERMISSION_READ;
    }

    /// @notice Sets the write permission for a user
    /// @param tokenId The vault identifier
    /// @param user The address of the user
    /// @custom:error NotProposalVaultManager if the caller is not the proposal vault manager
    function setPermissionWrite(uint256 tokenId, address user) external onlyProposalVaultManager {
        permissions[tokenId][user] = VaultPermissionsLib.PERMISSION_WRITE;
        emit PermissionUpgraded(user, tokenId);
    }

    /// @notice Upgrades a user's permission level for a vault
    /// @param tokenId The vault identifier
    /// @param user The address of the user
    /// @custom:error InvalidUpgrade if the user doesn't have READ permission
    /// @custom:error ZeroAddress if the user is the zero address
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error NotVaultOwner if the caller is not the vault owner
    function upgradePermission(uint256 tokenId, address user) external {
        if (user == address(0)) revert ZeroAddress();
        if (permissions[tokenId][user] != VaultPermissionsLib.PERMISSION_READ) {
            revert InvalidUpgrade();
        }

        // Then check vault state
        address owner = vaultOwner[tokenId];
        if (owner == address(0)) revert VaultDoesNotExist();
        if (msg.sender != owner) revert NotVaultOwner();

        permissions[tokenId][user] = VaultPermissionsLib.PERMISSION_WRITE;
        emit PermissionUpgraded(user, tokenId);
    }

    /// @notice Revokes access for a user from a vault
    /// @param tokenId The vault identifier
    /// @param to The address to revoke access from
    /// @custom:error ZeroAddress if the address to revoke is the zero address
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error NotVaultOwner if the caller is not the vault owner
    /// @custom:error CannotRevokeAccessToSelf if trying to revoke access from the vault owner
    /// @custom:error NoAccessToRevoke if the user has no access to revoke
    function revokeAccess(uint256 tokenId, address to) external {
        if (to == address(0)) revert ZeroAddress();
        address owner = vaultOwner[tokenId];
        if (owner == address(0)) revert VaultDoesNotExist();
        if (msg.sender != owner) revert NotVaultOwner();
        if (to == owner) revert CannotRevokeAccessToSelf();
        if (permissions[tokenId][to] == VaultPermissionsLib.PERMISSION_NONE) {
            revert NoAccessToRevoke();
        }

        permissions[tokenId][to] = VaultPermissionsLib.PERMISSION_NONE;
        _burn(to, tokenId, 1);

        emit VaultAccessRevoked(to, tokenId);
    }
}
