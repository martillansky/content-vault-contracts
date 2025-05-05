// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {IVaultErrors} from "../interfaces/IVaultErrors.sol";

/// @title VaultPermissionsLib - Library for vault permissions
library VaultPermissionsLib {
    // Permission Levels: uint8 constants to save gas
    uint8 internal constant PERMISSION_NONE = 0;
    uint8 internal constant PERMISSION_READ = 1;
    uint8 internal constant PERMISSION_WRITE = 2;

    /// @notice Returns true if the permission is read
    /// @param permission The permission to check
    /// @return True if the permission is read
    function hasReadPermission(uint8 permission) internal pure returns (bool) {
        return permission == PERMISSION_READ;
    }

    /// @notice Returns true if the permission is write
    /// @param permission The permission to check
    /// @return True if the permission is write
    function hasWritePermission(uint8 permission) internal pure returns (bool) {
        return permission == PERMISSION_WRITE;
    }

    /// @notice Returns true if the permission is valid
    /// @param permission The permission to check
    /// @return True if the permission is valid
    function isValidPermission(uint8 permission) internal pure returns (bool) {
        return permission == PERMISSION_READ || permission == PERMISSION_WRITE;
    }

    /// @notice Checks if the caller can revoke access
    /// @param caller The caller of the function
    /// @param to The address to revoke access to
    /// @param owner The owner of the vault
    /// @param permission The permission to check
    function canRevokeAccess(address caller, address to, address owner, uint8 permission) internal pure {
        if (to == address(0)) revert IVaultErrors.ZeroAddress();
        if (owner == address(0)) revert IVaultErrors.VaultDoesNotExist();
        if (caller != owner) revert IVaultErrors.NotVaultOwner();
        if (to == owner) revert IVaultErrors.CannotRevokeAccessToSelf();
        if (permission == PERMISSION_NONE) {
            revert IVaultErrors.NoAccessToRevoke();
        }
    }
}
