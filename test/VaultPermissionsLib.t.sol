// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";
import {VaultPermissionsLib} from "../src/libs/VaultPermissionsLib.sol";
import {IVaultErrors} from "../src/interfaces/IVaultErrors.sol";

contract VaultPermissionsLibTest is Test {
    function test_PermissionConstants() public pure {
        assertEq(VaultPermissionsLib.PERMISSION_NONE, 0);
        assertEq(VaultPermissionsLib.PERMISSION_READ, 1);
        assertEq(VaultPermissionsLib.PERMISSION_WRITE, 2);
    }

    function test_IsValidPermission() public pure {
        // Test valid permissions
        assertTrue(VaultPermissionsLib.isValidPermission(VaultPermissionsLib.PERMISSION_READ));
        assertTrue(VaultPermissionsLib.isValidPermission(VaultPermissionsLib.PERMISSION_WRITE));

        // Test invalid permissions
        assertFalse(VaultPermissionsLib.isValidPermission(VaultPermissionsLib.PERMISSION_NONE));
        assertFalse(VaultPermissionsLib.isValidPermission(3));
        assertFalse(VaultPermissionsLib.isValidPermission(type(uint8).max));
    }

    function test_HasReadPermission() public pure {
        // Test read permission
        assertTrue(VaultPermissionsLib.hasReadPermission(VaultPermissionsLib.PERMISSION_READ));
        // Test write permission (should not have read permission)
        assertFalse(VaultPermissionsLib.hasReadPermission(VaultPermissionsLib.PERMISSION_WRITE));
        // Test no permission
        assertFalse(VaultPermissionsLib.hasReadPermission(VaultPermissionsLib.PERMISSION_NONE));
        // Test invalid permission
        assertFalse(VaultPermissionsLib.hasReadPermission(3));
    }

    function test_HasWritePermission() public pure {
        assertFalse(VaultPermissionsLib.hasWritePermission(VaultPermissionsLib.PERMISSION_READ));
        assertTrue(VaultPermissionsLib.hasWritePermission(VaultPermissionsLib.PERMISSION_WRITE));
        assertFalse(VaultPermissionsLib.hasWritePermission(VaultPermissionsLib.PERMISSION_NONE));
        assertFalse(VaultPermissionsLib.hasWritePermission(3));
    }

    function test_CanRevokeAccess() public {
        address caller = address(0x1);
        address to = address(0x2);
        address owner = address(0x3);

        // Test case: caller is not the owner
        try this.callCanRevokeAccess(caller, to, owner, VaultPermissionsLib.PERMISSION_READ) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.NotVaultOwner.selector);
        }

        // Test case: to is zero address
        try this.callCanRevokeAccess(owner, address(0), owner, VaultPermissionsLib.PERMISSION_READ) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.ZeroAddress.selector);
        }

        // Test case: owner is zero address
        try this.callCanRevokeAccess(owner, to, address(0), VaultPermissionsLib.PERMISSION_READ) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.VaultDoesNotExist.selector);
        }

        // Test case: trying to revoke access to self
        try this.callCanRevokeAccess(owner, owner, owner, VaultPermissionsLib.PERMISSION_READ) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.CannotRevokeAccessToSelf.selector);
        }

        // Test case: no access to revoke
        try this.callCanRevokeAccess(owner, to, owner, VaultPermissionsLib.PERMISSION_NONE) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.NoAccessToRevoke.selector);
        }
    }

    function callCanRevokeAccess(address caller, address to, address owner, uint8 permission) external pure {
        VaultPermissionsLib.canRevokeAccess(caller, to, owner, permission);
    }

    function test_PermissionHierarchy() public pure {
        // Write permission does not imply read permission
        uint8 writePermission = VaultPermissionsLib.PERMISSION_WRITE;
        assertFalse(VaultPermissionsLib.hasReadPermission(writePermission));
        assertTrue(VaultPermissionsLib.hasWritePermission(writePermission));

        // Read permission does not imply write permission
        uint8 readPermission = VaultPermissionsLib.PERMISSION_READ;
        assertTrue(VaultPermissionsLib.hasReadPermission(readPermission));
        assertFalse(VaultPermissionsLib.hasWritePermission(readPermission));

        // No permission implies neither read nor write
        uint8 noPermission = VaultPermissionsLib.PERMISSION_NONE;
        assertFalse(VaultPermissionsLib.hasReadPermission(noPermission));
        assertFalse(VaultPermissionsLib.hasWritePermission(noPermission));
    }

    function test_InvalidPermissionBoundaries() public {
        address caller = address(0x1);
        address to = address(0x2);
        address owner = address(0x3);

        // Test case: permission > PERMISSION_WRITE
        try this.callCanRevokeAccess(caller, to, owner, 3) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.NotVaultOwner.selector);
        }

        // Test case: permission < PERMISSION_NONE
        try this.callCanRevokeAccess(caller, to, owner, type(uint8).max) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.NotVaultOwner.selector);
        }
    }

    function test_RevokeAccessEdgeCases() public {
        address caller = address(0x1);
        address to = address(0x2);
        address owner = address(0x3);

        // Test case: caller has no access to revoke
        try this.callCanRevokeAccess(caller, to, owner, VaultPermissionsLib.PERMISSION_READ) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.NotVaultOwner.selector);
        }

        // Test case: invalid permission
        try this.callCanRevokeAccess(caller, to, owner, 3) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.NotVaultOwner.selector);
        }

        // Test case: permission is PERMISSION_NONE
        try this.callCanRevokeAccess(caller, to, owner, VaultPermissionsLib.PERMISSION_NONE) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), IVaultErrors.NotVaultOwner.selector);
        }
    }
}
