// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";
import {SchemaManager} from "../src/SchemaManager.sol";
import {VaultPermissionsLib} from "../src/libs/VaultPermissionsLib.sol";
import {IVaultErrors} from "../src/interfaces/IVaultErrors.sol";
import {IVaultPermissions} from "../src/interfaces/IVaultPermissions.sol";
import {VaultPermissions} from "../src/VaultPermissions.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract VaultPermissionsTest is Test, IERC1155Receiver {
    Vault public vault;
    SchemaManager public schemaManager;
    string public schemaId = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
    address public owner;
    address public user1;
    address public user2;
    address public user3;
    uint256 public constant TOKEN_ID = 1;

    event VaultAccessGranted(address indexed to, uint256 indexed tokenId, uint8 permission);
    event VaultAccessRevoked(address indexed to, uint256 indexed tokenId);

    function setUp() public {
        owner = makeAddr("alice");
        user1 = makeAddr("bob");
        user2 = makeAddr("charlie");
        user3 = makeAddr("dave");

        vm.startPrank(owner);

        // Deploy SchemaManager and Vault
        schemaManager = new SchemaManager();
        vault = new Vault(address(schemaManager));

        // Set up schema
        schemaManager.setSchema(schemaId);

        // Set up proposal vault manager
        vault.setProposalVaultManager(owner);

        // Create the test vault
        vault.createVault("Test Vault", "Test Description");

        vm.stopPrank();
    }

    function onERC1155Received(address, address, uint256, uint256, bytes memory)
        public
        virtual
        override
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory)
        public
        virtual
        override
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }

    function test_GrantAccess() public {
        vm.startPrank(owner);

        // Create a new vault for this test
        vault.createVault("Test Vault 2", "Test Description 2");
        uint256 newTokenId = 2;

        vm.expectEmit(true, true, true, true);
        emit VaultAccessGranted(user1, newTokenId, VaultPermissionsLib.PERMISSION_READ);

        vault.grantAccess(user1, newTokenId, VaultPermissionsLib.PERMISSION_READ);

        assertEq(vault.permissions(newTokenId, user1), VaultPermissionsLib.PERMISSION_READ);

        vm.stopPrank();
    }

    function test_RevokeAccess() public {
        vm.startPrank(owner);

        // Create a new vault for this test
        vault.createVault("Test Vault 2", "Test Description 2");
        uint256 newTokenId = 2;

        // First grant access
        vault.grantAccess(user1, newTokenId, VaultPermissionsLib.PERMISSION_READ);

        vm.expectEmit(true, true, true, true);
        emit VaultAccessRevoked(user1, newTokenId);

        vault.revokeAccess(newTokenId, user1);

        assertEq(vault.permissions(newTokenId, user1), VaultPermissionsLib.PERMISSION_NONE);

        vm.stopPrank();
    }

    function test_GetPermission() public {
        vm.startPrank(owner);

        // Create a new vault for this test
        vault.createVault("Test Vault 2", "Test Description 2");
        uint256 newTokenId = 2;

        // Grant read permission
        vault.grantAccess(user1, newTokenId, VaultPermissionsLib.PERMISSION_READ);

        assertEq(vault.permissions(newTokenId, user1), VaultPermissionsLib.PERMISSION_READ);

        // Grant write permission to another user
        vault.grantAccess(user2, newTokenId, VaultPermissionsLib.PERMISSION_WRITE);

        assertEq(vault.permissions(newTokenId, user2), VaultPermissionsLib.PERMISSION_WRITE);

        vm.stopPrank();
    }

    function test_DowngradePermission() public {
        vm.startPrank(owner);

        // Create a new vault for this test
        vault.createVault("Test Vault 2", "Test Description 2");
        uint256 newTokenId = 2;

        // First grant write permission
        vault.grantAccess(user1, newTokenId, VaultPermissionsLib.PERMISSION_WRITE);

        // Revoke access first
        vault.revokeAccess(newTokenId, user1);

        // Then grant read permission
        vault.grantAccess(user1, newTokenId, VaultPermissionsLib.PERMISSION_READ);

        assertEq(vault.permissions(newTokenId, user1), VaultPermissionsLib.PERMISSION_READ);

        vm.stopPrank();
    }

    function test_RevertGrantAccess_ZeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(IVaultErrors.ZeroAddress.selector);
        vault.grantAccess(address(0), TOKEN_ID, VaultPermissionsLib.PERMISSION_READ);
        vm.stopPrank();
    }

    function test_RevertRevokeAccess_ZeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(IVaultErrors.ZeroAddress.selector);
        vault.revokeAccess(TOKEN_ID, address(0));
        vm.stopPrank();
    }

    function test_UpgradePermission() public {
        vm.startPrank(owner);

        // Create a new vault for this test
        vault.createVault("Test Vault 2", "Test Description 2");
        uint256 newTokenId = 2;

        // First grant read permission
        vault.grantAccess(user1, newTokenId, VaultPermissionsLib.PERMISSION_READ);

        // Upgrade to write permission using upgradePermission
        vault.upgradePermission(newTokenId, user1);

        assertFalse(vault.isPermissionVaultRead(newTokenId, user1));
        assertTrue(vault.isPermissionVaultWrite(newTokenId, user1));

        vm.stopPrank();
    }
}
