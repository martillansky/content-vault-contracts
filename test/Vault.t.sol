// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../src/Vault.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {IERC1155Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract VaultTest is Test, IERC1155Receiver {
    Vault public vault;
    address public alice;
    address public bob;
    address public charlie;

    function setUp() public {
        vault = new Vault();
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");

        // Set up the schema as the owner
        vm.startPrank(vault.owner());
        vault.setSchema("ipfs://QmTestSchemaHash123456789");
        vm.stopPrank();
    }

    function testCreateVault() public {
        vm.prank(alice);
        vault.createVault(1);

        assertEq(vault.vaultExists(1), true);
        assertEq(vault.getVaultOwner(1), alice);
    }

    function test_RevertWhen_CreateVaultWithZeroAddress() public {
        vm.startPrank(address(0));
        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(0)));
        vault.createVault(1);
        vm.stopPrank();
    }

    function test_RevertWhen_CreateVaultWithExistingId() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.AlreadyHasToken.selector));
        vault.createVault(1);
        vm.stopPrank();
    }

    function testGrantAccess() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vm.stopPrank();

        assertEq(vault.getPermission(1, bob), vault.PERMISSION_READ());
    }

    function test_RevertWhen_GrantAccessWithInvalidPermission() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidPermission.selector));
        vault.grantAccess(bob, 1, 3);
        vm.stopPrank();
    }

    function test_RevertWhen_GrantAccessToZeroAddress() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.ZeroAddress.selector));
        vault.grantAccess(address(0), 1, 1);
        vm.stopPrank();
    }

    function test_RevertWhen_GrantAccessToExistingToken() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 1);
        vm.expectRevert(abi.encodeWithSelector(Vault.AlreadyHasToken.selector));
        vault.grantAccess(bob, 1, 1);
        vm.stopPrank();
    }

    function test_RevertWhen_GrantAccessToNonExistentVault() public {
        vm.expectRevert(abi.encodeWithSelector(Vault.VaultDoesNotExist.selector));
        vault.grantAccess(bob, 1, 1);
    }

    function test_RevertWhen_GrantAccessAsNonOwner() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.stopPrank();

        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSelector(Vault.NotVaultOwner.selector));
        vault.grantAccess(charlie, 1, 1);
        vm.stopPrank();
    }

    function testRevokeAccess() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vault.revokeAccess(1, bob);
        vm.stopPrank();

        assertEq(vault.getPermission(1, bob), vault.PERMISSION_NONE());
    }

    function test_RevertWhen_RevokeAccessToZeroAddress() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.ZeroAddress.selector));
        vault.revokeAccess(1, address(0));
        vm.stopPrank();
    }

    function test_RevertWhen_RevokeAccessToSelf() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.CannotRevokeAccessToSelf.selector));
        vault.revokeAccess(1, alice);
        vm.stopPrank();
    }

    function testUpgradePermission() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vault.upgradePermission(1, bob, vault.PERMISSION_WRITE());
        vm.stopPrank();

        assertEq(vault.getPermission(1, bob), vault.PERMISSION_WRITE());
    }

    function test_RevertWhen_UpgradePermissionFromNonRead() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 2);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidUpgrade.selector));
        vault.upgradePermission(1, bob, 2);
    }

    function test_RevertWhen_UpgradePermissionToNonWrite() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 1);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidUpgrade.selector));
        vault.upgradePermission(1, bob, 1);
    }

    function test_RevertWhen_UpgradePermissionWithInvalidPermission() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 1);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidUpgrade.selector));
        vault.upgradePermission(1, bob, 3);
        vm.stopPrank();
    }

    function testStoreContentWithMetadata() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, vault.PERMISSION_WRITE());
        vm.stopPrank();

        vm.prank(bob);
        vault.storeContentWithMetadata(1, "ipfs://QmTestContentHash123456789", '{"name": "test"}');
    }

    function test_RevertWhen_StoreContentWithEmptyHash() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 2);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidIPFSHash.selector));
        vm.prank(bob);
        vault.storeContentWithMetadata(1, "", '{"name": "test"}');
    }

    function test_RevertWhen_StoreContentWithEmptyMetadata() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 2);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidSchema.selector));
        vm.prank(bob);
        vault.storeContentWithMetadata(1, "ipfs://QmTestContentHash123456789", "");
    }

    function testStoreContentBatch() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, vault.PERMISSION_WRITE());
        vm.stopPrank();

        string[] memory hashes = new string[](3);
        string[] memory metas = new string[](3);
        for (uint256 i = 0; i < 3; i++) {
            hashes[i] = "ipfs://QmTestContentHash123456789";
            metas[i] = '{"title":"test"}';
        }

        vm.prank(bob);
        vault.storeContentBatch(1, hashes, metas);
    }

    function test_RevertWhen_StoreContentBatchWithEmptyArrays() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 2);
        vm.stopPrank();

        string[] memory hashes = new string[](0);
        string[] memory metas = new string[](0);

        vm.expectRevert(abi.encodeWithSelector(Vault.EmptyArray.selector));
        vm.prank(bob);
        vault.storeContentBatch(1, hashes, metas);
    }

    function test_RevertWhen_StoreContentBatchWithMismatchedLengths() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 2);
        vm.stopPrank();

        string[] memory hashes = new string[](2);
        string[] memory metas = new string[](3);
        for (uint256 i = 0; i < 2; i++) {
            hashes[i] = "ipfs://QmTestContentHash123456789";
        }
        for (uint256 i = 0; i < 3; i++) {
            metas[i] = '{"title":"test"}';
        }

        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidSchema.selector));
        vm.prank(bob);
        vault.storeContentBatch(1, hashes, metas);
    }

    function testSetURI() public {
        string memory newURI = "https://example.com/metadata/{id}.json";
        vm.prank(vault.owner());
        vault.setURI(newURI);
    }

    function test_RevertWhen_SetURINonOwner() public {
        string memory newURI = "https://example.com/metadata/{id}.json";
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        vm.prank(alice);
        vault.setURI(newURI);
    }

    function testSchemaManagement() public {
        vm.startPrank(vault.owner());
        vault.setSchema("ipfs://QmTestSchemaHash2");
        assertEq(vault.getCurrentSchema(), "ipfs://QmTestSchemaHash2");

        vault.deprecateSchema(2);
        assertEq(vault.deprecatedSchemas(2), true);
        vm.stopPrank();
    }

    function test_RevertWhen_SetSchemaNonOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        vm.prank(alice);
        vault.setSchema("ipfs://QmTestSchemaHash2");
    }

    function test_RevertWhen_DeprecateSchemaNonOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        vm.prank(alice);
        vault.deprecateSchema(1);
    }

    function test_RevertWhen_DeprecateSchemaInvalidIndex() public {
        vm.prank(vault.owner());
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidSchemaIndex.selector));
        vault.deprecateSchema(0);
    }

    function test_RevertWhen_GetSchemaInvalidIndex() public {
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidSchemaIndex.selector));
        vault.getSchema(0);
    }

    function testVerifyVaultState() public {
        assertEq(vault.vaultExists(999), false);
        assertEq(vault.getVaultOwner(999), address(0));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.VaultDoesNotExist.selector));
        vault.grantAccess(bob, 999, 1);
    }

    function testGrantAccessValidation() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidPermission.selector));
        vault.grantAccess(bob, 1, 3);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.ZeroAddress.selector));
        vault.grantAccess(address(0), 1, 1);
    }

    function testErrorPropagation() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.stopPrank();

        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidPermission.selector));
        vault.grantAccess(bob, 1, 3);
        vm.stopPrank();
    }

    function testOperationOrder() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.stopPrank();

        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidPermission.selector));
        vault.grantAccess(bob, 1, 3);
        vm.stopPrank();

        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.ZeroAddress.selector));
        vault.grantAccess(address(0), 1, 1);
    }

    function testSequenceOfEvents() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.stopPrank();

        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidPermission.selector));
        vault.grantAccess(bob, 1, 3);
        vm.stopPrank();

        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.ZeroAddress.selector));
        vault.grantAccess(address(0), 1, 1);
    }

    function testStateTransitions() public {
        // Initial state
        assertEq(vault.vaultExists(1), false);
        assertEq(vault.getVaultOwner(1), address(0));
        assertEq(vault.balanceOf(alice, 1), 0);
        assertEq(vault.balanceOf(bob, 1), 0);
        assertEq(vault.getPermission(1, alice), 0);
        assertEq(vault.getPermission(1, bob), 0);

        // Create vault
        vm.startPrank(alice);
        vault.createVault(1);
        vm.stopPrank();

        // After creation
        assertEq(vault.vaultExists(1), true);
        assertEq(vault.getVaultOwner(1), alice);
        assertEq(vault.balanceOf(alice, 1), 1);
        assertEq(vault.balanceOf(bob, 1), 0);
        assertEq(vault.getPermission(1, alice), 0);
        assertEq(vault.getPermission(1, bob), 0);

        // Grant access
        vm.startPrank(alice);
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vm.stopPrank();

        // After granting access
        assertEq(vault.vaultExists(1), true);
        assertEq(vault.getVaultOwner(1), alice);
        assertEq(vault.balanceOf(alice, 1), 1);
        assertEq(vault.balanceOf(bob, 1), 1);
        assertEq(vault.getPermission(1, alice), 0);
        assertEq(vault.getPermission(1, bob), vault.PERMISSION_READ());

        // Upgrade permission
        vm.startPrank(alice);
        vault.upgradePermission(1, bob, vault.PERMISSION_WRITE());
        vm.stopPrank();

        // After upgrading permission
        assertEq(vault.vaultExists(1), true);
        assertEq(vault.getVaultOwner(1), alice);
        assertEq(vault.balanceOf(alice, 1), 1);
        assertEq(vault.balanceOf(bob, 1), 1);
        assertEq(vault.getPermission(1, alice), 0);
        assertEq(vault.getPermission(1, bob), vault.PERMISSION_WRITE());

        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidPermission.selector));
        vault.grantAccess(charlie, 1, 3);
        vm.stopPrank();
    }

    function test_RevertWhen_RevokeAccessFromOwner() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.CannotRevokeAccessToSelf.selector));
        vault.revokeAccess(1, alice);
        vm.stopPrank();
    }

    function test_RevertWhen_RevokeAccessFromNonExistentVault() public {
        vm.expectRevert(abi.encodeWithSelector(Vault.VaultDoesNotExist.selector));
        vault.revokeAccess(999, alice);
    }

    function test_RevertWhen_RevokeAccessFromUserWithoutAccess() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.NoAccessToRevoke.selector));
        vault.revokeAccess(1, bob);
        vm.stopPrank();
    }

    function test_RevertWhen_UpgradePermissionForNonExistentVault() public {
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidUpgrade.selector));
        vault.upgradePermission(1, bob, 2);
    }

    function test_RevertWhen_UpgradePermissionForUserWithoutAccess() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidUpgrade.selector));
        vault.upgradePermission(1, bob, 2);
        vm.stopPrank();
    }

    function test_RevertWhen_StoreContentWithoutWritePermission() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vault.grantAccess(bob, 1, 1);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Vault.NoWritePermission.selector));
        vault.storeContentWithMetadata(1, "ipfs://QmHash", "metadata");
    }

    function test_RevertWhen_StoreContentToNonExistentVault() public {
        vm.expectRevert(abi.encodeWithSelector(Vault.NoWritePermission.selector));
        vault.storeContentWithMetadata(999, "ipfs://QmHash", "metadata");
    }

    function test_RevertWhen_StoreContentWithInvalidIPFSHash() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.expectRevert(abi.encodeWithSelector(Vault.NoWritePermission.selector));
        vault.storeContentWithMetadata(1, "invalid_hash", "metadata");
        vm.stopPrank();
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }
}
