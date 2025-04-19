// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract VaultTest is Test {
    Vault public vault;
    address public owner;
    address public alice;
    address public bob;
    address public charlie;

    function setUp() public {
        // Label addresses for better error messages
        owner = address(this);
        vm.label(owner, "Owner");

        alice = makeAddr("alice");
        vm.label(alice, "Alice");

        bob = makeAddr("bob");
        vm.label(bob, "Bob");

        charlie = makeAddr("charlie");
        vm.label(charlie, "Charlie");

        // Deploy the vault contract with this contract as owner
        vm.prank(owner);
        vault = new Vault();

        // Set up initial schema
        vault.setSchema("QmSchema1");

        // Clear any existing state
        vm.clearMockedCalls();
    }

    // Schema Tests
    function testSetSchema() public {
        vault.setSchema("QmSchema2");
        assertEq(vault.getCurrentSchema(), "QmSchema2");
    }

    function test_RevertWhen_NotOwnerSetsSchema() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        vault.setSchema("QmSchema2");
    }

    // Vault Creation Tests
    function testCreateVault() public {
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");
        assertTrue(vault.vaultExists(1));
        assertEq(vault.getVaultOwner(1), alice);
        assertEq(vault.getPermission(1, alice), vault.PERMISSION_WRITE());
    }

    function test_RevertWhen_CreateVaultWithoutSchema() public {
        // Deploy new vault without schema
        vault = new Vault();
        vm.prank(alice);
        vm.expectRevert(Vault.NoSchema.selector);
        vault.createVault("Vault 1", "Description 1");
    }

    // Access Control Tests
    function testGrantAccess() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vm.stopPrank();
        assertEq(vault.getPermission(1, bob), vault.PERMISSION_READ());
    }

    function testRevokeAccess() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vault.revokeAccess(1, bob);
        vm.stopPrank();
        assertEq(vault.getPermission(1, bob), vault.PERMISSION_NONE());
    }

    function testUpgradePermission() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vault.upgradePermission(1, bob, vault.PERMISSION_WRITE());
        vm.stopPrank();
        assertEq(vault.getPermission(1, bob), vault.PERMISSION_WRITE());
    }

    function test_RevertWhen_NotVaultOwnerGrantsAccess() public {
        uint8 permissionRead = vault.PERMISSION_READ();
        vm.deal(alice, 1 ether);
        vm.deal(bob, 1 ether);
        vm.deal(charlie, 1 ether);

        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Debug info
        assertTrue(vault.vaultExists(1), "Vault should exist");
        assertEq(vault.getVaultOwner(1), alice, "Alice should be the owner");
        assertEq(vault.getPermission(1, alice), vault.PERMISSION_WRITE(), "Alice should have write permission");
        assertEq(vault.balanceOf(charlie, 1), 0, "Charlie should not have token");

        vm.prank(bob);
        vm.expectRevert(Vault.NotVaultOwner.selector);
        vault.grantAccess(charlie, 1, permissionRead);
    }

    function test_RevertWhen_NotVaultOwnerRevokesAccess() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vm.stopPrank();

        vm.prank(bob);
        vm.expectRevert(Vault.NotVaultOwner.selector);
        vault.revokeAccess(1, charlie);
    }

    function test_RevertWhen_RevokeAccessToSelf() public {
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        vm.prank(alice);
        vm.expectRevert(Vault.CannotRevokeAccessToSelf.selector);
        vault.revokeAccess(1, alice);
    }

    // Content Storage Tests
    function testStoreContent() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.storeContentWithMetadata(1, bytes("encryptedCID"), true, "metadata");
        vm.stopPrank();
    }

    function test_RevertWhen_NoWritePermissionStoresContent() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, vault.PERMISSION_READ());
        vm.stopPrank();

        vm.prank(bob);
        vm.expectRevert(Vault.NoWritePermission.selector);
        vault.storeContentWithMetadata(1, bytes("encryptedCID"), true, "metadata");
    }

    // Batch Operations Tests
    function testStoreContentBatch() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        bytes[] memory cids = new bytes[](2);
        cids[0] = bytes("encryptedCID1");
        cids[1] = bytes("encryptedCID2");

        bytes[] memory metadatas = new bytes[](2);
        metadatas[0] = "metadata1";
        metadatas[1] = "metadata2";

        vault.storeContentBatch(1, cids, true, metadatas);
        vm.stopPrank();
    }

    function test_RevertWhen_EmptyBatch() public {
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        bytes[] memory cids = new bytes[](0);
        bytes[] memory metadatas = new bytes[](0);

        vm.prank(alice);
        vm.expectRevert(Vault.EmptyArray.selector);
        vault.storeContentBatch(1, cids, true, metadatas);
    }

    function test_RevertWhen_MismatchedBatchLengths() public {
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        bytes[] memory cids = new bytes[](2);
        cids[0] = bytes("encryptedCID1");
        cids[1] = bytes("encryptedCID2");

        bytes[] memory metadatas = new bytes[](1);
        metadatas[0] = "metadata1";

        vm.prank(alice);
        vm.expectRevert(Vault.MismatchedArrayLengths.selector);
        vault.storeContentBatch(1, cids, true, metadatas);
    }

    // Additional test cases to improve coverage
    function testGetNonce() public {
        // Initially nonce should be 0
        assertEq(vault.getNonce(owner), 0);

        // After setting schema, nonce should still be 0
        vault.setSchema("QmSchema3");
        assertEq(vault.getNonce(owner), 0);
    }

    function testGetSchema() public {
        string memory schema1 = "QmSchema1";
        string memory schema2 = "QmSchema2";

        // Clear existing schema from setUp
        vm.prank(owner);
        vault = new Vault();

        // Set up multiple schemas
        vault.setSchema(schema1);
        vault.setSchema(schema2);

        // Test getting valid schema
        assertEq(vault.getSchema(1), schema1);
        assertEq(vault.getSchema(2), schema2);

        // Test getting current schema (should be the last one set)
        assertEq(vault.getCurrentSchema(), schema2);
    }

    function test_RevertWhen_InvalidSchemaIndex() public {
        // Test with index 0
        vm.expectRevert(Vault.InvalidSchemaIndex.selector);
        vault.getSchema(0);

        // Test with index beyond last schema
        vm.expectRevert(Vault.InvalidSchemaIndex.selector);
        vault.getSchema(10);
    }

    function testTransferVaultOwnership() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Transfer ownership to bob
        vm.prank(alice);
        vault.transferVaultOwnership(1, bob);

        // Verify bob is now the owner
        assertEq(vault.getVaultOwner(1), bob);
    }

    function test_RevertWhen_TransferVaultOwnershipToZeroAddress() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to transfer to zero address
        vm.prank(alice);
        vm.expectRevert(Vault.ZeroAddress.selector);
        vault.transferVaultOwnership(1, address(0));
    }

    function test_RevertWhen_TransferNonExistentVault() public {
        // Try to transfer a non-existent vault
        vm.prank(alice);
        vm.expectRevert(Vault.VaultDoesNotExist.selector);
        vault.transferVaultOwnership(999, bob);
    }

    function test_RevertWhen_NotVaultOwnerTransfersOwnership() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Bob tries to transfer ownership
        vm.prank(bob);
        vm.expectRevert(Vault.NotVaultOwner.selector);
        vault.transferVaultOwnership(1, charlie);
    }

    function test_RevertWhen_GrantAccessToZeroAddress() public {
        // Create a vault for alice
        uint8 permissionRead = vault.PERMISSION_READ();
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to grant access to zero address
        vm.expectRevert(Vault.ZeroAddress.selector);
        vault.grantAccess(address(0), 1, permissionRead);
        vm.stopPrank();
    }

    function test_RevertWhen_GrantAccessToNonExistentVault() public {
        // Try to grant access to a non-existent vault
        // First clear any existing schema to ensure vault creation is not possible
        vm.prank(owner);
        vault = new Vault();

        // Set schema to allow vault operations
        vault.setSchema("QmSchema1");

        // Try to grant access to a non-existent vault
        uint8 permissionRead = vault.PERMISSION_READ();
        vm.startPrank(alice);
        vm.expectRevert(Vault.VaultDoesNotExist.selector);
        vault.grantAccess(bob, 999, permissionRead);
        vm.stopPrank();
    }

    function test_RevertWhen_GrantAccessWithInvalidPermission() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to grant invalid permission
        vm.prank(alice);
        vm.expectRevert(Vault.InvalidPermission.selector);
        vault.grantAccess(bob, 1, 99); // Invalid permission level
    }

    function test_RevertWhen_GrantAccessToUserWithExistingToken() public {
        // Create a vault for alice
        uint8 permissionRead = vault.PERMISSION_READ();
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Grant access to bob
        vault.grantAccess(bob, 1, permissionRead);

        // Try to grant access to bob again (should fail)
        vm.expectRevert(Vault.AlreadyHasToken.selector);
        vault.grantAccess(bob, 1, permissionRead);
        vm.stopPrank();
    }

    function test_RevertWhen_UpgradePermissionToInvalidLevel() public {
        // Create a vault for alice
        uint8 permissionRead = vault.PERMISSION_READ();
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Grant read access to bob
        vault.grantAccess(bob, 1, permissionRead);

        // Try to upgrade to invalid permission level (PERMISSION_READ)
        vm.expectRevert(Vault.InvalidUpgrade.selector);
        vault.upgradePermission(1, bob, permissionRead);
        vm.stopPrank();
    }

    function test_RevertWhen_UpgradePermissionForNonReader() public {
        // Create a vault for alice
        uint8 permissionWrite = vault.PERMISSION_WRITE();
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to upgrade permission for user without read access
        vm.expectRevert(Vault.InvalidUpgrade.selector);
        vault.upgradePermission(1, bob, permissionWrite);
        vm.stopPrank();
    }

    function test_RevertWhen_UpgradePermissionToZeroAddress() public {
        // Create a vault for alice
        uint8 permissionWrite = vault.PERMISSION_WRITE();
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to upgrade permission for zero address
        vm.expectRevert(Vault.ZeroAddress.selector);
        vault.upgradePermission(1, address(0), permissionWrite);
        vm.stopPrank();
    }

    function test_RevertWhen_RevokeAccessToZeroAddress() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to revoke access for zero address
        vm.prank(alice);
        vm.expectRevert(Vault.ZeroAddress.selector);
        vault.revokeAccess(1, address(0));
    }

    function test_RevertWhen_RevokeAccessFromNonExistentVault() public {
        // Try to revoke access from a non-existent vault
        vm.prank(alice);
        vm.expectRevert(Vault.VaultDoesNotExist.selector);
        vault.revokeAccess(999, bob);
    }

    function test_RevertWhen_RevokeAccessFromUserWithoutAccess() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to revoke access from user without access
        vm.prank(alice);
        vm.expectRevert(Vault.NoAccessToRevoke.selector);
        vault.revokeAccess(1, bob);
    }

    function testSetURI() public {
        // Set a new URI
        vault.setURI("https://example.com/token/{id}.json");

        // Verify URI was set (we can't directly test the internal state, but we can verify it doesn't revert)
    }

    function testGetVaultSchemaIndex() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Verify schema index
        assertEq(vault.getVaultSchemaIndex(1), 1);
    }

    // Store constants at the top level to ensure they're available even after contract reverts
    bytes32 constant METADATA_SIGNATURE_TYPEHASH =
        keccak256("MetadataHash(string metadata,uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 constant METADATA_ARRAY_SIGNATURE_TYPEHASH =
        keccak256("MetadataArrayHash(string[] metadata,uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 constant PERMISSION_GRANT_TYPEHASH =
        keccak256("PermissionGrant(address to,uint256 tokenId,uint8 permission,uint256 nonce,uint256 deadline)");

    function test_RevertWhen_StoreContentWithMetadataSigned_ExpiredSignature() public {
        uint8 permissionWrite = vault.PERMISSION_WRITE();
        uint256 deadline = block.timestamp - 1; // Expired deadline

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, permissionWrite);
        vm.stopPrank();

        // Create proper EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                METADATA_SIGNATURE_TYPEHASH,
                keccak256(bytes("metadata")),
                uint256(1),
                uint256(0), // nonce
                deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(1), digest); // alice's key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(Vault.SignatureExpired.selector);
        vault.storeContentWithMetadataSigned(1, bytes("encryptedCID"), true, "metadata", deadline, signature);
    }

    function test_RevertWhen_StoreContentWithMetadataSigned_InvalidSignature() public {
        uint8 permissionWrite = vault.PERMISSION_WRITE();
        uint256 deadline = block.timestamp + 3600;

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, permissionWrite);
        vm.stopPrank();

        // Create proper EIP-712 signature but with wrong signer (bob)
        bytes32 structHash = keccak256(
            abi.encode(
                METADATA_SIGNATURE_TYPEHASH,
                keccak256(bytes("metadata")),
                uint256(1),
                uint256(0), // nonce
                deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(2), digest); // bob's key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(Vault.InvalidSignature.selector);
        vault.storeContentWithMetadataSigned(1, bytes("encryptedCID"), true, "metadata", deadline, signature);
    }

    function test_RevertWhen_StoreContentBatchWithSignature_ExpiredSignature() public {
        uint8 permissionWrite = vault.PERMISSION_WRITE();
        uint256 deadline = block.timestamp - 1;

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, permissionWrite);
        vm.stopPrank();

        bytes[] memory metadatas = new bytes[](1);
        metadatas[0] = "metadata1";

        // Create proper EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                METADATA_ARRAY_SIGNATURE_TYPEHASH,
                keccak256(abi.encode(metadatas)),
                uint256(1),
                uint256(0), // nonce
                deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(1), digest); // alice's key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(Vault.SignatureExpired.selector);
        vault.storeContentBatchWithSignature(1, new bytes[](1), true, metadatas, deadline, signature);
    }

    function test_RevertWhen_GrantAccessWithSignature_ExpiredSignature() public {
        uint8 permissionRead = vault.PERMISSION_READ();
        uint256 deadline = block.timestamp - 1;

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vm.stopPrank();

        // Create proper EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                PERMISSION_GRANT_TYPEHASH,
                charlie,
                uint256(1),
                permissionRead,
                uint256(0), // nonce
                deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(1), digest); // alice's key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(alice);
        vm.expectRevert(Vault.SignatureExpired.selector);
        vault.grantAccessWithSignature(charlie, 1, permissionRead, deadline, signature);
    }

    function test_RevertWhen_GrantAccessWithSignature_InvalidSignature() public {
        uint8 permissionRead = vault.PERMISSION_READ();
        uint256 deadline = block.timestamp + 3600;

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vm.stopPrank();

        // Create proper EIP-712 signature but with wrong signer (bob)
        bytes32 structHash = keccak256(
            abi.encode(
                PERMISSION_GRANT_TYPEHASH,
                charlie,
                uint256(1),
                permissionRead,
                uint256(0), // nonce
                deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(2), digest); // bob's key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(alice);
        vm.expectRevert(Vault.InvalidSignature.selector);
        vault.grantAccessWithSignature(charlie, 1, permissionRead, deadline, signature);
    }

    // Helper function to create EIP-712 digests
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
    }
}
