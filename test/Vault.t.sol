// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";
import {SchemaManager} from "../src/SchemaManager.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {VaultSignatureValidator} from "../src/VaultSignatureValidator.sol";
import {IVaultSignatureValidator} from "../src/interfaces/IVaultSignatureValidator.sol";
import {ISchemaManager} from "../src/interfaces/ISchemaManager.sol";
import {IVaultErrors} from "../src/interfaces/IVaultErrors.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {VaultPermissionsLib} from "../src/libs/VaultPermissionsLib.sol";
import {VaultTypehashLib} from "../src/libs/VaultTypehashLib.sol";

contract VaultTest is Test {
    Vault public vault;
    SchemaManager public schemaManager;
    address public owner;
    address public alice;
    address public bob;
    address public charlie;
    address public dave;

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

        dave = makeAddr("dave");
        vm.label(dave, "Dave");

        // Set up initial schema
        vm.prank(alice);
        schemaManager = new SchemaManager();

        // Deploy the vault contract with alice as owner
        vm.prank(alice);
        vault = new Vault(address(schemaManager));

        // Set up proposal vault manager
        vm.prank(alice);
        vault.setProposalVaultManager(alice);

        // Verify ownership
        assertEq(vault.owner(), alice, "Vault owner should be alice");

        // Set up initial schema as alice
        vm.prank(alice);
        schemaManager.setSchema("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");

        // Clear any existing state
        vm.clearMockedCalls();
    }

    // Helper function to create a signature for permission grant
    function signPermissionGrant(
        uint256 privateKey,
        address to,
        uint256 tokenId,
        uint8 permission,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(VaultTypehashLib.PERMISSION_GRANT_TYPEHASH, to, tokenId, permission, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // Helper function to create a signature for metadata
    function signMetadata(uint256 privateKey, string memory metadata, uint256 tokenId, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                VaultTypehashLib.METADATA_SIGNATURE_TYPEHASH, keccak256(bytes(metadata)), tokenId, nonce, deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // Helper function to create a signature for metadata array
    function signMetadataArray(
        uint256 privateKey,
        string[] memory metadatas,
        uint256 tokenId,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32[] memory metadataHashes = new bytes32[](metadatas.length);
        for (uint256 i = 0; i < metadatas.length; i++) {
            metadataHashes[i] = keccak256(bytes(metadatas[i]));
        }
        bytes32 structHash = keccak256(
            abi.encode(
                VaultTypehashLib.METADATA_ARRAY_SIGNATURE_TYPEHASH,
                keccak256(abi.encodePacked(metadataHashes)),
                tokenId,
                nonce,
                deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // Helper function to compute EIP712 hash
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19\x01", IVaultSignatureValidator(address(vault)).getDomainSeparator(), structHash)
        );
    }

    // Schema Tests
    function testSetSchema() public {
        vm.prank(alice);
        schemaManager.setSchema("QmWvM3J9JZMPXqKZT4XUKj3h3ZzNhj2PxT2Q8zGvLimVeG");
        assertEq(
            schemaManager.schemaCIDs(schemaManager.lastSchemaIndex()), "QmWvM3J9JZMPXqKZT4XUKj3h3ZzNhj2PxT2Q8zGvLimVeG"
        );
    }

    function test_RevertWhen_NotOwnerSetsSchema() public {
        // Test schema manager ownership
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, bob));
        schemaManager.setSchema("QmSchema2");
    }

    // Vault Creation Tests
    function testCreateVault() public {
        // Create vault as alice (the owner and proposal vault manager)
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vm.stopPrank();

        // Verify ownership and permissions
        address vaultOwner = vault.vaultOwner(1);
        assertEq(vaultOwner, alice);
        assertEq(vault.permissions(1, alice), VaultPermissionsLib.PERMISSION_WRITE);
    }

    function test_RevertWhen_CreateVaultWithoutSchema() public {
        // Deploy new schema manager and vault without any schema
        SchemaManager newSchemaManager = new SchemaManager();
        Vault newVault = new Vault(address(newSchemaManager));
        vm.prank(alice);
        vm.expectRevert(ISchemaManager.NoSchema.selector);
        newVault.createVault("Vault 1", "Description 1");
    }

    // Access Control Tests
    function testGrantAccess() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vm.stopPrank();
        assertEq(vault.permissions(1, bob), VaultPermissionsLib.PERMISSION_READ);
    }

    function testRevokeAccess() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vault.revokeAccess(1, bob);
        vm.stopPrank();
        assertEq(vault.permissions(1, bob), VaultPermissionsLib.PERMISSION_NONE);
    }

    function testUpgradePermission() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vault.upgradePermission(1, bob);
        vm.stopPrank();
        assertEq(vault.permissions(1, bob), VaultPermissionsLib.PERMISSION_WRITE);
    }

    function test_RevertWhen_NotVaultOwnerGrantsAccess() public {
        uint8 permissionRead = VaultPermissionsLib.PERMISSION_READ;
        vm.deal(alice, 1 ether);
        vm.deal(bob, 1 ether);
        vm.deal(charlie, 1 ether);

        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Debug info
        address vaultOwner = vault.vaultOwner(1);
        assertEq(vaultOwner, alice, "Alice should be the owner");
        assertEq(
            vault.permissions(1, alice), VaultPermissionsLib.PERMISSION_WRITE, "Alice should have write permission"
        );
        assertEq(vault.balanceOf(charlie, 1), 0, "Charlie should not have token");

        vm.prank(bob);
        vm.expectRevert(IVaultErrors.NotVaultOwner.selector);
        vault.grantAccess(charlie, 1, permissionRead);
    }

    function test_RevertWhen_NotVaultOwnerRevokesAccess() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectRevert(IVaultErrors.NotVaultOwner.selector);
        vault.revokeAccess(1, charlie);
    }

    function test_RevertWhen_RevokeAccessToSelf() public {
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        vm.prank(alice);
        vm.expectRevert(IVaultErrors.CannotRevokeAccessToSelf.selector);
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
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectRevert(IVaultErrors.NoWritePermission.selector);
        vault.storeContentWithMetadata(1, bytes("encryptedCID"), true, "metadata");
    }

    // Batch Operations Tests
    function testStoreContentBatch() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        bytes[] memory cids = new bytes[](2);
        cids[0] = bytes("encryptedCID1");
        cids[1] = bytes("encryptedCID2");

        string[] memory metadatas = new string[](2);
        metadatas[0] = "metadata1";
        metadatas[1] = "metadata2";

        vault.storeContentBatch(1, cids, true, metadatas);
        vm.stopPrank();
    }

    function test_RevertWhen_EmptyBatch() public {
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        bytes[] memory cids = new bytes[](0);
        string[] memory metadatas = new string[](0);

        vm.prank(alice);
        vm.expectRevert(IVaultErrors.EmptyArray.selector);
        vault.storeContentBatch(1, cids, true, metadatas);
    }

    function test_RevertWhen_MismatchedBatchLengths() public {
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        bytes[] memory cids = new bytes[](2);
        cids[0] = bytes("encryptedCID1");
        cids[1] = bytes("encryptedCID2");

        string[] memory metadatas = new string[](1);
        metadatas[0] = "metadata1";

        vm.prank(alice);
        vm.expectRevert(IVaultErrors.MismatchedArrayLengths.selector);
        vault.storeContentBatch(1, cids, true, metadatas);
    }

    // Additional test cases to improve coverage
    function testGetNonce() public {
        // Initially nonce should be 0
        assertEq(vault.nonces(alice), 0);

        // After setting schema, nonce should still be 0
        vm.prank(alice);
        schemaManager.setSchema("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");
        assertEq(vault.nonces(alice), 0);
    }

    function testGetSchema() public {
        string memory schema1 = "QmWvM3J9JZMPXqKZT4XUKj3h3ZzNhj2PxT2Q8zGvLimVeG";
        string memory schema2 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";

        // Set up multiple schemas
        vm.startPrank(alice);
        schemaManager.setSchema(schema1);
        schemaManager.setSchema(schema2);
        vm.stopPrank();

        // Test getting valid schema (index 2 and 3 since we have one from setUp)
        assertEq(schemaManager.schemaCIDs(2), schema1);
        assertEq(schemaManager.schemaCIDs(3), schema2);

        // Test getting current schema (should be the last one set)
        assertEq(schemaManager.schemaCIDs(schemaManager.lastSchemaIndex()), schema2);
    }

    function testTransferVaultOwnership() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Transfer ownership to bob
        vm.prank(alice);
        vault.transferVaultOwnership(1, bob);

        // Verify bob is now the owner
        address vaultOwner = vault.vaultOwner(1);
        assertEq(vaultOwner, bob);
    }

    function test_RevertWhen_TransferVaultOwnershipToZeroAddress() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to transfer to zero address
        vm.prank(alice);
        vm.expectRevert(IVaultErrors.ZeroAddress.selector);
        vault.transferVaultOwnership(1, address(0));
    }

    function test_RevertWhen_TransferNonExistentVault() public {
        // Try to transfer a non-existent vault
        vm.prank(alice);
        vm.expectRevert(IVaultErrors.VaultDoesNotExist.selector);
        vault.transferVaultOwnership(999, bob);
    }

    function test_RevertWhen_NotVaultOwnerTransfersOwnership() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Bob tries to transfer ownership
        vm.prank(bob);
        vm.expectRevert(IVaultErrors.NotVaultOwner.selector);
        vault.transferVaultOwnership(1, charlie);
    }

    function test_RevertWhen_GrantAccessToZeroAddress() public {
        // Create a vault for alice
        uint8 permissionRead = VaultPermissionsLib.PERMISSION_READ;
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to grant access to zero address
        vm.expectRevert(IVaultErrors.ZeroAddress.selector);
        vault.grantAccess(address(0), 1, permissionRead);
        vm.stopPrank();
    }

    function test_RevertWhen_GrantAccessToNonExistentVault() public {
        // Try to grant access to a non-existent vault
        // First clear any existing schema to ensure vault creation is not possible
        vm.prank(alice);
        vault = new Vault(address(schemaManager));

        // Set schema to allow vault operations
        vm.prank(alice);
        schemaManager.setSchema("QmWvM3J9JZMPXqKZT4XUKj3h3ZzNhj2PxT2Q8zGvLimVeG");

        // Try to grant access to a non-existent vault
        uint8 permissionRead = VaultPermissionsLib.PERMISSION_READ;
        vm.startPrank(alice);
        vm.expectRevert(IVaultErrors.VaultDoesNotExist.selector);
        vault.grantAccess(bob, 999, permissionRead);
        vm.stopPrank();
    }

    function test_RevertWhen_GrantAccessWithInvalidPermission() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to grant invalid permission
        vm.prank(alice);
        vm.expectRevert(IVaultErrors.InvalidPermission.selector);
        vault.grantAccess(bob, 1, 99); // Invalid permission level
    }

    function test_RevertWhen_GrantAccessToUserWithExistingToken() public {
        // Create a vault for alice
        uint8 permissionRead = VaultPermissionsLib.PERMISSION_READ;
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Grant access to bob
        vault.grantAccess(bob, 1, permissionRead);

        // Try to grant access to bob again (should fail)
        vm.expectRevert(IVaultErrors.AlreadyHasToken.selector);
        vault.grantAccess(bob, 1, permissionRead);
        vm.stopPrank();
    }

    function test_RevertWhen_UpgradePermissionForNonReader() public {
        // Create a vault for alice
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to upgrade permission for user without read access
        vm.expectRevert(IVaultErrors.InvalidUpgrade.selector);
        vault.upgradePermission(1, bob);
        vm.stopPrank();
    }

    function test_RevertWhen_UpgradePermissionToZeroAddress() public {
        // Create a vault for alice
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to upgrade permission for zero address
        vm.expectRevert(IVaultErrors.ZeroAddress.selector);
        vault.upgradePermission(1, address(0));
        vm.stopPrank();
    }

    function test_RevertWhen_RevokeAccessToZeroAddress() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to revoke access for zero address
        vm.prank(alice);
        vm.expectRevert(IVaultErrors.ZeroAddress.selector);
        vault.revokeAccess(1, address(0));
    }

    function test_RevertWhen_RevokeAccessFromNonExistentVault() public {
        // Try to revoke access from a non-existent vault
        vm.prank(alice);
        vm.expectRevert(IVaultErrors.VaultDoesNotExist.selector);
        vault.revokeAccess(999, bob);
    }

    function test_RevertWhen_RevokeAccessFromUserWithoutAccess() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Try to revoke access from user without access
        vm.prank(alice);
        vm.expectRevert(IVaultErrors.NoAccessToRevoke.selector);
        vault.revokeAccess(1, bob);
    }

    function testSetURI() public {
        // Set a new URI as alice
        vm.prank(alice);
        vault.setURI("https://example.com/token/{id}.json");

        // Verify URI was set (we can't directly test the internal state, but we can verify it doesn't revert)
    }

    function testGetVaultSchemaIndex() public {
        // Create a vault for alice
        vm.prank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Verify schema index
        uint256 schemaIndex = schemaManager.vaultSchemaIndex(1);
        assertEq(schemaIndex, 1);
    }

    function test_RevertWhen_StoreContentWithMetadataSigned_ExpiredSignature() public {
        uint8 permissionWrite = VaultPermissionsLib.PERMISSION_WRITE;
        uint256 deadline = block.timestamp - 1; // Expired deadline

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, permissionWrite);
        vm.stopPrank();

        // Create proper EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                VaultTypehashLib.METADATA_SIGNATURE_TYPEHASH,
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
        vm.expectRevert(IVaultSignatureValidator.SignatureExpired.selector);
        vault.storeContentWithMetadataSigned(1, bytes("encryptedCID"), true, "metadata", deadline, signature);
    }

    function test_RevertWhen_StoreContentWithMetadataSigned_InvalidSignature() public {
        uint8 permissionWrite = VaultPermissionsLib.PERMISSION_WRITE;
        uint256 deadline = block.timestamp + 3600;

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, permissionWrite);
        vm.stopPrank();

        // Create proper EIP-712 signature but with wrong signer (bob)
        bytes32 structHash = keccak256(
            abi.encode(
                VaultTypehashLib.METADATA_SIGNATURE_TYPEHASH,
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
        vm.expectRevert(IVaultSignatureValidator.InvalidSignature.selector);
        vault.storeContentWithMetadataSigned(1, bytes("encryptedCID"), true, "metadata", deadline, signature);
    }

    function test_RevertWhen_StoreContentBatchWithSignature_ExpiredSignature() public {
        uint8 permissionWrite = VaultPermissionsLib.PERMISSION_WRITE;
        uint256 deadline = block.timestamp - 1;

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, permissionWrite);
        vm.stopPrank();

        string[] memory metadatas = new string[](1);
        metadatas[0] = "metadata1";

        // Create proper EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                VaultTypehashLib.METADATA_ARRAY_SIGNATURE_TYPEHASH,
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
        vm.expectRevert(IVaultSignatureValidator.SignatureExpired.selector);
        vault.storeContentBatchWithSignature(1, new bytes[](1), true, metadatas, deadline, signature);
    }

    function test_RevertWhen_GrantAccessWithSignature_ExpiredSignature() public {
        uint8 permissionRead = VaultPermissionsLib.PERMISSION_READ;
        uint256 deadline = block.timestamp - 1;

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vm.stopPrank();

        // Create proper EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                VaultTypehashLib.PERMISSION_GRANT_TYPEHASH,
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
        vm.expectRevert(IVaultSignatureValidator.SignatureExpired.selector);
        vault.grantAccessWithSignature(charlie, 1, permissionRead, deadline, signature);
    }

    function test_RevertWhen_GrantAccessWithSignature_InvalidSignature() public {
        uint8 permissionRead = VaultPermissionsLib.PERMISSION_READ;
        uint256 deadline = block.timestamp + 3600;

        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vm.stopPrank();

        // Create proper EIP-712 signature but with wrong signer (bob)
        bytes32 structHash = keccak256(
            abi.encode(
                VaultTypehashLib.PERMISSION_GRANT_TYPEHASH,
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
        vm.expectRevert(IVaultSignatureValidator.InvalidSignature.selector);
        vault.grantAccessWithSignature(charlie, 1, permissionRead, deadline, signature);
    }
}
