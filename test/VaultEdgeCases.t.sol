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

contract VaultEdgeCasesTest is Test {
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

    // Test multiple vaults creation and management
    function testMultipleVaults() public {
        // Create multiple vaults
        vm.startPrank(alice);
        schemaManager.setSchema("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG");

        vault.createVault("Vault 1", "Description 1");
        vault.createVault("Vault 2", "Description 2");
        vault.createVault("Vault 3", "Description 3");
        vm.stopPrank();

        // Verify vault ownership
        assertEq(vault.vaultOwner(1), alice);
        assertEq(vault.vaultOwner(2), alice);
        assertEq(vault.vaultOwner(3), alice);

        // Grant different permissions to different users
        vm.startPrank(alice);
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vault.grantAccess(charlie, 2, VaultPermissionsLib.PERMISSION_WRITE);
        vault.grantAccess(dave, 3, VaultPermissionsLib.PERMISSION_READ);
        vm.stopPrank();

        // Verify permissions
        assertEq(vault.permissions(1, bob), VaultPermissionsLib.PERMISSION_READ);
        assertEq(vault.permissions(2, charlie), VaultPermissionsLib.PERMISSION_WRITE);
        assertEq(vault.permissions(3, dave), VaultPermissionsLib.PERMISSION_READ);
    }

    // Test permission inheritance after ownership transfer
    function testPermissionInheritanceAfterTransfer() public {
        // Create vault and grant permissions
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vault.grantAccess(charlie, 1, VaultPermissionsLib.PERMISSION_WRITE);
        vm.stopPrank();

        // Transfer ownership
        vm.prank(alice);
        vault.transferVaultOwnership(1, bob);

        // Verify permissions remain unchanged
        assertEq(vault.permissions(1, bob), VaultPermissionsLib.PERMISSION_READ);
        assertEq(vault.permissions(1, charlie), VaultPermissionsLib.PERMISSION_WRITE);
    }

    // Test complex permission upgrade scenarios
    function testComplexPermissionUpgrades() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Grant read access to multiple users
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vault.grantAccess(charlie, 1, VaultPermissionsLib.PERMISSION_READ);
        vault.grantAccess(dave, 1, VaultPermissionsLib.PERMISSION_READ);

        // Upgrade some users to write access
        vault.upgradePermission(1, bob);
        vault.upgradePermission(1, charlie);
        vm.stopPrank();

        // Verify permissions
        assertEq(vault.permissions(1, bob), VaultPermissionsLib.PERMISSION_WRITE);
        assertEq(vault.permissions(1, charlie), VaultPermissionsLib.PERMISSION_WRITE);
        assertEq(vault.permissions(1, dave), VaultPermissionsLib.PERMISSION_READ);
    }

    // Test batch operations with large arrays
    function testLargeBatchOperations() public {
        vm.startPrank(alice);
        vault.createVault("Vault 1", "Description 1");

        // Create large arrays
        bytes[] memory cids = new bytes[](10);
        string[] memory metadatas = new string[](10);

        for (uint256 i = 0; i < 10; i++) {
            cids[i] = bytes(string.concat("encryptedCID", Strings.toString(i)));
            metadatas[i] = string.concat("metadata", Strings.toString(i));
        }

        // Store content batch
        vault.storeContentBatch(1, cids, true, metadatas);
        vm.stopPrank();
    }

    // Test signature replay attacks
    function testSignatureReplayAttack() public {
        uint8 permissionRead = VaultPermissionsLib.PERMISSION_READ;
        uint256 deadline = block.timestamp + 3600;

        // Use a known private key for alice
        uint256 alicePrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        address aliceAddress = vm.addr(alicePrivateKey);

        // Create vault as alice
        vm.startPrank(aliceAddress);
        vault.createVault("Vault 1", "Description 1");
        vm.stopPrank();

        // Get the current nonce for alice
        uint256 nonce = vault.getNonce(aliceAddress);

        // Create signature with the current nonce
        bytes32 structHash = keccak256(
            abi.encode(VaultTypehashLib.PERMISSION_GRANT_TYPEHASH, bob, uint256(1), permissionRead, nonce, deadline)
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First grant should succeed
        vm.prank(aliceAddress);
        vault.grantAccessWithSignature(bob, 1, permissionRead, deadline, signature);

        // Verify bob has the permission
        assertEq(vault.permissions(1, bob), permissionRead);

        // Verify nonce was incremented
        assertEq(vault.getNonce(aliceAddress), nonce + 1);

        // Second grant with same signature but to a different address should fail due to invalid signature (nonce mismatch)
        vm.prank(aliceAddress);
        vm.expectRevert(IVaultSignatureValidator.InvalidSignature.selector);
        vault.grantAccessWithSignature(
            charlie, // Different recipient
            1,
            permissionRead,
            deadline,
            signature
        );
    }

    // Test concurrent operations
    function testConcurrentOperations() public {
        vm.startPrank(alice);
        //schemaManager.setSchema("QmSchema1");
        vault.createVault("Vault 1", "Description 1");
        vault.createVault("Vault 2", "Description 2");
        vm.stopPrank();

        // Simulate concurrent operations
        vm.startPrank(alice);
        vault.grantAccess(bob, 1, VaultPermissionsLib.PERMISSION_READ);
        vault.grantAccess(charlie, 2, VaultPermissionsLib.PERMISSION_READ);
        vault.upgradePermission(1, bob);
        vault.revokeAccess(2, charlie);
        vm.stopPrank();

        // Verify final state
        assertEq(vault.permissions(1, bob), VaultPermissionsLib.PERMISSION_WRITE);
        assertEq(vault.permissions(2, charlie), VaultPermissionsLib.PERMISSION_NONE);
    }

    // Test edge cases for schema management
    function testSchemaEdgeCases() public {
        // Test setting multiple schemas
        string[] memory schemas = new string[](5);
        schemas[0] = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        schemas[1] = "QmWvM3J9JZMPXqKZT4XUKj3h3ZzNhj2PxT2Q8zGvLimVeG";
        schemas[2] = "QmT8CZxRBNekM8oH8rZuzn9G5aXXJDmxcyfW81mpNZ6Kc4";
        schemas[3] = "QmPK1s3pNYLi9ERiq3BDxKa4XosgWwFRQUydHUtz4YgpqB";
        schemas[4] = "QmQK1s3pNYLi9ERiq3BDxKa4XosgWwFRQUydHUtz4YgpqC";

        // Deploy new schema manager to test independently
        vm.prank(alice);
        SchemaManager newSchemaManager = new SchemaManager();

        for (uint256 i = 0; i < schemas.length; i++) {
            vm.prank(alice);
            newSchemaManager.setSchema(schemas[i]);
            assertEq(newSchemaManager.schemaCIDs(i + 1), schemas[i]);
        }

        // Test getting last schema index
        assertEq(newSchemaManager.lastSchemaIndex(), 5);

        // Test getting schema for non-existent vault
        vm.expectRevert(ISchemaManager.NoSchema.selector);
        newSchemaManager.getSchema(999);
    }

    // Test URI management
    function testURIManagement() public {
        // Test setting URI
        vm.startPrank(alice);
        string memory newURI = "https://example.com/token/{id}.json";
        vault.setURI(newURI);

        // Test setting empty URI
        vault.setURI("");

        // Test setting very long URI
        string memory longURI = string.concat(
            "https://example.com/token/",
            Strings.toString(block.timestamp),
            "/",
            Strings.toString(block.number),
            "/{id}.json"
        );
        vault.setURI(longURI);
        vm.stopPrank();
    }

    // Test permission checks for non-existent vaults
    function testPermissionChecksForNonExistentVaults() public view {
        // Test permission checks for non-existent vault
        assertEq(vault.permissions(999, alice), VaultPermissionsLib.PERMISSION_NONE);
        assertEq(vault.permissions(999, bob), VaultPermissionsLib.PERMISSION_NONE);
        assertEq(vault.permissions(999, charlie), VaultPermissionsLib.PERMISSION_NONE);
    }

    // Test vault creation with different schemas
    function testVaultCreationWithDifferentSchemas() public {
        // Create a new schema manager for this test
        vm.prank(alice);
        SchemaManager newSchemaManager = new SchemaManager();

        // Deploy a new vault with the new schema manager
        vm.prank(alice);
        Vault newVault = new Vault(address(newSchemaManager));
        // Set up proposal vault manager
        vm.prank(alice);
        newVault.setProposalVaultManager(alice);

        // Set up multiple schemas
        vm.startPrank(alice);
        newSchemaManager.setSchema("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"); // Schema index 1
        newVault.createVault("Vault 1", "Description 1");
        newSchemaManager.setSchema("QmWvM3J9JZMPXqKZT4XUKj3h3ZzNhj2PxT2Q8zGvLimVeG"); // Schema index 2
        newVault.createVault("Vault 2", "Description 2");
        newSchemaManager.setSchema("QmT8CZxRBNekM8oH8rZuzn9G5aXXJDmxcyfW81mpNZ6Kc4"); // Schema index 3
        newVault.createVault("Vault 3", "Description 3");
        vm.stopPrank();

        // Verify schema assignments
        assertEq(newSchemaManager.vaultSchemaIndex(1), 1);
        assertEq(newSchemaManager.vaultSchemaIndex(2), 2);
        assertEq(newSchemaManager.vaultSchemaIndex(3), 3);
    }
}
