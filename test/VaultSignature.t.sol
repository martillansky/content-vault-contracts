// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultSignatureTest is Test {
    Vault vault;
    address alice = vm.addr(1);
    address bob = vm.addr(2);
    uint256 alicePk = 0x1;

    bytes32 constant PERMISSION_GRANT_TYPEHASH =
        keccak256("PermissionGrant(address to,uint256 tokenId,uint8 permission,uint256 nonce,uint256 deadline)");

    function setUp() public {
        vault = new Vault();
        vm.prank(vault.owner());
        vault.setSchema(keccak256("QmWATWQ7fVPP2EFGu71UkfnqhYXDYH566qy47CnJDgvs8u"));
        vm.prank(alice);
        vault.createVault(1);
    }

    function testGrantAccessWithSignature() public {
        uint256 nonce = vault.getNonce(alice);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = _getPermissionGrantDigest(bob, 1, vault.PERMISSION_WRITE(), nonce, deadline);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vault.grantAccessWithSignature(bob, 1, vault.PERMISSION_WRITE(), deadline, sig);

        assertEq(vault.permissions(1, bob), vault.PERMISSION_WRITE());
        assertEq(vault.getNonce(alice), nonce + 1);
    }

    function test_RevertWhen_InvalidSignature() public {
        uint256 nonce = vault.getNonce(alice);
        uint256 deadline = block.timestamp + 1 hours;
        uint8 writePermission = vault.PERMISSION_WRITE();

        bytes32 digest = _getPermissionGrantDigest(bob, 1, writePermission, nonce, deadline);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0x2, digest); // Wrong private key
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidSignature.selector));
        vault.grantAccessWithSignature(bob, 1, writePermission, deadline, sig);
    }

    function test_RevertWhen_NonExistentVault() public {
        uint256 nonce = vault.getNonce(alice);
        uint256 deadline = block.timestamp + 1 hours;
        uint8 writePermission = vault.PERMISSION_WRITE();

        bytes32 digest = _getPermissionGrantDigest(
            bob,
            999, // Non-existent vault
            writePermission,
            nonce,
            deadline
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Vault.VaultDoesNotExist.selector));
        vault.grantAccessWithSignature(bob, 999, writePermission, deadline, sig);
    }

    function test_RevertWhen_SignatureExpired() public {
        uint256 nonce = vault.getNonce(alice);
        uint256 deadline = block.timestamp + 1 hours;
        uint8 writePermission = vault.PERMISSION_WRITE();

        bytes32 digest = _getPermissionGrantDigest(bob, 1, writePermission, nonce, deadline);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.warp(block.timestamp + 2 hours);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Vault.SignatureExpired.selector));
        vault.grantAccessWithSignature(bob, 1, writePermission, deadline, sig);
    }

    function test_RevertWhen_SignatureReplay() public {
        uint256 nonce = vault.getNonce(alice);
        uint256 deadline = block.timestamp + 1 hours;
        uint8 writePermission = vault.PERMISSION_WRITE();

        bytes32 digest = _getPermissionGrantDigest(bob, 1, writePermission, nonce, deadline);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vault.grantAccessWithSignature(bob, 1, writePermission, deadline, sig);

        // Try to replay with a different nonce
        nonce = vault.getNonce(alice);
        digest = _getPermissionGrantDigest(bob, 1, writePermission, nonce, deadline);

        (v, r, s) = vm.sign(alicePk, digest);
        sig = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Vault.AlreadyHasToken.selector));
        vault.grantAccessWithSignature(bob, 1, writePermission, deadline, sig);
    }

    function test_RevertWhen_InvalidPermissionLevel() public {
        uint256 nonce = vault.getNonce(alice);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = _getPermissionGrantDigest(
            bob,
            1,
            3, // Invalid permission level
            nonce,
            deadline
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Vault.InvalidPermission.selector));
        vault.grantAccessWithSignature(bob, 1, 3, deadline, sig);
    }

    function _getPermissionGrantDigest(address to, uint256 tokenId, uint8 permission, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(PERMISSION_GRANT_TYPEHASH, to, tokenId, permission, nonce, deadline));

        return keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
    }
}
