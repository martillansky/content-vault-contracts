// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../src/Vault.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VaultSignatureTest is Test {
    Vault vault;
    address alice = vm.addr(1);
    address bob = vm.addr(2);
    address charlie = vm.addr(3);
    uint256 alicePrivateKey = 1;
    uint256 bobPrivateKey = 2;

    function setUp() public {
        // Create a new vault instance for each test
        vault = new Vault();

        // Set up the schema as the owner
        vm.startPrank(vault.owner());
        vault.setSchema("ipfs://QmTestSchemaHash123456789");
        vm.stopPrank();
    }

    function testGrantAccessWithSignature() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.stopPrank();

        uint256 nonce = vault.getNonce(alice);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _getPermissionGrantDigest(bob, 1, vault.PERMISSION_READ(), nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vault.grantAccessWithSignature(bob, 1, vault.PERMISSION_READ(), deadline, signature);

        assertEq(vault.getPermission(1, bob), vault.PERMISSION_READ());
    }

    function test_RevertWhen_SignatureReplay() public {
        vm.startPrank(alice);
        vault.createVault(1);
        vm.stopPrank();

        uint256 nonce = vault.nonces(alice);
        uint256 deadline = block.timestamp + 3600;
        bytes32 digest = _getPermissionGrantDigest(bob, 1, vault.PERMISSION_READ(), nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First call should succeed
        vault.grantAccessWithSignature(bob, 1, vault.PERMISSION_READ(), deadline, signature);

        // Verify that Bob has the token
        assertEq(vault.balanceOf(bob, 1), 1);

        // Get the updated nonce after the first call
        nonce = vault.nonces(alice);

        // Generate new digest with updated nonce
        digest = _getPermissionGrantDigest(bob, 1, vault.PERMISSION_READ(), nonce, deadline);
        (v, r, s) = vm.sign(alicePrivateKey, digest);
        signature = abi.encodePacked(r, s, v);

        // Second call should fail with AlreadyHasToken because Bob already has access
        vm.expectRevert(Vault.AlreadyHasToken.selector);
        vault.grantAccessWithSignature(
            bob,
            1,
            //vault.PERMISSION_READ(),
            1,
            deadline,
            signature
        );
    }

    function _getPermissionGrantDigest(address to, uint256 tokenId, uint8 permission, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash =
            keccak256(abi.encode(vault.PERMISSION_GRANT_TYPEHASH(), to, tokenId, permission, nonce, deadline));

        return keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
    }
}
