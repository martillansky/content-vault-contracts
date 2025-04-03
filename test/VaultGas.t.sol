// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultGasTest is Test {
    Vault vault;
    address user = vm.addr(1);
    address target = vm.addr(2);
    uint256 userPk = 0x1;

    function setUp() public {
        vault = new Vault();
        vm.prank(vault.owner());
        vault.setSchema("ipfs://QmTestSchemaHash123456789");
        vm.prank(user);
        vault.createVault(1);
    }

    function testGasGrantAccess() public {
        vm.startPrank(user);
        vault.grantAccess(target, 1, vault.PERMISSION_WRITE());
        vm.stopPrank();
    }

    function testGasGrantAccessWithSignature() public {
        uint256 nonce = vault.getNonce(user);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 structHash = keccak256(
            abi.encode(vault.PERMISSION_GRANT_TYPEHASH(), target, 1, vault.PERMISSION_WRITE(), nonce, deadline)
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(target);
        vault.grantAccessWithSignature(target, 1, vault.PERMISSION_WRITE(), deadline, sig);
    }

    function testGasStoreContent() public {
        vm.startPrank(user);
        vault.grantAccess(target, 1, vault.PERMISSION_WRITE());
        vm.stopPrank();

        vm.prank(target);
        vault.storeContentWithMetadata(1, "ipfs://QmTestContentHash123456789", '{"title":"test"}');
    }

    function testGasBatchStoreContent() public {
        vm.startPrank(user);
        vault.grantAccess(target, 1, vault.PERMISSION_WRITE());
        vm.stopPrank();

        string[] memory hashes = new string[](3);
        string[] memory metas = new string[](3);
        for (uint256 i = 0; i < 3; i++) {
            hashes[i] = "ipfs://QmTestContentHash123456789";
            metas[i] = '{"title":"test"}';
        }

        vm.prank(target);
        vault.storeContentBatch(1, hashes, metas);
    }
}
