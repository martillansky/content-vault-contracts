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
        vault.setSchema(keccak256("QmWATWQ7fVPP2EFGu71UkfnqhYXDYH566qy47CnJDgvs8u"));
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
            abi.encode(
                keccak256("PermissionGrant(address to,uint256 tokenId,uint8 permission,uint256 nonce,uint256 deadline)"),
                target,
                1,
                vault.PERMISSION_WRITE(),
                nonce,
                deadline
            )
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
        vault.storeContentWithMetadata(
            1,
            keccak256("k51qzi5uqu5dh9ihj9u2k5zk8ygjk3l5mh7akbt8b6medi77r5w55g4rg8chx3"),
            keccak256('{"title":"test"}')
        );
    }

    function testGasBatchStoreContent() public {
        vm.startPrank(user);
        vault.grantAccess(target, 1, vault.PERMISSION_WRITE());
        vm.stopPrank();

        bytes32[] memory hashes = new bytes32[](3);
        bytes32[] memory metas = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            if (i == 0) {
                hashes[i] = keccak256("QmWATWQ7fVPP2EFGu71UkfnqhYXDYH566qy47CnJDgvs8u");
            } else if (i == 1) {
                hashes[i] = keccak256("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
            } else {
                hashes[i] = keccak256("k51qzi5uqu5dh9ihj9u2k5zk8ygjk3l5mh7akbt8b6medi77r5w55g4rg8chx3");
            }
            metas[i] = keccak256('{"title":"test"}');
        }

        vm.prank(target);
        vault.storeContentBatch(1, hashes, metas);
    }
}
