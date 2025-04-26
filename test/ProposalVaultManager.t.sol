// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Test} from "forge-std/Test.sol";
import {ProposalVaultManager} from "../src/ProposalVaultManager.sol";
import {Vault} from "../src/Vault.sol";
import {SchemaManager} from "../src/SchemaManager.sol";
import {VaultPermissionsLib} from "../src/libs/VaultPermissionsLib.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract MockTokenContract {
    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }
}

contract ProposalVaultManagerTest is Test {
    ProposalVaultManager public proposalVaultManager;
    Vault public vault;
    SchemaManager public schemaManager;
    MockTokenContract public mockToken;
    string public schemaId = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
    address public owner;
    address public user1;
    address public user2;
    uint256 public constant TOKEN_ID = 1;

    event VaultFromProposalCreated(
        uint256 indexed tokenId,
        bytes32 indexed proposalId,
        string name,
        string description,
        uint256 chainId,
        address indexed tokenContract,
        string schemaCID
    );

    event VaultFromProposalPinned(address indexed to, uint256 indexed tokenId, uint8 permission);

    event VaultFromProposalUnpinned(address indexed to, uint256 indexed tokenId);

    function setUp() public {
        owner = makeAddr("alice");
        user1 = makeAddr("bob");
        user2 = makeAddr("charlie");

        vm.startPrank(owner);

        // Deploy contracts
        schemaManager = new SchemaManager();
        vault = new Vault(address(schemaManager));
        proposalVaultManager = new ProposalVaultManager(address(vault));
        mockToken = new MockTokenContract();

        // Set up schema
        schemaManager.setSchema(schemaId);

        // Set up proposal vault manager
        vault.setProposalVaultManager(address(proposalVaultManager));

        vm.stopPrank();
    }

    function test_CreateVaultFromProposal() public {
        vm.startPrank(owner);

        bytes32 proposalId = keccak256("test proposal");
        uint256 chainId = block.chainid;
        string memory name = "Test Vault";
        string memory description = "Test Description";

        vm.expectEmit(true, true, true, true);
        emit VaultFromProposalCreated(TOKEN_ID, proposalId, name, description, chainId, address(mockToken), schemaId);

        proposalVaultManager.createVaultFromProposal(proposalId, name, description, chainId, address(mockToken));

        vm.stopPrank();
    }

    /* function test_PinVaultFromProposal() public {
        vm.startPrank(owner);

        bytes32 proposalId = keccak256("test proposal");
        uint256 chainId = block.chainid;
        string memory name = "Test Vault";
        string memory description = "Test Description";

        proposalVaultManager.createVaultFromProposal(
            proposalId,
            name,
            description,
            chainId,
            address(mockToken)
        );

        vm.expectEmit(true, true, true, true);
        emit VaultFromProposalPinned(
            owner,
            TOKEN_ID,
            VaultPermissionsLib.PERMISSION_WRITE
        );

        proposalVaultManager.pinVaultFromProposal(proposalId, address(owner));

        vm.stopPrank();
    }

    function test_UnpinVaultFromProposal() public {
        vm.startPrank(owner);

        bytes32 proposalId = keccak256("test proposal");
        uint256 chainId = block.chainid;
        string memory name = "Test Vault";
        string memory description = "Test Description";

        proposalVaultManager.createVaultFromProposal(
            proposalId,
            name,
            description,
            chainId,
            address(mockToken)
        );

        proposalVaultManager.pinVaultFromProposal(proposalId, address(owner));

        vm.expectEmit(true, true, true, true);
        emit VaultFromProposalUnpinned(owner, TOKEN_ID);

        proposalVaultManager.unpinVaultFromProposal(proposalId);

        vm.stopPrank();
    } */

    function test_RevertCreateVaultFromProposal_InvalidChainId() public {
        vm.startPrank(owner);

        bytes32 proposalId = keccak256("test proposal");
        uint256 invalidChainId = 0; // Using 0 as invalid chain ID
        string memory name = "Test Vault";
        string memory description = "Test Description";

        vm.expectRevert(ProposalVaultManager.InvalidChainId.selector);

        proposalVaultManager.createVaultFromProposal(proposalId, name, description, invalidChainId, address(mockToken));

        vm.stopPrank();
    }

    function test_RevertCreateVaultFromProposal_InvalidTokenContract() public {
        vm.startPrank(owner);

        bytes32 proposalId = keccak256("test proposal");
        uint256 chainId = block.chainid;
        address invalidTokenContract = address(0); // Using zero address as invalid token contract
        string memory name = "Test Vault";
        string memory description = "Test Description";

        vm.expectRevert(ProposalVaultManager.InvalidTokenContract.selector);

        proposalVaultManager.createVaultFromProposal(proposalId, name, description, chainId, invalidTokenContract);

        vm.stopPrank();
    }
}
