// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Vault} from "../src/Vault.sol";
import {SchemaManager} from "../src/SchemaManager.sol";
import {ProposalVaultManager} from "../src/ProposalVaultManager.sol";

/// @dev Call the createVault function on the Vault contract deployed on local anvil network.
contract CallLocal is Script {
    address wallet0 = vm.envAddress("ANVIL_WALLET_0");
    address wallet1 = vm.envAddress("ANVIL_WALLET_1");
    address wallet2 = vm.envAddress("ANVIL_WALLET_2");

    address vaultAddr = vm.envAddress("ANVIL_VAULT");
    Vault vault = Vault(vaultAddr);
    ProposalVaultManager proposalVaultManager = ProposalVaultManager(vm.envAddress("ANVIL_PROPOSAL_VAULT_MANAGER"));
    SchemaManager schemaManager = SchemaManager(vm.envAddress("ANVIL_SCHEMA_MANAGER"));

    function createVault(string memory name, string memory desc) public {
        vault.createVault(name, desc);
    }

    function vaultOwner(uint256 tokenId) public view {
        address owner = vault.vaultOwner(tokenId);
        console2.log("Vault owner:", owner);
    }

    function createProposalVault(bytes32 proposalId) public {
        proposalVaultManager.createVaultFromProposal(
            proposalId,
            "[NIP-110] Cut NOTE Emissions",
            "This proposal is to cut NOTE emissions by 50%",
            42161,
            0x019bE259BC299F3F653688c7655C87F998Bc7bC1
        );
    }

    function run() external {
        bytes32 proposalId = 0x72e04e056a186557bdc408e04befa35509648d89db5674ebcb952027990f71c0;

        console2.log("Wallet 0");
        vm.startBroadcast(vm.envUint("ANVIL_PRIVATE_KEY"));

        console2.log("Vault owner:", vault.owner());
        console2.log("Schema owner:", schemaManager.owner());
        console2.log("Proposal vault manager owner:", proposalVaultManager.owner());

        createVault("Project Files", "DAOs files");
        vaultOwner(1); // wallet 0 is the owner of the vault 1
        vault.grantAccess(wallet1, 1, 2); // wallet 1 has write permission to the vault 1
        createProposalVault(proposalId); // wallet 0 creates the vault 2 from a proposal
        vaultOwner(2); // master crosschain granter is the owner of the vault 2, wallet 0 has read permission
        console2.log("Has permission:", vault.hasGrantedPermission(2, wallet0));
        console2.log("Has permission read:", vault.isPermissionVaultRead(2, wallet0));
        console2.log("Has permission write:", vault.isPermissionVaultWrite(2, wallet0));

        console2.log("Balance wallet0 of vault 1:", vault.balanceOf(wallet0, 1));
        console2.log("Balance wallet0 of vault 2:", vault.balanceOf(wallet0, 2));

        console2.log("Balance wallet1 of vault 2:", vault.balanceOf(wallet1, 2));

        console2.log("Last token id:", vault.getLastTokenId());
        console2.log("Schema CID:", schemaManager.schemaCIDs(1));

        vm.stopBroadcast();

        console2.log("Wallet Master Granter");
        vm.startBroadcast(vm.envUint("ANVIL_PRIVATE_KEY_9"));

        console2.log("Has permission wallet0 to 2:", vault.hasGrantedPermission(2, wallet0));
        console2.log("Has permission read:", vault.isPermissionVaultRead(2, wallet0));

        console2.log("Has permission write:", vault.isPermissionVaultWrite(2, wallet0));

        console2.log("Has permission wallet1 to 2:", vault.hasGrantedPermission(2, wallet1));
        proposalVaultManager.pinVaultFromProposal(proposalId, wallet1);
        console2.log("Has permission wallet1 to 2:", vault.hasGrantedPermission(2, wallet1));
        console2.log("Has permission read:", vault.isPermissionVaultRead(2, wallet0));

        console2.log("Has permission write:", vault.isPermissionVaultWrite(2, wallet0));

        console2.log("Balance wallet1 of vault 2:", vault.balanceOf(wallet1, 2));
        proposalVaultManager.upgradePermissionVaultFromProposal(proposalId, wallet0);
        console2.log("Has permission wallet0 to 2:", vault.hasGrantedPermission(2, wallet0));

        console2.log("Has permission read:", vault.isPermissionVaultRead(2, wallet0));
        console2.log("Has permission write:", vault.isPermissionVaultWrite(2, wallet0));
        proposalVaultManager.unpinVaultFromProposal(proposalId, wallet0);
        console2.log("Has permission wallet0 to 2:", vault.hasGrantedPermission(2, wallet0));
        vm.stopBroadcast();
    }
}
