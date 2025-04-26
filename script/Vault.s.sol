// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Vault} from "../src/Vault.sol";
import {SchemaManager} from "../src/SchemaManager.sol";
import {ProposalVaultManager} from "../src/ProposalVaultManager.sol";

/// @dev Deploys the Vault contract to the selected network.
/// @dev Deploys the ProposalVaultManager contract to the selected network.
contract VaultScript is Script {
    function run() external {
        bool isLocal = vm.envOr("IS_LOCAL", false);

        if (isLocal) {
            //address sender = vm.envAddress("ANVIL_SENDER");
            vm.startBroadcast(vm.envUint("ANVIL_PRIVATE_KEY"));
        } else {
            uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
            vm.startBroadcast(deployerPrivateKey); // Use key for testnet/mainnet
        }

        SchemaManager schemaManager = new SchemaManager();
        Vault vault = new Vault(address(schemaManager));
        ProposalVaultManager proposalVaultManager = new ProposalVaultManager(address(vault));
        vault.setProposalVaultManager(address(proposalVaultManager));

        // ------------------------------------------------------------------------
        // TODO: MasterCrosschainGranter.sol
        // This must be the CrosschainGranter contract deployed on mainnet.
        // It communicates with other CrosschainGranter contracts deployed on
        // other chains. The MasterCrosschainGranter contract is the owner of
        // all the vaults created from snapshot proposals. It has the ability to
        // grant permission to vaults from proposal to any user that has
        // positive balance of the token required by the proposal which grants
        // voting power to the user.
        // ------------------------------------------------------------------------
        address wallet9 = vm.envAddress("ANVIL_WALLET_9");
        proposalVaultManager.setVaultMasterCrosschainGranter(wallet9);

        schemaManager.setSchema("bafkreicdjjyjxjw3esxfztkg5j6uwwmayord4c3nmyzquhmgurhtzubcm4");

        console2.log("SchemaManager deployed to", address(schemaManager));
        console2.log("Vault deployed to", address(vault));
        console2.log("ProposalVaultManager deployed to", address(proposalVaultManager));

        vm.stopBroadcast();
    }
}
