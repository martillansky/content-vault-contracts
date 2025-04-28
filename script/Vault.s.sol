// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Vault} from "../src/Vault.sol";
import {SchemaManager} from "../src/SchemaManager.sol";
import {ProposalVaultManager} from "../src/ProposalVaultManager.sol";
import {MasterCrosschainGranter} from "../src/MasterCrosschainGranter.sol";
import {MasterGateway} from "../src/MasterGateway.sol";

/// @dev Deploys the Vault contract to the selected network.
/// @dev Deploys the ProposalVaultManager contract to the selected network.
contract VaultScript is Script {
    function run() external {
        bool isLocal = vm.envOr("IS_LOCAL", false);

        if (isLocal) {
            vm.startBroadcast(vm.envUint("ANVIL_PRIVATE_KEY"));
        } else {
            uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
            vm.startBroadcast(deployerPrivateKey); // Use key for testnet/mainnet
        }

        SchemaManager schemaManager = new SchemaManager();
        Vault vault = new Vault(address(schemaManager));
        ProposalVaultManager proposalVaultManager = new ProposalVaultManager(
            address(vault)
        );
        vault.setProposalVaultManager(address(proposalVaultManager));
        MasterCrosschainGranter masterCrosschainGranter = new MasterCrosschainGranter(
                address(proposalVaultManager)
            );
        proposalVaultManager.setVaultMasterCrosschainGranter(
            address(masterCrosschainGranter)
        );
        address amBridgeAddress = vm.envAddress("MAINNET_BRIDGE");
        MasterGateway masterGateway = new MasterGateway(
            amBridgeAddress,
            address(masterCrosschainGranter)
        );
        masterCrosschainGranter.setGateway(address(masterGateway));

        schemaManager.setSchema(
            "bafkreicdjjyjxjw3esxfztkg5j6uwwmayord4c3nmyzquhmgurhtzubcm4"
        );

        console2.log("SchemaManager deployed to", address(schemaManager));
        console2.log("Vault deployed to", address(vault));
        console2.log(
            "ProposalVaultManager deployed to",
            address(proposalVaultManager)
        );
        console2.log(
            "MasterCrosschainGranter deployed to",
            address(masterCrosschainGranter)
        );
        console2.log("MasterGateway deployed to", address(masterGateway));

        vm.stopBroadcast();
    }
}
