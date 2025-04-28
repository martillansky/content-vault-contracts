// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {MasterGateway} from "../src/MasterGateway.sol";
import {ForeignCrosschainGranter} from "../src/ForeignCrosschainGranter.sol";
import {ForeignGateway} from "../src/ForeignGateway.sol";

/// @dev Deploys the ForeignCrosschainGranter contract to the selected network.
/// @dev Deploys the ForeignGateway contract to the selected network.
contract VaultCrosschainScript is Script {
    function run() external {
        bool isLocal = vm.envOr("IS_LOCAL", false);

        if (isLocal) {
            vm.startBroadcast(vm.envUint("ANVIL_PRIVATE_KEY"));
        } else {
            uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
            vm.startBroadcast(deployerPrivateKey); // Use key for testnet/mainnet
        }

        ForeignCrosschainGranter foreignCrosschainGranter = new ForeignCrosschainGranter();
        address masterGatewayAddress = vm.envAddress("MASTER_GATEWAY");
        address amBridgeAddress = vm.envAddress("FOREIGN_BRIDGE");

        ForeignGateway foreignGateway = new ForeignGateway(
            masterGatewayAddress,
            amBridgeAddress,
            address(foreignCrosschainGranter)
        );

        foreignCrosschainGranter.setGateway(address(foreignGateway));

        MasterGateway masterGateway = MasterGateway(masterGatewayAddress);
        uint256 foreignChainId = vm.envUint("FOREIGN_CHAIN_ID");
        masterGateway.registerForeignGateway(
            foreignChainId,
            address(foreignGateway)
        );

        console2.log(
            "ForeignCrosschainGranter deployed to",
            address(foreignCrosschainGranter)
        );
        console2.log("ForeignGateway deployed to", address(foreignGateway));

        vm.stopBroadcast();
    }
}
