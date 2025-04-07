// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {Vault} from "../src/Vault.sol";

/// @dev Deploys the Vault contract to the selected network.
contract VaultScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        new Vault();

        vm.stopBroadcast();
    }
}
