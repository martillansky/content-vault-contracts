// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {Vault} from "../src/Vault.sol";

/// @dev Deploys the Vault contract to the selected network.
contract VaultScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        Vault vault = new Vault();

        vm.stopBroadcast();
    }
}
