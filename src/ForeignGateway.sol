// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {IGateway} from "./interfaces/IGateway.sol";
import {IForeignGateway} from "./interfaces/IForeignGateway.sol";
import {IBridge} from "./interfaces/IBridge.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title ForeignGateway
/// @notice ForeignGateway contract for cross-chain communication
contract ForeignGateway is IGateway, IForeignGateway, Ownable {
    /// @notice The address of the master gateway in the vault's home chain
    address public immutable masterGateway;

    /// @notice The address of the bridge in this (vault's foreign) chain
    address public immutable amBridgeAddress;

    /// @notice The address of the foreign chain's crosschain granter instance
    address public immutable foreignCrosschainGranter;

    /// @notice Constructor
    /// @param _masterGateway The address of the master gateway in the home chain
    /// @param _amBridgeAddress The address of the foreign chain's bridge instance
    constructor(
        address _masterGateway,
        address _amBridgeAddress,
        address _foreignCrosschainGranter
    ) Ownable(msg.sender) {
        masterGateway = _masterGateway;
        amBridgeAddress = _amBridgeAddress;
        foreignCrosschainGranter = _foreignCrosschainGranter;
    }

    /// @notice Sends a message to the home chain's gateway instance
    /// @param _message The message to send
    function sendMessageToVaultsHomeChain(bytes memory _message) external {
        if (msg.sender != foreignCrosschainGranter) revert InvalidSender();
        IBridge amBridge = IBridge(amBridgeAddress);
        amBridge.requireToPassMessage(
            masterGateway,
            abi.encodeCall(this.receiveMessage, (_message)),
            amBridge.maxGasPerTx()
        );
    }

    /// @notice Receives a message from another chain's gateway instance
    /// @param _message The message to receive
    function receiveMessage(bytes memory _message) external {
        if (msg.sender != masterGateway) revert InvalidSender();
        (bool success, ) = foreignCrosschainGranter.call(_message);
        if (!success) revert MessageCallFailed();
    }
}
