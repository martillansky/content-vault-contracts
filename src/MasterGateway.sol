// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {IGateway} from "./interfaces/IGateway.sol";
import {IMasterGateway} from "./interfaces/IMasterGateway.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IBridge} from "./interfaces/IBridge.sol";

/// @title MasterGateway
/// @notice MasterGateway contract for cross-chain communication
contract MasterGateway is IGateway, IMasterGateway, Ownable {
    /// @notice The address of the home chain's bridge instance
    address public immutable amBridgeAddress;

    /// @notice The address of the home chain's gateway instance
    address public immutable masterCrosschainGranter;

    /// @notice Mapping of chainId to corresponding deployed gateway
    mapping(uint256 => address) public chainIdToGateway;

    mapping(uint256 => uint256) public indexToChainId;
    uint256 public lastIndex;

    /// @notice Constructor
    /// @param _amBridgeAddress The address of the home chain's bridge instance
    /// @param _masterCrosschainGranter The address of the master crosschain granter instance
    constructor(address _amBridgeAddress, address _masterCrosschainGranter) Ownable(msg.sender) {
        amBridgeAddress = _amBridgeAddress;
        masterCrosschainGranter = _masterCrosschainGranter;
    }

    /// @notice Registers a foreign gateway for a given chainId
    /// @param chainId The chainId of the foreign chain
    /// @param foreignGateway The address of the foreign chain's gateway instance
    function registerForeignGateway(uint256 chainId, address foreignGateway) external onlyOwner {
        chainIdToGateway[chainId] = foreignGateway;
        lastIndex++;
        indexToChainId[lastIndex] = chainId;

        emit ForeignGatewayRegistered(chainId, foreignGateway);
    }

    /// @notice Sends a message to another chain's gateway instance
    /// @param _message The message to send
    function sendMessageToForeignGateway(uint256 chainId, bytes memory _message) external {
        if (msg.sender != masterCrosschainGranter) revert InvalidSender();
        address foreignGateway = chainIdToGateway[chainId];
        if (foreignGateway == address(0)) revert InvalidChainId();

        IBridge amBridge = IBridge(amBridgeAddress);
        amBridge.requireToPassMessage(
            foreignGateway, abi.encodeCall(this.receiveMessage, (_message)), amBridge.maxGasPerTx()
        );
    }

    /// @notice Receives a message from another chain's gateway instance
    /// @param _message The message to receive
    function receiveMessage(bytes memory _message) external {
        for (uint256 i = 1; i <= lastIndex; ++i) {
            if (msg.sender == chainIdToGateway[indexToChainId[i]]) {
                (bool success,) = masterCrosschainGranter.call(_message);
                if (!success) revert MessageCallFailed();
                return;
            }
        }
        revert InvalidSender();
    }

    /// @notice Gets the gateway for a given chainId
    /// @param chainId The chainId of the foreign chain
    /// @return The address of the foreign chain's gateway instance
    function getGateway(uint256 chainId) external view returns (address) {
        return chainIdToGateway[chainId];
    }
}
