// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title IMasterGateway
/// @notice Interface for the MasterGateway contract
interface IMasterGateway {
    /// @notice The event emitted when a foreign gateway is registered
    event ForeignGatewayRegistered(uint256 chainId, address foreignGateway);

    /// @notice The error emitted when the chain id is invalid
    error InvalidChainId();

    /// @notice Sends a message to another chain's gateway instance
    /// @param _message The message to send
    function sendMessageToForeignGateway(
        uint256 chainId,
        bytes memory _message
    ) external;

    /// @notice Gets the gateway for a given chainId
    /// @param chainId The chainId of the foreign chain
    /// @return The address of the foreign chain's gateway instance
    function getGateway(uint256 chainId) external view returns (address);
}
