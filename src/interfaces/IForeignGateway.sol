// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title IForeignGateway
/// @notice Interface for the ForeignGateway contract
interface IForeignGateway {
    /// @notice Sends a message to the home chain's gateway instance
    /// @param _message The message to send
    function sendMessageToVaultsHomeChain(bytes memory _message) external;
}
