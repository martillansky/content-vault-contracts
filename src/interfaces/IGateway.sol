// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title IGateway
/// @notice Interface for the Gateway contract
interface IGateway {
    /// @notice The error emitted when the sender is invalid
    error InvalidSender();
    /// @notice The error emitted when the message call fails
    error MessageCallFailed();

    /// @notice Receives a message from another chain's gateway instance
    /// @param _message The message to receive
    function receiveMessage(bytes memory _message) external;
}
