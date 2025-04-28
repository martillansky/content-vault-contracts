// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title IBridge
/// @notice Interface for the Bridge contract
interface IBridge {
    function requireToPassMessage(address _contract, bytes memory _data, uint256 _gas) external returns (bytes32);

    function maxGasPerTx() external view returns (uint256);

    function messageSender() external view returns (address);
}
