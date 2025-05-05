// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

interface ISchemaManager {
    // Events
    event SchemaSet(uint256 indexed index, string schemaCID);

    // Errors
    /// @notice Error thrown when no schema is set
    error NoSchema();
    /// @notice Error thrown when the schema CID is invalid
    error InvalidSchemaCID();

    // Functions
    function schemaCIDs(uint256) external view returns (string memory);
    function vaultSchemaIndex(uint256) external view returns (uint256);
    function getSchema(uint256) external view returns (string memory);
    function getLastSchemaIndex() external view returns (uint256);
    function getSchemaFromVault(uint256) external view returns (string memory);
    function setLastSchemaIndexToVault(uint256) external;
}
