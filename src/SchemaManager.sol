// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ISchemaManager} from "./interfaces/ISchemaManager.sol";
import {CIDValidatorLib} from "./libs/CIDValidatorLib.sol";

/// @title SchemaManager - Manager of the JSON Schema Models for content vault metadata
contract SchemaManager is Ownable, ISchemaManager {
    constructor() Ownable(msg.sender) {}

    // Mapping of schemas: schemaIndex -> CID to the JSON schema
    mapping(uint256 => string) public schemaCIDs;

    // Mapping of vaults: tokenId -> schemaIndex
    mapping(uint256 => uint256) public vaultSchemaIndex;

    // Index of the last schema
    uint256 public lastSchemaIndex;

    /// @notice Sets a new schema for content validation
    /// @param schemaCID The CID of the JSON schema
    /// @custom:error NotOwner if the caller is not the contract owner
    /// @custom:error InvalidSchemaCID if the schema CID is invalid
    function setSchema(string memory schemaCID) external onlyOwner {
        if (!CIDValidatorLib.isValidCID(schemaCID)) revert InvalidSchemaCID();

        lastSchemaIndex++;
        schemaCIDs[lastSchemaIndex] = schemaCID;
        emit SchemaSet(lastSchemaIndex, schemaCID);
    }

    /// @notice Gets the schema for a vault
    /// @param tokenId The tokenId of the vault
    /// @return The schema for the vault
    function getSchemaFromVault(uint256 tokenId) external view returns (string memory) {
        return schemaCIDs[vaultSchemaIndex[tokenId]];
    }

    /// @notice Gets the schema for a given schema index
    /// @param schemaIndex The index of the schema
    /// @return The schema for the given schema index
    /// @custom:error NoSchema if the schema index is greater than the last schema index
    function getSchema(uint256 schemaIndex) external view returns (string memory) {
        if (schemaIndex > lastSchemaIndex) revert NoSchema();
        return schemaCIDs[schemaIndex];
    }

    /// @notice Gets the last schema index
    /// @return The last schema index
    /// @custom:error NoSchema if no schemas have been set
    function getLastSchemaIndex() external view returns (uint256) {
        if (lastSchemaIndex == 0) revert NoSchema();
        return lastSchemaIndex;
    }

    /// @notice Sets the last schema index to a vault
    /// @param tokenId The tokenId of the vault
    /// @custom:error NotOwner if the caller is not the contract owner
    /// @custom:error NoSchema if no schemas have been set
    function setLastSchemaIndexToVault(uint256 tokenId) external {
        if (lastSchemaIndex == 0) revert NoSchema();
        vaultSchemaIndex[tokenId] = lastSchemaIndex;
    }
}
