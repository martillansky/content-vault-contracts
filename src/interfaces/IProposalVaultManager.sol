// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

/// @title IProposalVaultManager
/// @notice Interface for the ProposalVaultManager contract
interface IProposalVaultManager {
    /// @notice Creates a vault from a proposal
    /// @param proposalId The id of the proposal
    /// @param name The name of the vault
    /// @param description The description of the vault
    /// @param chainId The chain id of the vault
    /// @param tokenContract The address of the token contract
    function createVaultFromProposal(
        bytes32 proposalId,
        string memory name,
        string memory description,
        uint256 chainId,
        address tokenContract,
        address user
    ) external;

    /// @notice Upgrades the permission of a vault from a proposal
    /// @param proposalId The id of the proposal
    /// @param user The user to upgrade the permission for
    function upgradePermissionVaultFromProposal(bytes32 proposalId, address user) external;
}
