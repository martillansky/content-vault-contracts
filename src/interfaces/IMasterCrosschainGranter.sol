// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

interface IMasterCrosschainGranter {
    /// @notice Event emitted when a vault from proposal permission upgrade is requested
    event VaultFromProposalPermissionUpgraded(bytes32 indexed proposalId, address indexed user);

    /// @notice Error thrown when the chainId is invalid
    error InvalidChainId();

    /// @notice Upgrades the permission of a vault from a proposal
    /// @param proposalId The id of the proposal
    /// @param user The user to upgrade the permission for
    function upgradePermissionVaultFromProposal(bytes32 proposalId, address user) external;
}
