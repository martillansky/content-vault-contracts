// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

interface IForeignCrosschainGranter {
    /// @notice Event emitted when a vault from proposal permission upgrade is requested
    event VaultFromProposalPermissionUpgradeRequested(
        bytes32 indexed proposalId,
        address indexed user
    );

    /// @notice Error emitted when a proposal is already registered
    error ProposalAlreadyRegistered();

    /// @notice Registers a vault from a proposal on the home chain
    /// @param proposalId The id of the proposal
    /// @param tokenContract The address of the token contract
    function registerVaultFromProposalOnTokenHomeChain(
        bytes32 proposalId,
        address tokenContract
    ) external;
}
