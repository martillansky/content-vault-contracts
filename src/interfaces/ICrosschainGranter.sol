// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

interface ICrosschainGranter {
    // Metadata for each vault from a proposal
    struct ProposalMetadata {
        bytes32 proposalId;
        address tokenContract;
    }

    // Events
    event VaultFromProposalRegisteredOnHomeChain(bytes32 indexed proposalId, address indexed tokenContract);

    /// @notice Error thrown when the token contract is invalid
    error InvalidTokenContract();
    /// @notice Error thrown when the token address is invalid
    error InvalidTokenAddress();
    /// @notice Error thrown when the vault from proposal does not exist
    error VaultFromProposalDoesNotExist();
    /// @notice Error thrown when the user doesn't have enough balance
    error NotEnoughBalance();
    /// @notice Error thrown when the gateway does not exist
    error GatewayDoesNotExist();
    /// @notice Error thrown when the sender is invalid
    error InvalidSender();

    function setGateway(address _gateway) external;
}
