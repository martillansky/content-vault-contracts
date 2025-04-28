// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {ProposalVaultManager} from "./ProposalVaultManager.sol";
import {ERC20TokenProposalLib} from "./libs/ERC20TokenProposalLib.sol";
import {ICrosschainGranter} from "./interfaces/ICrosschainGranter.sol";
import {IMasterCrosschainGranter} from "./interfaces/IMasterCrosschainGranter.sol";
import {IForeignCrosschainGranter} from "./interfaces/IForeignCrosschainGranter.sol";
import {IForeignGateway} from "./interfaces/IForeignGateway.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract ForeignCrosschainGranter is ICrosschainGranter, IForeignCrosschainGranter, Ownable {
    /// @notice The gateway contract to communicate with the home chain's
    /// gateway instance and with the home chain's MasterCrosschainGranter
    address public foreignGateway;

    // Mapping of Vaults from proposals: proposalId -> ProposalMetadata
    mapping(bytes32 => ProposalMetadata) public proposalIdToVault;

    /// @notice Constructor
    constructor() Ownable(msg.sender) {}

    /// @notice Sets the foreign gateway
    /// @param _foreignGateway The address of the foreign gateway
    function setGateway(address _foreignGateway) external onlyOwner {
        foreignGateway = _foreignGateway;
    }

    /// @notice Requests the upgrade of the permission of a vault from a
    /// proposal to the home chain's MasterCrosschainGranter
    /// @param proposalId The id of the proposal
    function upgradePermissionVaultFromProposal(bytes32 proposalId) external {
        ProposalMetadata memory proposalMetadata = proposalIdToVault[proposalId];
        address tokenContract = proposalMetadata.tokenContract;
        if (tokenContract == address(0)) revert VaultFromProposalDoesNotExist();
        if (ERC20TokenProposalLib.balanceOf(tokenContract, msg.sender) == 0) {
            revert NotEnoughBalance();
        }
        if (foreignGateway == address(0)) revert GatewayDoesNotExist();
        IForeignGateway(foreignGateway).sendMessageToVaultsHomeChain(
            abi.encodeWithSelector(
                IMasterCrosschainGranter.upgradePermissionVaultFromProposal.selector, proposalId, msg.sender
            )
        );
        emit VaultFromProposalPermissionUpgradeRequested(proposalId, msg.sender);
    }

    // ----------------------------------------------------
    // IForeignCrosschainGranter - Receive functions
    // ----------------------------------------------------

    /// @notice Registers a vault from a proposal requested by the home
    /// chain's MasterCrosschainGranter on the token's home chain
    /// @param proposalId The id of the proposal
    /// @param tokenContract The address of the token contract
    function registerVaultFromProposalOnTokenHomeChain(bytes32 proposalId, address tokenContract) external {
        if (msg.sender != foreignGateway) revert InvalidSender();
        if (!ERC20TokenProposalLib.isValidTokenContract(tokenContract)) {
            revert InvalidTokenContract();
        }
        if (proposalIdToVault[proposalId].tokenContract != address(0)) {
            revert ProposalAlreadyRegistered();
        }
        proposalIdToVault[proposalId] = ProposalMetadata({proposalId: proposalId, tokenContract: tokenContract});
        emit VaultFromProposalRegisteredOnHomeChain(proposalId, tokenContract);
    }
}
