// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {ProposalVaultManager} from "./ProposalVaultManager.sol";
import {ERC20TokenProposalLib} from "./libs/ERC20TokenProposalLib.sol";
import {ICrosschainGranter} from "./interfaces/ICrosschainGranter.sol";
import {IMasterGateway} from "./interfaces/IMasterGateway.sol";
import {IMasterCrosschainGranter} from "./interfaces/IMasterCrosschainGranter.sol";
import {IForeignCrosschainGranter} from "./interfaces/IForeignCrosschainGranter.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract MasterCrosschainGranter is
    ICrosschainGranter,
    IMasterCrosschainGranter,
    Ownable
{
    /// @notice The address of the master gateway
    address public masterGateway;

    /// @notice The proposal vault manager contract
    address public immutable proposalVaultManager;

    // Mapping of Vaults from proposals: proposalId -> ProposalMetadata
    mapping(bytes32 => ProposalMetadata) public proposalIdToVault;

    /// @notice Constructor
    /// @param _proposalVaultManager The address of the proposal vault manager contract
    constructor(address _proposalVaultManager) Ownable(msg.sender) {
        proposalVaultManager = _proposalVaultManager;
    }

    /// @notice Sets the master gateway
    /// @param _masterGateway The address of the master gateway
    function setGateway(address _masterGateway) external onlyOwner {
        masterGateway = _masterGateway;
    }

    /// @notice Creates a vault from a proposal
    /// @param proposalId The id of the proposal
    /// @param name The name of the vault
    /// @param description The description of the vault
    /// @param chainId The chainId of the token's home chain
    /// @param tokenContract The address of the token contract
    function createVaultFromProposal(
        bytes32 proposalId,
        string memory name,
        string memory description,
        uint256 chainId,
        address tokenContract
    ) external {
        if (!ERC20TokenProposalLib.isValidChainId(chainId))
            revert InvalidChainId();
        uint256 thisChainId = block.chainid;
        if (chainId == thisChainId)
            if (!ERC20TokenProposalLib.isValidTokenContract(tokenContract))
                revert InvalidTokenContract();
            else if (!ERC20TokenProposalLib.isValidTokenAddress(tokenContract))
                revert InvalidTokenAddress();

        ProposalVaultManager(proposalVaultManager).createVaultFromProposal(
            proposalId,
            name,
            description,
            msg.sender
        );

        if (chainId != thisChainId) {
            address gateway = IMasterGateway(masterGateway).getGateway(chainId);
            if (gateway == address(0)) revert GatewayDoesNotExist();
            IMasterGateway(gateway).sendMessageToForeignGateway(
                chainId,
                abi.encodeWithSelector(
                    IForeignCrosschainGranter
                        .registerVaultFromProposalOnTokenHomeChain
                        .selector,
                    proposalId,
                    tokenContract
                )
            );
        } else {
            proposalIdToVault[proposalId] = ProposalMetadata({
                proposalId: proposalId,
                tokenContract: tokenContract
            });
            emit VaultFromProposalRegisteredOnHomeChain(
                proposalId,
                tokenContract
            );
        }
    }

    // ----------------------------------------------------
    // IMasterCrosschainGranter - Receive functions
    // ----------------------------------------------------

    /// @notice Upgrades the permission of a vault from a proposal
    /// on the same chain only if the user has enough balance of the
    /// proposal's strategy token
    /// @param proposalId The id of the proposal
    /// @param user The user to upgrade the permission for
    function upgradePermissionVaultFromProposal(
        bytes32 proposalId,
        address user
    ) external {
        if (msg.sender != masterGateway) revert InvalidSender();
        ProposalMetadata memory proposalMetadata = proposalIdToVault[
            proposalId
        ];
        address tokenContract = proposalMetadata.tokenContract;
        if (tokenContract == address(0)) revert VaultFromProposalDoesNotExist();
        if (ERC20TokenProposalLib.balanceOf(tokenContract, user) == 0)
            revert NotEnoughBalance();
        ProposalVaultManager(proposalVaultManager)
            .upgradePermissionVaultFromProposal(proposalId, user);
        emit VaultFromProposalPermissionUpgraded(proposalId, user);
    }
}
