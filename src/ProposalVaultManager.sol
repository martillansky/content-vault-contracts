// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {ISchemaManager} from "./interfaces/ISchemaManager.sol";
import {IVault} from "./interfaces/IVault.sol";
import {IVaultAccessControl} from "./interfaces/IVaultAccessControl.sol";
import {IVaultPermissions} from "./interfaces/IVaultPermissions.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IVaultErrors} from "./interfaces/IVaultErrors.sol";

/// @title ProposalVaultManager - Manages vaults created from cross-chain proposals
/// @notice This contract handles the creation and management of vaults that originate from cross-chain proposals
/// @dev Inherits from ERC1155 for token management and Ownable for access control
contract ProposalVaultManager is Ownable, IVaultErrors {
    /// @notice Error thrown when the caller is not the master crosschain granter
    error NotMasterCrosschainGranter();
    /// @notice Error thrown when the vault is already pinned, user already has permission
    error VaultAlreadyPinned();

    /// @notice The address of the Vault contract
    //Vault public vault;
    IVaultAccessControl public vaultAccessControl;
    IVault public vaultCore;
    IVaultPermissions public vaultPermissions;

    // Address of the master crosschain granter
    address public vaultMasterCrosschainGranter;

    // Mapping of Vaults from proposals: proposalId -> tokenId
    mapping(bytes32 => uint256) public proposalIdToVault;

    // ----------------------------- //
    //        Events                 //
    // ----------------------------- //

    /// @notice Emitted when a new vault is created from a proposal
    /// @param tokenId The ID of the created vault token
    /// @param proposalId The ID of the proposal that created the vault
    /// @param name The name of the vault
    /// @param description The description of the vault
    /// @param schemaCID The CID of the schema used for the vault
    event VaultFromProposalCreated(
        uint256 indexed tokenId,
        bytes32 indexed proposalId,
        string name,
        string description,
        string schemaCID
    );

    /// @notice Emitted when a vault is pinned to a user
    /// @param to The address of the user the vault is pinned to
    /// @param tokenId The ID of the vault token
    /// @param permission The permission level granted
    event VaultFromProposalPinned(
        address indexed to,
        uint256 indexed tokenId,
        uint8 permission
    );

    /// @notice Emitted when a vault is unpinned from a user
    /// @param to The address of the user the vault is unpinned from
    /// @param tokenId The ID of the vault token
    event VaultFromProposalUnpinned(
        address indexed to,
        uint256 indexed tokenId
    );

    // ----------------------------- //
    //        Modifiers              //
    // ----------------------------- //

    modifier onlyVaultMasterCrosschainGranter() {
        if (msg.sender != vaultMasterCrosschainGranter) {
            revert NotMasterCrosschainGranter();
        }
        _;
    }

    // ----------------------------- //
    //        Constructor            //
    // ----------------------------- //

    /// @notice Constructor for the ProposalVaultManager
    /// @param _vault The address of the Vault contract
    constructor(address _vault) Ownable(msg.sender) {
        //vault = Vault(_vault);
        vaultAccessControl = IVaultAccessControl(_vault);
        vaultCore = IVault(_vault);
        vaultPermissions = IVaultPermissions(_vault);
    }

    /// @notice Sets the master crosschain granter
    /// @dev Only callable by the contract owner
    /// @param masterGranter The address of the master crosschain granter
    function setVaultMasterCrosschainGranter(
        address masterGranter
    ) external onlyOwner {
        vaultMasterCrosschainGranter = masterGranter;
    }

    /// @notice Creates a new vault from a proposalId
    /// @dev Creates a new vault token and sets up initial permissions
    /// @param proposalId The proposalId of the vault
    /// @param name The name of the vault
    /// @param description The description of the vault
    function createVaultFromProposal(
        bytes32 proposalId,
        string memory name,
        string memory description,
        address user
    ) external onlyVaultMasterCrosschainGranter {
        uint256 lastTokenId = vaultCore.getLastTokenId();

        // As it might revert, it is done before incrementing lastTokenId
        ISchemaManager(vaultCore.schemaManager()).setLastSchemaIndexToVault(
            lastTokenId + 1
        );
        uint256 newTokenId = vaultCore.incrementLastTokenId();

        vaultAccessControl.mintVaultAccess(user, newTokenId);

        // sets vault owner to master crosschain granter
        vaultCore.assignVaultFromProposalOwnership(
            newTokenId,
            vaultMasterCrosschainGranter
        );

        proposalIdToVault[proposalId] = newTokenId;

        // Set the permission to read for the creator
        //      -- Permission is set to write through upgradePermissionVaultFromProposal
        //      called by the master crosschain granter(from chainId)
        //      after verifying positive balance of the token contract
        vaultPermissions.setPermissionRead(newTokenId, msg.sender);

        emit VaultFromProposalCreated(
            newTokenId,
            proposalId,
            name,
            description,
            /* chainId,
            tokenContract, */
            ISchemaManager(vaultCore.schemaManager()).getSchemaFromVault(
                newTokenId
            )
        );
        emit VaultFromProposalPinned(
            msg.sender,
            newTokenId,
            vaultPermissions.getPermissionRead()
        );
    }

    /// @notice Pins a vault from a proposal to the caller
    /// @dev Emits a VaultFromProposalPinned event
    /// @param proposalId The proposalId of the vault
    /// @param user The address of the user to pin the vault to
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error ZeroAddress if the user address is zero
    /// @custom:error VaultAlreadyPinned if the vault is already pinned, user already has permission
    function pinVaultFromProposal(
        bytes32 proposalId,
        address user
    ) external onlyVaultMasterCrosschainGranter {
        uint256 tokenId = proposalIdToVault[proposalId];
        if (tokenId == 0) revert VaultDoesNotExist();

        if (user == address(0)) revert ZeroAddress();
        if (vaultAccessControl.getVaultBalance(user, tokenId) > 0) {
            revert VaultAlreadyPinned();
        }

        vaultAccessControl.mintVaultAccess(user, tokenId);
        vaultPermissions.setPermissionRead(tokenId, user);
        emit VaultFromProposalPinned(
            user,
            tokenId,
            vaultPermissions.getPermissionRead()
        );
    }

    /// @notice Unpins a vault from proposal to the caller
    /// @dev Emits a VaultFromProposalUnpinned event
    /// @param proposalId The proposalId of the vault
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error ZeroAddress if the user address is zero
    /// @custom:error NoAccessToRevoke if the user has no access to revoke
    /// @custom:error NotVaultOwner if the caller is not the master crosschain granter
    function unpinVaultFromProposal(
        bytes32 proposalId,
        address user
    ) external onlyVaultMasterCrosschainGranter {
        uint256 tokenId = proposalIdToVault[proposalId];
        if (tokenId == 0) revert VaultDoesNotExist();

        if (user == address(0)) revert ZeroAddress();

        if (!vaultPermissions.hasGrantedPermission(tokenId, user)) {
            revert NoAccessToRevoke();
        }
        if (vaultAccessControl.getVaultBalance(user, tokenId) == 0) {
            vaultPermissions.setPermissionNone(tokenId, user);
            revert NoAccessToRevoke();
        }
        vaultPermissions.setPermissionNone(tokenId, user);
        vaultAccessControl.burnVaultAccess(user, tokenId);

        emit VaultFromProposalUnpinned(user, tokenId);
    }

    /// @notice Upgrades a user's permission level for a vault
    /// @dev Only callable by the master crosschain granter
    /// @param proposalId The proposalId of the vault
    /// @param user The address of the user
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error ZeroAddress if the user address is zero
    /// @custom:error InvalidUpgrade if the user doesn't have read permission
    /// @custom:error NotMasterCrosschainGranter if the caller is not the master crosschain granter
    function upgradePermissionVaultFromProposal(
        bytes32 proposalId,
        address user
    ) external onlyVaultMasterCrosschainGranter {
        uint256 tokenId = proposalIdToVault[proposalId];
        if (tokenId == 0) revert VaultDoesNotExist();

        if (user == address(0)) revert ZeroAddress();
        if (!vaultPermissions.isPermissionVaultRead(tokenId, user)) {
            revert InvalidUpgrade();
        }

        vaultPermissions.setPermissionWrite(tokenId, user);
    }
}
