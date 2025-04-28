// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ISchemaManager} from "./interfaces/ISchemaManager.sol";
import {VaultSignatureValidator} from "./VaultSignatureValidator.sol";
import {VaultPermissions} from "./VaultPermissions.sol";
import {IVault} from "./interfaces/IVault.sol";
import {IVaultErrors} from "./interfaces/IVaultErrors.sol";
import {VaultTypehashLib} from "./libs/VaultTypehashLib.sol";
import {VaultPermissionsLib} from "./libs/VaultPermissionsLib.sol";

/// @title Vault - A tokenized, permissioned content vault system using ERC1155 and EIP-712
contract Vault is IVault, Ownable, VaultSignatureValidator, VaultPermissions {
    // ----------------------------- //
    //        Constants & Types      //
    // ----------------------------- //

    // Address of the SchemaManager contract
    address public schemaManager;

    /// @notice The last tokenId used
    uint256 public lastTokenId;

    /// @notice Constructor for the Vault contract
    /// @param _schemaManager The address of the SchemaManager contract
    constructor(address _schemaManager) ERC1155("") Ownable(msg.sender) {
        schemaManager = _schemaManager;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("Vault")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Sets the ProposalVaultManager contract
    /// @param _manager The address of the ProposalVaultManager contract
    /// @custom:error NotOwner if the caller is not the contract owner
    function setProposalVaultManager(address _manager) external onlyOwner {
        proposalVaultManager = _manager;
    }

    /// @notice Returns the last tokenId
    /// @return The last tokenId
    function getLastTokenId() external view returns (uint256) {
        return lastTokenId;
    }

    /// @notice Increments the last tokenId
    /// @return The new last tokenId
    function incrementLastTokenId() external returns (uint256) {
        lastTokenId++;
        return lastTokenId;
    }

    /// @notice Creates a new vault using the current schema
    /// @param name The name of the vault
    /// @param description The description of the vault
    function createVault(
        string memory name,
        string memory description
    ) external {
        ISchemaManager(schemaManager).setLastSchemaIndexToVault(
            lastTokenId + 1
        ); // Might revert. Done before incrementing lastTokenId
        lastTokenId++;

        _mint(msg.sender, lastTokenId, 1, "");

        vaultOwner[lastTokenId] = msg.sender;
        permissions[lastTokenId][msg.sender] = VaultPermissionsLib
            .PERMISSION_WRITE;

        emit VaultCreated(
            lastTokenId,
            msg.sender,
            name,
            description,
            ISchemaManager(schemaManager).getSchemaFromVault(lastTokenId)
        );
    }

    /// @notice Assigns a vault from a proposal ownership to a manager
    /// @param tokenId The vault identifier
    /// @param masterCrosschainGranter The master crosschain granter address
    /// @custom:error NotProposalVaultManager if the caller is not the proposal vault manager
    function assignVaultFromProposalOwnership(
        uint256 tokenId,
        address masterCrosschainGranter
    ) external onlyProposalVaultManager {
        vaultOwner[tokenId] = masterCrosschainGranter;
    }

    /// @notice Transfers ownership of a vault to a new address
    /// @param tokenId The vault identifier
    /// @param newOwner The new owner address
    /// @custom:error ZeroAddress if the new owner is the zero address
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error NotVaultOwner if the caller is not the vault owner
    function transferVaultOwnership(
        uint256 tokenId,
        address newOwner
    ) external {
        if (newOwner == address(0)) revert ZeroAddress();
        if (vaultOwner[tokenId] == address(0)) revert VaultDoesNotExist();
        if (msg.sender != vaultOwner[tokenId]) revert NotVaultOwner();

        address oldOwner = vaultOwner[tokenId];
        vaultOwner[tokenId] = newOwner;

        emit VaultTransferred(tokenId, oldOwner, newOwner);
    }

    /// @notice Grants access to a user for a specific vault
    /// @param to The address to grant access to
    /// @param tokenId The vault identifier
    /// @param permission The permission level to grant
    /// @custom:error InvalidPermission if the permission is not READ or WRITE
    /// @custom:error ZeroAddress if the recipient is the zero address
    /// @custom:error AlreadyHasToken if the recipient already has the token
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error NotVaultOwner if the caller is not the vault owner
    function grantAccess(
        address to,
        uint256 tokenId,
        uint8 permission
    ) external {
        // Check permissions first
        if (
            permission != VaultPermissionsLib.PERMISSION_READ &&
            permission != VaultPermissionsLib.PERMISSION_WRITE
        ) {
            revert InvalidPermission();
        }
        if (to == address(0)) revert ZeroAddress();
        if (balanceOf(to, tokenId) != 0) revert AlreadyHasToken();

        // Then check vault state
        address owner = vaultOwner[tokenId];
        if (owner == address(0)) revert VaultDoesNotExist();
        if (msg.sender != owner) revert NotVaultOwner();

        _mint(to, tokenId, 1, "");
        permissions[tokenId][to] = permission;

        emit VaultAccessGranted(to, tokenId, permission);
    }

    /// @notice Grants permission to a user via EIP-712 signature
    /// @param to The address to grant access to
    /// @param tokenId The vault identifier
    /// @param permission The permission level to grant
    /// @param deadline The deadline for the signature
    /// @param signature The EIP-712 signature
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error ZeroAddress if the recipient is the zero address
    /// @custom:error InvalidPermission if the permission is not READ or WRITE
    /// @custom:error AlreadyHasToken if the recipient already has the token
    /// @custom:error SignatureExpired if the signature has expired
    /// @custom:error InvalidSignature if the signature is invalid
    function grantAccessWithSignature(
        address to,
        uint256 tokenId,
        uint8 permission,
        uint256 deadline,
        bytes calldata signature
    ) external {
        // First check if the vault exists and get its owner
        address owner = vaultOwner[tokenId];
        if (owner == address(0)) revert VaultDoesNotExist();
        if (to == address(0)) revert ZeroAddress();
        if (
            permission != VaultPermissionsLib.PERMISSION_READ &&
            permission != VaultPermissionsLib.PERMISSION_WRITE
        ) {
            revert InvalidPermission();
        }
        if (balanceOf(to, tokenId) != 0) revert AlreadyHasToken();

        _verifySignature(
            keccak256(
                abi.encode(
                    VaultTypehashLib.PERMISSION_GRANT_TYPEHASH,
                    to,
                    tokenId,
                    permission,
                    nonces[owner],
                    deadline
                )
            ),
            owner,
            deadline,
            signature
        );

        _mint(to, tokenId, 1, "");
        permissions[tokenId][to] = permission;

        emit VaultAccessGranted(to, tokenId, permission);
    }

    /// @notice Stores content with metadata in a vault
    /// @param tokenId The vault identifier
    /// @param encryptedCID The encrypted CID of the content
    /// @param isCIDEncrypted Whether the CID is encrypted
    /// @param metadata The metadata associated with the content
    /// @custom:error NoWritePermission if the caller doesn't have write permission
    function storeContentWithMetadata(
        uint256 tokenId,
        bytes calldata encryptedCID,
        bool isCIDEncrypted,
        string calldata metadata
    ) external {
        if (
            permissions[tokenId][msg.sender] !=
            VaultPermissionsLib.PERMISSION_WRITE
        ) {
            revert NoWritePermission();
        }
        emit ContentStoredWithMetadata(
            msg.sender,
            tokenId,
            encryptedCID,
            isCIDEncrypted,
            metadata,
            false
        );
    }

    /// @notice Stores multiple content items with metadata in a vault
    /// @param tokenId The vault identifier
    /// @param encryptedCIDs Array of encrypted CIDs
    /// @param areCIDsEncrypted Boolean indicating if the CIDs are encrypted
    /// @param metadatas Array of metadatas
    /// @custom:error NoWritePermission if the caller doesn't have write permission
    /// @custom:error EmptyArray if either array is empty
    /// @custom:error MismatchedArrayLengths if the arrays have different lengths
    function storeContentBatch(
        uint256 tokenId,
        bytes[] calldata encryptedCIDs,
        bool areCIDsEncrypted,
        string[] calldata metadatas
    ) external {
        if (
            permissions[tokenId][msg.sender] !=
            VaultPermissionsLib.PERMISSION_WRITE
        ) {
            revert NoWritePermission();
        }
        if (encryptedCIDs.length == 0 || metadatas.length == 0) {
            revert EmptyArray();
        }
        if (encryptedCIDs.length != metadatas.length) {
            revert MismatchedArrayLengths();
        }

        for (uint256 i = 0; i < encryptedCIDs.length; ++i) {
            emit ContentStoredWithMetadata(
                msg.sender,
                tokenId,
                encryptedCIDs[i],
                areCIDsEncrypted,
                metadatas[i],
                false
            );
        }
    }

    /// @notice Stores content with metadata and EIP-712 signature
    /// @param tokenId The vault identifier
    /// @param encryptedCID The (private) encrypted cid to the content
    /// @param isCIDEncrypted Whether the CID is encrypted
    /// @param metadata The signed metadata associated with the content
    /// @param deadline The deadline for the signature
    /// @param signature The EIP-712 signature
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error NoWritePermission if the caller doesn't have write permission
    /// @custom:error SignatureExpired if the signature has expired
    /// @custom:error InvalidSignature if the signature is invalid
    function storeContentWithMetadataSigned(
        uint256 tokenId,
        bytes calldata encryptedCID,
        bool isCIDEncrypted,
        string calldata metadata,
        uint256 deadline,
        bytes calldata signature
    ) external {
        address owner = vaultOwner[tokenId];
        if (owner == address(0)) revert VaultDoesNotExist();
        if (
            permissions[tokenId][msg.sender] !=
            VaultPermissionsLib.PERMISSION_WRITE
        ) {
            revert NoWritePermission();
        }

        _verifySignature(
            keccak256(
                abi.encode(
                    VaultTypehashLib.METADATA_SIGNATURE_TYPEHASH,
                    keccak256(bytes(metadata)),
                    tokenId,
                    nonces[owner],
                    deadline
                )
            ),
            owner,
            deadline,
            signature
        );

        emit ContentStoredWithMetadata(
            msg.sender,
            tokenId,
            encryptedCID,
            isCIDEncrypted,
            metadata,
            true
        );
    }

    /// @notice Stores content with metadata and EIP-712 signature
    /// @param tokenId The vault identifier
    /// @param encryptedCIDs The (private) encrypted cids to the contents
    /// @param areCIDsEncrypted Boolean indicating if the CIDs are encrypted
    /// @param metadatas The signed metadatas associated with the contents
    /// @param deadline The deadline for the signature
    /// @param signature The EIP-712 signature
    /// @custom:error VaultDoesNotExist if the vault doesn't exist
    /// @custom:error NoWritePermission if the caller doesn't have write permission
    /// @custom:error EmptyArray if either array is empty
    /// @custom:error MismatchedArrayLengths if the arrays have different lengths
    /// @custom:error SignatureExpired if the signature has expired
    /// @custom:error InvalidSignature if the signature is invalid
    function storeContentBatchWithSignature(
        uint256 tokenId,
        bytes[] calldata encryptedCIDs,
        bool areCIDsEncrypted,
        string[] calldata metadatas,
        uint256 deadline,
        bytes calldata signature
    ) external {
        address owner = vaultOwner[tokenId];
        if (owner == address(0)) revert VaultDoesNotExist();
        if (
            permissions[tokenId][msg.sender] !=
            VaultPermissionsLib.PERMISSION_WRITE
        ) {
            revert NoWritePermission();
        }
        if (encryptedCIDs.length == 0 || metadatas.length == 0) {
            revert EmptyArray();
        }
        if (encryptedCIDs.length != metadatas.length) {
            revert MismatchedArrayLengths();
        }

        // Build bytes32[] of metadata hashes
        bytes32[] memory metadataHashes = new bytes32[](metadatas.length);
        for (uint256 i = 0; i < metadatas.length; i++) {
            metadataHashes[i] = keccak256(bytes(metadatas[i]));
        }
        _verifySignature(
            keccak256(
                abi.encode(
                    VaultTypehashLib.METADATA_ARRAY_SIGNATURE_TYPEHASH,
                    keccak256(abi.encodePacked(metadataHashes)),
                    tokenId,
                    nonces[owner],
                    deadline
                )
            ),
            owner,
            deadline,
            signature
        );

        for (uint256 i = 0; i < encryptedCIDs.length; i++) {
            emit ContentStoredWithMetadata(
                msg.sender,
                tokenId,
                encryptedCIDs[i],
                areCIDsEncrypted,
                metadatas[i],
                true
            );
        }
    }

    // ----------------------------- //
    //           URI Management      //
    // ----------------------------- //

    /// @notice Sets a new base URI for ERC1155 metadata
    /// @param newuri The new URI
    function setURI(string memory newuri) external onlyOwner {
        _setURI(newuri);
        emit URI(newuri, 0);
    }

    // ----------------------------- //
    //       Access Control          //
    // ----------------------------- //

    function mintVaultAccess(
        address to,
        uint256 tokenId
    ) external onlyProposalVaultManager {
        _mint(to, tokenId, 1, "");
    }

    function burnVaultAccess(
        address from,
        uint256 tokenId
    ) external onlyProposalVaultManager {
        _burn(from, tokenId, 1);
    }

    function getVaultBalance(
        address user,
        uint256 tokenId
    ) external view onlyProposalVaultManager returns (uint256) {
        return balanceOf(user, tokenId);
    }
}
