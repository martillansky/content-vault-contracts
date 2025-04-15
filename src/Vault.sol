// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title Vault - A tokenized, permissioned content vault system using ERC1155 and EIP-712
contract Vault is ERC1155, Ownable, EIP712 {
    using ECDSA for bytes32;

    // ----------------------------- //
    //        Constants & Types      //
    // ----------------------------- //

    // Permission Levels: uint8 constants to save gas
    uint8 public constant PERMISSION_NONE = 0;
    uint8 public constant PERMISSION_READ = 1;
    uint8 public constant PERMISSION_WRITE = 2;

    // EIP-712 Domain struct
    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    // Metadata for each vault
    struct VaultMetadata {
        address owner;
        uint256 currentSchemaIndex;
    }

    // ----------------------------- //
    //        Schema Handling        //
    // ----------------------------- //

    // Mapping of schemas: schemaIndex -> CID to the JSON schema
    mapping(uint256 => string) public schemaCIDs;

    // Index of the last schema
    uint256 public lastSchemaIndex;

    // Mapping of nonces: address -> nonce
    mapping(address => uint256) public nonces;

    event SchemaSet(uint256 indexed index, string schemaCID);

    /// @notice Gets the current nonce for an address
    /// @param owner The address to check
    /// @return The current nonce
    function getNonce(address owner) public view returns (uint256) {
        return nonces[owner];
    }

    /// @notice Sets a new schema for content validation
    /// @param schemaCID The CID of the JSON schema
    function setSchema(string memory schemaCID) external onlyOwner {
        lastSchemaIndex++;
        schemaCIDs[lastSchemaIndex] = schemaCID;
        emit SchemaSet(lastSchemaIndex, schemaCID);
    }

    /// @notice Retrieves a schema by its index
    /// @param index The index of the schema to retrieve
    /// @return The IPFS hash of the schema
    function getSchema(uint256 index) public view returns (string memory) {
        if (index == 0 || index > lastSchemaIndex) revert InvalidSchemaIndex();
        return schemaCIDs[index];
    }

    /// @notice Gets the current active schema
    /// @return The IPFS hash of the current schema
    function getCurrentSchema() public view returns (string memory) {
        return schemaCIDs[lastSchemaIndex];
    }

    // ----------------------------- //
    //        Vault Management       //
    // ----------------------------- //

    // Mapping of vaults: tokenId -> metadata
    mapping(uint256 => VaultMetadata) public vaults;

    // Mapping of permissions: tokenId -> address -> permission
    mapping(uint256 => mapping(address => uint8)) public permissions;

    event VaultCreated(
        uint256 indexed tokenId, address indexed owner, string name, string description, string schemaCID
    );
    event VaultAccessGranted(address indexed to, uint256 indexed tokenId, uint8 permission);
    event VaultAccessRevoked(address indexed to, uint256 indexed tokenId);
    event PermissionUpgraded(address indexed user, uint256 indexed tokenId, uint8 newPermission);
    event ContentStoredWithMetadata(
        address indexed sender,
        uint256 indexed tokenId,
        bytes encryptedCID,
        bool isCIDEncrypted,
        bytes metadata,
        bool isMetadataSigned
    );
    event VaultTransferred(uint256 indexed tokenId, address indexed from, address indexed to);

    error NotVaultOwner();
    error AlreadyHasToken();
    error NoWritePermission();
    error InvalidPermission();
    error CannotRevokeAccessToSelf();
    error NoAccessToRevoke();
    error InvalidSchemaIndex();
    error MismatchedArrayLengths();
    error VaultDoesNotExist();
    error InvalidUpgrade();
    error InvalidSignature();
    error SignatureExpired();
    error ZeroAddress();
    error EmptyArray();
    error NoSchema();

    bytes32 internal constant METADATA_SIGNATURE_TYPEHASH =
        keccak256("MetadataHash(string metadata,uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 internal constant METADATA_ARRAY_SIGNATURE_TYPEHASH =
        keccak256("MetadataArrayHash(string[] metadata,uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 internal constant PERMISSION_GRANT_TYPEHASH =
        keccak256("PermissionGrant(address to,uint256 tokenId,uint8 permission,uint256 nonce,uint256 deadline)");
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public immutable DOMAIN_SEPARATOR;

    EIP712Domain private domain_separator_struct =
        EIP712Domain({name: "Vault", version: "1", chainId: block.chainid, verifyingContract: address(this)});

    constructor() ERC1155("") Ownable(msg.sender) EIP712("Vault", "1") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(domain_separator_struct.name)),
                keccak256(bytes(domain_separator_struct.version)),
                domain_separator_struct.chainId,
                domain_separator_struct.verifyingContract
            )
        );
    }

    /// @notice Creates a new vault using the current schema
    /// @param tokenId The unique identifier for the vault
    function createVault(uint256 tokenId, string memory name, string memory description) external {
        uint256 schemaIndex = lastSchemaIndex;
        if (schemaIndex == 0) revert NoSchema();
        if (vaults[tokenId].owner != address(0)) revert AlreadyHasToken();

        _mint(msg.sender, tokenId, 1, "");

        vaults[tokenId] = VaultMetadata({owner: msg.sender, currentSchemaIndex: schemaIndex});
        permissions[tokenId][msg.sender] = PERMISSION_WRITE;

        emit VaultCreated(tokenId, msg.sender, name, description, schemaCIDs[schemaIndex]);
    }

    /// @notice Transfers ownership of a vault to a new address
    /// @param tokenId The vault identifier
    /// @param newOwner The new owner address
    function transferVaultOwnership(uint256 tokenId, address newOwner) external {
        if (newOwner == address(0)) revert ZeroAddress();
        VaultMetadata storage vault = vaults[tokenId];
        if (vault.owner == address(0)) revert VaultDoesNotExist();
        if (msg.sender != vault.owner) revert NotVaultOwner();

        address oldOwner = vault.owner;
        vault.owner = newOwner;

        emit VaultTransferred(tokenId, oldOwner, newOwner);
    }

    /// @notice Grants access to a user for a specific vault
    /// @param to The address to grant access to
    /// @param tokenId The vault identifier
    /// @param permission The permission level to grant
    function grantAccess(address to, uint256 tokenId, uint8 permission) external {
        // Check permissions first
        if (permission != PERMISSION_READ && permission != PERMISSION_WRITE) {
            revert InvalidPermission();
        }
        if (to == address(0)) revert ZeroAddress();
        if (balanceOf(to, tokenId) != 0) revert AlreadyHasToken();

        // Then check vault state
        address owner = vaults[tokenId].owner;
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
    function grantAccessWithSignature(
        address to,
        uint256 tokenId,
        uint8 permission,
        uint256 deadline,
        bytes calldata signature
    ) external {
        // First check if the vault exists and get its owner
        address owner = vaults[tokenId].owner;
        if (owner == address(0)) revert VaultDoesNotExist();
        if (to == address(0)) revert ZeroAddress();
        if (permission != PERMISSION_READ && permission != PERMISSION_WRITE) {
            revert InvalidPermission();
        }
        if (balanceOf(to, tokenId) != 0) revert AlreadyHasToken();

        _verifySignature(
            keccak256(abi.encode(PERMISSION_GRANT_TYPEHASH, to, tokenId, permission, nonces[owner], deadline)),
            owner,
            deadline,
            signature
        );

        _mint(to, tokenId, 1, "");
        permissions[tokenId][to] = permission;

        emit VaultAccessGranted(to, tokenId, permission);
    }

    /// @notice Upgrades a user's permission level for a vault
    /// @param tokenId The vault identifier
    /// @param user The address of the user
    /// @param newPermission The new permission level
    function upgradePermission(uint256 tokenId, address user, uint8 newPermission) external {
        // Check permissions first
        if (newPermission != PERMISSION_WRITE) revert InvalidUpgrade();
        if (user == address(0)) revert ZeroAddress();
        if (permissions[tokenId][user] != PERMISSION_READ) {
            revert InvalidUpgrade();
        }

        // Then check vault state
        address owner = vaults[tokenId].owner;
        if (owner == address(0)) revert VaultDoesNotExist();
        if (msg.sender != owner) revert NotVaultOwner();

        permissions[tokenId][user] = newPermission;
        emit PermissionUpgraded(user, tokenId, newPermission);
    }

    /// @notice Revokes access for a user from a vault
    /// @param tokenId The vault identifier
    /// @param to The address to revoke access from
    function revokeAccess(uint256 tokenId, address to) external {
        if (to == address(0)) revert ZeroAddress();
        address owner = vaults[tokenId].owner;
        if (owner == address(0)) revert VaultDoesNotExist();
        if (msg.sender != owner) revert NotVaultOwner();
        if (to == owner) revert CannotRevokeAccessToSelf();
        if (permissions[tokenId][to] == PERMISSION_NONE) {
            revert NoAccessToRevoke();
        }

        permissions[tokenId][to] = PERMISSION_NONE;
        _burn(to, tokenId, 1);

        emit VaultAccessRevoked(to, tokenId);
    }

    /// @notice Stores content with metadata in a vault
    /// @param tokenId The vault identifier
    /// @param encryptedCID The encrypted CID of the content
    /// @param isCIDEncrypted Whether the CID is encrypted
    /// @param metadata The metadata associated with the content
    function storeContentWithMetadata(
        uint256 tokenId,
        bytes calldata encryptedCID,
        bool isCIDEncrypted,
        bytes calldata metadata
    ) external {
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }
        emit ContentStoredWithMetadata(msg.sender, tokenId, encryptedCID, isCIDEncrypted, metadata, false);
    }

    /// @notice Stores multiple content items with metadata in a vault
    /// @param tokenId The vault identifier
    /// @param encryptedCIDs Array of encrypted CIDs
    /// @param areCIDsEncrypted Boolean indicating if the CIDs are encrypted
    /// @param metadatas Array of metadatas
    function storeContentBatch(
        uint256 tokenId,
        bytes[] calldata encryptedCIDs,
        bool areCIDsEncrypted,
        bytes[] calldata metadatas
    ) external {
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }
        if (encryptedCIDs.length == 0 || metadatas.length == 0) {
            revert EmptyArray();
        }
        if (encryptedCIDs.length != metadatas.length) {
            revert MismatchedArrayLengths();
        }

        for (uint256 i = 0; i < encryptedCIDs.length; ++i) {
            emit ContentStoredWithMetadata(msg.sender, tokenId, encryptedCIDs[i], areCIDsEncrypted, metadatas[i], false);
        }
    }

    /// @notice Stores content with metadata and EIP-712 signature
    /// @param tokenId The vault identifier
    /// @param encryptedCID The (private) encrypted cid to the content
    /// @param isCIDEncrypted Whether the CID is encrypted
    /// @param metadata The signed metadata associated with the content
    /// @param deadline The deadline for the signature
    /// @param signature The EIP-712 signature
    function storeContentWithMetadataSigned(
        uint256 tokenId,
        bytes calldata encryptedCID,
        bool isCIDEncrypted,
        bytes calldata metadata,
        uint256 deadline,
        bytes calldata signature
    ) external {
        address owner = vaults[tokenId].owner;
        if (owner == address(0)) revert VaultDoesNotExist();
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }

        _verifySignature(
            keccak256(abi.encode(METADATA_SIGNATURE_TYPEHASH, metadata, tokenId, nonces[owner], deadline)),
            owner,
            deadline,
            signature
        );

        emit ContentStoredWithMetadata(msg.sender, tokenId, encryptedCID, isCIDEncrypted, metadata, true);
    }

    /// @notice Stores content with metadata and EIP-712 signature
    /// @param tokenId The vault identifier
    /// @param encryptedCIDs The (private) encrypted cids to the contents
    /// @param areCIDsEncrypted Boolean indicating if the CIDs are encrypted
    /// @param metadatas The signed metadatas associated with the contents
    /// @param deadline The deadline for the signature
    /// @param signature The EIP-712 signature
    function storeContentBatchWithSignature(
        uint256 tokenId,
        bytes[] calldata encryptedCIDs,
        bool areCIDsEncrypted,
        bytes[] calldata metadatas,
        uint256 deadline,
        bytes calldata signature
    ) external {
        address owner = vaults[tokenId].owner;
        if (owner == address(0)) revert VaultDoesNotExist();
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }
        if (encryptedCIDs.length == 0 || metadatas.length == 0) {
            revert EmptyArray();
        }
        if (encryptedCIDs.length != metadatas.length) {
            revert MismatchedArrayLengths();
        }

        _verifySignature(
            keccak256(abi.encode(METADATA_ARRAY_SIGNATURE_TYPEHASH, metadatas, tokenId, nonces[owner], deadline)),
            owner,
            deadline,
            signature
        );

        for (uint256 i = 0; i < encryptedCIDs.length; i++) {
            emit ContentStoredWithMetadata(msg.sender, tokenId, encryptedCIDs[i], areCIDsEncrypted, metadatas[i], true);
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
    //           View Helpers        //
    // ----------------------------- //

    /// @notice Checks if a vault exists
    /// @param tokenId The vault identifier
    /// @return bool indicating if the vault exists
    function vaultExists(uint256 tokenId) public view returns (bool) {
        return vaults[tokenId].owner != address(0);
    }

    /// @notice Gets the owner of a vault
    /// @param tokenId The vault identifier
    /// @return The owner's address
    function getVaultOwner(uint256 tokenId) public view returns (address) {
        return vaults[tokenId].owner;
    }

    /// @notice Gets the permission level for a user in a vault
    /// @param tokenId The vault identifier
    /// @param user The user's address
    /// @return The permission level
    function getPermission(uint256 tokenId, address user) public view returns (uint8) {
        return permissions[tokenId][user];
    }

    /// @notice Gets the current schema index for a vault
    /// @param tokenId The vault identifier
    /// @return The current schema index
    function getVaultSchemaIndex(uint256 tokenId) external view returns (uint256) {
        return vaults[tokenId].currentSchemaIndex;
    }

    function _verifySignature(bytes32 structHash, address owner, uint256 deadline, bytes calldata signature) internal {
        if (block.timestamp > deadline) revert SignatureExpired();

        // Create a digest of the full batch for EIP-712 signature
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ECDSA.recover(digest, signature);
        if (signer != owner) revert InvalidSignature();

        nonces[owner]++;
    }
}
