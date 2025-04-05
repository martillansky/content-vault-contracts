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

    // Mapping of schemas: schemaIndex -> CID hash to the JSON schema
    mapping(uint256 => bytes32) public schemaHashes;

    // Mapping of deprecated schemas: schemaIndex -> bool
    mapping(uint256 => bool) public deprecatedSchemas;

    // Index of the last schema
    uint256 public lastSchemaIndex;

    // Mapping of nonces: address -> nonce
    mapping(address => uint256) public nonces;

    event SchemaSet(uint256 indexed index, bytes32 schemaHash);
    event SchemaDeprecated(uint256 indexed index, bytes32 schemaHash);
    event SchemaUpdated(uint256 indexed index, bytes32 oldHash, bytes32 newHash);

    /// @notice Gets the current nonce for an address
    /// @param owner The address to check
    /// @return The current nonce
    function getNonce(address owner) public view returns (uint256) {
        return nonces[owner];
    }

    /// @notice Sets a new schema for content validation
    /// @param schemaHash The CID hash of the JSON schema
    function setSchema(bytes32 schemaHash) external onlyOwner {
        lastSchemaIndex++;
        schemaHashes[lastSchemaIndex] = schemaHash;
        emit SchemaSet(lastSchemaIndex, schemaHash);
    }

    /// @notice Updates an existing schema
    /// @param index The index of the schema hash to update
    /// @param newHash The new CID hash of the JSON schema
    function updateSchema(uint256 index, bytes32 newHash) external onlyOwner {
        if (index == 0 || index > lastSchemaIndex) revert InvalidSchemaIndex();
        if (deprecatedSchemas[index]) revert InvalidSchema();

        bytes32 oldHash = schemaHashes[index];
        schemaHashes[index] = newHash;
        emit SchemaUpdated(index, oldHash, newHash);
    }

    /// @notice Deprecates a schema, preventing its use in new content
    /// @param index The index of the schema to deprecate
    function deprecateSchema(uint256 index) external onlyOwner {
        if (index == 0 || index > lastSchemaIndex) revert InvalidSchemaIndex();
        deprecatedSchemas[index] = true;
        emit SchemaDeprecated(index, schemaHashes[index]);
    }

    /// @notice Retrieves a schema by its index
    /// @param index The index of the schema to retrieve
    /// @return The IPFS hash of the schema
    function getSchema(uint256 index) public view returns (bytes32) {
        if (index == 0 || index > lastSchemaIndex) revert InvalidSchemaIndex();
        return schemaHashes[index];
    }

    /// @notice Gets the current active schema
    /// @return The IPFS hash of the current schema
    function getCurrentSchema() public view returns (bytes32) {
        return schemaHashes[lastSchemaIndex];
    }

    // ----------------------------- //
    //        Vault Management       //
    // ----------------------------- //

    // Mapping of vaults: tokenId -> metadata
    mapping(uint256 => VaultMetadata) public vaults;

    // Mapping of permissions: tokenId -> address -> permission
    mapping(uint256 => mapping(address => uint8)) public permissions;

    event VaultCreated(uint256 indexed tokenId, address indexed owner, bytes32 schemaHash);
    event VaultAccessGranted(address indexed to, uint256 indexed tokenId, uint8 permission);
    event VaultAccessRevoked(address indexed to, uint256 indexed tokenId);
    event PermissionUpgraded(address indexed user, uint256 indexed tokenId, uint8 newPermission);
    event ContentStoredWithMetadata(
        address indexed sender, uint256 indexed tokenId, bytes32 ipfsHash, bytes32 metadataHash
    );
    event VaultTransferred(uint256 indexed tokenId, address indexed from, address indexed to);

    error NotVaultOwner();
    error AlreadyHasToken();
    error NoWritePermission();
    error InvalidPermission();
    error CannotRevokeAccessToSelf();
    error NoAccessToRevoke();
    error InvalidSchema();
    error InvalidSchemaIndex();
    error MismatchedArrayLengths();
    error VaultDoesNotExist();
    error InvalidUpgrade();
    error InvalidSignature();
    error SignatureExpired();
    error ZeroAddress();
    error EmptyArray();

    bytes32 internal constant METADATA_SIGNATURE_TYPEHASH =
        keccak256("MetadataHash(bytes32 metadataHash,uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 internal constant METADATA_ARRAY_SIGNATURE_TYPEHASH =
        keccak256("MetadataArrayHash(bytes32[] metadataHashes,uint256 tokenId,uint256 nonce,uint256 deadline)");
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
    function createVault(uint256 tokenId) external {
        uint256 schemaIndex = lastSchemaIndex;
        if (deprecatedSchemas[schemaIndex]) revert InvalidSchema();
        if (vaults[tokenId].owner != address(0)) revert AlreadyHasToken();

        _mint(msg.sender, tokenId, 1, "");

        vaults[tokenId] = VaultMetadata({owner: msg.sender, currentSchemaIndex: schemaIndex});
        permissions[tokenId][msg.sender] = PERMISSION_WRITE;

        emit VaultCreated(tokenId, msg.sender, schemaHashes[schemaIndex]);
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
        if (block.timestamp > deadline) revert SignatureExpired();

        // Get the current nonce for signature verification
        uint256 nonce = nonces[owner];

        bytes32 structHash = keccak256(abi.encode(PERMISSION_GRANT_TYPEHASH, to, tokenId, permission, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ECDSA.recover(digest, signature);

        if (signer != owner) revert InvalidSignature();

        // Only update nonce after successful signature verification
        nonces[owner]++;

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
    /// @param cidHash The CID hash of the content
    /// @param metadataHash The hash of the metadata associated with the content
    function storeContentWithMetadata(uint256 tokenId, bytes32 cidHash, bytes32 metadataHash) external {
        if (deprecatedSchemas[vaults[tokenId].currentSchemaIndex]) {
            revert InvalidSchema();
        }
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }
        emit ContentStoredWithMetadata(msg.sender, tokenId, cidHash, metadataHash);
    }

    /// @notice Stores multiple content items with metadata in a vault
    /// @param tokenId The vault identifier
    /// @param cidHashes Array of CID hashes
    /// @param metadataHashes Array of metadata hashes
    function storeContentBatch(uint256 tokenId, bytes32[] calldata cidHashes, bytes32[] memory metadataHashes)
        external
    {
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }
        if (cidHashes.length == 0 || metadataHashes.length == 0) {
            revert EmptyArray();
        }
        if (cidHashes.length != metadataHashes.length) {
            revert MismatchedArrayLengths();
        }

        for (uint256 i = 0; i < cidHashes.length; ++i) {
            emit ContentStoredWithMetadata(msg.sender, tokenId, cidHashes[i], metadataHashes[i]);
        }
    }

    /// @notice Stores content with metadata and EIP-712 signature
    /// @param tokenId The vault identifier
    /// @param cidHash The (private) cid hash to the content
    /// @param metadataHash The signed metadata hash associated with the content
    /// @param deadline The deadline for the signature
    /// @param signature The EIP-712 signature
    function storeContentWithMetadataSigned(
        uint256 tokenId,
        bytes32 cidHash,
        bytes32 metadataHash,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (deprecatedSchemas[vaults[tokenId].currentSchemaIndex]) {
            revert InvalidSchema();
        }
        if (block.timestamp > deadline) revert SignatureExpired();

        address owner = vaults[tokenId].owner;
        if (owner == address(0)) revert VaultDoesNotExist();
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }

        uint256 nonce = nonces[owner];

        bytes32 structHash = keccak256(abi.encode(METADATA_SIGNATURE_TYPEHASH, metadataHash, tokenId, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ECDSA.recover(digest, signature);
        if (signer != owner) revert InvalidSignature();

        nonces[owner]++;

        emit ContentStoredWithMetadata(msg.sender, tokenId, cidHash, metadataHash);
    }

    /// @notice Stores content with metadata and EIP-712 signature
    /// @param tokenId The vault identifier
    /// @param cidHashes The (private) cid hashes to the contents
    /// @param metadataHashes The signed metadata hashes associated with the contents
    /// @param deadline The deadline for the signature
    /// @param signature The EIP-712 signature
    function storeContentBatchWithSignature(
        uint256 tokenId,
        bytes32[] calldata cidHashes,
        bytes32[] calldata metadataHashes,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (deprecatedSchemas[vaults[tokenId].currentSchemaIndex]) {
            revert InvalidSchema();
        }
        if (block.timestamp > deadline) revert SignatureExpired();
        address owner = vaults[tokenId].owner;
        if (owner == address(0)) revert VaultDoesNotExist();
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }
        if (cidHashes.length == 0 || metadataHashes.length == 0) {
            revert EmptyArray();
        }
        if (cidHashes.length != metadataHashes.length) {
            revert MismatchedArrayLengths();
        }

        // Create a digest of the full batch for EIP-712 signature
        uint256 nonce = nonces[owner];

        bytes32 structHash =
            keccak256(abi.encode(METADATA_ARRAY_SIGNATURE_TYPEHASH, metadataHashes, tokenId, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ECDSA.recover(digest, signature);
        if (signer != owner) revert InvalidSignature();

        nonces[owner]++;

        // Store content events (CID left empty or hashed elsewhere)
        for (uint256 i = 0; i < metadataHashes.length; i++) {
            emit ContentStoredWithMetadata(msg.sender, tokenId, cidHashes[i], metadataHashes[i]);
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
}
