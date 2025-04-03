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

    // IPFS hash prefix
    string public constant IPFS_PREFIX_STRING = "ipfs://";
    bytes32 public constant IPFS_PREFIX = keccak256(abi.encodePacked(IPFS_PREFIX_STRING));
    bytes32 public constant IPFS_CID_PREFIX = keccak256(abi.encodePacked("Qm"));

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

    // Mapping of schemas: schemaIndex -> IPFS hash
    mapping(uint256 => string) public schemaHashes;

    // Mapping of deprecated schemas: schemaIndex -> bool
    mapping(uint256 => bool) public deprecatedSchemas;

    // Index of the last schema
    uint256 public lastSchemaIndex;

    // Mapping of nonces: address -> nonce
    mapping(address => uint256) public nonces;

    event SchemaSet(uint256 indexed index, string ipfsHash);
    event SchemaDeprecated(uint256 indexed index, string ipfsHash);
    event SchemaUpdated(uint256 indexed index, string oldHash, string newHash);

    /// @notice Gets the current nonce for an address
    /// @param owner The address to check
    /// @return The current nonce
    function getNonce(address owner) public view returns (uint256) {
        return nonces[owner];
    }

    /// @notice Sets a new schema for content validation
    /// @param ipfsHash The IPFS hash of the JSON schema
    function setSchema(string memory ipfsHash) external onlyOwner {
        if (!isValidIPFSHash(ipfsHash)) revert InvalidSchema();
        lastSchemaIndex++;
        schemaHashes[lastSchemaIndex] = ipfsHash;
        emit SchemaSet(lastSchemaIndex, ipfsHash);
    }

    /// @notice Updates an existing schema
    /// @param index The index of the schema to update
    /// @param newHash The new IPFS hash of the JSON schema
    function updateSchema(uint256 index, string memory newHash) external onlyOwner {
        if (index == 0 || index > lastSchemaIndex) revert InvalidSchemaIndex();
        if (!isValidIPFSHash(newHash)) revert InvalidSchema();
        if (deprecatedSchemas[index]) revert InvalidSchema();

        string memory oldHash = schemaHashes[index];
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
    function getSchema(uint256 index) public view returns (string memory) {
        if (index == 0 || index > lastSchemaIndex) revert InvalidSchemaIndex();
        return schemaHashes[index];
    }

    /// @notice Gets the current active schema
    /// @return The IPFS hash of the current schema
    function getCurrentSchema() public view returns (string memory) {
        return schemaHashes[lastSchemaIndex];
    }

    // ----------------------------- //
    //        Vault Management       //
    // ----------------------------- //

    // Mapping of vaults: tokenId -> metadata
    mapping(uint256 => VaultMetadata) public vaults;

    // Mapping of permissions: tokenId -> address -> permission
    mapping(uint256 => mapping(address => uint8)) public permissions;

    event VaultCreated(uint256 indexed tokenId, address indexed owner, string schemaHash);
    event VaultAccessGranted(address indexed to, uint256 indexed tokenId, uint8 permission);
    event VaultAccessRevoked(address indexed to, uint256 indexed tokenId);
    event PermissionUpgraded(address indexed user, uint256 indexed tokenId, uint8 newPermission);
    event ContentStoredWithMetadata(
        address indexed sender, uint256 indexed tokenId, string schemaHash, string ipfsHash, string metadata
    );
    event ContentBatchStored(address indexed sender, uint256 indexed tokenId, uint256 count);
    event VaultTransferred(uint256 indexed tokenId, address indexed from, address indexed to);

    error NotVaultOwner();
    error AlreadyHasToken();
    error NoWritePermission();
    error InvalidPermission();
    error CannotRevokeAccessToSelf();
    error NoAccessToRevoke();
    error InvalidSchema();
    error InvalidSchemaIndex();
    error VaultDoesNotExist();
    error InvalidUpgrade();
    error InvalidSignature();
    error SignatureExpired();
    error ZeroAddress();
    error EmptyArray();
    error InvalidIPFSHash();

    bytes32 public constant PERMISSION_GRANT_TYPEHASH =
        keccak256("PermissionGrant(address to,uint256 tokenId,uint8 permission,uint256 nonce,uint256 deadline)");
    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public immutable DOMAIN_SEPARATOR;

    EIP712Domain domain_separator_struct =
        EIP712Domain({name: "Vault", version: "1", chainId: block.chainid, verifyingContract: address(this)});

    constructor() ERC1155("") Ownable(msg.sender) EIP712("Vault", "1") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(abi.encodePacked(domain_separator_struct.name)),
                keccak256(abi.encodePacked(domain_separator_struct.version)),
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
    /// @param ipfsHash The IPFS hash of the content
    /// @param metadata The metadata associated with the content
    function storeContentWithMetadata(uint256 tokenId, string memory ipfsHash, string memory metadata) external {
        if (deprecatedSchemas[vaults[tokenId].currentSchemaIndex]) {
            revert InvalidSchema();
        }
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }
        if (!isValidIPFSHash(ipfsHash)) revert InvalidIPFSHash();
        if (bytes(metadata).length == 0) revert InvalidSchema();

        emit ContentStoredWithMetadata(
            msg.sender, tokenId, schemaHashes[vaults[tokenId].currentSchemaIndex], ipfsHash, metadata
        );
    }

    /// @notice Stores multiple content items with metadata in a vault
    /// @param tokenId The vault identifier
    /// @param ipfsHashes Array of IPFS hashes
    /// @param metadatas Array of metadata strings
    function storeContentBatch(uint256 tokenId, string[] memory ipfsHashes, string[] memory metadatas) external {
        if (permissions[tokenId][msg.sender] != PERMISSION_WRITE) {
            revert NoWritePermission();
        }
        if (ipfsHashes.length == 0 || metadatas.length == 0) {
            revert EmptyArray();
        }
        if (ipfsHashes.length != metadatas.length) revert InvalidSchema();

        uint256 schemaIndex = vaults[tokenId].currentSchemaIndex;
        string memory schemaHash = schemaHashes[schemaIndex];

        for (uint256 i = 0; i < ipfsHashes.length; ++i) {
            if (!isValidIPFSHash(ipfsHashes[i])) revert InvalidIPFSHash();
            if (bytes(metadatas[i]).length == 0) revert InvalidSchema();

            emit ContentStoredWithMetadata(msg.sender, tokenId, schemaHash, ipfsHashes[i], metadatas[i]);
        }

        emit ContentBatchStored(msg.sender, tokenId, ipfsHashes.length);
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

    /// @notice Validates if a string is a valid IPFS hash
    /// @param hash The hash to validate
    /// @return bool indicating if the hash is valid
    function isValidIPFSHash(string memory hash) public pure returns (bool) {
        bytes memory hashBytes = bytes(hash);
        if (hashBytes.length < 7) return false; // Minimum length for "ipfs://"

        // Check for "ipfs://" prefix
        bytes memory prefixBytes = bytes(IPFS_PREFIX_STRING);
        for (uint256 i = 0; i < 7; i++) {
            if (hashBytes[i] != prefixBytes[i]) return false;
        }

        // Check for CID prefix (Qm)
        if (hashBytes.length < 9) return false;
        if (hashBytes[7] != "Q" || hashBytes[8] != "m") return false;

        // Check that the rest of the string is not empty
        return hashBytes.length > 9;
    }
}
