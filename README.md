# 🧱 Vault Smart Contract

A tokenized, permissioned content vault system built on **ERC1155** and **EIP-712**, designed for secure content sharing, schema evolution, and flexible access control.

---

## 👤 Author

- [Martin Moguillansky](https://github.com/martillansky)

---

## 🌟 Objectives

- **Token-Gated Storage**: Each vault is represented by an ERC1155 token (`tokenId`). Ownership grants access.
- **Permission Control**: Vault owners can grant `READ` or `WRITE` permissions to others.
- **Schema-Aware Content**: Vaults are schema-bound, allowing content validation and versioning.
- **Off-Chain Signatures**: Uses EIP-712 for gasless permission granting via signed messages.
- **Indexing-Friendly Events**: Emits detailed events for content storage and schema lifecycle.

---

## 🏗️ Technology Design

### ✅ ERC1155 Token Standard

- Each vault is represented by a `tokenId`.
- Multiple users can share access to the same vault via token balance.

### ✅ EIP-712 Typed Signatures

- Vault owners can grant access to others using signed messages.
- Replay protection via nonces.
- Expiry protection via `deadline`.

### ✅ Schema Versioning

- Vaults reference a schema index (e.g., an IPFS hash of a JSON schema).
- Schemas cannot be updated or deprecated once set.

### ✅ Access Permissions

- `PERMISSION_NONE = 0`: No access
- `PERMISSION_READ = 1`: Can read content
- `PERMISSION_WRITE = 2`: Can read and write content
- Stored per `tokenId` + `user` in the `permissions` mapping.

### ✅ Content Storage

- Content is stored as encrypted CIDs (Content Identifiers)
- The `isCIDEncrypted` flag indicates whether the CID is encrypted
- Metadata is stored as strings that conform to the vault's schema
- Metadata can be signed using EIP-712 signatures

### ✅ Events for Indexing

- `VaultCreated(uint256 indexed tokenId, address indexed owner, string schemaCID)`
- `VaultAccessGranted(address indexed to, uint256 indexed tokenId, uint8 permission)`
- `VaultAccessRevoked(address indexed to, uint256 indexed tokenId)`
- `PermissionUpgraded(address indexed user, uint256 indexed tokenId, uint8 newPermission)`
- `ContentStoredWithMetadata(address indexed sender, uint256 indexed tokenId, bytes encryptedCID, bool isCIDEncrypted, string metadata, bool isMetadataSigned)`
- `VaultTransferred(uint256 indexed tokenId, address indexed from, address indexed to)`
- `SchemaSet(uint256 indexed index, string schemaCID)`
- `URI(string value, uint256 indexed id)`

### ✅ Testing & Coverage

- Comprehensive test suite using Foundry
- Current coverage metrics:
  - Lines: 85.71% (108/126)
  - Statements: 81.21% (121/149)
  - Branches: 64.86% (24/37)
  - Functions: 95.45% (21/22)
- Coverage reports generated in CI pipeline
- Gas optimization tracking via `.gas-snapshot`

### ✅ Error Handling

The contract implements custom errors for better gas efficiency and clearer error messages:

| Error Selector               | Description                                         |
| ---------------------------- | --------------------------------------------------- |
| `NotVaultOwner()`            | Caller is not the vault owner                       |
| `AlreadyHasToken()`          | Address already has access to the vault             |
| `NoWritePermission()`        | Caller lacks write permission                       |
| `InvalidPermission()`        | Invalid permission level specified                  |
| `CannotRevokeAccessToSelf()` | Attempted to revoke own access                      |
| `NoAccessToRevoke()`         | Attempted to revoke access from user without access |
| `InvalidSchemaIndex()`       | Invalid schema index provided                       |
| `MismatchedArrayLengths()`   | Array length mismatch in batch operations           |
| `VaultDoesNotExist()`        | Vault doesn't exist                                 |
| `InvalidUpgrade()`           | Invalid permission upgrade attempt                  |
| `InvalidSignature()`         | Invalid EIP-712 signature                           |
| `SignatureExpired()`         | Signature has expired                               |
| `ZeroAddress()`              | Zero address provided                               |
| `EmptyArray()`               | Empty array provided for batch operations           |
| `NoSchema()`                 | No schema has been set                              |

---

## 🔐 Key Functions

### Schema Management

- `setSchema(string schemaCID)`: Set a new schema (owner only)
- `getSchema(uint256 index)`: Get schema by index
- `getCurrentSchema()`: Get current active schema

### Vault Management

- `createVault(uint256 tokenId)`: Create a new vault
- `transferVaultOwnership(uint256 tokenId, address newOwner)`: Transfer vault ownership
- `vaultExists(uint256 tokenId)`: Check if vault exists
- `getVaultOwner(uint256 tokenId)`: Get vault owner
- `getVaultSchemaIndex(uint256 tokenId)`: Get vault's schema index

### Permission Management

- `grantAccess(address to, uint256 tokenId, uint8 permission)`: Grant access
- `grantAccessWithSignature(address to, uint256 tokenId, uint8 permission, uint256 deadline, bytes signature)`: Grant access with EIP-712 signature
- `revokeAccess(uint256 tokenId, address to)`: Revoke access
- `upgradePermission(uint256 tokenId, address user, uint8 newPermission)`: Upgrade permission level
- `getPermission(uint256 tokenId, address user)`: Get user's permission level

### Content Management

- `storeContentWithMetadata(uint256 tokenId, bytes encryptedCID, bool isCIDEncrypted, string metadata)`: Store content with metadata
- `storeContentWithMetadataSigned(uint256 tokenId, bytes encryptedCID, bool isCIDEncrypted, string metadata, uint256 deadline, bytes signature)`: Store content with signed metadata
- `storeContentBatch(uint256 tokenId, bytes[] encryptedCIDs, bool areCIDsEncrypted, string[] metadatas)`: Store multiple content items
- `storeContentBatchWithSignature(uint256 tokenId, bytes[] encryptedCIDs, bool areCIDsEncrypted, string[] metadatas, uint256 deadline, bytes signature)`: Store multiple content items with signed metadata

### URI Management

- `setURI(string newuri)`: Set a new base URI for ERC1155 metadata

### Helper Functions

- `getNonce(address owner)`: Get the current nonce for an address

---

## 🛠 Example Usage

### Create a Vault

```solidity
vault.createVault(1); // Creates vault with tokenId = 1
```

### Grant Access

```solidity
vault.grantAccess(user, 1, PERMISSION_WRITE);
```

### Grant Access with Signature (EIP-712)

```typescript
const message = {
  to: user,
  tokenId: 1,
  permission: PERMISSION_WRITE,
  nonce: await vault.getNonce(owner),
  deadline: Math.floor(Date.now() / 1000) + 3600,
};

const signature = await signer._signTypedData(domain, types, message);
await vault.grantAccessWithSignature(
  user,
  1,
  PERMISSION_WRITE,
  message.deadline,
  signature
);
```

### Store Content

```solidity
vault.storeContentWithMetadata(
  1,                    // tokenId
  encryptedCID,         // encrypted content identifier
  true,                 // isCIDEncrypted
  "metadata"            // metadata string
);
```

### Store Content with Signature

```typescript
const message = {
  metadata: "metadata",
  tokenId: 1,
  nonce: await vault.getNonce(owner),
  deadline: Math.floor(Date.now() / 1000) + 3600,
};

const signature = await signer._signTypedData(domain, types, message);
await vault.storeContentWithMetadataSigned(
  1, // tokenId
  encryptedCID, // encrypted content identifier
  true, // isCIDEncrypted
  "metadata", // metadata string
  message.deadline, // deadline
  signature // EIP-712 signature
);
```

### Store Batch Content

```solidity
bytes[] memory cids = new bytes[](2);
cids[0] = bytes("encryptedCID1");
cids[1] = bytes("encryptedCID2");

string[] memory metadatas = new string[](2);
metadatas[0] = "metadata1";
metadatas[1] = "metadata2";

vault.storeContentBatch(1, cids, true, metadatas);
```

### Store Batch Content with Signature

```typescript
const metadatas = ["metadata1", "metadata2"];

const message = {
  metadatas: metadatas,
  tokenId: 1,
  nonce: await vault.getNonce(owner),
  deadline: Math.floor(Date.now() / 1000) + 3600,
};

const signature = await signer._signTypedData(domain, types, message);
await vault.storeContentBatchWithSignature(
  1, // tokenId
  cids, // encrypted content identifiers
  true, // areCIDsEncrypted
  metadatas, // metadata strings
  message.deadline, // deadline
  signature // EIP-712 signature
);
```

### Transfer Vault Ownership

```solidity
vault.transferVaultOwnership(1, newOwner);
```

---

## 🛠 Development Commands

### Using Yarn (Recommended)

```bash
# Install dependencies
yarn install

# Testing
yarn test           # Run tests
yarn test:coverage  # Run tests with coverage
yarn test:gas      # Generate gas snapshot
yarn test:gas:diff # Show gas differences

# Development
yarn build        # Build the project
yarn fmt         # Format code
yarn fmt:check   # Check formatting
yarn clean       # Clean build artifacts

# Deployment and Verification
yarn deploy:sepolia  # Deploy to Sepolia
yarn deploy:mainnet # Deploy to Mainnet
yarn verify:sepolia # Verify on Sepolia
yarn verify:mainnet # Verify on Mainnet
```

---

## ✅ Pre-Push Checklist

Before pushing changes, run these commands in order:

```bash
# 1. Clean and build
yarn clean
yarn build

# 2. Run tests with coverage
yarn test:coverage

# 3. Check formatting
yarn fmt:check

# 4. Generate gas snapshot
yarn test:gas
```

All commands should pass without errors. The CI pipeline will run these checks as well.

---

## 🌐 Network Configuration

### Environment Variables

Create a `.env` file in the root directory:

```bash
# Network RPC URLs
RPC_URL_SEPOLIA=https://eth-sepolia.g.alchemy.com/v2/your-api-key
RPC_URL_MAINNET=https://eth-mainnet.g.alchemy.com/v2/your-api-key

# Contract addresses (after deployment)
VAULT_ADDRESS_SEPOLIA=0x...
VAULT_ADDRESS_MAINNET=0x...

# Etherscan API key for verification
ETHERSCAN_API_KEY=your_etherscan_api_key

# Deployer private key
PRIVATE_KEY=your_private_key_here
```

### Deployment and Verification

Deploy and verify using yarn commands:

```bash
# Deploy to Sepolia testnet
yarn deploy:sepolia

# Deploy to mainnet
yarn deploy:mainnet

# Verify on Sepolia
yarn verify:sepolia

# Verify on mainnet
yarn verify:mainnet
```

---

## 📚 Developer Notes

- Use `getVaultOwner(tokenId)` to determine the vault creator.
- Use `permissions[tokenId][user]` to check user access.
- Use `getNonce(owner)` to retrieve the current nonce for signature replay protection.
- All `storeContent*` functions require `PERMISSION_WRITE`.
- Schemas cannot be updated or deprecated once set.
- Content CIDs can be encrypted (specified by `isCIDEncrypted` flag).
- Metadata must conform to the vault's schema.

---

## 📜 License

This project is licensed under the **Elastic License 2.0**.You may use, modify, and share this code for **non-commercial purposes**.Commercial use requires a commercial license from the author.

See the [LICENSE](./LICENSE) file for more details.

---

## 💧 Foundry Developer Tools

This project uses [Foundry](https://book.getfoundry.sh/) for Solidity development.

You can also run Forge commands directly:

```bash
forge build         # compile
forge test          # run tests
forge snapshot      # run gas snapshots
forge fmt           # format
anvil               # local testnet
```

See [`README-Foundry.md`](./README-Foundry.md) for full CLI reference.

---

## ⚡️ Gas Snapshot Tracking

We track gas usage using `forge snapshot` and enforce stability across commits.

### CI Diff Check

The `gas.yml` GitHub Action runs on each push and pull request. If gas usage changes, the workflow will fail.

To update the snapshot manually:

```bash
forge snapshot
git add .gas-snapshot
git commit -m "Update gas snapshot"
```
