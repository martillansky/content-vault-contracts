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
- Schemas can be **deprecated** to block new content submissions against outdated formats.

### ✅ Access Permissions

- `PERMISSION_READ = 1`
- `PERMISSION_WRITE = 2`
- Stored per `tokenId` + `user` in the `permissions` mapping.

### ✅ Events for Indexing

- `VaultCreated`, `ContentStoredWithMetadata`, `ContentBatchStored`, etc.
- Designed for integration with **The Graph** or other off-chain data consumers.

### ✅ Testing & Coverage

- Comprehensive test suite using Foundry
- Current coverage metrics:
  - Lines: 78.68% (107/136)
  - Statements: 74.27% (127/171)
  - Branches: 48.78% (20/41)
  - Functions: 73.91% (17/23)
- Coverage reports generated in CI pipeline
- Gas optimization tracking via `.gas-snapshot`

### ✅ Error Handling

The contract implements custom errors for better gas efficiency and clearer error messages:

| Error Selector             | Description                                               |
| -------------------------- | --------------------------------------------------------- |
| `ZeroAddress`              | Attempted to use the zero address                         |
| `VaultDoesNotExist`        | Operation on a non-existent vault                         |
| `VaultAlreadyExists`       | Attempted to create a vault that already exists           |
| `NoWritePermission`        | Operation requiring write permission attempted without it |
| `InvalidPermission`        | Attempted to grant an invalid permission value            |
| `InvalidIPFSHash`          | Provided IPFS hash is invalid                             |
| `InvalidSchema`            | Schema validation failed                                  |
| `CannotRevokeAccessToSelf` | Attempted to revoke own access                            |
| `AlreadyHasToken`          | User already has access to the vault                      |
| `InvalidUpgrade`           | Invalid permission upgrade attempt                        |
| `InvalidNonce`             | Invalid nonce in signature verification                   |
| `SignatureExpired`         | Signature past its deadline                               |
| `InvalidSignature`         | Signature verification failed                             |

---

## 🔐 Key Functions

| Function                               | Description                                                |
| -------------------------------------- | ---------------------------------------------------------- |
| `createVault(tokenId)`                 | Mints a new vault using the current schema.                |
| `grantAccess(to, tokenId, permission)` | Grants direct access by the vault owner.                   |
| `grantAccessWithSignature(...)`        | EIP-712-based gasless access granting via signed messages. |
| `revokeAccess(tokenId, to)`            | Revokes access and burns token from `to`.                  |
| `upgradePermission(tokenId, user)`     | Upgrades `READ` to `WRITE` for a user.                     |
| `storeContentWithMetadata(...)`        | Stores a content hash + metadata in the vault.             |
| `storeContentBatch(...)`               | Batched version for gas optimization.                      |
| `deprecateSchema(index)`               | Marks a schema as deprecated.                              |
| `setURI(newUri)`                       | Updates ERC1155 base metadata URI.                         |

---

## 🛠 Example Usage

### Create a Vault

```solidity
vault.createVault(1); // tokenId = 1
```

### Grant Write Access

```solidity
vault.grantAccess(user, 1, PERMISSION_WRITE);
```

### Grant Access with Signature (EIP-712)

```typescript
const message = {
  to: user,
  tokenId: 1,
  permission: 2, // write
  nonce: await vault.getNonce(owner),
  deadline: Math.floor(Date.now() / 1000) + 3600,
};

const signature = await signer._signTypedData(domain, types, message);
await vault.grantAccessWithSignature(user, 1, 2, message.deadline, signature);
```

### Store Content

```solidity
vault.storeContentWithMetadata(1, "ipfs://Qm...", '{"title":"example"}');
```

### Store Batch Content

```solidity
string[] memory hashes = new string[](3);
string[] memory metas = new string[](3);
for (uint256 i = 0; i < 3; i++) {
    hashes[i] = "ipfs://Qm...";
    metas[i] = '{"title":"example"}';
}
vault.storeContentBatch(1, hashes, metas);
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
