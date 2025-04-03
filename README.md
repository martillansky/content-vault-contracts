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
- Minimum 90% code coverage requirement
- Coverage reports generated in CI pipeline
- Gas optimization tracking via `.gas-snapshot`

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
yarn lint        # Run linting (format + build)
yarn clean       # Clean build artifacts

# Deployment (requires RPC_URL environment variable)
# Example: RPC_URL=https://eth-mainnet.g.alchemy.com/v2/your-api-key yarn deploy
yarn deploy      # Deploy to network
```

### Direct Forge Commands

You can also run Forge commands directly:

```bash
forge test -vvv
forge test -vvv --coverage
forge snapshot
forge build
forge fmt
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
RPC_URL_MAINNET=https://eth-mainnet.g.alchemy.com/v2/your-api-key
RPC_URL_SEPOLIA=https://eth-sepolia.g.alchemy.com/v2/your-api-key

# Deployer private key (without 0x prefix)
PRIVATE_KEY=your_private_key_here
```

### Deployment Commands

Deploy to different networks using:

```bash
# Deploy to Sepolia testnet
forge script script/Vault.s.sol:VaultScript --rpc-url $RPC_URL_SEPOLIA --broadcast

# Deploy to mainnet
forge script script/Vault.s.sol:VaultScript --rpc-url $RPC_URL_MAINNET --broadcast
```

Or using yarn:

```bash
# Deploy to Sepolia testnet
RPC_URL=$RPC_URL_SEPOLIA yarn deploy

# Deploy to mainnet
RPC_URL=$RPC_URL_MAINNET yarn deploy
```

### Verification

After deployment, verify the contract on Etherscan:

```bash
forge verify-contract <DEPLOYED_ADDRESS> Vault --chain-id <CHAIN_ID>
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

Run commands:

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
