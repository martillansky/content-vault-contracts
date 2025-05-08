# 🦋 Libélula: Decentralized Content Vaults

Libélula is a tokenized, permissioned content vault protocol built on **ERC-1155** and **EIP-712**, designed to enable secure content sharing, decentralized curation, and DAO-driven monetization — with seamless **cross-chain access control**.

---

## 🔧 Features

- **Token-Gated Vaults** via ERC-1155 tokens
- **Fine-Grained Permissions**: `READ` / `WRITE`
- **EIP-712 Gasless Signatures**
- **Schema-Aware Metadata** (IPFS CIDs)
- **Cross-Chain Access** via token ownership on foreign chains
- **Snapshot DAO integration**
- **Indexing-friendly events** for The Graph
- **Modular and upgrade-ready**

---

## 🧩 Key Components

### 🧱 Vault Contract

- ERC-1155 token represents vault access
- Permissions stored per `tokenId` and `user`
- Off-chain metadata stored via encrypted CIDs
- Uses EIP-712 signatures to grant access

### 🧠 SchemaManager

- Manages immutable schema CIDs per vault
- Vaults must opt into a schema on creation
- Supports versioning and off-chain schema validation

### 🧑‍⚖️ ProposalVaultManager

- Creates vaults tied to off-chain proposals
- Allows pinning/unpinning vaults by contributors
- Stores proposal–vault mapping and emits structured events

### 🔗 Cross-Chain Access

- **MasterCrosschainGranter** (Ethereum/Gnosis Home Chains)

  - Checks user balance of strategy token
  - Relays permission upgrade request via bridge

- **ForeignCrosschainGranter** (e.g. Gnosis Chiado)

  - Validates token balance locally
  - Sends message to Vault home chain via bridge

- **MasterGateway / ForeignGateway**
  - Secure, permissioned message routers
  - Integrated with AMB-style bridges (e.g., Gnosis Bridge)

---

## 🧪 Testnet Deployments

| Contract                 | Sepolia Testnet                                                                                                                 | Chiado Testnet (Gnosis)                                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Vault                    | [`0xA4556112a1847F4B8bfc9D2B55F34A2638f4188E`](https://sepolia.etherscan.io/address/0xA4556112a1847F4B8bfc9D2B55F34A2638f4188E) | `—`                                                                                                                                     |
| SchemaManager            | [`0x1cB1c91C8cF2E12Ea2BeEb5D952FF29123f04Caf`](https://sepolia.etherscan.io/address/0x1cB1c91C8cF2E12Ea2BeEb5D952FF29123f04Caf) | `—`                                                                                                                                     |
| ProposalVaultManager     | [`0x16D8fec0c6D2831a0F54BB468191587f6F2cd8Bd`](https://sepolia.etherscan.io/address/0x16D8fec0c6D2831a0F54BB468191587f6F2cd8Bd) | `—`                                                                                                                                     |
| MasterCrosschainGranter  | [`0x3ee5516B43d02cAD3aE2859892aB7c8A5648B819`](https://sepolia.etherscan.io/address/0x3ee5516B43d02cAD3aE2859892aB7c8A5648B819) | `—`                                                                                                                                     |
| MasterGateway            | [`0x46843BAa2cc929088d475eE7F10426B50BAE2E6b`](https://sepolia.etherscan.io/address/0x46843baa2cc929088d475ee7f10426b50bae2e6b) | `—`                                                                                                                                     |
| ForeignCrosschainGranter | `—`                                                                                                                             | [`0xF184708c885d00a8b1C0Ab5288f2ee9f7a9d5531`](https://gnosis-chiado.blockscout.com/address/0xF184708c885d00a8b1C0Ab5288f2ee9f7a9d5531) |
| ForeignGateway           | `—`                                                                                                                             | [`0x00f450cB1CAc375E4257E22AD30Faf08d46f0f85`](https://gnosis-chiado.blockscout.com/address/0x00f450cB1CAc375E4257E22AD30Faf08d46f0f85) |

---

## 🧭 Use Case: DAO-Funded Curation & Vault Monetization

### 📖 Narrative

Libélula enables **DAOs to fund vaults** and use Snapshot to **curate content collaboratively**.

1. A DAO creates and funds a new vault.
2. A Snapshot proposal is linked to the vault.
3. DAO members vote to **rank** the vault’s content.
4. Contributors whose submissions rank above a threshold receive **a share of the DAO’s funding**.
5. The DAO benefits from curated knowledge, and contributors are rewarded fairly.

### 📰 Example

A DAO sponsors a special issue of a decentralized magazine by funding a vault titled:

> "**[DAO Name] Special Issue on MEV Governance**"

The DAO sets a vault funding pool (e.g., 10 ETH). Contributors submit research, models, or arguments. After voting, the top-ranked submissions (e.g., top 5) share the prize.

This mechanism creates **aligned incentives**, **high-quality outputs**, and **on-chain traceability** of intellectual collaboration.

---

## 🪙 Token-Based Access Example

| Vault ID | Chain    | Token Address                                                  | Min Balance | Permission |
| -------- | -------- | -------------------------------------------------------------- | ----------- | ---------- |
| 40       | Polygon  | `0xD6DF932A45C0f255f85145f286eA0b292B21C90B`                   | 10 AAVE     | `WRITE`    |
| 72       | Arbitrum | `0xABC...` (NFT)                                               | 1           | `READ`     |
| 87       | Gnosis   | `0xDCA67FD8324990792C0bfaE95903B8A64097754F` (CHAINLINK TOKEN) | 1 LINK      | `READ`     |
| 99       | Gnosis   | `0xABC...` (GNO)                                               | 1           | `WRITE`    |

- Note:
  - we are currently live on testnets, Sepolia and Chiado. The project includes crosschain token-gated capability from Polygon, Arbitrum and Gnosis to Ethereum (Libélula's home-chain).

---

## 📡 Cross-Chain Permission Flow

```plaintext
User (on Mainnet)
     │
[Requests access to Vault linked to AAVE Snapshot Proposal]
     ▼
ProposalVaultManager
     │           │
     │    [Mints access token]
     │           ▼
     │     Vault.sol (Ethereum)
     │           │
     │    [Sets READ permission]
     ▼
MasterCrosschainGranter + MasterGateway
     │
[Requests crosschain state update]
     │
ForeignCrosschainGranter + Foreign Gateway (Polygon)
     │
Map → proposalId + vaultId + tokenAdress


User (on Polygon)
     │
[Request Write Access to Vault]
     ▼
ForeignCrosschainGranter + Foreign Gateway (Polygon)
     │
[Balance Check: AAVE >= 10]
     ▼
Bridge → Message → Ethereum
     │
MasterCrosschainGranter + MasterGateway
     ▼
ProposalVaultManager
     ▼
Vault.sol (Ethereum)
     │
[Sets WRITE permission]
```

---

## 🔬 Crosschain Architecture Overview

```
                                           ┌────────────────────────────┐
                                           │     Frontend / Snapshot    │
                                           └────────────┬───────────────┘
                                                        │
                                                        ▼
┌────────────────────────────────┐         ┌───────────────────────────────┐
│       Foreign Gateway          │   AMB   │        Master Gateway         │
│  + Foreign CrosschainGranter   │◄───────►│   + Master CrosschainGranter  │
└────────────────────────────────┘         └───────────────────────────────┘
        │                                                 │
        ▼                                                 ▼
 Token contract                                  ProposalVaultManager
 (ERC20 or NFT)                                Vault.sol + SchemaManager

```

---

## 🧠 Technical Highlights

- Fully modular contracts

- Gas-efficient EIP-712 signature processing

- Native ERC-1155 for composability

- Support for encrypted and signed content

- Extensive events for subgraph indexing

- On-chain replay protection for signed messages

---

## 📜 License

This project is licensed under the **Elastic License 2.0**. You may use, modify, and share this code for **non-commercial purposes**. Commercial use requires a commercial license from the author.

See the [LICENSE](./LICENSE) file for more details.

---

## 👤 Author

- [Martin Moguillansky](https://github.com/martillansky)

---

## 🤝 Want to Contribute / Support?

Reach me out through this repo
