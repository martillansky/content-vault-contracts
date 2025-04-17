# 🔩 Cross-Chain Access Control for Libélula Content Vaults

This document outlines a future extension to the **Libélula Vault protocol**, enabling decentralized access permissions based on token ownership across multiple blockchains. This upgrade facilitates dynamic, DAO-integrated content collaboration using vaults as gated content spaces.

---

## ✨ Motivation

As DAOs become more complex and distributed, access to resources — including gated content — must reflect governance dynamics that span multiple chains. This proposal enables vaults to grant permissions based on users’ token balances from other chains, aligned with DAO participation or reputation models.

---

## 🎯 Objective

Enable DAOs to configure vault access rights (read/write) for users holding governance tokens **on other chains**, without requiring those tokens to be bridged to the chain where the vault is deployed.

This enables decentralized content collaboration tied to real governance power across ecosystems.

---

## 🔐 Vault Access by Token Ownership

Each vault can specify two optional token access requirements:

| Permission | Token Address | Chain ID | Min Balance |
|------------|----------------|----------|-------------|
| `read`     | 0x...          | 137      | 1.5         |
| `write`    | 0x...          | 1        | 10          |

These rules are set at vault creation and reference token contracts on any supported EVM-compatible chain.

---

## 🏗️ Protocol Components

### 1. `Vault.sol` (Ethereum Mainnet)

- Maintains vault metadata and permission mappings.
- Delegates cross-chain token ownership verification.
- Stores per-vault token-based access rules.
- Mints ERC-1155 access tokens upon successful verification.

```solidity
enum PermissionLevel { None, Read, Write }

struct RemoteAccessRule {
  uint256 chainId;
  address tokenContract;
  uint256 minBalance;
  PermissionLevel permission;
}

mapping(uint256 => RemoteAccessRule[]) public vaultAccessRules;
mapping(uint256 => address) public accessGrantersByChain;
```

---

### 2. `MasterAccessGranter.sol` (Deployed Per Chain)

- Verifies if the caller owns a required token in sufficient quantity.
- Emits a secure message using an AMB (Arbitrary Message Bridge).
- Protects against replay attacks via unique nonces.

---

### 3. Cross-Chain Bridge

- Responsible for delivering access confirmations across chains.
- Ensures message integrity and authenticity (e.g., AMB, LayerZero, Axelar).

---

## ↺ Flow Example: AAVE Token on Polygon

A vault on Ethereum grants write access based on AAVE holdings on Polygon.

1. A user requests access via `requestAccess()` on `MasterAccessGranter` (Polygon).
2. The contract checks balance of AAVE:  
   `0xD6DF932A45C0f255f85145f286eA0b292B21C90B`
3. If the balance ≥ 10 AAVE, an access message is relayed to mainnet.
4. `Vault.sol` receives the message and grants the access token.

```plaintext
┌────────────┐     requestAccess()     ┌────────────────────────┐
│  Frontend  ├────────────────────────▶│ MasterAccessGranter.sol│
└────┬───────┘                         └────────────┬───────────┘
     │                                           Check: AAVE ≥ 10
     ▼                                               │
┌────────────┐◀────── Message from AMB ◀─────────────┘
│ Vault.sol  │       Mint ERC-1155 access token
└────────────┘
```

---

## 🧠 Snapshot Integration (Primary Use Case)

A powerful use case is integration with **Snapshot**. When a proposal is created on Snapshot, the author can create a corresponding Libélula vault.

Holders of voting power (via token or strategy) can be granted access to:

- **Read** supporting documents
- **Post** rebuttals or evidence
- **Contribute** versioned amendments

The vault becomes a **living record** of the governance proposal, capturing deliberation beyond on-chain voting.

---

## 🔎 Additional Use Cases

- **Research Groups**: Token-gated working spaces for DAOs.
- **Cross-chain contributor access**: NFT or ERC-20 holder eligibility.
- **Retroactive archive access**: Eligibility at snapshot block.
- **Multichain gated newsletters**.
- **NFT-based write access** (e.g., staking rewards or reputation NFTs).

---

## 🛠️ Technical Considerations

- ✅ **Bridge security**: Only allow verified bridge messages.
- ✅ **Token support**: ERC-20 and ERC-721 to start. ERC-1155 optional.
- ✅ **Gas efficiency**: Minimal cost to grant access post-bridge.
- ✅ **Indexing**: Subgraph must track cross-chain grants.
- ✅ **Permission expiry**: Optional time limit on access.
- ✅ **Replay protection**: Use nonces in messages.
- ✅ **AccessGranters registry**: `Vault.sol` must whitelist trusted instances.

---

## ⚠️ Challenges

- Ensuring message delivery guarantees (e.g., fallback if bridge fails).
- Avoiding abuse via spammed requests (rate limits? staking?).
- Managing revoked access if user dumps tokens.
- Designing trust-minimized bridge interactions.
- Coordinating chain deployments of `MasterAccessGranter`.

---

## 🔮 Future Enhancements

- ✅ Support **ZK Proofs** for off-chain balance validation.
- ✅ Multi-token weighted permission scoring.
- ✅ Integration with **LayerZero, Axelar, Hyperlane** bridges.
- ✅ Voting power-based access instead of raw balances.
- ✅ GUI for DAO admins to configure access vaults.

---

## 📘 Appendix

**Example Chains & Tokens**:

| Chain     | Token           | Use         |
|-----------|------------------|-------------|
| Polygon   | AAVE             | Write access |
| Arbitrum  | Custom NFT       | Read access  |

**Supported Bridges**:
- AMB
- LayerZero
- Axelar
- Hyperlane
- Wormhole

**Patterns**:
- Minimal Proxy for gas savings
- Event-based subgraph sync
