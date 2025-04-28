#!/bin/bash
set -e

# Load environment variables
source .env

# Encode constructor arguments
echo "Encoding constructor arguments..."

VAULT_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address)" $SCHEMA_MANAGER_ADDRESS_SEPOLIA)
PROPOSAL_VAULT_MANAGER_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address)" $VAULT_ADDRESS_SEPOLIA)

echo "Constructor args prepared!"
echo

# Verify Vault
echo "Verifying Vault..."
forge verify-contract \
  --chain-id 11155111 \
  $VAULT_ADDRESS_SEPOLIA \
  src/Vault.sol:Vault \
  --constructor-args $VAULT_CONSTRUCTOR_ARGS \
  --etherscan-api-key $ETHERSCAN_API_KEY

# Verify SchemaManager
echo "Verifying SchemaManager..."
forge verify-contract \
  --chain-id 11155111 \
  $SCHEMA_MANAGER_ADDRESS_SEPOLIA \
  src/SchemaManager.sol:SchemaManager \
  --etherscan-api-key $ETHERSCAN_API_KEY

# Verify ProposalVaultManager
echo "Verifying ProposalVaultManager..."
forge verify-contract \
  --chain-id 11155111 \
  $PROPOSAL_VAULT_MANAGER_ADDRESS_SEPOLIA \
  src/ProposalVaultManager.sol:ProposalVaultManager \
  --constructor-args $PROPOSAL_VAULT_MANAGER_CONSTRUCTOR_ARGS \
  --etherscan-api-key $ETHERSCAN_API_KEY

echo
echo "All contracts verified successfully!"
