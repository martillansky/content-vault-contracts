#!/bin/bash
set -e

# Load environment variables
source .env

# Encode constructor arguments
echo "Encoding constructor arguments..."

VAULT_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address)" $SCHEMA_MANAGER_ADDRESS_SEPOLIA)
PROPOSAL_VAULT_MANAGER_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address)" $VAULT_ADDRESS_SEPOLIA)
MASTER_CROSSCHAIN_GRANTER_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address)" $PROPOSAL_VAULT_MANAGER_ADDRESS_SEPOLIA)
MASTER_GATEWAY_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address,address)" $HOME_BRIDGE_SEPOLIA $MASTER_CROSSCHAIN_GRANTER_ADDRESS_SEPOLIA)
FOREIGN_GATEWAY_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address,address,address)" $MASTER_GATEWAY_ADDRESS_SEPOLIA $FOREIGN_BRIDGE_CHIADO $FOREIGN_CROSSCHAIN_GRANTER_ADDRESS_CHIADO)

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

# Verify MasterCrosschainGranter
echo "Verifying MasterCrosschainGranter..."
forge verify-contract \
  --chain-id 11155111 \
  $MASTER_CROSSCHAIN_GRANTER_ADDRESS_SEPOLIA \
  src/MasterCrosschainGranter.sol:MasterCrosschainGranter \
  --constructor-args $MASTER_CROSSCHAIN_GRANTER_CONSTRUCTOR_ARGS \
  --etherscan-api-key $ETHERSCAN_API_KEY

# Verify MasterGateway
echo "Verifying MasterGateway..."
forge verify-contract \
  --chain-id 11155111 \
  $MASTER_GATEWAY_ADDRESS_SEPOLIA \
  src/MasterGateway.sol:MasterGateway \
  --constructor-args $MASTER_GATEWAY_CONSTRUCTOR_ARGS \
  --etherscan-api-key $ETHERSCAN_API_KEY

echo
echo "All contracts on Sepolia verified successfully!"
echo

echo "Verifying contracts on Chiado..."

# Verify ForeignCrosschainGranter
echo "Verifying ForeignCrosschainGranter..."
forge verify-contract \
  --chain-id 10200 \
  $FOREIGN_CROSSCHAIN_GRANTER_ADDRESS_CHIADO \
  src/ForeignCrosschainGranter.sol:ForeignCrosschainGranter \
  --rpc-url https://rpc.chiadochain.net \
  --verifier blockscout \
  --verifier-url 'https://gnosis-chiado.blockscout.com/api/'

# Verify ForeignGateway
echo "Verifying ForeignGateway..."
forge verify-contract \
  --chain-id 10200 \
  $FOREIGN_GATEWAY_ADDRESS_CHIADO \
  src/ForeignGateway.sol:ForeignGateway \
  --constructor-args $FOREIGN_GATEWAY_CONSTRUCTOR_ARGS \
  --rpc-url https://rpc.chiadochain.net \
  --verifier blockscout \
  --verifier-url 'https://gnosis-chiado.blockscout.com/api/'

echo
echo "All contracts on Chiado verified successfully!"
echo
echo "All contracts verified successfully!"
