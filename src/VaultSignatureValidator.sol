// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IVaultSignatureValidator} from "./interfaces/IVaultSignatureValidator.sol";
import {EIP712TypedDataLib} from "./libs/EIP712TypedDataLib.sol";

abstract contract VaultSignatureValidator is IVaultSignatureValidator {
    using ECDSA for bytes32;

    // Mapping of nonces: address -> nonce
    mapping(address => uint256) public nonces;

    // ----------------------------- //
    //        Type Hashes            //
    // ----------------------------- //

    /// @dev EIP-712 domain separator (must be set once in inheriting contract)
    bytes32 internal DOMAIN_SEPARATOR;

    /// @notice Gets the current nonce for an address
    /// @param signer The address to get the nonce for
    /// @return The current nonce for the address
    function getNonce(address signer) external view returns (uint256) {
        return nonces[signer];
    }

    /// @notice Returns the domain separator used in the encoding of the signature for EIP712
    /// @return bytes32 The domain separator
    function getDomainSeparator() external view returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }

    /// @notice Verifies a signature
    /// @param structHash The struct hash to verify
    /// @param owner The owner of the signature
    /// @param deadline The deadline of the signature
    /// @param signature The signature to verify
    /// @custom:error SignatureExpired if the signature has expired
    /// @custom:error InvalidSignature if the signature is invalid
    function _verifySignature(bytes32 structHash, address owner, uint256 deadline, bytes calldata signature) internal {
        if (block.timestamp > deadline) revert SignatureExpired();

        bytes32 digest = EIP712TypedDataLib.hashTypedDataV4(DOMAIN_SEPARATOR, structHash); // Use OpenZeppelin EIP712 helper
        address signer = ECDSA.recover(digest, signature);
        if (signer != owner) revert InvalidSignature();

        nonces[owner]++;
    }
}
