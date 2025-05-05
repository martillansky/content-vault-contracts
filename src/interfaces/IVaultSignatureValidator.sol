// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

interface IVaultSignatureValidator {
    // Errors
    error InvalidSignature();
    error SignatureExpired();

    // Functions
    function getNonce(address account) external view returns (uint256);
    function getDomainSeparator() external view returns (bytes32);
}
