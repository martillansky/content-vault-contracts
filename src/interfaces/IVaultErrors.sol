// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

interface IVaultErrors {
    // ----------------------------- //
    //        Errors                 //
    // ----------------------------- //

    error NotVaultOwner();
    error AlreadyHasToken();
    error NoWritePermission();
    error InvalidPermission();
    error CannotRevokeAccessToSelf();
    error NoAccessToRevoke();
    error InvalidSchemaIndex();
    error MismatchedArrayLengths();
    error VaultDoesNotExist();
    error InvalidUpgrade();
    error ZeroAddress();
    error EmptyArray();
    error NotProposalVaultManager();
}
