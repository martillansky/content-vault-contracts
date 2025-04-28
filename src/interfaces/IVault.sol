// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

interface IVault {
    // ----------------------------- //
    //        Events                 //
    // ----------------------------- //

    event VaultCreated(
        uint256 indexed tokenId, address indexed owner, string name, string description, string schemaCID
    );
    event VaultAccessGranted(address indexed to, uint256 indexed tokenId, uint8 permission);
    event ContentStoredWithMetadata(
        address indexed sender,
        uint256 indexed tokenId,
        bytes encryptedCID,
        bool isCIDEncrypted,
        string metadata,
        bool isMetadataSigned
    );
    event VaultTransferred(uint256 indexed tokenId, address indexed from, address indexed to);

    // ----------------------------- //
    //        Functions              //
    // ----------------------------- //

    function getLastTokenId() external view returns (uint256);
    function schemaManager() external view returns (address);
    function incrementLastTokenId() external returns (uint256);
    function assignVaultFromProposalOwnership(uint256 tokenId, address masterCrosschainGranter) external;
}
