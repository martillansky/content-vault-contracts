// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.22;

import {ERC1155, balanceOf} from "lib/openzeppelin-contracts/contracts/token/ERC1155/ERC1155.sol";
import {Ownable, onlyOwner} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";

contract Vault is ERC1155, Ownable {
    mapping(uint256 => string) public schemas;
    uint256 public lastSchemaIndex;

    event ContentStored(
        address indexed sender,
        uint256 indexed tokenId,
        string ipfsHash,
        uint256 schemaIndex
    );

    constructor() ERC1155("") Ownable(msg.sender) {}

    function mint(uint256 tokenId) public onlyOwner {
        _mint(msg.sender, tokenId, 1, "");
    }

    function storeContent(
        uint256 tokenId,
        string memory ipfsHash
    ) public onlyOwner {
        require(balanceOf(msg.sender, tokenId) > 0, "You don't own this token");
        emit ContentStored(msg.sender, tokenId, ipfsHash, lastSchemaIndex);
    }

    function setSchema(string memory schema) public onlyOwner {
        lastSchemaIndex++;
        schemas[lastSchemaIndex] = schema;
    }

    function getSchema(uint256 index) public view returns (string memory) {
        return schemas[index];
    }

    function getCurrentSchema() public view returns (uint256) {
        return schemas[lastSchemaIndex];
    }
}
