// SPDX-License-Identifier: Elastic-2.0
pragma solidity ^0.8.22;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

library ERC20TokenProposalLib {
    /// @notice Validates if a chainId is valid
    /// @param _chainId The chainId to validate
    /// @return True if the chainId is valid, false otherwise
    function isValidChainId(uint256 _chainId) internal pure returns (bool) {
        return _chainId != 0;
    }

    /// @notice Validates if a token contract is valid
    /// @param _tokenContract The token contract to validate
    /// @return True if the token contract is valid, false otherwise
    function isValidTokenContract(address _tokenContract) internal view returns (bool) {
        if (_tokenContract == address(0)) return false;
        if (ERC20(_tokenContract).totalSupply() == 0) return false;
        return true;
        /* 
        // Check if the address has code (is a contract)
        uint256 size;
        assembly {
            size := extcodesize(_tokenContract)
        }
        return size > 0; */
    }

    /// @notice Validates if a token address is valid
    /// @param _tokenAddress The token address to validate
    /// @return True if the token address is valid, false otherwise
    function isValidTokenAddress(address _tokenAddress) internal pure returns (bool) {
        if (_tokenAddress == address(0)) return false;
        return true;
    }

    /// @notice Returns the balance of a user for a token
    /// @param _tokenAddress The token address
    /// @param _user The user to get the balance of
    /// @return The balance of the user for the token
    function balanceOf(address _tokenAddress, address _user) internal view returns (uint256) {
        return ERC20(_tokenAddress).balanceOf(_user);
    }
}
