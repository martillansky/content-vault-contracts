// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";

contract VaultTest is Test {
    Vault public vault;

    function setUp() public {
        vault = new Vault();
        vault.setNumber(0);
    }

    function test_Increment() public {
        vault.increment();
        assertEq(vault.number(), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        vault.setNumber(x);
        assertEq(vault.number(), x);
    }
}
