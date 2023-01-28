//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

interface IRenderEngine {
  // EIP 4883
  function renderTokenById(uint256 tokenId) external view returns (string memory);
}