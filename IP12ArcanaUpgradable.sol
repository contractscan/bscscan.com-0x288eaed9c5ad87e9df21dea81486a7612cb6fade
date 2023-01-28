//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

interface IP12ArcanaUpgradable {
  function getVotingPower(uint256 tokenId) external view returns (uint256);

  event SignerSet(address signer, bool valid);
  event RenderEngineSet(address renderEngin);
  event LockSet(bool lock);
  event PowerUpdate(uint256 tokenId, uint256 power);
  event AnswerUriUpdate(uint256 tokenId, string uri);
}