// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.17;

import '@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol';
import '@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol';
import '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';
import '@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol';
import '@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol';
import '@openzeppelin/contracts/utils/Base64.sol';
import '@openzeppelin/contracts/utils/Strings.sol';

import '@p12/contracts-lib/contracts/access/SafeOwnableUpgradeable.sol';

import './interface/IP12ArcanaUpgradable.sol';
import './interface/IRenderEngine.sol';

contract P12ArcanaUpgradable is
  IP12ArcanaUpgradable,
  ERC2771ContextUpgradeable,
  SafeOwnableUpgradeable,
  UUPSUpgradeable,
  ERC721Upgradeable,
  EIP712Upgradeable
{
  using ECDSAUpgradeable for bytes32;

  bytes32 private constant _TYPEHASH = keccak256('PowerUpdate(uint256 tokenId,uint256 power,uint256 deadline)');

  //
  address public renderEngine;

  string private _description;

  bool private _lock;

  // signers
  mapping(address => bool) public signers;

  // voting powers
  mapping(uint256 => uint256) private _powers;

  // tokenId => ipfs uri
  mapping(uint256 => string) public answersUri;

  // hash(r,s,v) => bool
  mapping(bytes32 => bool) public signatureUsed;

  constructor(address forwarder_) initializer ERC2771ContextUpgradeable(forwarder_) {}

  function initialize(
    string calldata name_,
    string calldata symbol_,
    string calldata version_,
    string calldata description_
  ) public initializer {
    _description = description_;
    __Ownable_init_unchained();
    __ERC721_init_unchained(name_, symbol_);
    __EIP712_init_unchained(name_, version_);
  }

  function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

  function _msgSender() internal view virtual override(ContextUpgradeable, ERC2771ContextUpgradeable) returns (address sender) {
    return ERC2771ContextUpgradeable._msgSender();
  }

  function _msgData() internal view virtual override(ERC2771ContextUpgradeable, ContextUpgradeable) returns (bytes calldata) {
    return ERC2771ContextUpgradeable._msgData();
  }

  //
  function getBattlePass() external {
    require(balanceOf(_msgSender()) == 0, 'P12Arcana: already have pass');

    _safeMint(_msgSender(), uint256(uint160(_msgSender())));
  }

  function getBattlePass(address user) external {
    require(balanceOf(user) == 0, 'P12Arcana: already have pass');

    _safeMint(user, uint256(uint160(user)));
  }

  function updateAnswerUri(uint256 tokenId, string calldata uri) external whenNotLocked {
    require(ownerOf(tokenId) == _msgSender(), 'P12Arcana: not token owner');

    answersUri[tokenId] = uri;
    emit AnswerUriUpdate(tokenId, uri);
  }

  function updatePower(
    uint256 tokenId,
    uint256 power,
    uint256 deadline
  ) external onlySigner {
    require(deadline > block.timestamp, 'P12Arcana: outdated request');
    _powers[tokenId] = power;

    emit PowerUpdate(tokenId, power);
  }

  function updatePower(
    uint256 tokenId,
    uint256 power,
    uint256 deadline,
    bytes calldata signature
  ) external {
    require(!signatureUsed[keccak256(signature)], 'P12Arcana: sig already used');
    require(deadline > block.timestamp, 'P12Arcana: outdated sig');

    address signer = _hashTypedDataV4(keccak256(abi.encode(_TYPEHASH, tokenId, power, deadline))).recover(signature);

    require(signers[signer], 'P12Arcana: sig not from signer');

    _powers[tokenId] = power;

    signatureUsed[keccak256(signature)] = true;

    emit PowerUpdate(tokenId, power);
  }

  function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
    _requireMinted(tokenId);

    string memory SVG = IRenderEngine(renderEngine).renderTokenById(tokenId);

    string memory metadata = Base64.encode(
      bytes(
        string.concat(
          '{"name": "',
          name(),
          '","description":"',
          _description,
          '","image":"',
          'data:image/svg+xml;base64,',
          Base64.encode(bytes(SVG)),
          '","attributes": [{"display_type": "number","trait_type": "power","value": ',
          Strings.toString(_powers[tokenId]),
          '}]}'
        )
      )
    );

    return string.concat('data:application/json;base64,', metadata);
  }

  function _beforeTokenTransfer(
    address from,
    address,
    uint256
  ) internal virtual override {
    require(from == address(0), 'P12Arcana: can not transfer');
  }

  function getVotingPower(uint256 tokenId) external view override returns (uint256) {
    return _powers[tokenId];
  }

  function setLock(bool lock_) external onlyOwner {
    _lock = lock_;
    emit LockSet(lock_);
  }

  function setSigner(address signer, bool valid) external onlyOwner {
    signers[signer] = valid;

    emit SignerSet(signer, valid);
  }

  function setRenderEngin(address newEngine) external onlyOwner {
    renderEngine = newEngine;

    emit RenderEngineSet(newEngine);
  }

  modifier onlySigner() {
    require(signers[_msgSender()] == true, 'P12Arcana: not signer');
    _;
  }

  modifier whenNotLocked() {
    require(!_lock, 'P12Arcana: locked');
    _;
  }
}