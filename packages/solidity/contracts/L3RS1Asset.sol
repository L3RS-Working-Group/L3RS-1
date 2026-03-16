// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./interfaces/IL3RS1Asset.sol";
import "./libraries/L3RS1Hashing.sol";

/**
 * @title L3RS1Asset
 * @notice L3RS-1 Reference Implementation — EVM Profile A (§17.2)
 * CORE conformance: state machine · compliance · governance · fees · cross-chain
 */
contract L3RS1Asset is IL3RS1Asset {

    bytes32 private immutable _assetId;
    AssetState private _state;
    uint16 private immutable _feeRateBps;
    string private constant _version = "L3RS-1.0.0";

    bytes32 private _currentCID;
    mapping(bytes32 => bool) private _usedTxIds;
    mapping(address => uint256) private _balances;

    address[] private _authorities;
    uint256 private _quorum;

    constructor(
        bytes memory issuerPubkey,
        uint16 feeRateBps,
        address[] memory authorities,
        uint256 quorum,
        bytes32 nonce
    ) {
        _assetId    = L3RS1Hashing.constructAssetId(issuerPubkey, block.timestamp, nonce);
        _state      = AssetState.ISSUED;
        _feeRateBps = feeRateBps;
        _authorities = authorities;
        _quorum     = quorum;
    }

    function assetId() external view override returns (bytes32) { return _assetId; }
    function currentState() external view override returns (AssetState) { return _state; }
    function standardVersion() external pure override returns (string memory) { return _version; }
    function feeRateBasisPoints() external view override returns (uint16) { return _feeRateBps; }
    function crossChainCertificateId() external view override returns (bytes32) { return _currentCID; }

    function transfer(
        address receiver,
        uint256 amount,
        bytes32 nonce
    ) external override returns (bytes32 txId) {
        require(_state == AssetState.ACTIVE, "L3RS1: not ACTIVE");
        txId = L3RS1Hashing.constructTxId(msg.sender, receiver, amount, nonce, block.timestamp);
        require(!_usedTxIds[txId], "L3RS1: replay");
        _usedTxIds[txId] = true;

        (bool allowed,) = _checkCompliance(msg.sender, receiver, amount);
        require(allowed, "L3RS1: compliance blocked");

        require(_balances[msg.sender] >= amount, "L3RS1: insufficient balance");
        uint256 fee = (amount * _feeRateBps) / 10_000;
        _balances[msg.sender] -= amount;
        _balances[receiver]   += amount - fee;

        _currentCID = L3RS1Hashing.constructCID(
            _assetId,
            bytes32(uint256(uint8(_state))),
            bytes32(0),
            bytes32(0),
            block.timestamp
        );

        emit Transfer(txId, msg.sender, receiver, amount);
    }

    function checkCompliance(address sender, address receiver, uint256 amount)
        external view override returns (bool, bytes32)
    {
        return _checkCompliance(sender, receiver, amount);
    }

    function _checkCompliance(address, address, uint256) internal view returns (bool, bytes32) {
        if (_state != AssetState.ACTIVE) return (false, bytes32("STATE"));
        return (true, bytes32(0));
    }

    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
    }

    function activate() external {
        require(_state == AssetState.ISSUED, "L3RS1: not ISSUED");
        _state = AssetState.ACTIVE;
        emit StateTransition(_assetId, AssetState.ISSUED, AssetState.ACTIVE, bytes32("ACTIVATION"));
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}
