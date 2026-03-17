// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./interfaces/IL3RS1Asset.sol";
import "./libraries/L3RS1Hashing.sol";

/**
 * @title L3RS1Asset
 * @notice L3RS-1 Reference Implementation — EVM Profile A (§17.2)
 */
contract L3RS1Asset is IL3RS1Asset {

    bytes32 private immutable _assetId;
    AssetState private _state;
    uint16 private immutable _feeRateBps;

    mapping(bytes32 => bool)    private _usedNonces;   // nonce → used
    mapping(address => uint256) private _balances;

    constructor(
        bytes  memory issuerPubkey,
        uint16        feeRateBps,
        bytes32       nonce
    ) {
        _assetId    = L3RS1Hashing.constructAssetId(issuerPubkey, block.timestamp, nonce);
        _state      = AssetState.ISSUED;
        _feeRateBps = feeRateBps;
    }

    // ── View functions ────────────────────────────────────────────────────────

    function assetId() external view override returns (bytes32) {
        return _assetId;
    }

    function currentState() external view override returns (AssetState) {
        return _state;
    }

    function standardVersion() external pure override returns (string memory) {
        return "L3RS-1.0.0";
    }

    function feeRateBasisPoints() external view override returns (uint16) {
        return _feeRateBps;
    }

    function crossChainCertificateId() external view override returns (bytes32) {
        return L3RS1Hashing.constructCID(
            _assetId,
            bytes32(uint256(uint8(_state))),
            bytes32(0),
            bytes32(0),
            block.timestamp
        );
    }

    // ── State machine ─────────────────────────────────────────────────────────

    function activate() external {
        require(_state == AssetState.ISSUED, "L3RS1: not ISSUED");
        emit StateTransition(_assetId, AssetState.ISSUED, AssetState.ACTIVE, bytes32("ACTIVATION"));
        _state = AssetState.ACTIVE;
    }

    // ── Transfer ──────────────────────────────────────────────────────────────

    function transfer(
        address receiver,
        uint256 amount,
        bytes32 nonce
    ) external override returns (bytes32 txId) {
        require(_state == AssetState.ACTIVE, "L3RS1: not ACTIVE");
        require(!_usedNonces[nonce], "L3RS1: replay");  // §9.6 replay protection via nonce
        _usedNonces[nonce] = true;

        require(_balances[msg.sender] >= amount, "L3RS1: insufficient balance");
        uint256 fee = (amount * _feeRateBps) / 10_000;
        _balances[msg.sender] -= amount;
        _balances[receiver]   += (amount - fee);

        txId = L3RS1Hashing.constructTxId(msg.sender, receiver, amount, nonce, block.timestamp);
        emit Transfer(txId, msg.sender, receiver, amount);
    }

    // ── Compliance ────────────────────────────────────────────────────────────

    function checkCompliance(
        address sender,
        address receiver,
        uint256 amount
    ) external view override returns (bool allowed, bytes32 blockingRuleId) {
        sender;
        receiver;
        amount;
        if (_state != AssetState.ACTIVE) {
            return (false, bytes32("STATE"));
        }
        return (true, bytes32(0));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}
