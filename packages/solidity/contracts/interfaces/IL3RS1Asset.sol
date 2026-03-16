// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title IL3RS1Asset
 * @notice L3RS-1 On-chain Asset Interface — Profile A (§17.2)
 */
interface IL3RS1Asset {
    enum AssetState { ISSUED, ACTIVE, RESTRICTED, FROZEN, SUSPENDED, REDEEMED, BURNED }

    event StateTransition(bytes32 indexed assetId, AssetState from, AssetState to, bytes32 trigger);
    event Transfer(bytes32 indexed txId, address indexed sender, address indexed receiver, uint256 amount);
    event GovernanceOverride(bytes32 indexed overrideId, address indexed authority, bytes32 action);

    function assetId() external view returns (bytes32);
    function currentState() external view returns (AssetState);
    function standardVersion() external view returns (string memory);
    function feeRateBasisPoints() external view returns (uint16);

    function transfer(address receiver, uint256 amount, bytes32 nonce) external returns (bytes32 txId);
    function checkCompliance(address sender, address receiver, uint256 amount)
        external view returns (bool allowed, bytes32 blockingRuleId);
    function crossChainCertificateId() external view returns (bytes32);
}
