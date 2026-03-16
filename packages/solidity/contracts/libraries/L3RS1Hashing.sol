// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title L3RS1Hashing
 * @notice Canonical hash constructions for L3RS-1 on-chain enforcement.
 * Uses keccak256 (EVM native) as H() per §10.3.
 */
library L3RS1Hashing {

    /// §2.2 — I = H(pk_issuer || ts || nonce)
    function constructAssetId(
        bytes memory issuerPubkey,
        uint256 timestamp,
        bytes32 nonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(issuerPubkey, timestamp, nonce));
    }

    /// §8.3 — CID = H(I || SH || CH || GH || t)
    function constructCID(
        bytes32 assetId,
        bytes32 stateHash,
        bytes32 complianceHash,
        bytes32 governanceHash,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            assetId, stateHash, complianceHash, governanceHash, timestamp
        ));
    }

    /// §9.6 — TxID = H(sender || receiver || amount || nonce || timestamp)
    function constructTxId(
        address sender,
        address receiver,
        uint256 amount,
        bytes32 nonce,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, receiver, amount, nonce, timestamp));
    }
}
