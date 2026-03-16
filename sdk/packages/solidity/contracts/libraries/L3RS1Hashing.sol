// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title L3RS1Hashing
 * @notice On-chain implementation of L3RS-1 canonical hash constructions.
 *
 * All functions use keccak256 (EVM native) as H().
 * Per §10.3 the hash function must be collision-resistant — keccak256 satisfies this.
 * Note: off-chain implementations use SHA-256. On-chain uses keccak256.
 * Cross-chain certificates bridging off-chain/on-chain MUST normalise the hash function.
 */
library L3RS1Hashing {

    // ─── §2.2 Asset_ID ───────────────────────────────────────────────────────

    /**
     * @notice I = H(pk_issuer || ts || nonce) — §2.2
     */
    function constructAssetId(
        bytes memory issuerPubkey,
        uint256 timestamp,
        bytes32 nonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(issuerPubkey, timestamp, nonce));
    }

    // ─── §8.3 Cross-Chain Certificate Identifier ─────────────────────────────

    /**
     * @notice CID = H(I || SH || CH || GH || t) — §8.3
     * Invariant I₁₁: any change to (S, C, G, J, L) produces a different CID.
     */
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

    // ─── §9.6 Transaction ID ─────────────────────────────────────────────────

    /**
     * @notice TxID = H(sender || receiver || amount || nonce || timestamp) — §9.6
     */
    function constructTxId(
        address sender,
        address receiver,
        uint256 amount,
        bytes32 nonce,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, receiver, amount, nonce, timestamp));
    }

    // ─── §5.7 Legal Basis ────────────────────────────────────────────────────

    /**
     * @notice BASIS = H(legal_document || jurisdiction || case_id) — §5.7
     */
    function constructLegalBasis(
        bytes32 legalDocHash,
        bytes2 jurisdiction,
        bytes32 caseId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(legalDocHash, jurisdiction, caseId));
    }

    // ─── §5.10 Override Record ────────────────────────────────────────────────

    /**
     * @notice Override_Record = H(OID || AUTH || ACTION || TS) — §5.10
     */
    function constructOverrideHash(
        bytes32 overrideId,
        address authority,
        bytes32 action,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(overrideId, authority, action, timestamp));
    }

    // ─── §12.3 Legal Document Hash ───────────────────────────────────────────

    /**
     * @notice LH = H(document_bytes || jurisdiction || version) — §12.3
     */
    function constructLegalHash(
        bytes memory documentBytes,
        bytes2 jurisdiction,
        string memory version
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(documentBytes, jurisdiction, version));
    }

    // ─── §9.11 State Hash ────────────────────────────────────────────────────

    /**
     * @notice StateHash = H(assetId || balancesHash || complianceState || governanceState) — §9.11
     */
    function constructStateHash(
        bytes32 assetId,
        bytes32 balancesHash,
        bytes32 complianceHash,
        bytes32 governanceHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(assetId, balancesHash, complianceHash, governanceHash));
    }

    // ─── §8.11 Chain ID ──────────────────────────────────────────────────────

    /**
     * @notice ChainID = H(chain_name || network_type || genesis_hash) — §8.11
     */
    function constructChainId(
        string memory chainName,
        string memory networkType,
        bytes32 genesisHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(chainName, networkType, genesisHash));
    }
}
