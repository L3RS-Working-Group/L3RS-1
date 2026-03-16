// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IL3RS1Asset
 * @notice L3RS-1 On-chain Asset Interface — Profile A: Smart Contract VM (§17.2)
 *
 * Implements the L3RS-1 CORE conformance class for EVM environments.
 * Compliance logic executes BEFORE all balance mutations — §17.8.
 * All state transitions follow §2.5 exactly.
 * Gas is bounded per §14.13 (no unbounded loops in compliance evaluation).
 */
interface IL3RS1Asset {

    // ─── Enums (§2.3, §2.4) ──────────────────────────────────────────────────

    enum AssetType {
        CBDC, INDUSTRY_STABLE, REGULATED_SECURITY,
        UTILITY, GOVERNANCE, STORAGE_BACKED
    }

    enum AssetState {
        ISSUED, ACTIVE, RESTRICTED, FROZEN, SUSPENDED, REDEEMED, BURNED
    }

    enum EnforcementAction {
        REJECT, FREEZE, RESTRICT, FLAG, REQUIRE_DISCLOSURE
    }

    // ─── Events ───────────────────────────────────────────────────────────────

    /// Emitted on every valid state transition (§2.5, §5.10)
    event StateTransition(
        bytes32 indexed assetId,
        AssetState indexed from,
        AssetState indexed to,
        bytes32 trigger
    );

    /// Emitted on every compliant transfer (§9.10 settlement proof)
    event Transfer(
        bytes32 indexed txId,
        address indexed sender,
        address indexed receiver,
        uint256 amount,
        bytes32 feeRecordHash
    );

    /// Emitted on every governance override (§5.10)
    event GovernanceOverride(
        bytes32 indexed overrideId,
        address indexed authority,
        bytes32 action,
        bytes32 legalBasisHash
    );

    /// Emitted when compliance blocks a transfer (§4.12)
    event ComplianceBlock(
        bytes32 indexed ruleId,
        address indexed sender,
        address indexed receiver,
        bytes32 action
    );

    // ─── Core Asset Queries ───────────────────────────────────────────────────

    /// §2.1 — Returns the canonical asset identifier
    function assetId() external view returns (bytes32);

    /// §2.3 — Asset type (immutable after issuance)
    function assetType() external view returns (AssetType);

    /// §2.4 — Current asset state
    function currentState() external view returns (AssetState);

    /// §1.3 — Jurisdiction (ISO 3166-1 alpha-2, packed as bytes2)
    function jurisdiction() external view returns (bytes2);

    /// §3.2 — Identity requirement level (0–3)
    function identityLevel() external view returns (uint8);

    /// §12.2 — Legal mirror hash
    function legalMirrorHash() external view returns (bytes32);

    /// §13.13 — Standard version string
    function standardVersion() external view returns (string memory);

    // ─── §2.6 Transfer Execution ─────────────────────────────────────────────

    /**
     * @notice Execute a compliant transfer per §2.6-2.7.
     * Executes in exact order:
     *   1. Identity validation
     *   2. Compliance evaluation
     *   3. Governance override check
     *   4. Fee routing
     *   5. Balance update
     * @param receiver Transfer recipient
     * @param amount   Token amount
     * @param nonce    Unique per-sender nonce (§9.6 replay protection)
     * @return txId    Settlement transaction identifier
     */
    function transfer(
        address receiver,
        uint256 amount,
        bytes32 nonce
    ) external returns (bytes32 txId);

    // ─── §9.10 Settlement Proof ───────────────────────────────────────────────

    /**
     * @notice Returns a verifiable settlement proof for a completed transfer.
     */
    function getSettlementProof(bytes32 txId)
        external view returns (
            bytes32 blockHash,
            uint256 blockNumber,
            bytes32 stateHash,
            uint256 timestamp
        );

    // ─── §4 Compliance ────────────────────────────────────────────────────────

    /**
     * @notice Evaluate compliance rules for a proposed transfer.
     * Returns true if transfer would be permitted.
     * O(n) per §14.3 — n is bounded at issuance.
     */
    function checkCompliance(
        address sender,
        address receiver,
        uint256 amount
    ) external view returns (bool allowed, bytes32 blockingRuleId);

    // ─── §5 Governance Override ───────────────────────────────────────────────

    /**
     * @notice Execute a validated governance override per §5.6.
     * Requires valid signature + quorum for EMERGENCY_ROLLBACK.
     */
    function executeOverride(
        bytes32 overrideId,
        bytes32 action,
        address target,
        bytes32 legalBasisHash,
        bytes memory signature
    ) external;

    // ─── §6 Fee Info ──────────────────────────────────────────────────────────

    /// Returns the fee rate in basis points (0–9999)
    function feeRateBasisPoints() external view returns (uint16);

    // ─── §7 Reserve (optional for non-backed assets) ─────────────────────────

    /// Returns the reserve status if applicable
    function reserveStatus() external view returns (bytes32);

    // ─── §8 Cross-Chain Certificate ───────────────────────────────────────────

    /**
     * @notice Returns the current cross-chain certificate identifier.
     * CID = H(assetId || stateHash || complianceHash || govHash || timestamp)
     */
    function crossChainCertificateId() external view returns (bytes32);

    /**
     * @notice Verify an inbound cross-chain certificate.
     * Rejects if compliance/governance hashes differ — §8.9.
     */
    function verifyCrossChainCertificate(
        bytes32 cid,
        bytes32 originStateHash,
        bytes32 originComplianceHash,
        bytes32 originGovernanceHash,
        uint256 timestamp
    ) external view returns (bool valid);
}
