/**
 * L3RS-1 Fee Routing, Reserve, Cross-Chain, and Settlement Modules
 * §6 Fee Routing · §7 Reserve · §8 Cross-Chain · §9 Settlement
 */

import {
  ReserveStatus,
  AttestationFrequency,
  type FeeModule,
  type ReserveInterface,
  type CrossChainMetadata,
  type TransferEvent,
  type SettlementProof,
  type Asset,
  type ComplianceModule,
  type GovernanceModule,
} from "../types/index.js";
import {
  constructCID,
  constructTxId,
  hashObject,
  sha256Concat,
} from "../crypto/index.js";

// ══════════════════════════════════════════════════════════════════════════════
// §6 Fee Routing Architecture
// ══════════════════════════════════════════════════════════════════════════════

export interface FeeDistribution {
  readonly totalFee: bigint;
  readonly allocations: readonly { recipient: string; amount: bigint }[];
  readonly feeRecordHash: string;
}

/**
 * distribute_fees(A, amount) — §6.5
 * Atomicity: if any allocation fails, entire transaction reverts — §6.6.
 * O(m) complexity per §14.5.
 */
export function distributeFees(
  feeModule: FeeModule,
  amount: bigint,
  txId: string,
  timestamp: number,
): FeeDistribution {
  validateFeeModule(feeModule);

  const totalFee = (amount * BigInt(feeModule.baseRateBasisPoints)) / 10000n;

  const allocations = feeModule.allocations.map((alloc) => ({
    recipient: alloc.recipient,
    amount: (totalFee * BigInt(alloc.basisPoints)) / 10000n,
  }));

  // §6.10 FeeRecord = H(tx_id || fee || timestamp)
  const txBuf  = Buffer.from(txId, "hex");
  const feeBuf = Buffer.from(totalFee.toString(16).padStart(64, "0"), "hex");
  const tsBuf  = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(timestamp));
  const feeRecordHash = sha256Concat(txBuf, feeBuf, tsBuf);

  return { totalFee, allocations, feeRecordHash };
}

/**
 * §6.12 Economic Integrity Constraint:
 * - No negative allocation
 * - Sum of basis points MUST equal 10000
 * - No hidden fee extraction
 */
export function validateFeeModule(feeModule: FeeModule): void {
  if (feeModule.baseRateBasisPoints < 0 || feeModule.baseRateBasisPoints >= 10000) {
    throw new Error("Base rate must be in range [0, 10000) basis points");
  }

  const total = feeModule.allocations.reduce((sum, a) => sum + a.basisPoints, 0);
  if (total !== 10000) {
    throw new Error(`Fee allocation basis points must sum to 10000; got ${total}`);
  }

  for (const alloc of feeModule.allocations) {
    if (alloc.basisPoints < 0) {
      throw new Error("Negative fee allocation is not permitted");
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// §7 Reserve and Asset Backing Verification
// ══════════════════════════════════════════════════════════════════════════════

/** §7.8 ReserveStatus(B) ∈ {VALID, STALE, INVALID, UNKNOWN} */
export function validateReserve(
  reserve: ReserveInterface,
  nowUnix: number,
  auditHashVerifier?: (hash: string) => boolean,
): ReserveStatus {
  // Verify audit hash
  if (auditHashVerifier) {
    if (!auditHashVerifier(reserve.auditHash)) return ReserveStatus.INVALID;
  }

  // Check attestation staleness per §7.7
  const staleThreshold = attestationFrequencyToSeconds(reserve.attestationFrequency);
  const auditTimestamp = extractTimestampFromAuditHash(reserve.auditHash);

  if (auditTimestamp === null) return ReserveStatus.UNKNOWN;

  const age = nowUnix - auditTimestamp;
  if (age > staleThreshold) return ReserveStatus.STALE;

  return ReserveStatus.VALID;
}

function attestationFrequencyToSeconds(freq: AttestationFrequency): number {
  switch (freq) {
    case AttestationFrequency.REALTIME:  return 60;
    case AttestationFrequency.DAILY:     return 86400;
    case AttestationFrequency.WEEKLY:    return 604800;
    case AttestationFrequency.MONTHLY:   return 2592000;
    case AttestationFrequency.QUARTERLY: return 7776000;
    case AttestationFrequency.ANNUAL:    return 31536000;
  }
}

function extractTimestampFromAuditHash(_auditHash: string): number | null {
  // In production: the audit hash is anchored with metadata;
  // implementer provides an oracle to extract the attestation timestamp.
  return null;
}

/** §7.10 Redemption condition: S = ACTIVE ∧ ReserveStatus = VALID */
export function isRedeemable(
  asset: Asset,
  nowUnix: number,
  auditHashVerifier?: (hash: string) => boolean,
): boolean {
  if (asset.state !== "ACTIVE") return false;
  if (!asset.reserveInterface) return true; // non-backed assets are always redeemable if active
  return validateReserve(asset.reserveInterface, nowUnix, auditHashVerifier) === ReserveStatus.VALID;
}

// ══════════════════════════════════════════════════════════════════════════════
// §8 Cross-Chain Meta-Standard Architecture
// ══════════════════════════════════════════════════════════════════════════════

export interface CrossChainCertificate {
  readonly cid:            string;
  readonly assetId:        string;
  readonly stateHash:      string;
  readonly complianceHash: string;
  readonly governanceHash: string;
  readonly timestamp:      number;
}

/**
 * Build a cross-chain certificate — §8.3
 * CID = H(I || SH || CH || GH || t)
 */
export function buildCrossChainCertificate(
  asset: Asset,
  timestamp: number,
): CrossChainCertificate {
  const stateHash      = hashObject(asset.state);
  const complianceHash = hashObject(asset.complianceModule);
  const governanceHash = hashObject(asset.governanceModule);

  const cid = constructCID(
    asset.assetId,
    stateHash,
    complianceHash,
    governanceHash,
    timestamp,
  );

  return { cid, assetId: asset.assetId, stateHash, complianceHash, governanceHash, timestamp };
}

export interface CrossChainVerificationResult {
  readonly valid:  boolean;
  readonly error?: string;
}

/**
 * verify_crosschain(CID, origin_data) — §8.9
 * Recomputes CID and verifies all invariants hold.
 */
export function verifyCrossChain(
  cert: CrossChainCertificate,
  destMetadata: CrossChainMetadata,
  destCompliance: ComplianceModule,
  destGovernance: GovernanceModule,
  destAssetId: string,
): CrossChainVerificationResult {
  // §8.4 Asset_ID invariance
  if (destAssetId !== cert.assetId) {
    return { valid: false, error: "Asset_ID changed during cross-chain transfer" };
  }

  // Recompute CID
  const recomputed = constructCID(
    cert.assetId,
    cert.stateHash,
    cert.complianceHash,
    cert.governanceHash,
    cert.timestamp,
  );
  if (recomputed !== cert.cid) {
    return { valid: false, error: "CID recomputation mismatch — certificate integrity violated" };
  }

  // §8.5 Compliance hash MUST match
  const destComplianceHash = hashObject(destCompliance);
  if (destComplianceHash !== cert.complianceHash) {
    return { valid: false, error: "ComplianceHash modified on destination chain — downgrade attack" };
  }

  // §8.6 Governance hash MUST match
  const destGovernanceHash = hashObject(destGovernance);
  if (destGovernanceHash !== cert.governanceHash) {
    return { valid: false, error: "GovernanceHash modified on destination chain" };
  }

  // §8.10 Regulatory downgrade protection
  if (destMetadata.complianceHash !== cert.complianceHash) {
    return { valid: false, error: "Regulatory downgrade detected" };
  }

  return { valid: true };
}

// ══════════════════════════════════════════════════════════════════════════════
// §9 Deterministic Settlement and Finality
// ══════════════════════════════════════════════════════════════════════════════

export interface SettlementResult {
  readonly success:     boolean;
  readonly txId?:       string;
  readonly proof?:      SettlementProof;
  readonly error?:      string;
}

/**
 * §9.3 SettlementSuccess ⟺ Compliance ∧ Identity ∧ Fee ∧ Governance ∧ StateCommit
 * Partial settlement is NOT permitted.
 */
export function buildSettlementProof(
  event: TransferEvent,
  blockHeight: bigint,
  stateHash: string,
): SettlementProof {
  const txId = constructTxId(event);
  return {
    txId,
    blockHeight,
    stateHash,
    timestamp: event.timestamp,
  };
}

/** §9.6 Replay protection: TxID must not already exist in ledger history */
export function isReplay(
  event: TransferEvent,
  ledgerHistory: ReadonlySet<string>,
): boolean {
  const txId = constructTxId(event);
  return ledgerHistory.has(txId);
}

/** §9.9 Rollback recording — appends corrective entry, never erases */
export interface RollbackRecord {
  readonly rollbackHash:  string;
  readonly originalTxId:  string;
  readonly reason:        string;
  readonly timestamp:     number;
}

export function createRollbackRecord(
  originalTxId: string,
  reason: string,
  timestamp: number,
): RollbackRecord {
  const txBuf     = Buffer.from(originalTxId, "hex");
  const reasonBuf = Buffer.from(reason, "utf8");
  const tsBuf     = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(timestamp));
  const rollbackHash = sha256Concat(txBuf, reasonBuf, tsBuf);

  return { rollbackHash, originalTxId, reason, timestamp };
}
