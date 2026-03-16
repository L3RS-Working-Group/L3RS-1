/**
 * L3RS-1 Governance Override Module
 * §5 Governance Override Architecture
 *
 * Invariant I₄: Override requires valid signature AND quorum (where required).
 * Override SHALL NOT be discretionary or arbitrary — §5.1.
 */

import {
  GovernanceAction,
  type GovernanceModule,
  type OverrideObject,
} from "../types/index.js";
import { constructOverrideHash } from "../crypto/index.js";
import type { SignatureVerifier } from "../crypto/index.js";

// ─── §5.6 Override Validation Function ───────────────────────────────────────

export interface OverrideValidationResult {
  readonly valid:  boolean;
  readonly error?: string;
}

/**
 * validate_override(O) per §5.6:
 * 1. Verify signature
 * 2. If EMERGENCY_ROLLBACK: verify quorum
 * 3. Verify authority is registered
 * 4. Verify action is in allowed set
 * 5. Verify legal basis hash is present
 */
export function validateOverride(
  override: OverrideObject,
  governance: GovernanceModule,
  verifier: SignatureVerifier,
  allSignatures?: readonly { authority: string; signature: string }[],
): OverrideValidationResult {
  // §5.14 — Failure conditions

  // 1. Authority must be registered
  if (!governance.authorities.includes(override.authority)) {
    return { valid: false, error: "Authority not registered in governance module" };
  }

  // 2. Action must be in allowed set
  if (!governance.overrideTypes.includes(override.action)) {
    return { valid: false, error: `Action ${override.action} not permitted for this asset` };
  }

  // 3. Legal basis hash must be present — §5.7
  if (!override.legalBasis || override.legalBasis.length < 64) {
    return { valid: false, error: "Legal basis hash missing or malformed" };
  }

  // 4. Signature verification — §5.4
  const authorityPubKey = resolveAuthorityPubKey(override.authority, governance);
  if (!authorityPubKey) {
    return { valid: false, error: "Cannot resolve authority public key" };
  }

  const msg = Buffer.from(override.legalBasis, "hex");
  if (!verifier.verify(msg, override.signature, authorityPubKey)) {
    return { valid: false, error: "Signature verification failed" };
  }

  // 5. Quorum check for EMERGENCY_ROLLBACK — §5.5
  if (override.action === GovernanceAction.EMERGENCY_ROLLBACK) {
    const quorumResult = validateQuorum(governance, allSignatures ?? []);
    if (!quorumResult.met) {
      return { valid: false, error: `Quorum not met: ${quorumResult.count}/${quorumResult.required}` };
    }
  }

  return { valid: true };
}

// ─── §5.5 Quorum Requirement ─────────────────────────────────────────────────

interface QuorumResult {
  readonly met:      boolean;
  readonly count:    number;
  readonly required: number;
}

/**
 * Quorum = ⌈(2/3) × N⌉ where N is total governance key count.
 * EMERGENCY_ROLLBACK SHALL require quorum — §5.5.
 */
export function validateQuorum(
  governance: GovernanceModule,
  signatures: readonly { authority: string; signature: string }[],
): QuorumResult {
  const N = governance.authorities.length;
  const required = Math.ceil((2 / 3) * N);

  // Count distinct registered authorities who have signed
  const signingAuthorities = new Set(
    signatures
      .filter((s) => governance.authorities.includes(s.authority))
      .map((s) => s.authority),
  );

  const count = signingAuthorities.size;
  return { met: count >= required, count, required };
}

// ─── §5.8 Override Execution Semantics ───────────────────────────────────────

export type OverrideTrigger =
  | "FREEZE"
  | "RELEASE"
  | "BREACH"
  | "SEIZE"
  | "REDEMPTION"
  | "ROLLBACK";

/**
 * Maps governance action to the resulting state transition trigger.
 */
export function governanceActionToTrigger(action: GovernanceAction): OverrideTrigger | null {
  switch (action) {
    case GovernanceAction.FREEZE_BALANCE:     return "FREEZE";
    case GovernanceAction.UNFREEZE_BALANCE:   return "RELEASE";
    case GovernanceAction.RESTRICT_TRANSFER:  return "BREACH";
    case GovernanceAction.SEIZE_ASSET:        return "SEIZE";
    case GovernanceAction.FORCE_REDEMPTION:   return "REDEMPTION";
    case GovernanceAction.EMERGENCY_ROLLBACK: return "ROLLBACK";
    default:                                  return null;
  }
}

// ─── §5.10 Override Logging ───────────────────────────────────────────────────

export interface OverrideRecord {
  readonly recordHash: string;
  readonly overrideId: string;
  readonly authority:  string;
  readonly action:     GovernanceAction;
  readonly timestamp:  number;
  readonly immutable:  true; // marker — records are never deleted
}

/**
 * Override_Record = H(OID || AUTH || ACTION || TS) — §5.10
 * Records are immutable and append-only.
 */
export function createOverrideRecord(override: OverrideObject): OverrideRecord {
  const recordHash = constructOverrideHash(
    override.overrideId,
    override.authority,
    override.action,
    override.timestamp,
  );

  return {
    recordHash,
    overrideId: override.overrideId,
    authority:  override.authority,
    action:     override.action,
    timestamp:  override.timestamp,
    immutable:  true,
  };
}

// ─── §5.12 Separation of Duties ──────────────────────────────────────────────

/**
 * Validates that no single key controls both issuance and override authority.
 * §5.12: governance authority SHALL be separable from issuer authority.
 */
export function validateSeparationOfDuties(
  issuerPubKey: string,
  governance: GovernanceModule,
): boolean {
  return !governance.authorities.includes(issuerPubKey);
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

/**
 * In a production implementation, authority identifiers would resolve to
 * registered public keys via a governance registry.
 * Here we treat the authority string as the public key itself (simplified).
 */
function resolveAuthorityPubKey(
  authority: string,
  _governance: GovernanceModule,
): string | null {
  // Implementer provides registry lookup
  // Simplified: treat authority as pubkey hex
  return authority.length >= 64 ? authority : null;
}
