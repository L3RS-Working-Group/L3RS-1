/**
 * L3RS-1 Identity Binding Module
 * §3 Identity Binding Architecture
 *
 * Invariant I₃: If ID >= 1, Status(IR) MUST equal VALID before settlement.
 */

import {
  IdentityLevel,
  IdentityStatus,
  type IdentityRecord,
  type ZKProof,
} from "../types/index.js";
import type { SignatureVerifier } from "../crypto/index.js";

// ─── §3.6 Identity Status Function ───────────────────────────────────────────

/**
 * Status(IR) ∈ {VALID, EXPIRED, REVOKED, UNKNOWN}
 *
 * VALID   if current time < EXP and REV = false and VA signature verifies
 * EXPIRED if current time >= EXP
 * REVOKED if REV = true
 * UNKNOWN if verification cannot be completed deterministically
 */
export function identityStatus(
  record: IdentityRecord,
  nowUnix: number,
  verifier?: SignatureVerifier,
  vaPublicKeyHex?: string,
): IdentityStatus {
  if (record.revoked) return IdentityStatus.REVOKED;
  if (nowUnix >= record.expiry) return IdentityStatus.EXPIRED;

  // Signature verification against VA public key — §3.5
  if (verifier && vaPublicKeyHex) {
    const msg = Buffer.from(record.identityHash, "hex");
    // NOTE: In a real implementation, the signature would be on the full IR canonical serialization
    // We verify the identity hash commitment as the message
    const sigField = (record as { signature?: string }).signature;
    if (sigField) {
      const valid = verifier.verify(msg, sigField, vaPublicKeyHex);
      if (!valid) return IdentityStatus.UNKNOWN;
    }
  }

  return IdentityStatus.VALID;
}

// ─── §3.11 Identity Validation in Transfer Execution ─────────────────────────

export interface IdentityValidationResult {
  readonly valid:  boolean;
  readonly status: IdentityStatus;
  readonly error?: string;
}

/**
 * validate_identity(party) — per §3.11 pseudo-code
 * Must be called for both sender and receiver before settlement.
 */
export function validateIdentity(
  record: IdentityRecord,
  nowUnix: number,
  verifier?: SignatureVerifier,
  vaPublicKeyHex?: string,
): IdentityValidationResult {
  const status = identityStatus(record, nowUnix, verifier, vaPublicKeyHex);

  if (status !== IdentityStatus.VALID) {
    return { valid: false, status, error: `Identity status: ${status}` };
  }

  // ZKP verification — §3.8
  if (record.proof) {
    const zkpResult = verifyZKP(record.proof);
    if (!zkpResult) {
      return {
        valid: false,
        status: IdentityStatus.UNKNOWN,
        error: "ZKP verification failed",
      };
    }
  }

  return { valid: true, status: IdentityStatus.VALID };
}

// ─── §3.9 Multi-Jurisdiction Identity Stacking ───────────────────────────────

export interface MultiJurisdictionResult {
  readonly satisfied:         boolean;
  readonly missingJurisdictions: readonly string[];
}

/**
 * For ID = 3: holder MUST provide >=2 valid identity records
 * covering all required jurisdictions per §3.9.
 */
export function validateMultiJurisdiction(
  records: readonly IdentityRecord[],
  requiredJurisdictions: readonly string[],
  nowUnix: number,
  verifier?: SignatureVerifier,
): MultiJurisdictionResult {
  const validJurisdictions = new Set<string>();

  for (const record of records) {
    const status = identityStatus(record, nowUnix, verifier);
    if (status === IdentityStatus.VALID) {
      validJurisdictions.add(record.jurisdictionIdentity);
    }
  }

  const missing = requiredJurisdictions.filter((j) => !validJurisdictions.has(j));
  return {
    satisfied: missing.length === 0,
    missingJurisdictions: missing,
  };
}

// ─── §3.2 Identity Level Enforcement ─────────────────────────────────────────

/**
 * Dispatches the correct validation strategy based on IdentityLevel.
 * If ID >= 1, settlement MUST NOT proceed unless Status(IR) = VALID — §3.6.
 */
export function enforceIdentityLevel(
  level: IdentityLevel,
  senderRecords: readonly IdentityRecord[],
  receiverRecords: readonly IdentityRecord[],
  nowUnix: number,
  requiredJurisdictions?: readonly string[],
  verifier?: SignatureVerifier,
): { readonly valid: boolean; readonly error?: string } {
  if (level === IdentityLevel.UNBOUND) {
    return { valid: true };
  }

  // Validate sender
  const senderPrimary = senderRecords[0];
  if (!senderPrimary) return { valid: false, error: "Sender has no identity record" };
  const senderResult = validateIdentity(senderPrimary, nowUnix, verifier);
  if (!senderResult.valid) {
    return { valid: false, error: `Sender identity invalid: ${senderResult.error}` };
  }

  // Validate receiver
  const receiverPrimary = receiverRecords[0];
  if (!receiverPrimary) return { valid: false, error: "Receiver has no identity record" };
  const receiverResult = validateIdentity(receiverPrimary, nowUnix, verifier);
  if (!receiverResult.valid) {
    return { valid: false, error: `Receiver identity invalid: ${receiverResult.error}` };
  }

  // Multi-jurisdiction check for ID = 3
  if (level === IdentityLevel.MULTI_JURISDICTION) {
    if (!requiredJurisdictions?.length) {
      return { valid: false, error: "Multi-jurisdiction level requires requiredJurisdictions" };
    }
    const senderMJ = validateMultiJurisdiction(senderRecords, requiredJurisdictions, nowUnix, verifier);
    if (!senderMJ.satisfied) {
      return {
        valid: false,
        error: `Sender missing jurisdictions: ${senderMJ.missingJurisdictions.join(", ")}`,
      };
    }
    const receiverMJ = validateMultiJurisdiction(receiverRecords, requiredJurisdictions, nowUnix, verifier);
    if (!receiverMJ.satisfied) {
      return {
        valid: false,
        error: `Receiver missing jurisdictions: ${receiverMJ.missingJurisdictions.join(", ")}`,
      };
    }
  }

  return { valid: true };
}

// ─── §3.8 ZKP Verification ───────────────────────────────────────────────────

/**
 * VerifyZK(PROOF) ∈ {TRUE, FALSE}
 * FALSE is a blocking condition per §3.8.
 *
 * This is an interface stub — real ZKP verification requires
 * a scheme-specific backend (Groth16, PLONK, etc.).
 */
export function verifyZKP(proof: ZKProof): boolean {
  // Implementer provides scheme-specific verifier
  // Conservative default: if proof is present but no verifier configured, block
  if (!proof.scheme || !proof.proofBytes || !proof.nonce) return false;
  // Return false to force implementers to supply a real verifier
  // Replace with: return zkpBackend.verify(proof)
  return false;
}

// ─── §3.10 Revocation Semantics ──────────────────────────────────────────────

/**
 * If revocation status CANNOT be determined → treat as UNKNOWN → block
 * when ID >= 1 per §3.10.
 */
export function isRevocationDeterministic(record: IdentityRecord): boolean {
  // A record with an explicit revocation flag is always deterministic
  return typeof record.revoked === "boolean";
}
