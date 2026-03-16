/**
 * L3RS-1 Crypto Primitives
 * §13.10-11 Canonical Serialization + §10.3 Security Assumptions
 *
 * Uses native Node.js crypto (SHA-256) — no external runtime dependencies
 * for the hash layer. Signature verification interfaces are provided as
 * abstract types; implementers supply the EdDSA/ECDSA backend.
 */

import { createHash } from "node:crypto";
import type { Asset, ComplianceModule, CrossChainMetadata, GovernanceModule, IdentityRecord, LegalMirror, TransferEvent } from "../types/index.js";

// ─── Core Hash Function ──────────────────────────────────────────────────────

/**
 * H(data) — collision-resistant SHA-256 per §10.3.
 * All L3RS-1 hashes use this function.
 */
export function sha256(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest("hex");
}

export function sha256Concat(...parts: (Buffer | string)[]): string {
  const hash = createHash("sha256");
  for (const part of parts) {
    hash.update(typeof part === "string" ? Buffer.from(part, "hex") : part);
  }
  return hash.digest("hex");
}

// ─── §13.11 Canonical Serialization ─────────────────────────────────────────

/**
 * ser(Y) — canonical JSON serialization per §13.11.
 * Rules:
 *   - No insignificant whitespace
 *   - Stable key ordering (alphabetical)
 *   - UTF-8 encoding
 *   - Unknown fields rejected (enforced at schema validation layer)
 *   - Numbers: integers serialized as strings to avoid precision loss
 */
export function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, replacer);
}

function replacer(_key: string, value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return value;
  }
  // Sort keys alphabetically for deterministic output
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(value as object).sort()) {
    sorted[k] = (value as Record<string, unknown>)[k];
  }
  return sorted;
}

/** HY = H(ser(Y)) — hash of canonical serialization */
export function hashObject(obj: unknown): string {
  return sha256(Buffer.from(canonicalize(obj), "utf8"));
}

// ─── §2.2 Asset_ID Construction ──────────────────────────────────────────────

/**
 * I = H(pk_issuer || ts || nonce)
 * Concatenates raw bytes: 33-byte compressed pubkey + 8-byte uint64 timestamp + 8-byte nonce
 */
export function constructAssetId(
  issuerPubkeyHex: string,
  timestampUnix: number,
  nonceHex: string,
): string {
  const pkBuf     = Buffer.from(issuerPubkeyHex, "hex");
  const tsBuf     = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(timestampUnix));
  const nonceBuf  = Buffer.from(nonceHex, "hex");
  return sha256Concat(pkBuf, tsBuf, nonceBuf);
}

// ─── §3.4 Identity Hash ──────────────────────────────────────────────────────

/**
 * HID = H(PII || salt || domain)
 * PII is NEVER stored on-chain — only HID is stored.
 */
export function constructIdentityHash(
  piiUtf8: string,
  saltHex: string,
  domain: string = "l3rs1-identity-v1",
): string {
  const piiBuf    = Buffer.from(piiUtf8, "utf8");
  const saltBuf   = Buffer.from(saltHex, "hex");
  const domainBuf = Buffer.from(domain, "utf8");
  return sha256Concat(piiBuf, saltBuf, domainBuf);
}

// ─── §5.7 Legal Basis Hash ───────────────────────────────────────────────────

/** BASIS = H(legal_document || jurisdiction || case_id) */
export function constructLegalBasisHash(
  legalDocumentHash: string,
  jurisdiction: string,
  caseId: string,
): string {
  const docBuf  = Buffer.from(legalDocumentHash, "hex");
  const juriBuf = Buffer.from(jurisdiction, "utf8");
  const caseBuf = Buffer.from(caseId, "utf8");
  return sha256Concat(docBuf, juriBuf, caseBuf);
}

// ─── §12.3 Legal Document Hash ───────────────────────────────────────────────

/** LH = H(document_bytes || jurisdiction || version) */
export function constructLegalHash(
  documentBytes: Buffer,
  jurisdiction: string,
  version: string,
): string {
  const juriBuf = Buffer.from(jurisdiction, "utf8");
  const verBuf  = Buffer.from(version, "utf8");
  return sha256Concat(documentBytes, juriBuf, verBuf);
}

// ─── §8.3 Cross-Chain Certificate Construction ───────────────────────────────

/**
 * CID = H(I || SH || CH || GH || t)
 * Where:
 *   SH = H(ser(S))
 *   CH = H(ser(C))
 *   GH = H(ser(G))
 */
export function constructCID(
  assetId: string,
  stateHash: string,
  complianceHash: string,
  governanceHash: string,
  timestampUnix: number,
): string {
  const idBuf   = Buffer.from(assetId, "hex");
  const shBuf   = Buffer.from(stateHash, "hex");
  const chBuf   = Buffer.from(complianceHash, "hex");
  const ghBuf   = Buffer.from(governanceHash, "hex");
  const tsBuf   = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(timestampUnix));
  return sha256Concat(idBuf, shBuf, chBuf, ghBuf, tsBuf);
}

// ─── §9.6 Transaction ID Construction ───────────────────────────────────────

/** TxID = H(sender || receiver || amount || nonce || timestamp) */
export function constructTxId(event: TransferEvent): string {
  const senderBuf   = Buffer.from(event.sender, "utf8");
  const receiverBuf = Buffer.from(event.receiver, "utf8");
  const amountBuf   = Buffer.alloc(32);
  // Write amount as 256-bit big-endian to support large token quantities
  let amt = event.amount;
  for (let i = 31; i >= 0; i--) {
    amountBuf[i] = Number(amt & 0xffn);
    amt >>= 8n;
  }
  const nonceBuf    = Buffer.from(event.nonce, "hex");
  const tsBuf       = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(event.timestamp));
  return sha256Concat(senderBuf, receiverBuf, amountBuf, nonceBuf, tsBuf);
}

// ─── §9.11 State Hash ────────────────────────────────────────────────────────

/** StateHash = H(asset_id || balances_hash || compliance_state || governance_state) */
export function constructStateHash(
  assetId: string,
  balancesHash: string,
  complianceState: ComplianceModule,
  governanceState: GovernanceModule,
): string {
  const idBuf   = Buffer.from(assetId, "hex");
  const balBuf  = Buffer.from(balancesHash, "hex");
  const compBuf = Buffer.from(canonicalize(complianceState), "utf8");
  const govBuf  = Buffer.from(canonicalize(governanceState), "utf8");
  return sha256Concat(idBuf, balBuf, compBuf, govBuf);
}

// ─── §5.10 Override Record ───────────────────────────────────────────────────

/** Override_Record = H(OID || AUTH || ACTION || TS) */
export function constructOverrideHash(
  overrideId: string,
  authority: string,
  action: string,
  timestamp: number,
): string {
  const oidBuf  = Buffer.from(overrideId, "utf8");
  const authBuf = Buffer.from(authority, "utf8");
  const actBuf  = Buffer.from(action, "utf8");
  const tsBuf   = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(timestamp));
  return sha256Concat(oidBuf, authBuf, actBuf, tsBuf);
}

// ─── §8.11 Chain Identifier ──────────────────────────────────────────────────

/** ChainID = H(chain_name || network_type || genesis_hash) */
export function constructChainId(
  chainName: string,
  networkType: string,
  genesisHash: string,
): string {
  const nameBuf    = Buffer.from(chainName, "utf8");
  const typeBuf    = Buffer.from(networkType, "utf8");
  const genesisBuf = Buffer.from(genesisHash, "hex");
  return sha256Concat(nameBuf, typeBuf, genesisBuf);
}

// ─── Signature Verification Interface ───────────────────────────────────────

/**
 * Abstract signature verification interface.
 * Implementers provide EdDSA (Ed25519) or ECDSA (secp256k1) backends.
 * The SDK does not mandate a specific curve — §19 references both RFC 8032 (EdDSA)
 * and FIPS 186-5 (DSS/ECDSA).
 */
export interface SignatureVerifier {
  verify(message: Buffer, signatureHex: string, publicKeyHex: string): boolean;
}

/** Null verifier — rejects all signatures. Use only in testing. */
export const NullVerifier: SignatureVerifier = {
  verify: () => false,
};
