/**
 * @l3rs1/sdk — L3RS-1 Reference Implementation
 * Layer-3 Regulated Asset Standard v1.0.0 — CROSSCHAIN Conformance
 *
 * Pure deterministic library. No I/O, no transport, no ledger coupling.
 * Implements all invariants I₁–I₁₁ per §10 and §15.
 */

export * from "./types/index.js";
export * from "./crypto/index.js";
export * from "./modules/asset.js";
export * from "./modules/compliance.js";
export * from "./modules/identity.js";
export * from "./modules/governance.js";
export * from "./modules/transfer.js";
export * from "./modules/settlement.js";

export const SDK_VERSION     = "1.0.0";
export const STANDARD_VERSION = "L3RS-1.0.0";
export const CONFORMANCE_CLASS = "CROSSCHAIN";
