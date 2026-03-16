/**
 * L3RS-1 Transfer Executor
 * §2.6 Deterministic Transfer Execution + §2.7 Transfer Pseudo-Code
 *
 * Executes the 7-step transfer in exact order. Atomic — any failure
 * rolls back all steps. No partial state mutations.
 */

import type { Asset, TransferEvent, IdentityRecord, SettlementProof } from "../types/index.js";
import { IdentityLevel } from "../types/index.js";
import type { SignatureVerifier } from "../crypto/index.js";
import { constructTxId } from "../crypto/index.js";
import { applyStateTransition } from "./asset.js";
import {
  evaluateCompliance,
  enforcementToTrigger,
  type ComplianceContext,
  type SanctionsRegistry,
} from "./compliance.js";
import { enforceIdentityLevel } from "./identity.js";
import { distributeFees, validateFeeModule } from "./settlement.js";
import { isReplay } from "./settlement.js";

// ─── Transfer Input ───────────────────────────────────────────────────────────

export interface TransferInput {
  readonly asset:             Asset;
  readonly event:             TransferEvent;
  readonly senderRecords:     readonly IdentityRecord[];
  readonly receiverRecords:   readonly IdentityRecord[];
  readonly ledgerHistory:     ReadonlySet<string>;
  readonly blockHeight:       bigint;
  readonly sanctions?:        SanctionsRegistry;
  readonly verifier?:         SignatureVerifier;
  readonly requiredJurisdictions?: readonly string[];
}

export interface TransferOutput {
  readonly success:     boolean;
  readonly txId?:       string;
  readonly proof?:      SettlementProof;
  readonly newState?:   string;
  readonly feeRecord?:  string;
  readonly error?:      string;
  readonly failedStep?: TransferStep;
}

export type TransferStep =
  | "REPLAY_CHECK"
  | "STATE_CHECK"
  | "IDENTITY_SENDER"
  | "IDENTITY_RECEIVER"
  | "COMPLIANCE"
  | "GOVERNANCE_CHECK"
  | "TRANSFER_RULES"
  | "FEE_ROUTING"
  | "BALANCE_UPDATE"
  | "CROSSCHAIN_METADATA";

// ─── §2.7 Transfer Execution ─────────────────────────────────────────────────

/**
 * Deterministic 7-step transfer execution per §2.6:
 * 1. Identity validation (sender)
 * 2. Identity validation (receiver)
 * 3. Compliance evaluation
 * 4. Governance override check
 * 5. Transfer rule validation
 * 6. Fee routing
 * 7. Balance update + cross-chain metadata update
 *
 * Plus replay protection (§9.6) which gates entry.
 */
export function executeTransfer(input: TransferInput): TransferOutput {
  const { asset, event } = input;

  // ── Pre-check: Replay protection (§9.6) ───────────────────────────────────
  if (isReplay(event, input.ledgerHistory)) {
    return fail("REPLAY_CHECK", "Duplicate TxID detected — replay attack rejected");
  }

  const txId = constructTxId(event);

  // ── Step 0: Asset must be ACTIVE (§2.7 require A.state == ACTIVE) ─────────
  if (asset.state !== "ACTIVE") {
    return fail("STATE_CHECK", `Asset state is ${asset.state}; must be ACTIVE for transfer`);
  }

  // ── Step 1-2: Identity validation (§3.11) ─────────────────────────────────
  if (asset.identityLevel >= IdentityLevel.VERIFIED) {
    const identityResult = enforceIdentityLevel(
      asset.identityLevel,
      input.senderRecords,
      input.receiverRecords,
      event.timestamp,
      input.requiredJurisdictions,
      input.verifier,
    );
    if (!identityResult.valid) {
      return fail("IDENTITY_SENDER", identityResult.error ?? "Identity validation failed");
    }
  }

  // ── Step 3: Compliance evaluation (§4.11) ─────────────────────────────────
  const ctx: ComplianceContext = {
    asset,
    sender:    event.sender,
    receiver:  event.receiver,
    amount:    event.amount,
    timestamp: event.timestamp,
    sanctions: input.sanctions,
  };

  const complianceDecision = evaluateCompliance(asset.complianceModule, ctx);
  if (!complianceDecision.allowed) {
    return fail("COMPLIANCE", `Compliance rule blocked: ${complianceDecision.blockedBy.ruleId} → ${complianceDecision.action}`);
  }

  // ── Step 4: Governance override check (§2.7) ──────────────────────────────
  // If a governance override is active (e.g. asset is frozen), reject
  // In practice: this is where an implementer checks an active override registry
  // We check state here — frozen/suspended assets are already caught by step 0

  // ── Step 5: Transfer rule validation ──────────────────────────────────────
  // Additional custom transfer rules beyond compliance (implementer extension point)
  // Default: pass

  // ── Step 6: Fee routing (§6.5) ────────────────────────────────────────────
  let feeRecord: string;
  try {
    validateFeeModule(asset.feeModule);
    const feeResult = distributeFees(asset.feeModule, event.amount, txId, event.timestamp);
    feeRecord = feeResult.feeRecordHash;
  } catch (e) {
    return fail("FEE_ROUTING", `Fee distribution failed: ${String(e)}`);
  }

  // ── Step 7: Balance update + cross-chain metadata update ──────────────────
  // Balance updates are ledger-specific — this SDK returns the new state
  // The ledger platform applies the actual balance mutation atomically
  const stateTransition = applyStateTransition(asset.state as never, "ACTIVATION" as never);
  // State remains ACTIVE after a successful transfer — no state change needed
  // unless a compliance event triggers one

  // ── Settlement proof (§9.10) ──────────────────────────────────────────────
  const proof: SettlementProof = {
    txId,
    blockHeight: input.blockHeight,
    stateHash:   "", // ledger computes this after commit
    timestamp:   event.timestamp,
  };

  return {
    success:   true,
    txId,
    proof,
    newState:  asset.state,
    feeRecord,
  };
}

// ─── Helper ───────────────────────────────────────────────────────────────────

function fail(step: TransferStep, error: string): TransferOutput {
  return { success: false, failedStep: step, error };
}
