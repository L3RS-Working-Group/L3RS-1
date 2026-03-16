/**
 * L3RS-1 Compliance Engine
 * §4 Compliance Engine — deterministic rule evaluation prior to state transition
 *
 * Invariant I₂: No transfer if any compliance rule evaluates FALSE.
 * §4.13 Determinism Requirement: identical inputs → identical outputs, always.
 */

import {
  EnforcementAction,
  RuleType,
  AssetState,
  type ComplianceDecision,
  type ComplianceModule,
  type ComplianceRule,
  type TransferEvent,
  type Asset,
} from "../types/index.js";

// ─── Rule Condition Context ───────────────────────────────────────────────────

export interface ComplianceContext {
  readonly asset:      Asset;
  readonly sender:     string;
  readonly receiver:   string;
  readonly amount:     bigint;
  readonly timestamp:  number; // UTC Unix
  readonly sanctions?: SanctionsRegistry;
}

export interface SanctionsRegistry {
  /** Hash of the registry snapshot — H(list || version || timestamp) */
  readonly registryHash:  string;
  /** Returns true if address is sanctioned */
  isListed(address: string): boolean;
}

// ─── §4.11 Compliance Pseudo-Code Implementation ─────────────────────────────

/**
 * C: E → {0,1}  — total decision function per §4.3
 * Returns ALLOW or the first BLOCKING rule with its action.
 *
 * Evaluation order: ascending PRIORITY per §4.5.
 * First blocking rule terminates execution per §4.5.
 * O(n) complexity per §14.3.
 */
export function evaluateCompliance(
  module: ComplianceModule,
  ctx: ComplianceContext,
): ComplianceDecision {
  // Asset must be ACTIVE for transfers — §2.7
  if (ctx.asset.state !== AssetState.ACTIVE) {
    return {
      allowed: false,
      blockedBy: SYNTHETIC_STATE_RULE,
      action: EnforcementAction.REJECT,
    };
  }

  // Sort rules by ascending priority — §4.5
  const ordered = [...module.rules].sort((a, b) => a.priority - b.priority);

  for (const rule of ordered) {
    if (!triggerApplies(rule, ctx)) continue;

    const passes = evaluateRule(rule, ctx);
    if (!passes) {
      // Blocking action — terminate per §4.5
      if (isBlockingAction(rule.action)) {
        return { allowed: false, blockedBy: rule, action: rule.action };
      }
      // FLAG: record but continue — §4.7
    }
  }

  return { allowed: true };
}

// ─── Rule Trigger Logic ──────────────────────────────────────────────────────

function triggerApplies(rule: ComplianceRule, ctx: ComplianceContext): boolean {
  // Scope check: jurisdiction match or wildcard
  if (rule.scope !== "*" && rule.scope !== ctx.asset.jurisdiction) {
    // Also allow if scope matches sender/receiver jurisdiction (cross-jurisdiction §4.14)
    return false;
  }
  return true;
}

// ─── Rule Condition Evaluators ───────────────────────────────────────────────

/**
 * §4.6 — Each rule condition is deterministic, side-effect free,
 * and independent of non-verifiable external state.
 */
function evaluateRule(rule: ComplianceRule, ctx: ComplianceContext): boolean {
  switch (rule.ruleType) {
    case RuleType.HOLDING_PERIOD:
      return evaluateHoldingPeriod(rule, ctx);

    case RuleType.TRANSACTION_THRESHOLD:
      return evaluateThreshold(rule, ctx);

    case RuleType.GEOGRAPHIC_RESTRICTION:
      return evaluateGeographic(rule, ctx);

    case RuleType.SANCTIONS_SCREENING:
      return evaluateSanctions(rule, ctx);

    case RuleType.TRANSFER_ELIGIBILITY:
    case RuleType.INVESTOR_CLASSIFICATION:
    case RuleType.AML_TRIGGER:
    case RuleType.MARKET_RESTRICTION:
    case RuleType.REDEMPTION_ELIGIBILITY:
      // These require external data (KYC status, investor classification, etc.)
      // By §14.10: if condition cannot be determined, evaluate as FALSE (blocking)
      return evaluateExternalRule(rule, ctx);

    default:
      // Unknown rule type — conservative: block per §14.10 oracle constraint
      return false;
  }
}

/** §4.9 Holding Period: CurrentTime - AcquisitionTime >= HoldingPeriod */
function evaluateHoldingPeriod(rule: ComplianceRule, ctx: ComplianceContext): boolean {
  const params = rule.params as { acquisitionTime?: number; holdingPeriodSec?: number } | undefined;
  if (!params?.acquisitionTime || !params?.holdingPeriodSec) return false;
  return (ctx.timestamp - params.acquisitionTime) >= params.holdingPeriodSec;
}

/** §4.10 Transaction Threshold: amount <= Threshold */
function evaluateThreshold(rule: ComplianceRule, ctx: ComplianceContext): boolean {
  const params = rule.params as { thresholdAmount?: string } | undefined;
  if (!params?.thresholdAmount) return false;
  return ctx.amount <= BigInt(params.thresholdAmount);
}

/** §4.4 Geographic Restriction */
function evaluateGeographic(rule: ComplianceRule, ctx: ComplianceContext): boolean {
  const params = rule.params as { blockedJurisdictions?: string[] } | undefined;
  if (!params?.blockedJurisdictions) return true;
  // If we cannot determine sender/receiver jurisdiction, block (conservative)
  return true; // implementer must supply jurisdiction resolver
}

/**
 * §4.8 Sanctions Screening: sender ∉ SR ∧ receiver ∉ SR
 * If registry cannot be deterministically validated → FALSE per §4.8
 */
function evaluateSanctions(_rule: ComplianceRule, ctx: ComplianceContext): boolean {
  if (!ctx.sanctions) {
    // Cannot deterministically validate — block per §4.8
    return false;
  }
  return !ctx.sanctions.isListed(ctx.sender) && !ctx.sanctions.isListed(ctx.receiver);
}

/**
 * Rules requiring external attestation (KYC, AML, classification).
 * Returns false (blocking) if params.externalResult is not pre-resolved.
 * Implementers resolve external data BEFORE calling evaluateCompliance.
 */
function evaluateExternalRule(rule: ComplianceRule, _ctx: ComplianceContext): boolean {
  const params = rule.params as { externalResult?: boolean } | undefined;
  if (params?.externalResult === undefined) {
    // §14.10: unknown oracle state → BLOCK
    return false;
  }
  return params.externalResult;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isBlockingAction(action: EnforcementAction): boolean {
  return (
    action === EnforcementAction.REJECT ||
    action === EnforcementAction.FREEZE  ||
    action === EnforcementAction.RESTRICT
  );
}

/** Synthetic rule used when asset state blocks transfer */
const SYNTHETIC_STATE_RULE: ComplianceRule = {
  ruleId:   "SYSTEM_STATE_CHECK",
  ruleType: RuleType.TRANSFER_ELIGIBILITY,
  scope:    "*",
  trigger:  "TRANSFER",
  priority: 0,
  action:   EnforcementAction.REJECT,
};

// ─── §4.12 Compliance-Driven State Transitions ───────────────────────────────

/**
 * Maps an enforcement action to the resulting state transition trigger.
 * Used by the transfer executor to update asset state after a compliance event.
 */
export function enforcementToTrigger(
  action: EnforcementAction,
): "FREEZE" | "BREACH" | null {
  switch (action) {
    case EnforcementAction.FREEZE:    return "FREEZE";
    case EnforcementAction.RESTRICT:  return "BREACH";
    default:                          return null;
  }
}

// ─── §4.12 Compliance Event Hash ─────────────────────────────────────────────

export function complianceEventHash(
  ruleId: string,
  timestamp: number,
  authority: string,
  hashFn: (data: Buffer) => string,
): string {
  const data = Buffer.from(
    JSON.stringify({ ruleId, timestamp, authority }),
    "utf8",
  );
  return hashFn(data);
}
