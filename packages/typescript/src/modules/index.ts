/** L3RS-1 Core Modules — TypeScript */
import { constructTxId } from "../crypto/index.js";
import { AssetState, ComplianceDecision, ComplianceModule, EnforcementAction, FeeModule, IdentityLevel, IdentityStatus, RuleType, TransferEvent } from "../types/index.js";

// ── §2.5 State Transitions ───────────────────────────────────────────────────

const TRANSITIONS: [AssetState, string, AssetState][] = [
  [AssetState.ISSUED,     "ACTIVATION",    AssetState.ACTIVE],
  [AssetState.ACTIVE,     "BREACH",        AssetState.RESTRICTED],
  [AssetState.ACTIVE,     "FREEZE",        AssetState.FROZEN],
  [AssetState.RESTRICTED, "CLEARED",       AssetState.ACTIVE],
  [AssetState.FROZEN,     "RELEASE",       AssetState.ACTIVE],
  [AssetState.ACTIVE,     "REDEMPTION",    AssetState.REDEEMED],
  [AssetState.REDEEMED,   "FINALIZATION",  AssetState.BURNED],
  [AssetState.ACTIVE,     "SUSPENSION",    AssetState.SUSPENDED],
  [AssetState.SUSPENDED,  "REINSTATEMENT", AssetState.ACTIVE],
];

export function applyStateTransition(
  current: AssetState,
  trigger: string,
): { success: boolean; newState?: AssetState; error?: string } {
  if (current === AssetState.BURNED) {
    return { success: false, error: "BURNED is a terminal state" };
  }
  const match = TRANSITIONS.find(([f, t]) => f === current && t === trigger);
  if (match) return { success: true, newState: match[2] };
  return { success: false, error: `No transition from ${current} via ${trigger}` };
}

// ── §4 Compliance ────────────────────────────────────────────────────────────

const BLOCKING = new Set([EnforcementAction.REJECT, EnforcementAction.FREEZE, EnforcementAction.RESTRICT]);

export function evaluateCompliance(
  module: ComplianceModule,
  state: AssetState,
  sender: string,
  receiver: string,
  amount: bigint,
  timestamp: number,
  jurisdiction: string,
): ComplianceDecision {
  if (state !== AssetState.ACTIVE) {
    return { allowed: false };
  }
  const sorted = [...module.rules].sort((a, b) => a.priority - b.priority);
  for (const rule of sorted) {
    if (rule.scope !== "*" && rule.scope !== jurisdiction) continue;
    let passes = true;
    if (rule.ruleType === RuleType.HOLDING_PERIOD) {
      const acq = rule.params["acquisitionTime"] as number | undefined;
      const period = rule.params["holdingPeriodSec"] as number | undefined;
      if (acq == null || period == null) passes = false;
      else passes = (timestamp - acq) >= period;
    } else if (rule.ruleType === RuleType.TRANSACTION_THRESHOLD) {
      const t = rule.params["thresholdAmount"] as bigint | number | undefined;
      if (t == null) passes = false;
      else passes = amount <= BigInt(t);
    } else {
      passes = (rule.params["externalResult"] as boolean | undefined) ?? false;
    }
    if (!passes && BLOCKING.has(rule.action)) {
      return { allowed: false, blockedBy: rule, action: rule.action };
    }
  }
  return { allowed: true };
}

// ── §6.12 Fee Validation ─────────────────────────────────────────────────────

export function validateFeeModule(fee: FeeModule): void {
  const total = fee.allocations.reduce((s, a) => s + a.basisPoints, 0);
  if (total !== 10_000) throw new Error(`Fee allocations must sum to 10000; got ${total}`);
  if (fee.allocations.some(a => a.basisPoints < 0)) throw new Error("Negative allocation");
}

// ── §3.6 Identity Status ─────────────────────────────────────────────────────

export interface IdentityRecord {
  identityHash: string;
  verificationAuthority: string;
  jurisdictionIdentity: string;
  expiry: number;
  revoked: boolean;
}

export function identityStatus(record: IdentityRecord, nowUnix: number): IdentityStatus {
  if (record.revoked) return IdentityStatus.REVOKED;
  if (nowUnix >= record.expiry) return IdentityStatus.EXPIRED;
  return IdentityStatus.VALID;
}

// ── §9.6 Replay Protection ───────────────────────────────────────────────────

export function isReplay(event: TransferEvent, ledgerHistory: Set<string>): boolean {
  const txId = constructTxId(
    event.sender, event.receiver, event.amount, event.nonce, event.timestamp,
  );
  return ledgerHistory.has(txId);
}
