/**
 * L3RS-1 Asset State Machine
 * §2.4 Asset State Machine + §2.5 State Transition Matrix
 *
 * All transitions are deterministic and atomic per §2.5.
 * Invariant I₁: state transitions occur ONLY via validated functions.
 */

import { AssetState, type Asset } from "../types/index.js";

// ─── §2.5 State Transition Matrix ────────────────────────────────────────────

type StateTrigger =
  | "ACTIVATION"
  | "BREACH"
  | "FREEZE"
  | "CLEARED"
  | "RELEASE"
  | "REDEMPTION"
  | "FINALIZATION"
  | "SUSPENSION"
  | "REINSTATEMENT";

interface Transition {
  readonly from:    AssetState;
  readonly trigger: StateTrigger;
  readonly to:      AssetState;
}

/** Exact state transition matrix from §2.5 */
const TRANSITION_MATRIX: readonly Transition[] = [
  { from: AssetState.ISSUED,     trigger: "ACTIVATION",    to: AssetState.ACTIVE     },
  { from: AssetState.ACTIVE,     trigger: "BREACH",        to: AssetState.RESTRICTED },
  { from: AssetState.ACTIVE,     trigger: "FREEZE",        to: AssetState.FROZEN     },
  { from: AssetState.RESTRICTED, trigger: "CLEARED",       to: AssetState.ACTIVE     },
  { from: AssetState.FROZEN,     trigger: "RELEASE",       to: AssetState.ACTIVE     },
  { from: AssetState.ACTIVE,     trigger: "REDEMPTION",    to: AssetState.REDEEMED   },
  { from: AssetState.REDEEMED,   trigger: "FINALIZATION",  to: AssetState.BURNED     },
  { from: AssetState.ACTIVE,     trigger: "SUSPENSION",    to: AssetState.SUSPENDED  },
  { from: AssetState.SUSPENDED,  trigger: "REINSTATEMENT", to: AssetState.ACTIVE     },
];

// ─── Public API ──────────────────────────────────────────────────────────────

export interface StateTransitionResult {
  readonly success:   boolean;
  readonly newState?: AssetState;
  readonly error?:    string;
}

/**
 * Validates and applies a state transition per §2.5.
 * Returns new state if valid; error if not.
 * Does NOT mutate the asset — returns the new state value only.
 */
export function applyStateTransition(
  currentState: AssetState,
  trigger: StateTrigger,
): StateTransitionResult {
  // BURNED is a terminal state — §2.4
  if (currentState === AssetState.BURNED) {
    return { success: false, error: "BURNED is a terminal state; no further transitions permitted" };
  }

  const match = TRANSITION_MATRIX.find(
    (t) => t.from === currentState && t.trigger === trigger,
  );

  if (!match) {
    return {
      success: false,
      error: `No valid transition from ${currentState} via trigger ${trigger}`,
    };
  }

  return { success: true, newState: match.to };
}

/**
 * Returns true if the given transition is valid per §2.5.
 */
export function isValidTransition(
  from: AssetState,
  trigger: StateTrigger,
): boolean {
  return TRANSITION_MATRIX.some((t) => t.from === from && t.trigger === trigger);
}

/**
 * Returns all valid triggers from a given state.
 */
export function validTriggersFrom(state: AssetState): readonly StateTrigger[] {
  return TRANSITION_MATRIX
    .filter((t) => t.from === state)
    .map((t) => t.trigger);
}

/**
 * §2.1 — Validates an asset object's state is a valid AssetState enum value.
 * Enforces §13.14 strict validation.
 */
export function validateAssetState(state: unknown): state is AssetState {
  return Object.values(AssetState).includes(state as AssetState);
}

/**
 * §13.2 — Validates that an asset's required fields are present and well-formed.
 * Throws on any violation per §13.14 strict validation rules.
 */
export function validateAsset(asset: unknown): asserts asset is Asset {
  if (typeof asset !== "object" || asset === null) {
    throw new Error("Asset must be a non-null object");
  }
  const a = asset as Record<string, unknown>;

  const required = [
    "assetId", "assetType", "jurisdiction", "legalMirror",
    "identityLevel", "complianceModule", "governanceModule",
    "feeModule", "crossChainMetadata", "state", "standardVersion",
  ] as const;

  for (const field of required) {
    if (!(field in a)) {
      throw new Error(`Missing required field: ${field}`);
    }
  }

  if (!validateAssetState(a["state"])) {
    throw new Error(`Invalid AssetState value: ${String(a["state"])}`);
  }

  if (typeof a["jurisdiction"] !== "string" || !/^[A-Z]{2}$/.test(a["jurisdiction"] as string)) {
    throw new Error("Jurisdiction must be ISO 3166-1 alpha-2 (two uppercase letters)");
  }

  if (typeof a["standardVersion"] !== "string" || !a["standardVersion"].startsWith("L3RS-")) {
    throw new Error('standardVersion must start with "L3RS-"');
  }
}

export type { StateTrigger };
