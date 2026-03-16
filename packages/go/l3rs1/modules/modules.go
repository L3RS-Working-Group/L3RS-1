// Package modules implements L3RS-1 core protocol modules.
package modules

import (
	"fmt"
	"math"
	"sort"

	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/crypto"
	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/types"
)

// ── §2.5 State Machine ───────────────────────────────────────────────────────

type transition struct {
	from    types.AssetState
	trigger string
	to      types.AssetState
}

var transitionMatrix = []transition{
	{types.AssetStateIssued,     "ACTIVATION",    types.AssetStateActive},
	{types.AssetStateActive,     "BREACH",        types.AssetStateRestricted},
	{types.AssetStateActive,     "FREEZE",        types.AssetStateFrozen},
	{types.AssetStateRestricted, "CLEARED",       types.AssetStateActive},
	{types.AssetStateFrozen,     "RELEASE",       types.AssetStateActive},
	{types.AssetStateActive,     "REDEMPTION",    types.AssetStateRedeemed},
	{types.AssetStateRedeemed,   "FINALIZATION",  types.AssetStateBurned},
	{types.AssetStateActive,     "SUSPENSION",    types.AssetStateSuspended},
	{types.AssetStateSuspended,  "REINSTATEMENT", types.AssetStateActive},
}

// StateTransitionResult holds the outcome of a state transition attempt.
type StateTransitionResult struct {
	Success  bool
	NewState types.AssetState
	Error    string
}

// ApplyStateTransition implements §2.5 deterministic state machine.
func ApplyStateTransition(current types.AssetState, trigger string) StateTransitionResult {
	if current.IsTerminal() {
		return StateTransitionResult{Error: "BURNED is a terminal state"}
	}
	for _, row := range transitionMatrix {
		if row.from == current && trigger == row.trigger {
			return StateTransitionResult{Success: true, NewState: row.to}
		}
	}
	return StateTransitionResult{Error: fmt.Sprintf("no transition from %s via %s", current, trigger)}
}

// ── §4 Compliance ────────────────────────────────────────────────────────────

// EvaluateCompliance implements C: E → {0,1} per §4.3.
func EvaluateCompliance(
	module *types.ComplianceModule,
	state types.AssetState,
	sender, receiver string,
	amount uint64,
	timestamp int64,
	jurisdiction string,
) types.ComplianceDecision {
	if state != types.AssetStateActive {
		return types.ComplianceDecision{Allowed: false}
	}
	rules := make([]types.ComplianceRule, len(module.Rules))
	copy(rules, module.Rules)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })

	for i := range rules {
		rule := &rules[i]
		if rule.Scope != "*" && rule.Scope != jurisdiction {
			continue
		}
		passes := evalRule(rule, amount, timestamp)
		if !passes && rule.Action.IsBlocking() {
			return types.ComplianceDecision{Allowed: false, BlockedBy: rule, Action: rule.Action}
		}
	}
	return types.ComplianceDecision{Allowed: true}
}

func evalRule(rule *types.ComplianceRule, amount uint64, timestamp int64) bool {
	switch rule.RuleType {
	case types.RuleTypeHoldingPeriod:
		acq, ok1 := numParam(rule.Params, "acquisitionTime")
		period, ok2 := numParam(rule.Params, "holdingPeriodSec")
		if !ok1 || !ok2 {
			return false
		}
		return (timestamp - acq) >= period
	case types.RuleTypeTransactionThreshold:
		t, ok := numParam(rule.Params, "thresholdAmount")
		if !ok {
			return false
		}
		return int64(amount) <= t
	default:
		result, ok := rule.Params["externalResult"].(bool)
		return ok && result
	}
}

func numParam(params map[string]any, key string) (int64, bool) {
	v, ok := params[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

// ── §6.12 Fee Validation ─────────────────────────────────────────────────────

// ValidateFeeModule enforces §6.12 economic integrity constraint.
func ValidateFeeModule(fee *types.FeeModule) error {
	total := 0
	for _, a := range fee.Allocations {
		if a.BasisPoints < 0 {
			return fmt.Errorf("negative allocation not permitted")
		}
		total += a.BasisPoints
	}
	if total != 10_000 {
		return fmt.Errorf("fee allocations must sum to 10000; got %d", total)
	}
	return nil
}

// ── §3.6 Identity Status ─────────────────────────────────────────────────────

// IdentityStatus computes Status(IR) per §3.6.
func IdentityStatus(record *types.IdentityRecord, nowUnix int64) types.IdentityStatus {
	if record.Revoked {
		return types.IdentityStatusRevoked
	}
	if nowUnix >= record.Expiry {
		return types.IdentityStatusExpired
	}
	return types.IdentityStatusValid
}

// ── §5.5 Quorum Validation ───────────────────────────────────────────────────

// ValidateQuorum checks ⌈2/3 × N⌉ signatures are present.
func ValidateQuorum(authorities []string, signatures []string) (bool, int, int) {
	N := len(authorities)
	required := int(math.Ceil(float64(2*N) / 3.0))
	authSet := map[string]bool{}
	for _, a := range authorities {
		authSet[a] = true
	}
	signed := map[string]bool{}
	for _, s := range signatures {
		if authSet[s] {
			signed[s] = true
		}
	}
	return len(signed) >= required, len(signed), required
}

// ── §9.6 Replay Protection ───────────────────────────────────────────────────

// IsReplay returns true if the event's TxID is in ledger history.
func IsReplay(event *types.TransferEvent, ledgerHistory map[string]bool) (bool, error) {
	txID, err := crypto.ConstructTxID(
		event.Sender, event.Receiver, event.Amount, event.Nonce, event.Timestamp,
	)
	if err != nil {
		return false, err
	}
	return ledgerHistory[txID], nil
}
