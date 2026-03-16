// Package modules implements L3RS-1 core modules for Go.
// asset · compliance · identity · governance · settlement · transfer
package modules

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"sort"

	"github.com/l3rs1/sdk/go/l3rs1/crypto"
	"github.com/l3rs1/sdk/go/l3rs1/types"
)

// ══════════════════════════════════════════════════════════════════════════════
// §2 Asset State Machine
// ══════════════════════════════════════════════════════════════════════════════

var transitionMatrix = [][3]string{
	{"ISSUED", "ACTIVATION", "ACTIVE"},
	{"ACTIVE", "BREACH", "RESTRICTED"},
	{"ACTIVE", "FREEZE", "FROZEN"},
	{"RESTRICTED", "CLEARED", "ACTIVE"},
	{"FROZEN", "RELEASE", "ACTIVE"},
	{"ACTIVE", "REDEMPTION", "REDEEMED"},
	{"REDEEMED", "FINALIZATION", "BURNED"},
	{"ACTIVE", "SUSPENSION", "SUSPENDED"},
	{"SUSPENDED", "REINSTATEMENT", "ACTIVE"},
}

// ApplyStateTransition applies §2.5 state transition matrix. Invariant I₁.
func ApplyStateTransition(current types.AssetState, trigger string) (types.AssetState, error) {
	if current == types.AssetStateBurned {
		return "", fmt.Errorf("BURNED is a terminal state")
	}
	for _, row := range transitionMatrix {
		if string(current) == row[0] && trigger == row[1] {
			return types.AssetState(row[2]), nil
		}
	}
	return "", fmt.Errorf("no transition from %s via %s", current, trigger)
}

// ValidateAsset enforces §13.14 strict validation rules.
func ValidateAsset(a *types.Asset) error {
	if len(a.Jurisdiction) != 2 {
		return fmt.Errorf("jurisdiction must be ISO 3166-1 alpha-2")
	}
	if len(a.StandardVersion) < 5 || a.StandardVersion[:5] != "L3RS-" {
		return fmt.Errorf("standardVersion must start with L3RS-")
	}
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// §4 Compliance Engine
// ══════════════════════════════════════════════════════════════════════════════

// SanctionsRegistry is the interface for sanctions list integration (§4.8).
type SanctionsRegistry interface {
	RegistryHash() string
	IsListed(address string) bool
}

// ComplianceContext holds all inputs for a compliance evaluation.
type ComplianceContext struct {
	Asset     *types.Asset
	Sender    string
	Receiver  string
	Amount    *big.Int
	Timestamp int64
	Sanctions SanctionsRegistry
}

var syntheticStateRule = types.ComplianceRule{
	RuleID:   "SYSTEM_STATE_CHECK",
	RuleType: types.RuleTypeTransferEligibility,
	Scope:    "*",
	Trigger:  "TRANSFER",
	Priority: 0,
	Action:   types.EnforcementReject,
}

// EvaluateCompliance implements C: E → {0,1} per §4.3. O(n) per §14.3.
func EvaluateCompliance(module *types.ComplianceModule, ctx *ComplianceContext) types.ComplianceDecision {
	if ctx.Asset.State != types.AssetStateActive {
		return types.ComplianceDecision{Allowed: false, BlockedBy: &syntheticStateRule, Action: types.EnforcementReject}
	}

	rules := make([]types.ComplianceRule, len(module.Rules))
	copy(rules, module.Rules)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })

	for i := range rules {
		if !triggerApplies(&rules[i], ctx) {
			continue
		}
		if !evaluateRule(&rules[i], ctx) && isBlocking(rules[i].Action) {
			return types.ComplianceDecision{Allowed: false, BlockedBy: &rules[i], Action: rules[i].Action}
		}
	}
	return types.ComplianceDecision{Allowed: true}
}

func triggerApplies(rule *types.ComplianceRule, ctx *ComplianceContext) bool {
	return rule.Scope == "*" || rule.Scope == ctx.Asset.Jurisdiction
}

func evaluateRule(rule *types.ComplianceRule, ctx *ComplianceContext) bool {
	switch rule.RuleType {
	case types.RuleTypeHoldingPeriod:
		acq, ok1 := numParam(rule.Params, "acquisitionTime")
		period, ok2 := numParam(rule.Params, "holdingPeriodSec")
		if !ok1 || !ok2 {
			return false
		}
		return (ctx.Timestamp - acq) >= period
	case types.RuleTypeTransactionThreshold:
		threshStr, ok := rule.Params["thresholdAmount"].(string)
		if !ok {
			return false
		}
		threshold := new(big.Int)
		if _, ok := threshold.SetString(threshStr, 10); !ok {
			return false
		}
		return ctx.Amount.Cmp(threshold) <= 0
	case types.RuleTypeSanctionsScreening:
		if ctx.Sanctions == nil {
			return false // §4.8: cannot verify → block
		}
		return !ctx.Sanctions.IsListed(ctx.Sender) && !ctx.Sanctions.IsListed(ctx.Receiver)
	default:
		result, ok := rule.Params["externalResult"].(bool)
		if !ok {
			return false // §14.10: unknown → block
		}
		return result
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

func isBlocking(action types.EnforcementAction) bool {
	return action == types.EnforcementReject || action == types.EnforcementFreeze || action == types.EnforcementRestrict
}

// ══════════════════════════════════════════════════════════════════════════════
// §3 Identity Binding
// ══════════════════════════════════════════════════════════════════════════════

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

// ValidateIdentity implements validate_identity(party) per §3.11.
func ValidateIdentity(record *types.IdentityRecord, nowUnix int64) error {
	status := IdentityStatus(record, nowUnix)
	if status != types.IdentityStatusValid {
		return fmt.Errorf("identity status: %s", status)
	}
	if record.Proof != nil {
		return fmt.Errorf("ZKP verification not implemented — supply real verifier")
	}
	return nil
}

// EnforceIdentityLevel dispatches the correct validation strategy per §3.2.
func EnforceIdentityLevel(
	level types.IdentityLevel,
	senderRecords, receiverRecords []types.IdentityRecord,
	nowUnix int64,
	requiredJurisdictions []string,
) error {
	if level == types.IdentityLevelUnbound {
		return nil
	}
	if len(senderRecords) == 0 {
		return fmt.Errorf("sender has no identity record")
	}
	if err := ValidateIdentity(&senderRecords[0], nowUnix); err != nil {
		return fmt.Errorf("sender: %w", err)
	}
	if len(receiverRecords) == 0 {
		return fmt.Errorf("receiver has no identity record")
	}
	if err := ValidateIdentity(&receiverRecords[0], nowUnix); err != nil {
		return fmt.Errorf("receiver: %w", err)
	}
	if level == types.IdentityLevelMultiJurisdiction && len(requiredJurisdictions) > 0 {
		for _, party := range []struct {
			name    string
			records []types.IdentityRecord
		}{{"sender", senderRecords}, {"receiver", receiverRecords}} {
			valid := map[string]bool{}
			for _, r := range party.records {
				if IdentityStatus(&r, nowUnix) == types.IdentityStatusValid {
					valid[r.JurisdictionIdentity] = true
				}
			}
			for _, j := range requiredJurisdictions {
				if !valid[j] {
					return fmt.Errorf("%s missing jurisdiction: %s", party.name, j)
				}
			}
		}
	}
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// §5 Governance Override
// ══════════════════════════════════════════════════════════════════════════════

// OverrideRecord is the immutable audit record for a governance action (§5.10).
type OverrideRecord struct {
	RecordHash string
	OverrideID string
	Authority  string
	Action     types.GovernanceAction
	Timestamp  int64
}

// ValidateOverride implements validate_override(O) per §5.6. Invariant I₄.
func ValidateOverride(
	o *types.OverrideObject,
	gov *types.GovernanceModule,
	verifier crypto.SignatureVerifier,
	allSignatures [][2]string,
) error {
	found := false
	for _, a := range gov.Authorities {
		if a == o.Authority {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("authority not registered")
	}
	allowed := false
	for _, act := range gov.OverrideTypes {
		if act == o.Action {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("action %s not permitted", o.Action)
	}
	if len(o.LegalBasis) < 64 {
		return fmt.Errorf("legal basis hash missing")
	}
	msg, err := hex.DecodeString(o.LegalBasis)
	if err != nil {
		return fmt.Errorf("invalid legal basis: %w", err)
	}
	valid, err := verifier.Verify(msg, o.Signature, o.Authority)
	if err != nil || !valid {
		return fmt.Errorf("signature verification failed")
	}
	if o.Action == types.GovernanceEmergencyRollback {
		if err := validateQuorum(gov, allSignatures); err != nil {
			return err
		}
	}
	return nil
}

func validateQuorum(gov *types.GovernanceModule, sigs [][2]string) error {
	n := len(gov.Authorities)
	required := int(math.Ceil(float64(2*n) / 3.0))
	authSet := map[string]bool{}
	for _, a := range gov.Authorities {
		authSet[a] = true
	}
	signed := map[string]bool{}
	for _, s := range sigs {
		if authSet[s[0]] {
			signed[s[0]] = true
		}
	}
	if len(signed) < required {
		return fmt.Errorf("quorum not met: %d/%d", len(signed), required)
	}
	return nil
}

// CreateOverrideRecord builds the immutable audit record (§5.10).
func CreateOverrideRecord(o *types.OverrideObject) OverrideRecord {
	return OverrideRecord{
		RecordHash: crypto.ConstructOverrideHash(o.OverrideID, o.Authority, string(o.Action), o.Timestamp),
		OverrideID: o.OverrideID,
		Authority:  o.Authority,
		Action:     o.Action,
		Timestamp:  o.Timestamp,
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// §6 Fee Routing
// ══════════════════════════════════════════════════════════════════════════════

// FeeDistribution holds the result of a deterministic fee calculation.
type FeeDistribution struct {
	TotalFee      *big.Int
	Allocations   []FeeAlloc
	FeeRecordHash string
}

// FeeAlloc is a single fee allocation to a recipient.
type FeeAlloc struct {
	Recipient string
	Amount    *big.Int
}

// ValidateFeeModule enforces §6.12 Economic Integrity Constraint.
func ValidateFeeModule(fee *types.FeeModule) error {
	total := 0
	for _, a := range fee.Allocations {
		if a.BasisPoints < 0 {
			return fmt.Errorf("negative allocation not permitted")
		}
		total += a.BasisPoints
	}
	if total != 10_000 {
		return fmt.Errorf("fee basis points must sum to 10000; got %d", total)
	}
	return nil
}

// DistributeFees implements distribute_fees(A, amount) per §6.5.
func DistributeFees(fee *types.FeeModule, amount *big.Int, txID string, timestamp int64) (*FeeDistribution, error) {
	if err := ValidateFeeModule(fee); err != nil {
		return nil, err
	}
	totalFee := new(big.Int).Mul(amount, big.NewInt(int64(fee.BaseRateBasisPoints)))
	totalFee.Div(totalFee, big.NewInt(10_000))

	allocs := make([]FeeAlloc, len(fee.Allocations))
	for i, a := range fee.Allocations {
		share := new(big.Int).Mul(totalFee, big.NewInt(int64(a.BasisPoints)))
		share.Div(share, big.NewInt(10_000))
		allocs[i] = FeeAlloc{Recipient: a.Recipient, Amount: share}
	}

	txBytes, _ := hex.DecodeString(txID)
	feeBuf := make([]byte, 32)
	totalFee.FillBytes(feeBuf)
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(timestamp))
	feeRecordHash := crypto.SHA256Concat(txBytes, feeBuf, tsBuf)

	return &FeeDistribution{TotalFee: totalFee, Allocations: allocs, FeeRecordHash: feeRecordHash}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// §8 Cross-Chain
// ══════════════════════════════════════════════════════════════════════════════

// CrossChainCertificate holds a cross-chain transfer certificate (§8.3).
type CrossChainCertificate struct {
	CID            string
	AssetID        string
	StateHash      string
	ComplianceHash string
	GovernanceHash string
	Timestamp      int64
}

// BuildCrossChainCertificate constructs the CID per §8.3.
func BuildCrossChainCertificate(asset *types.Asset, timestamp int64) (*CrossChainCertificate, error) {
	stateHash, err := crypto.HashObject(asset.State)
	if err != nil {
		return nil, err
	}
	complianceHash, err := crypto.HashObject(asset.ComplianceModule)
	if err != nil {
		return nil, err
	}
	governanceHash, err := crypto.HashObject(asset.GovernanceModule)
	if err != nil {
		return nil, err
	}
	cid, err := crypto.ConstructCID(asset.AssetID, stateHash, complianceHash, governanceHash, timestamp)
	if err != nil {
		return nil, err
	}
	return &CrossChainCertificate{
		CID: cid, AssetID: asset.AssetID,
		StateHash: stateHash, ComplianceHash: complianceHash,
		GovernanceHash: governanceHash, Timestamp: timestamp,
	}, nil
}

// VerifyCrossChain implements verify_crosschain per §8.9.
func VerifyCrossChain(cert *CrossChainCertificate, destAssetID, destComplianceHash, destGovernanceHash string) error {
	if destAssetID != cert.AssetID {
		return fmt.Errorf("Asset_ID changed — invariant violated")
	}
	recomputed, err := crypto.ConstructCID(cert.AssetID, cert.StateHash, cert.ComplianceHash, cert.GovernanceHash, cert.Timestamp)
	if err != nil {
		return err
	}
	if recomputed != cert.CID {
		return fmt.Errorf("CID recomputation mismatch")
	}
	if destComplianceHash != cert.ComplianceHash {
		return fmt.Errorf("compliance downgrade detected")
	}
	if destGovernanceHash != cert.GovernanceHash {
		return fmt.Errorf("governance hash changed")
	}
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// §9 Settlement + §2.7 Transfer Executor
// ══════════════════════════════════════════════════════════════════════════════

// IsReplay returns true if the TxID already exists in ledger history (§9.6).
func IsReplay(event *types.TransferEvent, ledgerHistory map[string]bool) (bool, error) {
	txID, err := crypto.ConstructTxID(event.Sender, event.Receiver, event.Amount, event.Nonce, event.Timestamp)
	if err != nil {
		return false, err
	}
	return ledgerHistory[txID], nil
}

// TransferOutput is the result of a transfer execution attempt.
type TransferOutput struct {
	Success    bool
	TxID       string
	Proof      *types.SettlementProof
	FeeRecord  string
	Error      string
	FailedStep string
}

// ExecuteTransfer implements §2.6 deterministic 7-step transfer execution.
func ExecuteTransfer(
	asset *types.Asset,
	event *types.TransferEvent,
	senderRecords, receiverRecords []types.IdentityRecord,
	ledgerHistory map[string]bool,
	blockHeight *big.Int,
	sanctions SanctionsRegistry,
	requiredJurisdictions []string,
) TransferOutput {
	fail := func(step, msg string) TransferOutput {
		return TransferOutput{Success: false, FailedStep: step, Error: msg}
	}

	replay, err := IsReplay(event, ledgerHistory)
	if err != nil {
		return fail("REPLAY_CHECK", err.Error())
	}
	if replay {
		return fail("REPLAY_CHECK", "Duplicate TxID — replay rejected")
	}

	txID, err := crypto.ConstructTxID(event.Sender, event.Receiver, event.Amount, event.Nonce, event.Timestamp)
	if err != nil {
		return fail("TX_ID", err.Error())
	}

	if asset.State != types.AssetStateActive {
		return fail("STATE_CHECK", fmt.Sprintf("asset state %s is not ACTIVE", asset.State))
	}

	if asset.IdentityLevel >= types.IdentityLevelVerified {
		if err := EnforceIdentityLevel(asset.IdentityLevel, senderRecords, receiverRecords, event.Timestamp, requiredJurisdictions); err != nil {
			return fail("IDENTITY", err.Error())
		}
	}

	ctx := &ComplianceContext{
		Asset: asset, Sender: event.Sender, Receiver: event.Receiver,
		Amount: event.Amount, Timestamp: event.Timestamp, Sanctions: sanctions,
	}
	decision := EvaluateCompliance(&asset.ComplianceModule, ctx)
	if !decision.Allowed {
		msg := "compliance blocked"
		if decision.BlockedBy != nil {
			msg = fmt.Sprintf("blocked by rule: %s", decision.BlockedBy.RuleID)
		}
		return fail("COMPLIANCE", msg)
	}

	feeResult, err := DistributeFees(&asset.FeeModule, event.Amount, txID, event.Timestamp)
	if err != nil {
		return fail("FEE_ROUTING", err.Error())
	}

	proof := &types.SettlementProof{
		TxID:        txID,
		BlockHeight: blockHeight,
		StateHash:   "",
		Timestamp:   event.Timestamp,
	}

	return TransferOutput{
		Success:   true,
		TxID:      txID,
		Proof:     proof,
		FeeRecord: feeResult.FeeRecordHash,
	}
}
