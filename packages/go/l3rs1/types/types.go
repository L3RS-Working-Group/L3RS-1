// Package types defines all L3RS-1 canonical data types per §13.
// Maps directly to §13 Canonical Data Schema Specification.
package types

import "math/big"

// ─── §2.3 Asset Type ─────────────────────────────────────────────────────────

type AssetType string

const (
	AssetTypeCBDC              AssetType = "CBDC"
	AssetTypeIndustryStable    AssetType = "INDUSTRY_STABLE"
	AssetTypeRegulatedSecurity AssetType = "REGULATED_SECURITY"
	AssetTypeUtility           AssetType = "UTILITY"
	AssetTypeGovernance        AssetType = "GOVERNANCE"
	AssetTypeStorageBacked     AssetType = "STORAGE_BACKED"
)

// ─── §2.4 Asset State ────────────────────────────────────────────────────────

type AssetState string

const (
	AssetStateIssued     AssetState = "ISSUED"
	AssetStateActive     AssetState = "ACTIVE"
	AssetStateRestricted AssetState = "RESTRICTED"
	AssetStateFrozen     AssetState = "FROZEN"
	AssetStateSuspended  AssetState = "SUSPENDED"
	AssetStateRedeemed   AssetState = "REDEEMED"
	AssetStateBurned     AssetState = "BURNED"
)

// ─── §3.2 Identity Level ─────────────────────────────────────────────────────

type IdentityLevel int

const (
	IdentityLevelUnbound            IdentityLevel = 0
	IdentityLevelVerified           IdentityLevel = 1
	IdentityLevelSovereignValidated IdentityLevel = 2
	IdentityLevelMultiJurisdiction  IdentityLevel = 3
)

// ─── §3.6 Identity Status ────────────────────────────────────────────────────

type IdentityStatus string

const (
	IdentityStatusValid   IdentityStatus = "VALID"
	IdentityStatusExpired IdentityStatus = "EXPIRED"
	IdentityStatusRevoked IdentityStatus = "REVOKED"
	IdentityStatusUnknown IdentityStatus = "UNKNOWN"
)

// ─── §4.4 Rule Type ──────────────────────────────────────────────────────────

type RuleType string

const (
	RuleTypeTransferEligibility   RuleType = "TRANSFER_ELIGIBILITY"
	RuleTypeInvestorClassification RuleType = "INVESTOR_CLASSIFICATION"
	RuleTypeHoldingPeriod         RuleType = "HOLDING_PERIOD"
	RuleTypeGeographicRestriction RuleType = "GEOGRAPHIC_RESTRICTION"
	RuleTypeSanctionsScreening    RuleType = "SANCTIONS_SCREENING"
	RuleTypeTransactionThreshold  RuleType = "TRANSACTION_THRESHOLD"
	RuleTypeAMLTrigger            RuleType = "AML_TRIGGER"
	RuleTypeMarketRestriction     RuleType = "MARKET_RESTRICTION"
	RuleTypeRedemptionEligibility RuleType = "REDEMPTION_ELIGIBILITY"
)

// ─── §4.7 Enforcement Action ─────────────────────────────────────────────────

type EnforcementAction string

const (
	EnforcementReject            EnforcementAction = "REJECT"
	EnforcementFreeze            EnforcementAction = "FREEZE"
	EnforcementRestrict          EnforcementAction = "RESTRICT"
	EnforcementFlag              EnforcementAction = "FLAG"
	EnforcementRequireDisclosure EnforcementAction = "REQUIRE_DISCLOSURE"
)

// ─── §5.3 Governance Action ──────────────────────────────────────────────────

type GovernanceAction string

const (
	GovernanceFreezeBalance    GovernanceAction = "FREEZE_BALANCE"
	GovernanceUnfreezeBalance  GovernanceAction = "UNFREEZE_BALANCE"
	GovernanceRestrictTransfer GovernanceAction = "RESTRICT_TRANSFER"
	GovernanceSeizeAsset       GovernanceAction = "SEIZE_ASSET"
	GovernanceForceRedemption  GovernanceAction = "FORCE_REDEMPTION"
	GovernanceEmergencyRollback GovernanceAction = "EMERGENCY_ROLLBACK"
)

// ─── §7.5 Backing Type ───────────────────────────────────────────────────────

type BackingType string

const (
	BackingFiat       BackingType = "FIAT"
	BackingTreasury   BackingType = "TREASURY"
	BackingCommodity  BackingType = "COMMODITY"
	BackingRealEstate BackingType = "REAL_ESTATE"
	BackingEquity     BackingType = "EQUITY"
	BackingDebt       BackingType = "DEBT"
	BackingMixed      BackingType = "MIXED"
)

// ─── §7.7 Attestation Frequency ──────────────────────────────────────────────

type AttestationFrequency string

const (
	FreqRealtime  AttestationFrequency = "REALTIME"
	FreqDaily     AttestationFrequency = "DAILY"
	FreqWeekly    AttestationFrequency = "WEEKLY"
	FreqMonthly   AttestationFrequency = "MONTHLY"
	FreqQuarterly AttestationFrequency = "QUARTERLY"
	FreqAnnual    AttestationFrequency = "ANNUAL"
)

// ─── §7.8 Reserve Status ─────────────────────────────────────────────────────

type ReserveStatus string

const (
	ReserveValid   ReserveStatus = "VALID"
	ReserveStale   ReserveStatus = "STALE"
	ReserveInvalid ReserveStatus = "INVALID"
	ReserveUnknown ReserveStatus = "UNKNOWN"
)

// ─── §7.11 Insolvency Priority ───────────────────────────────────────────────

type InsolvencyPriority string

const (
	PrioritySenior       InsolvencyPriority = "SENIOR"
	PrioritySecured      InsolvencyPriority = "SECURED"
	PriorityUnsecured    InsolvencyPriority = "UNSECURED"
	PrioritySubordinated InsolvencyPriority = "SUBORDINATED"
)

// ─── §3.8 ZK Proof ───────────────────────────────────────────────────────────

type ZKProof struct {
	Scheme            string `json:"scheme"`
	Statement         string `json:"statement"`
	WitnessCommitment string `json:"witnessCommitment"`
	ProofBytes        string `json:"proofBytes"` // hex
	Nonce             string `json:"nonce"`
}

// ─── §3.3 Identity Record ─────────────────────────────────────────────────────

// IdentityRecord — IR = (HID, VA, JI, EXP, REV, ATTR, PROOF) per §3.3
type IdentityRecord struct {
	IdentityHash           string    `json:"identityHash"`
	VerificationAuthority  string    `json:"verificationAuthority"`
	JurisdictionIdentity   string    `json:"jurisdictionIdentity"`
	Expiry                 int64     `json:"expiry"` // UTC Unix timestamp
	Revoked                bool      `json:"revoked"`
	AttributeCommitments   []string  `json:"attributeCommitments,omitempty"`
	Proof                  *ZKProof  `json:"proof,omitempty"`
}

// ─── §12.2 Legal Mirror ──────────────────────────────────────────────────────

// LegalMirror — L = (J, LH, LV, TS, SIGN) per §12.2
type LegalMirror struct {
	Jurisdiction       string `json:"jurisdiction"`
	LegalHash          string `json:"legalHash"`
	LegalVersion       string `json:"legalVersion"`
	Timestamp          int64  `json:"timestamp"`
	AuthoritySignature string `json:"authoritySignature,omitempty"`
}

// ─── §13.5 Compliance Rule ───────────────────────────────────────────────────

type ComplianceRule struct {
	RuleID   string            `json:"ruleId"`
	RuleType RuleType          `json:"ruleType"`
	Scope    string            `json:"scope"`
	Trigger  string            `json:"trigger"`
	Priority int               `json:"priority"`
	Action   EnforcementAction `json:"action"`
	Params   map[string]any    `json:"params,omitempty"`
}

type ComplianceModule struct {
	Rules []ComplianceRule `json:"rules"`
}

// ─── §13.6 Governance Module ─────────────────────────────────────────────────

type GovernanceModule struct {
	Authorities     []string          `json:"authorities"`
	QuorumThreshold int               `json:"quorumThreshold"` // percentage e.g. 67
	OverrideTypes   []GovernanceAction `json:"overrideTypes"`
}

// ─── §5.2 Override Object ────────────────────────────────────────────────────

type OverrideObject struct {
	OverrideID string           `json:"overrideId"`
	Authority  string           `json:"authority"`
	Action     GovernanceAction `json:"action"`
	Target     string           `json:"target"`
	LegalBasis string           `json:"legalBasis"`
	Timestamp  int64            `json:"timestamp"`
	Signature  string           `json:"signature"`
}

// ─── §13.7 Fee Module ────────────────────────────────────────────────────────

type FeeAllocation struct {
	Recipient   string `json:"recipient"`
	BasisPoints int    `json:"basisPoints"`
}

type FeeModule struct {
	BaseRateBasisPoints int             `json:"baseRateBasisPoints"`
	Allocations         []FeeAllocation `json:"allocations"`
}

// ─── §13.8 Reserve Interface ─────────────────────────────────────────────────

type RedemptionLogic struct {
	Eligibility  string `json:"eligibility"`
	Procedure    string `json:"procedure"`
	Settlement   string `json:"settlement"`
	TimeframeSec int64  `json:"timeframeSec"`
}

type ReserveInterface struct {
	CustodianID           string               `json:"custodianId"`
	BackingType           BackingType          `json:"backingType"`
	AuditHash             string               `json:"auditHash"`
	AttestationFrequency  AttestationFrequency `json:"attestationFrequency"`
	InsolvencyPriority    InsolvencyPriority   `json:"insolvencyPriority"`
	RedemptionLogic       RedemptionLogic      `json:"redemptionLogic"`
}

// ─── §13.9 Cross-Chain Metadata ──────────────────────────────────────────────

type CrossChainMetadata struct {
	CertificateID  string `json:"certificateId"`
	OriginChainID  string `json:"originChainId"`
	ComplianceHash string `json:"complianceHash"`
	GovernanceHash string `json:"governanceHash"`
	StateHash      string `json:"stateHash"`
	Timestamp      int64  `json:"timestamp"`
}

// ─── §13.2 Canonical Asset Object ────────────────────────────────────────────

// Asset — A = (I, T, J, L, ID, C, R, G, F, B, X, S) per §2.1
type Asset struct {
	AssetID            string             `json:"assetId"`
	AssetType          AssetType          `json:"assetType"`
	Jurisdiction       string             `json:"jurisdiction"`
	LegalMirror        LegalMirror        `json:"legalMirror"`
	IdentityLevel      IdentityLevel      `json:"identityLevel"`
	ComplianceModule   ComplianceModule   `json:"complianceModule"`
	GovernanceModule   GovernanceModule   `json:"governanceModule"`
	FeeModule          FeeModule          `json:"feeModule"`
	ReserveInterface   *ReserveInterface  `json:"reserveInterface,omitempty"`
	CrossChainMetadata CrossChainMetadata `json:"crossChainMetadata"`
	State              AssetState         `json:"state"`
	StandardVersion    string             `json:"standardVersion"`
}

// ─── Transfer ────────────────────────────────────────────────────────────────

type TransferEvent struct {
	AssetID   string   `json:"assetId"`
	Sender    string   `json:"sender"`
	Receiver  string   `json:"receiver"`
	Amount    *big.Int `json:"amount"`
	Nonce     string   `json:"nonce"` // hex
	Timestamp int64    `json:"timestamp"`
}

type SettlementProof struct {
	TxID        string   `json:"txId"`
	BlockHeight *big.Int `json:"blockHeight"`
	StateHash   string   `json:"stateHash"`
	Timestamp   int64    `json:"timestamp"`
}

// ─── Compliance Decision ─────────────────────────────────────────────────────

type ComplianceDecision struct {
	Allowed   bool
	BlockedBy *ComplianceRule
	Action    EnforcementAction
}
