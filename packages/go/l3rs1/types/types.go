// Package types defines all L3RS-1 canonical types — §13.
package types

// AssetState — §2.4
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

func (s AssetState) IsTerminal() bool { return s == AssetStateBurned }

// AssetType — §2.3
type AssetType string

const (
	AssetTypeCBDC              AssetType = "CBDC"
	AssetTypeIndustryStable    AssetType = "INDUSTRY_STABLE"
	AssetTypeRegulatedSecurity AssetType = "REGULATED_SECURITY"
	AssetTypeUtility           AssetType = "UTILITY"
	AssetTypeGovernance        AssetType = "GOVERNANCE"
	AssetTypeStorageBacked     AssetType = "STORAGE_BACKED"
)

// IdentityLevel — §3.2
type IdentityLevel int

const (
	IdentityLevelUnbound             IdentityLevel = 0
	IdentityLevelVerified            IdentityLevel = 1
	IdentityLevelSovereignValidated  IdentityLevel = 2
	IdentityLevelMultiJurisdiction   IdentityLevel = 3
)

// IdentityStatus — §3.6
type IdentityStatus string

const (
	IdentityStatusValid   IdentityStatus = "VALID"
	IdentityStatusExpired IdentityStatus = "EXPIRED"
	IdentityStatusRevoked IdentityStatus = "REVOKED"
	IdentityStatusUnknown IdentityStatus = "UNKNOWN"
)

// RuleType — §4.4
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

// EnforcementAction — §4.7
type EnforcementAction string

const (
	EnforcementReject            EnforcementAction = "REJECT"
	EnforcementFreeze            EnforcementAction = "FREEZE"
	EnforcementRestrict          EnforcementAction = "RESTRICT"
	EnforcementFlag              EnforcementAction = "FLAG"
	EnforcementRequireDisclosure EnforcementAction = "REQUIRE_DISCLOSURE"
)

func (e EnforcementAction) IsBlocking() bool {
	return e == EnforcementReject || e == EnforcementFreeze || e == EnforcementRestrict
}

// GovernanceAction — §5.3
type GovernanceAction string

const (
	GovernanceFreezeBalance    GovernanceAction = "FREEZE_BALANCE"
	GovernanceUnfreezeBalance  GovernanceAction = "UNFREEZE_BALANCE"
	GovernanceRestrictTransfer GovernanceAction = "RESTRICT_TRANSFER"
	GovernanceSeizeAsset       GovernanceAction = "SEIZE_ASSET"
	GovernanceForceRedemption  GovernanceAction = "FORCE_REDEMPTION"
	GovernanceEmergencyRollback GovernanceAction = "EMERGENCY_ROLLBACK"
)

// ComplianceRule — §13.5
type ComplianceRule struct {
	RuleID   string            `json:"ruleId"`
	RuleType RuleType          `json:"ruleType"`
	Scope    string            `json:"scope"`
	Trigger  string            `json:"trigger"`
	Priority int               `json:"priority"`
	Action   EnforcementAction `json:"action"`
	Params   map[string]any    `json:"params,omitempty"`
}

// ComplianceModule — §4.2
type ComplianceModule struct {
	Rules []ComplianceRule `json:"rules"`
}

// GovernanceModule — §13.6
type GovernanceModule struct {
	Authorities     []string          `json:"authorities"`
	QuorumThreshold int               `json:"quorumThreshold"`
	OverrideTypes   []GovernanceAction `json:"overrideTypes"`
}

// FeeAllocation — §13.7
type FeeAllocation struct {
	Recipient   string `json:"recipient"`
	BasisPoints int    `json:"basisPoints"`
}

// FeeModule — §13.7
type FeeModule struct {
	BaseRateBasisPoints int             `json:"baseRateBasisPoints"`
	Allocations         []FeeAllocation `json:"allocations"`
}

// IdentityRecord — §3.3
type IdentityRecord struct {
	IdentityHash          string `json:"identityHash"`
	VerificationAuthority string `json:"verificationAuthority"`
	JurisdictionIdentity  string `json:"jurisdictionIdentity"`
	Expiry                int64  `json:"expiry"`
	Revoked               bool   `json:"revoked"`
}

// TransferEvent — §9.6
type TransferEvent struct {
	AssetID   string `json:"assetId"`
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	Amount    uint64 `json:"amount"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
}

// SettlementProof — §9.10
type SettlementProof struct {
	TxID        string `json:"txId"`
	BlockHeight uint64 `json:"blockHeight"`
	StateHash   string `json:"stateHash"`
	Timestamp   int64  `json:"timestamp"`
}

// ComplianceDecision — §4.3
type ComplianceDecision struct {
	Allowed   bool
	BlockedBy *ComplianceRule
	Action    EnforcementAction
}
