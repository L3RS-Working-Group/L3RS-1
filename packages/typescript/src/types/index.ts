/** L3RS-1 Type Definitions — §13 Canonical Data Schema */

export enum AssetType {
  CBDC               = "CBDC",
  INDUSTRY_STABLE    = "INDUSTRY_STABLE",
  REGULATED_SECURITY = "REGULATED_SECURITY",
  UTILITY            = "UTILITY",
  GOVERNANCE         = "GOVERNANCE",
  STORAGE_BACKED     = "STORAGE_BACKED",
}

export enum AssetState {
  ISSUED     = "ISSUED",
  ACTIVE     = "ACTIVE",
  RESTRICTED = "RESTRICTED",
  FROZEN     = "FROZEN",
  SUSPENDED  = "SUSPENDED",
  REDEEMED   = "REDEEMED",
  BURNED     = "BURNED",
}

export enum IdentityLevel { UNBOUND = 0, VERIFIED = 1, SOVEREIGN_VALIDATED = 2, MULTI_JURISDICTION = 3 }
export enum IdentityStatus { VALID = "VALID", EXPIRED = "EXPIRED", REVOKED = "REVOKED", UNKNOWN = "UNKNOWN" }

export enum RuleType {
  TRANSFER_ELIGIBILITY    = "TRANSFER_ELIGIBILITY",
  INVESTOR_CLASSIFICATION = "INVESTOR_CLASSIFICATION",
  HOLDING_PERIOD          = "HOLDING_PERIOD",
  GEOGRAPHIC_RESTRICTION  = "GEOGRAPHIC_RESTRICTION",
  SANCTIONS_SCREENING     = "SANCTIONS_SCREENING",
  TRANSACTION_THRESHOLD   = "TRANSACTION_THRESHOLD",
  AML_TRIGGER             = "AML_TRIGGER",
  MARKET_RESTRICTION      = "MARKET_RESTRICTION",
  REDEMPTION_ELIGIBILITY  = "REDEMPTION_ELIGIBILITY",
}

export enum EnforcementAction {
  REJECT             = "REJECT",
  FREEZE             = "FREEZE",
  RESTRICT           = "RESTRICT",
  FLAG               = "FLAG",
  REQUIRE_DISCLOSURE = "REQUIRE_DISCLOSURE",
}

export enum GovernanceAction {
  FREEZE_BALANCE     = "FREEZE_BALANCE",
  UNFREEZE_BALANCE   = "UNFREEZE_BALANCE",
  RESTRICT_TRANSFER  = "RESTRICT_TRANSFER",
  SEIZE_ASSET        = "SEIZE_ASSET",
  FORCE_REDEMPTION   = "FORCE_REDEMPTION",
  EMERGENCY_ROLLBACK = "EMERGENCY_ROLLBACK",
}

export enum BackingType { FIAT="FIAT", TREASURY="TREASURY", COMMODITY="COMMODITY", REAL_ESTATE="REAL_ESTATE", EQUITY="EQUITY", DEBT="DEBT", MIXED="MIXED" }
export enum AttestationFrequency { REALTIME="REALTIME", DAILY="DAILY", WEEKLY="WEEKLY", MONTHLY="MONTHLY", QUARTERLY="QUARTERLY", ANNUAL="ANNUAL" }
export enum ReserveStatus { VALID="VALID", STALE="STALE", INVALID="INVALID", UNKNOWN="UNKNOWN" }
export enum InsolvencyPriority { SENIOR="SENIOR", SECURED="SECURED", UNSECURED="UNSECURED", SUBORDINATED="SUBORDINATED" }

export interface ComplianceRule {
  ruleId:   string;
  ruleType: RuleType;
  scope:    string;
  trigger:  string;
  priority: number;
  action:   EnforcementAction;
  params:   Record<string, unknown>;
}

export interface ComplianceModule { rules: ComplianceRule[]; }
export interface GovernanceModule { authorities: string[]; quorumThreshold: number; overrideTypes: GovernanceAction[]; }
export interface FeeAllocation    { recipient: string; basisPoints: number; }
export interface FeeModule        { baseRateBasisPoints: number; allocations: FeeAllocation[]; }

export interface TransferEvent {
  assetId:   string;
  sender:    string;
  receiver:  string;
  amount:    bigint;
  nonce:     string;
  timestamp: number;
}

export interface SettlementProof {
  txId:        string;
  blockHeight: number;
  stateHash:   string;
  timestamp:   number;
}

export interface ComplianceDecision {
  allowed:   boolean;
  blockedBy?: ComplianceRule;
  action?:    EnforcementAction;
}
