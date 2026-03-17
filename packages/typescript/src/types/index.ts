/**
 * @module types
 * @description L3RS-1 canonical type definitions — §13 Canonical Data Schema.
 * All types map 1:1 to the JSON schema defined in the specification.
 */

/** §2.3 — Asset classification type. */
export enum AssetType {
  /** Central Bank Digital Currency */
  CBDC               = "CBDC",
  /** Industry-issued stablecoin */
  INDUSTRY_STABLE    = "INDUSTRY_STABLE",
  /** Regulated security token */
  REGULATED_SECURITY = "REGULATED_SECURITY",
  /** Utility token */
  UTILITY            = "UTILITY",
  /** Governance token */
  GOVERNANCE         = "GOVERNANCE",
  /** Storage-backed asset */
  STORAGE_BACKED     = "STORAGE_BACKED",
}

/** §2.4 — Asset lifecycle state. Terminal state: `BURNED`. */
export enum AssetState {
  /** Newly issued, not yet active */
  ISSUED     = "ISSUED",
  /** Active and transferable */
  ACTIVE     = "ACTIVE",
  /** Transfer restricted by compliance */
  RESTRICTED = "RESTRICTED",
  /** Frozen by governance override */
  FROZEN     = "FROZEN",
  /** Temporarily suspended */
  SUSPENDED  = "SUSPENDED",
  /** Redeemed, pending finalization */
  REDEEMED   = "REDEEMED",
  /** Terminal state — no further transitions */
  BURNED     = "BURNED",
}

/** §3.2 — Identity verification requirement level. */
export enum IdentityLevel {
  /** No identity binding required */
  UNBOUND              = 0,
  /** Standard KYC verification */
  VERIFIED             = 1,
  /** Sovereign-validated identity */
  SOVEREIGN_VALIDATED  = 2,
  /** Multi-jurisdiction stacking required */
  MULTI_JURISDICTION   = 3,
}

/** §3.6 — Identity record status. */
export enum IdentityStatus {
  VALID   = "VALID",
  EXPIRED = "EXPIRED",
  REVOKED = "REVOKED",
  UNKNOWN = "UNKNOWN",
}

/** §4.4 — Compliance rule classification. */
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

/** §4.7 — Action taken when a compliance rule blocks a transfer. */
export enum EnforcementAction {
  /** Reject the transfer outright */
  REJECT             = "REJECT",
  /** Freeze the asset */
  FREEZE             = "FREEZE",
  /** Restrict future transfers */
  RESTRICT           = "RESTRICT",
  /** Flag for review without blocking */
  FLAG               = "FLAG",
  /** Require disclosure before proceeding */
  REQUIRE_DISCLOSURE = "REQUIRE_DISCLOSURE",
}

/** §5.3 — Governance override action types. */
export enum GovernanceAction {
  FREEZE_BALANCE     = "FREEZE_BALANCE",
  UNFREEZE_BALANCE   = "UNFREEZE_BALANCE",
  RESTRICT_TRANSFER  = "RESTRICT_TRANSFER",
  SEIZE_ASSET        = "SEIZE_ASSET",
  FORCE_REDEMPTION   = "FORCE_REDEMPTION",
  /** Requires ⌈2/3⌉ quorum — §5.5 */
  EMERGENCY_ROLLBACK = "EMERGENCY_ROLLBACK",
}

/** §7.5 — Reserve backing type. */
export enum BackingType {
  FIAT        = "FIAT",
  TREASURY    = "TREASURY",
  COMMODITY   = "COMMODITY",
  REAL_ESTATE = "REAL_ESTATE",
  EQUITY      = "EQUITY",
  DEBT        = "DEBT",
  MIXED       = "MIXED",
}

/** §7.7 — Reserve attestation frequency. */
export enum AttestationFrequency {
  REALTIME  = "REALTIME",
  DAILY     = "DAILY",
  WEEKLY    = "WEEKLY",
  MONTHLY   = "MONTHLY",
  QUARTERLY = "QUARTERLY",
  ANNUAL    = "ANNUAL",
}

/** §7.8 — Reserve verification status. */
export enum ReserveStatus {
  VALID   = "VALID",
  STALE   = "STALE",
  INVALID = "INVALID",
  UNKNOWN = "UNKNOWN",
}

/** §7.11 — Insolvency claim priority. */
export enum InsolvencyPriority {
  SENIOR       = "SENIOR",
  SECURED      = "SECURED",
  UNSECURED    = "UNSECURED",
  SUBORDINATED = "SUBORDINATED",
}

/** §3.8 — Zero-knowledge proof attached to an identity record. */
export interface ZKProof {
  scheme:             string;
  statement:          string;
  witnessCommitment:  string;
  /** Hex-encoded proof bytes */
  proofBytes:         string;
  nonce:              string;
}

/** §3.3 — Identity record for a single party in a single jurisdiction. */
export interface IdentityRecord {
  /** H(PII || salt || domain) — §3.4 */
  identityHash:          string;
  verificationAuthority: string;
  jurisdictionIdentity:  string;
  /** Unix timestamp after which the record is expired */
  expiry:                number;
  revoked:               boolean;
  attributeCommitments?: string[];
  proof?:                ZKProof;
}

/** §12.2 — On-chain legal mirror reference. */
export interface LegalMirror {
  jurisdiction:        string;
  legalHash:           string;
  legalVersion:        string;
  timestamp:           number;
  authoritySignature?: string;
}

/** §5.2 — Governance override request object. */
export interface OverrideObject {
  overrideId:  string;
  authority:   string;
  action:      GovernanceAction;
  target:      string;
  /** SHA-256 hash of the legal basis document */
  legalBasis:  string;
  timestamp:   number;
  signature:   string;
}

/** §13.5 — A single compliance rule evaluated by the compliance engine. */
export interface ComplianceRule {
  ruleId:   string;
  ruleType: RuleType;
  /** `"*"` matches all jurisdictions */
  scope:    string;
  trigger:  string;
  /** Lower = evaluated first */
  priority: number;
  action:   EnforcementAction;
  params:   Record<string, unknown>;
}

/** §4.2 — Ordered set of compliance rules applied to every transfer. */
export interface ComplianceModule { rules: ComplianceRule[]; }

/** §13.6 — Governance configuration: authorities and permitted override types. */
export interface GovernanceModule {
  authorities:      string[];
  quorumThreshold:  number;
  overrideTypes:    GovernanceAction[];
}

/** §13.7 — Single fee recipient and their share in basis points. */
export interface FeeAllocation    { recipient: string; basisPoints: number; }

/** §13.7 — Fee routing configuration. Allocations must sum to 10000 bp. */
export interface FeeModule        { baseRateBasisPoints: number; allocations: FeeAllocation[]; }

/** §7.9 — Redemption procedure definition. */
export interface RedemptionLogic {
  eligibility:  string;
  procedure:    string;
  settlement:   string;
  timeframeSec: number;
}

/** §13.8 — Reserve backing interface. */
export interface ReserveInterface {
  custodianId:          string;
  backingType:          BackingType;
  auditHash:            string;
  attestationFrequency: AttestationFrequency;
  insolvencyPriority:   InsolvencyPriority;
  redemptionLogic:      RedemptionLogic;
}

/** §13.9 — Cross-chain certificate metadata. */
export interface CrossChainMetadata {
  certificateId:  string;
  originChainId:  string;
  complianceHash: string;
  governanceHash: string;
  stateHash:      string;
  timestamp:      number;
}

/** §2.1 — The complete L3RS-1 asset tuple A = (I, T, J, L, ID, C, R, G, F, B, X, S). */
export interface Asset {
  /** §2.2 — I = H(pk_issuer ∥ ts ∥ nonce) */
  assetId:            string;
  assetType:          AssetType;
  /** ISO 3166-1 alpha-2 */
  jurisdiction:       string;
  legalMirror:        LegalMirror;
  identityLevel:      IdentityLevel;
  complianceModule:   ComplianceModule;
  governanceModule:   GovernanceModule;
  feeModule:          FeeModule;
  crosschainMetadata: CrossChainMetadata;
  state:              AssetState;
  /** Must start with "L3RS-" */
  standardVersion:    string;
  reserveInterface?:  ReserveInterface;
}

/** §9.5 — Transfer event input. */
export interface TransferEvent {
  assetId:   string;
  sender:    string;
  receiver:  string;
  amount:    bigint;
  /** Hex-encoded nonce for replay protection */
  nonce:     string;
  timestamp: number;
}

/** §9.10 — Settlement proof output. */
export interface SettlementProof {
  /** §9.6 — TxID = H(sender ∥ receiver ∥ amount ∥ nonce ∥ timestamp) */
  txId:        string;
  blockHeight: number;
  stateHash:   string;
  timestamp:   number;
}

/** §4.3 — Output of the compliance engine C: E → {0,1}. */
export interface ComplianceDecision {
  allowed:    boolean;
  blockedBy?: ComplianceRule;
  action?:    EnforcementAction;
}
