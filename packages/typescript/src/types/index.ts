/**
 * L3RS-1 Type Definitions
 * Maps directly to §13 Canonical Data Schema Specification
 * All types are immutable by convention — use readonly everywhere.
 */

// ─── §2.3 Asset Type Enumeration ────────────────────────────────────────────

export enum AssetType {
  CBDC               = "CBDC",
  INDUSTRY_STABLE    = "INDUSTRY_STABLE",
  REGULATED_SECURITY = "REGULATED_SECURITY",
  UTILITY            = "UTILITY",
  GOVERNANCE         = "GOVERNANCE",
  STORAGE_BACKED     = "STORAGE_BACKED",
}

// ─── §2.4 Asset State Machine ────────────────────────────────────────────────

export enum AssetState {
  ISSUED     = "ISSUED",
  ACTIVE     = "ACTIVE",
  RESTRICTED = "RESTRICTED",
  FROZEN     = "FROZEN",
  SUSPENDED  = "SUSPENDED",
  REDEEMED   = "REDEEMED",
  BURNED     = "BURNED",
}

// ─── §3.2 Identity Requirement Level ────────────────────────────────────────

export enum IdentityLevel {
  UNBOUND              = 0,
  VERIFIED             = 1,
  SOVEREIGN_VALIDATED  = 2,
  MULTI_JURISDICTION   = 3,
}

// ─── §3.6 Identity Status ────────────────────────────────────────────────────

export enum IdentityStatus {
  VALID   = "VALID",
  EXPIRED = "EXPIRED",
  REVOKED = "REVOKED",
  UNKNOWN = "UNKNOWN",
}

// ─── §4.4 Compliance Rule Types ──────────────────────────────────────────────

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

// ─── §4.7 Enforcement Actions ────────────────────────────────────────────────

export enum EnforcementAction {
  REJECT             = "REJECT",
  FREEZE             = "FREEZE",
  RESTRICT           = "RESTRICT",
  FLAG               = "FLAG",
  REQUIRE_DISCLOSURE = "REQUIRE_DISCLOSURE",
}

// ─── §5.3 Governance Override Actions ───────────────────────────────────────

export enum GovernanceAction {
  FREEZE_BALANCE    = "FREEZE_BALANCE",
  UNFREEZE_BALANCE  = "UNFREEZE_BALANCE",
  RESTRICT_TRANSFER = "RESTRICT_TRANSFER",
  SEIZE_ASSET       = "SEIZE_ASSET",
  FORCE_REDEMPTION  = "FORCE_REDEMPTION",
  EMERGENCY_ROLLBACK = "EMERGENCY_ROLLBACK",
}

// ─── §7.5 Asset Backing Types ────────────────────────────────────────────────

export enum BackingType {
  FIAT        = "FIAT",
  TREASURY    = "TREASURY",
  COMMODITY   = "COMMODITY",
  REAL_ESTATE = "REAL_ESTATE",
  EQUITY      = "EQUITY",
  DEBT        = "DEBT",
  MIXED       = "MIXED",
}

// ─── §7.7 Attestation Frequency ─────────────────────────────────────────────

export enum AttestationFrequency {
  REALTIME  = "REALTIME",
  DAILY     = "DAILY",
  WEEKLY    = "WEEKLY",
  MONTHLY   = "MONTHLY",
  QUARTERLY = "QUARTERLY",
  ANNUAL    = "ANNUAL",
}

// ─── §7.8 Reserve Status ─────────────────────────────────────────────────────

export enum ReserveStatus {
  VALID   = "VALID",
  STALE   = "STALE",
  INVALID = "INVALID",
  UNKNOWN = "UNKNOWN",
}

// ─── §7.11 Insolvency Priority ───────────────────────────────────────────────

export enum InsolvencyPriority {
  SENIOR       = "SENIOR",
  SECURED      = "SECURED",
  UNSECURED    = "UNSECURED",
  SUBORDINATED = "SUBORDINATED",
}

// ─── §11.2 Conformance Classes ───────────────────────────────────────────────

export enum ConformanceClass {
  CORE       = "CORE",
  ENHANCED   = "ENHANCED",
  SOVEREIGN  = "SOVEREIGN",
  CROSSCHAIN = "CROSSCHAIN",
}

// ─── §3.3 Identity Record ────────────────────────────────────────────────────

/** §3.3 IR = (HID, VA, JI, EXP, REV, ATTR, PROOF) */
export interface IdentityRecord {
  readonly identityHash:           string;        // HID: H(PII || salt || domain)
  readonly verificationAuthority:  string;        // VA: resolvable to public key
  readonly jurisdictionIdentity:   string;        // JI: ISO 3166-1 alpha-2
  readonly expiry:                 number;        // EXP: UTC Unix timestamp
  readonly revoked:                boolean;       // REV: revocation flag
  readonly attributeCommitments?:  readonly string[]; // ATTR: H(a_i) selective disclosure
  readonly proof?:                 ZKProof;       // PROOF: optional ZK proof object
}

/** §3.8 ZKP compatibility */
export interface ZKProof {
  readonly scheme:             string;
  readonly statement:          string;
  readonly witnessCommitment:  string;
  readonly proofBytes:         string; // hex-encoded
  readonly nonce:              string;
}

// ─── §12.2 Legal Mirror ──────────────────────────────────────────────────────

/** §12.2 L = (J, LH, LV, TS, SIGN) */
export interface LegalMirror {
  readonly jurisdiction:         string; // ISO 3166-1 alpha-2
  readonly legalHash:            string; // LH: H(document || jurisdiction || version)
  readonly legalVersion:         string; // LV: MAJOR.MINOR
  readonly timestamp:            number; // UTC Unix timestamp
  readonly authoritySignature?:  string; // optional — hex-encoded
}

// ─── §13.5 Compliance Rule ───────────────────────────────────────────────────

export interface ComplianceRule {
  readonly ruleId:    string;
  readonly ruleType:  RuleType;
  readonly scope:     string;            // jurisdiction or asset scope
  readonly trigger:   string;            // event that invokes rule
  readonly priority:  number;            // evaluation order — ascending
  readonly action:    EnforcementAction;
  readonly params?:   Record<string, unknown>; // rule-specific parameters
}

/** §4.2 Compliance Module = ordered rule set */
export interface ComplianceModule {
  readonly rules: readonly ComplianceRule[];
}

// ─── §13.6 Governance Module ─────────────────────────────────────────────────

export interface GovernanceModule {
  readonly authorities:      readonly string[]; // registered governance public keys
  readonly quorumThreshold:  number;            // integer percentage e.g. 67
  readonly overrideTypes:    readonly GovernanceAction[];
}

// ─── §5.2 Override Object ────────────────────────────────────────────────────

/** §5.2 O = (OID, AUTH, ACTION, TARGET, BASIS, TS, SIG) */
export interface OverrideObject {
  readonly overrideId:   string;
  readonly authority:    string;          // AUTH: registered governance authority
  readonly action:       GovernanceAction;
  readonly target:       string;          // asset_id or address scope
  readonly legalBasis:   string;          // BASIS: H(legal_doc || jurisdiction || case_id)
  readonly timestamp:    number;          // UTC Unix timestamp
  readonly signature:    string;          // SIG: hex-encoded
}

// ─── §13.7 Fee Module ────────────────────────────────────────────────────────

export interface FeeAllocation {
  readonly recipient:    string; // address or identity
  readonly basisPoints:  number; // must sum to 10000 across all allocations
}

/** §6.7 F = (f, P, recipients) — immutable at issuance */
export interface FeeModule {
  readonly baseRateBasisPoints:  number;            // 0 <= f < 10000
  readonly allocations:          readonly FeeAllocation[];
}

// ─── §13.8 Reserve Interface ─────────────────────────────────────────────────

/** §7.3 B = (CID, ABT, AH, FREQ, RLOG, PRIORITY) */
export interface ReserveInterface {
  readonly custodianId:           string;
  readonly backingType:           BackingType;
  readonly auditHash:             string;            // H(audit_doc || period || timestamp)
  readonly attestationFrequency:  AttestationFrequency;
  readonly insolvencyPriority:    InsolvencyPriority;
  readonly redemptionLogic:       RedemptionLogic;
}

export interface RedemptionLogic {
  readonly eligibility:  string;
  readonly procedure:    string;
  readonly settlement:   string;
  readonly timeframeSec: number;
}

// ─── §13.9 Cross-Chain Metadata ──────────────────────────────────────────────

/** §8.2 X = (CID, Origin, Dest, StateHash, ComplianceHash, GovHash, Timestamp) */
export interface CrossChainMetadata {
  readonly certificateId:    string; // CID: H(asset_id || state_hash || compliance_hash || gov_hash || ts)
  readonly originChainId:    string; // H(chain_name || network_type || genesis_hash)
  readonly complianceHash:   string; // H(ser(ComplianceModule))
  readonly governanceHash:   string; // H(ser(GovernanceModule))
  readonly stateHash:        string; // H(ser(AssetState))
  readonly timestamp:        number; // UTC Unix timestamp
}

// ─── §13.2 Canonical Asset Object ────────────────────────────────────────────

/**
 * §2.1 A = (I, T, J, L, ID, C, R, G, F, B, X, S)
 * The canonical asset object per §13.2.
 * All fields are immutable except `state` and `crossChainMetadata`.
 */
export interface Asset {
  readonly assetId:           string;               // I: H(issuer_pk || ts || nonce)
  readonly assetType:         AssetType;             // T: immutable after issuance
  readonly jurisdiction:      string;               // J: ISO 3166-1 alpha-2
  readonly legalMirror:       LegalMirror;           // L
  readonly identityLevel:     IdentityLevel;         // ID
  readonly complianceModule:  ComplianceModule;      // C
  readonly governanceModule:  GovernanceModule;      // G
  readonly feeModule:         FeeModule;             // F
  readonly reserveInterface?: ReserveInterface;      // B: optional
  readonly crossChainMetadata: CrossChainMetadata;   // X
  readonly state:             AssetState;            // S: mutable via validated transitions
  readonly standardVersion:   string;               // e.g. "L3RS-1.0.0"
}

// ─── Transfer Context ────────────────────────────────────────────────────────

/** Input to the deterministic transfer function (§2.6, §2.7) */
export interface TransferEvent {
  readonly assetId:    string;
  readonly sender:     string;
  readonly receiver:   string;
  readonly amount:     bigint;
  readonly nonce:      string;       // unique per sender
  readonly timestamp:  number;       // UTC Unix timestamp
}

/** §9.6 TxID = H(sender || receiver || amount || nonce || timestamp) */
export interface TransactionId {
  readonly txId:   string; // hex
  readonly event:  TransferEvent;
}

/** §9.10 Settlement proof object */
export interface SettlementProof {
  readonly txId:        string;
  readonly blockHeight: bigint;
  readonly stateHash:   string;
  readonly timestamp:   number;
}

// ─── Compliance Decision ─────────────────────────────────────────────────────

export type ComplianceDecision =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly blockedBy: ComplianceRule; readonly action: EnforcementAction };
