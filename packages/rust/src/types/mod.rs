//! L3RS-1 Type Definitions
//! Maps directly to §13 Canonical Data Schema Specification.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── §2.3 Asset Type ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetType {
    Cbdc,
    IndustryStable,
    RegulatedSecurity,
    Utility,
    Governance,
    StorageBacked,
}

// ─── §2.4 Asset State ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetState {
    Issued,
    Active,
    Restricted,
    Frozen,
    Suspended,
    Redeemed,
    Burned,
}

impl AssetState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, AssetState::Burned)
    }
}

// ─── §3.2 Identity Level ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum IdentityLevel {
    Unbound = 0,
    Verified = 1,
    SovereignValidated = 2,
    MultiJurisdiction = 3,
}

impl From<IdentityLevel> for u8 {
    fn from(l: IdentityLevel) -> u8 { l as u8 }
}

impl TryFrom<u8> for IdentityLevel {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Unbound),
            1 => Ok(Self::Verified),
            2 => Ok(Self::SovereignValidated),
            3 => Ok(Self::MultiJurisdiction),
            _ => Err(format!("Invalid IdentityLevel: {v}")),
        }
    }
}

// ─── §3.6 Identity Status ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityStatus {
    Valid,
    Expired,
    Revoked,
    Unknown,
}

// ─── §4.4 Rule Type ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleType {
    TransferEligibility,
    InvestorClassification,
    HoldingPeriod,
    GeographicRestriction,
    SanctionsScreening,
    TransactionThreshold,
    AmlTrigger,
    MarketRestriction,
    RedemptionEligibility,
}

// ─── §4.7 Enforcement Action ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementAction {
    Reject,
    Freeze,
    Restrict,
    Flag,
    RequireDisclosure,
}

impl EnforcementAction {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Reject | Self::Freeze | Self::Restrict)
    }
}

// ─── §5.3 Governance Action ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceAction {
    FreezeBalance,
    UnfreezeBalance,
    RestrictTransfer,
    SeizeAsset,
    ForceRedemption,
    EmergencyRollback,
}

// ─── §7.5 Backing Type ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackingType {
    Fiat,
    Treasury,
    Commodity,
    RealEstate,
    Equity,
    Debt,
    Mixed,
}

// ─── §7.7 Attestation Frequency ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttestationFrequency {
    Realtime,
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Annual,
}

impl AttestationFrequency {
    pub fn to_seconds(&self) -> u64 {
        match self {
            Self::Realtime  => 60,
            Self::Daily     => 86_400,
            Self::Weekly    => 604_800,
            Self::Monthly   => 2_592_000,
            Self::Quarterly => 7_776_000,
            Self::Annual    => 31_536_000,
        }
    }
}

// ─── §7.8 Reserve Status ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReserveStatus {
    Valid,
    Stale,
    Invalid,
    Unknown,
}

// ─── §7.11 Insolvency Priority ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InsolvencyPriority {
    Senior,
    Secured,
    Unsecured,
    Subordinated,
}

// ─── §3.8 ZK Proof ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkProof {
    pub scheme:             String,
    pub statement:          String,
    pub witness_commitment: String,
    pub proof_bytes:        String, // hex
    pub nonce:              String,
}

// ─── §3.3 Identity Record ─────────────────────────────────────────────────────

/// IR = (HID, VA, JI, EXP, REV, ATTR, PROOF) — §3.3
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRecord {
    pub identity_hash:           String,
    pub verification_authority:  String,
    pub jurisdiction_identity:   String,
    pub expiry:                  i64,
    pub revoked:                 bool,
    #[serde(default)]
    pub attribute_commitments:   Vec<String>,
    pub proof:                   Option<ZkProof>,
}

// ─── §12.2 Legal Mirror ──────────────────────────────────────────────────────

/// L = (J, LH, LV, TS, SIGN) — §12.2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalMirror {
    pub jurisdiction:        String,
    pub legal_hash:          String,
    pub legal_version:       String,
    pub timestamp:           i64,
    pub authority_signature: Option<String>,
}

// ─── §13.5 Compliance Rule ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceRule {
    pub rule_id:   String,
    pub rule_type: RuleType,
    pub scope:     String,
    pub trigger:   String,
    pub priority:  i32,
    pub action:    EnforcementAction,
    #[serde(default)]
    pub params:    HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceModule {
    pub rules: Vec<ComplianceRule>,
}

// ─── §13.6 Governance Module ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceModule {
    pub authorities:      Vec<String>,
    pub quorum_threshold: u32, // integer percentage e.g. 67
    pub override_types:   Vec<GovernanceAction>,
}

// ─── §5.2 Override Object ────────────────────────────────────────────────────

/// O = (OID, AUTH, ACTION, TARGET, BASIS, TS, SIG) — §5.2
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideObject {
    pub override_id:  String,
    pub authority:    String,
    pub action:       GovernanceAction,
    pub target:       String,
    pub legal_basis:  String,
    pub timestamp:    i64,
    pub signature:    String,
}

// ─── §13.7 Fee Module ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeAllocation {
    pub recipient:    String,
    pub basis_points: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeModule {
    pub base_rate_basis_points: u32,
    pub allocations:            Vec<FeeAllocation>,
}

// ─── §13.8 Reserve Interface ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedemptionLogic {
    pub eligibility:    String,
    pub procedure:      String,
    pub settlement:     String,
    pub timeframe_sec:  i64,
}

/// B = (CID, ABT, AH, FREQ, RLOG, PRIORITY) — §7.3
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveInterface {
    pub custodian_id:           String,
    pub backing_type:           BackingType,
    pub audit_hash:             String,
    pub attestation_frequency:  AttestationFrequency,
    pub insolvency_priority:    InsolvencyPriority,
    pub redemption_logic:       RedemptionLogic,
}

// ─── §13.9 Cross-Chain Metadata ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossChainMetadata {
    pub certificate_id:  String,
    pub origin_chain_id: String,
    pub compliance_hash: String,
    pub governance_hash: String,
    pub state_hash:      String,
    pub timestamp:       i64,
}

// ─── §13.2 Canonical Asset Object ────────────────────────────────────────────

/// A = (I, T, J, L, ID, C, R, G, F, B, X, S) — §2.1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub asset_id:            String,
    pub asset_type:          AssetType,
    pub jurisdiction:        String,
    pub legal_mirror:        LegalMirror,
    pub identity_level:      IdentityLevel,
    pub compliance_module:   ComplianceModule,
    pub governance_module:   GovernanceModule,
    pub fee_module:          FeeModule,
    pub reserve_interface:   Option<ReserveInterface>,
    pub crosschain_metadata: CrossChainMetadata,
    pub state:               AssetState,
    pub standard_version:    String,
}

// ─── Transfer ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferEvent {
    pub asset_id:  String,
    pub sender:    String,
    pub receiver:  String,
    pub amount:    u128,  // use u128 for large token quantities
    pub nonce:     String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementProof {
    pub tx_id:        String,
    pub block_height: u64,
    pub state_hash:   String,
    pub timestamp:    i64,
}

// ─── Compliance Decision ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ComplianceDecision {
    Allow,
    Block { blocked_by: ComplianceRule, action: EnforcementAction },
}

impl ComplianceDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}
