//! L3RS-1 Core Modules — Rust
//! asset · compliance · identity · governance · settlement · transfer

use std::collections::HashSet;

use crate::{
    crypto::{construct_cid, construct_override_hash, construct_tx_id, hash_object, sha256_concat, SignatureVerifier},
    types::*,
    L3rsError,
};

// ══════════════════════════════════════════════════════════════════════════════
// §2 Asset State Machine
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub from:    AssetState,
    pub trigger: &'static str,
    pub to:      AssetState,
}

/// §2.5 State Transition Matrix — complete and exhaustive.
pub static TRANSITION_MATRIX: &[(&str, &str, &str)] = &[
    ("ISSUED",     "ACTIVATION",    "ACTIVE"),
    ("ACTIVE",     "BREACH",        "RESTRICTED"),
    ("ACTIVE",     "FREEZE",        "FROZEN"),
    ("RESTRICTED", "CLEARED",       "ACTIVE"),
    ("FROZEN",     "RELEASE",       "ACTIVE"),
    ("ACTIVE",     "REDEMPTION",    "REDEEMED"),
    ("REDEEMED",   "FINALIZATION",  "BURNED"),
    ("ACTIVE",     "SUSPENSION",    "SUSPENDED"),
    ("SUSPENDED",  "REINSTATEMENT", "ACTIVE"),
];

/// Apply a state transition per §2.5. Invariant I₁.
pub fn apply_state_transition(
    current: &AssetState,
    trigger: &str,
) -> Result<AssetState, L3rsError> {
    if current.is_terminal() {
        return Err(L3rsError::InvalidStateTransition(
            "BURNED is a terminal state".into(),
        ));
    }
    let current_str = format!("{current:?}").to_uppercase();
    for (from, t, to) in TRANSITION_MATRIX {
        if *from == current_str.as_str() && *t == trigger {
            return parse_state(to);
        }
    }
    Err(L3rsError::InvalidStateTransition(format!(
        "No transition from {current_str} via {trigger}"
    )))
}

fn parse_state(s: &str) -> Result<AssetState, L3rsError> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| L3rsError::InvalidStateTransition(e.to_string()))
}

/// §13.14 Strict asset validation.
pub fn validate_asset(asset: &Asset) -> Result<(), L3rsError> {
    if asset.jurisdiction.len() != 2 || !asset.jurisdiction.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(L3rsError::Validation("Jurisdiction must be ISO 3166-1 alpha-2".into()));
    }
    if !asset.standard_version.starts_with("L3RS-") {
        return Err(L3rsError::Validation("standardVersion must start with L3RS-".into()));
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// §4 Compliance Engine
// ══════════════════════════════════════════════════════════════════════════════

pub struct ComplianceContext<'a> {
    pub asset:     &'a Asset,
    pub sender:    &'a str,
    pub receiver:  &'a str,
    pub amount:    u128,
    pub timestamp: i64,
    pub sanctions: Option<&'a dyn SanctionsRegistry>,
}

pub trait SanctionsRegistry: Send + Sync {
    fn registry_hash(&self) -> &str;
    fn is_listed(&self, address: &str) -> bool;
}

/// C: E → {Allow, Block} — §4.3. O(n) per §14.3. Invariant I₂.
pub fn evaluate_compliance<'a>(
    module: &'a ComplianceModule,
    ctx: &ComplianceContext<'_>,
) -> ComplianceDecision {
    if ctx.asset.state != AssetState::Active {
        return ComplianceDecision::Block {
            blocked_by: synthetic_state_rule(),
            action: EnforcementAction::Reject,
        };
    }

    let mut rules = module.rules.clone();
    rules.sort_by_key(|r| r.priority);

    for rule in rules {
        if !trigger_applies(&rule, ctx) {
            continue;
        }
        if !evaluate_rule(&rule, ctx) && rule.action.is_blocking() {
            let action = rule.action.clone();
            return ComplianceDecision::Block { blocked_by: rule, action };
        }
    }

    ComplianceDecision::Allow
}

fn trigger_applies(rule: &ComplianceRule, ctx: &ComplianceContext<'_>) -> bool {
    rule.scope == "*" || rule.scope == ctx.asset.jurisdiction
}

fn evaluate_rule(rule: &ComplianceRule, ctx: &ComplianceContext<'_>) -> bool {
    match rule.rule_type {
        RuleType::HoldingPeriod => {
            let acq = rule.params.get("acquisitionTime").and_then(|v| v.as_i64());
            let period = rule.params.get("holdingPeriodSec").and_then(|v| v.as_i64());
            match (acq, period) {
                (Some(a), Some(p)) => (ctx.timestamp - a) >= p,
                _ => false,
            }
        }
        RuleType::TransactionThreshold => {
            let threshold = rule.params.get("thresholdAmount")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u128>().ok());
            threshold.map(|t| ctx.amount <= t).unwrap_or(false)
        }
        RuleType::SanctionsScreening => {
            match ctx.sanctions {
                None => false, // §4.8: cannot verify → block
                Some(reg) => !reg.is_listed(ctx.sender) && !reg.is_listed(ctx.receiver),
            }
        }
        _ => {
            // External rules: require pre-resolved result
            rule.params.get("externalResult")
                .and_then(|v| v.as_bool())
                .unwrap_or(false) // §14.10: unknown → block
        }
    }
}

fn synthetic_state_rule() -> ComplianceRule {
    ComplianceRule {
        rule_id:   "SYSTEM_STATE_CHECK".into(),
        rule_type: RuleType::TransferEligibility,
        scope:     "*".into(),
        trigger:   "TRANSFER".into(),
        priority:  0,
        action:    EnforcementAction::Reject,
        params:    Default::default(),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// §3 Identity Binding
// ══════════════════════════════════════════════════════════════════════════════

/// Status(IR) — §3.6. Invariant I₃.
pub fn identity_status(record: &IdentityRecord, now_unix: i64) -> IdentityStatus {
    if record.revoked      { return IdentityStatus::Revoked; }
    if now_unix >= record.expiry { return IdentityStatus::Expired; }
    IdentityStatus::Valid
}

/// validate_identity(party) — §3.11
pub fn validate_identity(record: &IdentityRecord, now_unix: i64) -> Result<(), L3rsError> {
    match identity_status(record, now_unix) {
        IdentityStatus::Valid => {}
        status => {
            return Err(L3rsError::IdentityInvalid(format!("{status:?}")));
        }
    }
    if record.proof.is_some() {
        // §3.8: conservative — ZKP requires real backend
        return Err(L3rsError::IdentityInvalid("ZKP verification not implemented".into()));
    }
    Ok(())
}

/// Multi-jurisdiction validation — §3.9
pub fn validate_multi_jurisdiction(
    records: &[IdentityRecord],
    required: &[String],
    now_unix: i64,
) -> Result<(), L3rsError> {
    let valid: HashSet<&str> = records
        .iter()
        .filter(|r| identity_status(r, now_unix) == IdentityStatus::Valid)
        .map(|r| r.jurisdiction_identity.as_str())
        .collect();

    let missing: Vec<&str> = required
        .iter()
        .filter(|j| !valid.contains(j.as_str()))
        .map(|j| j.as_str())
        .collect();

    if !missing.is_empty() {
        return Err(L3rsError::IdentityInvalid(format!(
            "Missing jurisdictions: {}", missing.join(", ")
        )));
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// §5 Governance Override
// ══════════════════════════════════════════════════════════════════════════════

pub struct OverrideRecord {
    pub record_hash: String,
    pub override_id: String,
    pub authority:   String,
    pub action:      GovernanceAction,
    pub timestamp:   i64,
}

/// validate_override(O) — §5.6. Invariant I₄.
pub fn validate_override(
    override_obj: &OverrideObject,
    governance: &GovernanceModule,
    verifier: &dyn SignatureVerifier,
    all_signatures: &[(&str, &str)],
) -> Result<(), L3rsError> {
    if !governance.authorities.contains(&override_obj.authority) {
        return Err(L3rsError::GovernanceViolation("Authority not registered".into()));
    }
    if !governance.override_types.contains(&override_obj.action) {
        return Err(L3rsError::GovernanceViolation("Action not permitted".into()));
    }
    if override_obj.legal_basis.len() < 64 {
        return Err(L3rsError::GovernanceViolation("Legal basis hash missing".into()));
    }
    let msg = hex::decode(&override_obj.legal_basis)
        .map_err(|e| L3rsError::Crypto(e.to_string()))?;
    let valid = verifier.verify(&msg, &override_obj.signature, &override_obj.authority)
        .map_err(|e| L3rsError::Crypto(e.to_string()))?;
    if !valid {
        return Err(L3rsError::GovernanceViolation("Signature invalid".into()));
    }
    if override_obj.action == GovernanceAction::EmergencyRollback {
        validate_quorum(governance, all_signatures)?;
    }
    Ok(())
}

fn validate_quorum(
    governance: &GovernanceModule,
    signatures: &[(&str, &str)],
) -> Result<(), L3rsError> {
    let n = governance.authorities.len();
    let required = (2 * n + 2) / 3; // ceil(2/3 * N)
    let signed: HashSet<&str> = signatures
        .iter()
        .filter(|(auth, _)| governance.authorities.contains(&auth.to_string()))
        .map(|(auth, _)| *auth)
        .collect();
    if signed.len() < required {
        return Err(L3rsError::GovernanceViolation(format!(
            "Quorum not met: {}/{required}", signed.len()
        )));
    }
    Ok(())
}

pub fn create_override_record(o: &OverrideObject) -> OverrideRecord {
    let action_str = serde_json::to_value(&o.action)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    OverrideRecord {
        record_hash: construct_override_hash(&o.override_id, &o.authority, &action_str, o.timestamp),
        override_id: o.override_id.clone(),
        authority:   o.authority.clone(),
        action:      o.action.clone(),
        timestamp:   o.timestamp,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// §6 Fee Routing
// ══════════════════════════════════════════════════════════════════════════════

pub struct FeeDistribution {
    pub total_fee:       u128,
    pub allocations:     Vec<(String, u128)>,
    pub fee_record_hash: String,
}

/// §6.12 Economic Integrity Constraint
pub fn validate_fee_module(fee: &FeeModule) -> Result<(), L3rsError> {
    let total: u32 = fee.allocations.iter().map(|a| a.basis_points).sum();
    if total != 10_000 {
        return Err(L3rsError::Validation(format!(
            "Fee basis points must sum to 10000; got {total}"
        )));
    }
    Ok(())
}

/// distribute_fees(A, amount) — §6.5
pub fn distribute_fees(
    fee: &FeeModule,
    amount: u128,
    tx_id: &str,
    timestamp: i64,
) -> Result<FeeDistribution, L3rsError> {
    validate_fee_module(fee)?;
    let total_fee = (amount * fee.base_rate_basis_points as u128) / 10_000;
    let allocations = fee.allocations.iter()
        .map(|a| (a.recipient.clone(), (total_fee * a.basis_points as u128) / 10_000))
        .collect();
    let ts = (timestamp as u64).to_be_bytes();
    let fee_record_hash = sha256_concat(&[
        &hex::decode(tx_id).unwrap_or_default(),
        &total_fee.to_be_bytes(),
        &ts,
    ]);
    Ok(FeeDistribution { total_fee, allocations, fee_record_hash })
}

// ══════════════════════════════════════════════════════════════════════════════
// §8 Cross-Chain
// ══════════════════════════════════════════════════════════════════════════════

pub struct CrossChainCertificate {
    pub cid:             String,
    pub asset_id:        String,
    pub state_hash:      String,
    pub compliance_hash: String,
    pub governance_hash: String,
    pub timestamp:       i64,
}

pub fn build_cross_chain_certificate(
    asset: &Asset,
    timestamp: i64,
) -> Result<CrossChainCertificate, L3rsError> {
    let state_hash      = hash_object(&asset.state)?;
    let compliance_hash = hash_object(&asset.compliance_module)?;
    let governance_hash = hash_object(&asset.governance_module)?;
    let cid = construct_cid(&asset.asset_id, &state_hash, &compliance_hash, &governance_hash, timestamp)?;
    Ok(CrossChainCertificate { cid, asset_id: asset.asset_id.clone(), state_hash, compliance_hash, governance_hash, timestamp })
}

pub fn verify_cross_chain(
    cert: &CrossChainCertificate,
    dest_asset_id: &str,
    dest_compliance_hash: &str,
    dest_governance_hash: &str,
) -> Result<(), L3rsError> {
    if dest_asset_id != cert.asset_id {
        return Err(L3rsError::CrossChainViolation("Asset_ID changed".into()));
    }
    let recomputed = construct_cid(
        &cert.asset_id, &cert.state_hash, &cert.compliance_hash,
        &cert.governance_hash, cert.timestamp,
    )?;
    if recomputed != cert.cid {
        return Err(L3rsError::CrossChainViolation("CID mismatch".into()));
    }
    if dest_compliance_hash != cert.compliance_hash {
        return Err(L3rsError::CrossChainViolation("Compliance downgrade".into()));
    }
    if dest_governance_hash != cert.governance_hash {
        return Err(L3rsError::CrossChainViolation("Governance hash changed".into()));
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// §9 Settlement + §2.7 Transfer Executor
// ══════════════════════════════════════════════════════════════════════════════

pub fn build_settlement_proof(
    event: &TransferEvent,
    block_height: u64,
    state_hash: String,
) -> Result<SettlementProof, L3rsError> {
    let tx_id = construct_tx_id(
        &event.sender, &event.receiver, event.amount, &event.nonce, event.timestamp,
    )?;
    Ok(SettlementProof { tx_id, block_height, state_hash, timestamp: event.timestamp })
}

pub fn is_replay(event: &TransferEvent, ledger_history: &HashSet<String>) -> Result<bool, L3rsError> {
    let tx_id = construct_tx_id(
        &event.sender, &event.receiver, event.amount, &event.nonce, event.timestamp,
    )?;
    Ok(ledger_history.contains(&tx_id))
}

pub struct TransferOutput {
    pub tx_id:       Option<String>,
    pub proof:       Option<SettlementProof>,
    pub fee_record:  Option<String>,
    pub error:       Option<String>,
    pub failed_step: Option<String>,
}

impl TransferOutput {
    pub fn success(&self) -> bool { self.error.is_none() }
}

/// §2.6 Deterministic 7-step transfer execution.
pub fn execute_transfer(
    asset: &Asset,
    event: &TransferEvent,
    sender_records: &[IdentityRecord],
    receiver_records: &[IdentityRecord],
    ledger_history: &HashSet<String>,
    block_height: u64,
    sanctions: Option<&dyn SanctionsRegistry>,
    required_jurisdictions: Option<&[String]>,
) -> TransferOutput {
    macro_rules! fail {
        ($step:expr, $msg:expr) => {
            return TransferOutput {
                tx_id: None, proof: None, fee_record: None,
                error: Some($msg.to_string()),
                failed_step: Some($step.to_string()),
            }
        };
    }

    match is_replay(event, ledger_history) {
        Ok(true)  => fail!("REPLAY_CHECK", "Duplicate TxID — replay rejected"),
        Err(e)    => fail!("REPLAY_CHECK", e.to_string()),
        Ok(false) => {}
    }

    let tx_id = match construct_tx_id(&event.sender, &event.receiver, event.amount, &event.nonce, event.timestamp) {
        Ok(id) => id,
        Err(e) => fail!("TX_ID", e.to_string()),
    };

    if asset.state != AssetState::Active {
        fail!("STATE_CHECK", format!("Asset state {:?} is not ACTIVE", asset.state));
    }

    if asset.identity_level >= IdentityLevel::Verified {
        let sender_primary = match sender_records.first() {
            Some(r) => r,
            None    => fail!("IDENTITY", "Sender has no identity record"),
        };
        if let Err(e) = validate_identity(sender_primary, event.timestamp) {
            fail!("IDENTITY_SENDER", e.to_string());
        }
        let receiver_primary = match receiver_records.first() {
            Some(r) => r,
            None    => fail!("IDENTITY", "Receiver has no identity record"),
        };
        if let Err(e) = validate_identity(receiver_primary, event.timestamp) {
            fail!("IDENTITY_RECEIVER", e.to_string());
        }
        if asset.identity_level == IdentityLevel::MultiJurisdiction {
            if let Some(juris) = required_jurisdictions {
                if let Err(e) = validate_multi_jurisdiction(sender_records, juris, event.timestamp) {
                    fail!("IDENTITY_MJ_SENDER", e.to_string());
                }
                if let Err(e) = validate_multi_jurisdiction(receiver_records, juris, event.timestamp) {
                    fail!("IDENTITY_MJ_RECEIVER", e.to_string());
                }
            }
        }
    }

    let ctx = ComplianceContext {
        asset, sender: &event.sender, receiver: &event.receiver,
        amount: event.amount, timestamp: event.timestamp, sanctions,
    };
    match evaluate_compliance(&asset.compliance_module, &ctx) {
        ComplianceDecision::Block { blocked_by, .. } => {
            fail!("COMPLIANCE", format!("Blocked by rule: {}", blocked_by.rule_id));
        }
        ComplianceDecision::Allow => {}
    }

    let fee_record = match distribute_fees(&asset.fee_module, event.amount, &tx_id, event.timestamp) {
        Ok(f)  => f.fee_record_hash,
        Err(e) => fail!("FEE_ROUTING", e.to_string()),
    };

    let proof = SettlementProof {
        tx_id: tx_id.clone(),
        block_height,
        state_hash: String::new(),
        timestamp: event.timestamp,
    };

    TransferOutput {
        tx_id: Some(tx_id),
        proof: Some(proof),
        fee_record: Some(fee_record),
        error: None,
        failed_step: None,
    }
}
