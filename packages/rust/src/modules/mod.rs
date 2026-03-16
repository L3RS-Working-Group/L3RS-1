//! L3RS-1 Core Modules — Rust
use std::collections::HashSet;
use crate::{crypto::construct_tx_id, types::*, L3rsError};

// ── §2.5 State Transitions ────────────────────────────────────────────────────

static TRANSITIONS: &[(&str, &str, &str)] = &[
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

pub fn apply_state_transition(current: &AssetState, trigger: &str) -> Result<AssetState, L3rsError> {
    if current.is_terminal() {
        return Err(L3rsError::InvalidStateTransition("BURNED is terminal".into()));
    }
    let cur = serde_json::to_value(current)
        .ok().and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    for (from, t, to) in TRANSITIONS {
        if *from == cur && *t == trigger {
            return serde_json::from_value(serde_json::Value::String(to.to_string()))
                .map_err(|e| L3rsError::Serialization(e.to_string()));
        }
    }
    Err(L3rsError::InvalidStateTransition(format!("No transition from {} via {}", cur, trigger)))
}

// ── §6.12 Fee Validation ─────────────────────────────────────────────────────

pub fn validate_fee_module(fee: &FeeModule) -> Result<(), L3rsError> {
    let total: u32 = fee.allocations.iter().map(|a| a.basis_points).sum();
    if total != 10_000 {
        return Err(L3rsError::Validation(format!(
            "Fee allocations must sum to 10000; got {}", total
        )));
    }
    Ok(())
}

// ── §3.6 Identity Status ─────────────────────────────────────────────────────

pub fn identity_status(record: &IdentityRecord, now: i64) -> IdentityStatus {
    if record.revoked       { return IdentityStatus::Revoked; }
    if now >= record.expiry { return IdentityStatus::Expired; }
    IdentityStatus::Valid
}

// ── §9.6 Replay Protection ────────────────────────────────────────────────────

pub fn is_replay(event: &TransferEvent, history: &HashSet<String>) -> Result<bool, L3rsError> {
    let tx_id = construct_tx_id(
        &event.sender, &event.receiver, event.amount, &event.nonce, event.timestamp,
    )?;
    Ok(history.contains(&tx_id))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use crate::crypto::*;
    use crate::modules::*;
    use crate::types::*;

    const PUBKEY:   &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const TS:       i64  = 1740355200;
    const NONCE:    &str = "0000000000000001";
    const EXPECTED: &str = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a";

    #[test]
    fn asset_id_canonical_vector() {
        assert_eq!(construct_asset_id(PUBKEY, TS, NONCE).unwrap(), EXPECTED);
    }

    #[test]
    fn asset_id_deterministic() {
        let a = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        let b = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn asset_id_nonce_sensitive() {
        let a = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        let b = construct_asset_id(PUBKEY, TS, "0000000000000002").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_key_sort() {
        let obj = serde_json::json!({"z": 3, "a": 1, "m": 2});
        let out = canonicalize(&obj).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":1,"m":2,"z":3}"#);
    }

    #[test]
    fn state_transitions_valid() {
        let cases = [
            (AssetState::Issued,     "ACTIVATION",    AssetState::Active),
            (AssetState::Active,     "BREACH",        AssetState::Restricted),
            (AssetState::Active,     "FREEZE",        AssetState::Frozen),
            (AssetState::Restricted, "CLEARED",       AssetState::Active),
            (AssetState::Frozen,     "RELEASE",       AssetState::Active),
            (AssetState::Active,     "REDEMPTION",    AssetState::Redeemed),
            (AssetState::Redeemed,   "FINALIZATION",  AssetState::Burned),
            (AssetState::Active,     "SUSPENSION",    AssetState::Suspended),
            (AssetState::Suspended,  "REINSTATEMENT", AssetState::Active),
        ];
        for (from, trigger, expected) in cases {
            let result = apply_state_transition(&from, trigger).unwrap();
            assert_eq!(result, expected, "failed: {:?} --{}-->", from, trigger);
        }
    }

    #[test]
    fn burned_is_terminal() {
        assert!(apply_state_transition(&AssetState::Burned, "ACTIVATION").is_err());
    }

    #[test]
    fn invalid_transition_rejected() {
        assert!(apply_state_transition(&AssetState::Issued, "FREEZE").is_err());
    }

    #[test]
    fn cid_deterministic() {
        let fill = |c: &str| c.repeat(64);
        let a = construct_cid(&fill("a"), &fill("b"), &fill("c"), &fill("d"), 1000).unwrap();
        let b = construct_cid(&fill("a"), &fill("b"), &fill("c"), &fill("d"), 1000).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn cid_timestamp_sensitive() {
        let fill = |c: &str| c.repeat(64);
        let a = construct_cid(&fill("a"), &fill("b"), &fill("c"), &fill("d"), 1000).unwrap();
        let b = construct_cid(&fill("a"), &fill("b"), &fill("c"), &fill("d"), 1001).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fee_validation() {
        let valid = FeeModule {
            base_rate_basis_points: 100,
            allocations: vec![
                FeeAllocation { recipient: "a".into(), basis_points: 2000 },
                FeeAllocation { recipient: "b".into(), basis_points: 3000 },
                FeeAllocation { recipient: "c".into(), basis_points: 2000 },
                FeeAllocation { recipient: "d".into(), basis_points: 2500 },
                FeeAllocation { recipient: "e".into(), basis_points: 500  },
            ],
        };
        assert!(validate_fee_module(&valid).is_ok());

        let invalid = FeeModule {
            base_rate_basis_points: 100,
            allocations: vec![FeeAllocation { recipient: "x".into(), basis_points: 5000 }],
        };
        assert!(validate_fee_module(&invalid).is_err());
    }

    #[test]
    fn identity_status_cases() {
        let now = 1_740_355_200i64;
        let valid   = IdentityRecord { identity_hash: "".into(), verification_authority: "".into(),
            jurisdiction_identity: "US".into(), expiry: 9_999_999_999, revoked: false };
        let expired = IdentityRecord { expiry: 1_000_000_000, ..valid.clone() };
        let revoked = IdentityRecord { revoked: true, ..valid.clone() };
        assert_eq!(identity_status(&valid,   now), IdentityStatus::Valid);
        assert_eq!(identity_status(&expired, now), IdentityStatus::Expired);
        assert_eq!(identity_status(&revoked, now), IdentityStatus::Revoked);
    }

    #[test]
    fn replay_protection() {
        let ev = TransferEvent { asset_id: "a".into(), sender: "alice".into(),
            receiver: "bob".into(), amount: 1000, nonce: NONCE.into(), timestamp: TS };
        let tx_id = construct_tx_id(&ev.sender, &ev.receiver, ev.amount, &ev.nonce, ev.timestamp).unwrap();
        let history: HashSet<String> = [tx_id].into();
        assert!(is_replay(&ev, &history).unwrap());

        let ev2 = TransferEvent { nonce: "0000000000000002".into(), ..ev };
        assert!(!is_replay(&ev2, &history).unwrap());
    }
}
