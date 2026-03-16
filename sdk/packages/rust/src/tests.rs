//! L3RS-1 Rust SDK Tests
//! Covers §2, §3, §6, §8, §9, §13

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use crate::crypto::*;
    use crate::modules::*;
    use crate::types::*;

    // ── §13.11 Canonical Serialization ───────────────────────────────────────

    #[test]
    fn canonical_keys_sorted_alphabetically() {
        let obj = serde_json::json!({"z": 3, "a": 1, "m": 2});
        let out = canonicalize(&obj).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":1,"m":2,"z":3}"#);
    }

    #[test]
    fn canonical_nested_keys_sorted() {
        let obj = serde_json::json!({"b": {"d": 4, "c": 3}, "a": 1});
        let out = canonicalize(&obj).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":1,"b":{"c":3,"d":4}}"#);
    }

    #[test]
    fn canonical_is_deterministic() {
        let obj = serde_json::json!({"jurisdiction": "US", "assetId": "abc", "state": "ACTIVE"});
        let a = canonicalize(&obj).unwrap();
        let b = canonicalize(&obj).unwrap();
        assert_eq!(a, b);
    }

    // ── §2.2 Asset_ID Construction ────────────────────────────────────────────

    const PUBKEY:   &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const TS:       i64  = 1740355200;
    const NONCE:    &str = "0000000000000001";
    const EXPECTED: &str = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a";

    #[test]
    fn asset_id_matches_canonical_vector() {
        let id = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        assert_eq!(id, EXPECTED);
    }

    #[test]
    fn asset_id_is_64_hex_chars() {
        let id = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        assert_eq!(id.len(), 64);
    }

    #[test]
    fn asset_id_is_deterministic() {
        let a = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        let b = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn asset_id_different_nonce_differs() {
        let a = construct_asset_id(PUBKEY, TS, NONCE).unwrap();
        let b = construct_asset_id(PUBKEY, TS, "0000000000000002").unwrap();
        assert_ne!(a, b);
    }

    // ── §2.5 State Transitions ────────────────────────────────────────────────

    #[test]
    fn valid_state_transitions() {
        let cases: &[(&str, &str, &str)] = &[
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
        for (from, trigger, expected) in cases {
            let from_state: AssetState = serde_json::from_str(&format!("\"{}\"", from)).unwrap();
            let result = apply_state_transition(&from_state, trigger)
                .unwrap_or_else(|_| panic!("transition {from} --{trigger}--> failed"));
            let expected_state: AssetState = serde_json::from_str(&format!("\"{}\"", expected)).unwrap();
            assert_eq!(result, expected_state, "{from} --{trigger}-->");
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

    // ── §8.3 Cross-Chain CID ──────────────────────────────────────────────────

    fn fill(ch: char) -> String { ch.to_string().repeat(64) }

    #[test]
    fn cid_is_64_hex_chars() {
        let cid = construct_cid(&fill('a'), &fill('b'), &fill('c'), &fill('d'), 1000).unwrap();
        assert_eq!(cid.len(), 64);
    }

    #[test]
    fn cid_is_deterministic() {
        let a = construct_cid(&fill('a'), &fill('b'), &fill('c'), &fill('d'), 1000).unwrap();
        let b = construct_cid(&fill('a'), &fill('b'), &fill('c'), &fill('d'), 1000).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn cid_changes_when_state_hash_changes() {
        let a = construct_cid(&fill('a'), &fill('b'), &fill('c'), &fill('d'), 1000).unwrap();
        let b = construct_cid(&fill('a'), &fill('e'), &fill('c'), &fill('d'), 1000).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn cid_changes_when_timestamp_changes() {
        let a = construct_cid(&fill('a'), &fill('b'), &fill('c'), &fill('d'), 1000).unwrap();
        let b = construct_cid(&fill('a'), &fill('b'), &fill('c'), &fill('d'), 1001).unwrap();
        assert_ne!(a, b);
    }

    // ── §9.6 TxID and Replay Protection ──────────────────────────────────────

    #[test]
    fn txid_is_64_hex_chars() {
        let id = construct_tx_id("alice", "bob", 1000u128, "0000000000000001", 1740355200).unwrap();
        assert_eq!(id.len(), 64);
    }

    #[test]
    fn txid_is_deterministic() {
        let a = construct_tx_id("alice", "bob", 1000u128, "0000000000000001", 1740355200).unwrap();
        let b = construct_tx_id("alice", "bob", 1000u128, "0000000000000001", 1740355200).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn same_event_is_replay() {
        let ev = TransferEvent {
            asset_id:  "asset1".into(),
            sender:    "alice".into(),
            receiver:  "bob".into(),
            amount:    1000,
            nonce:     "0000000000000001".into(),
            timestamp: 1740355200,
        };
        let txid = construct_tx_id(&ev.sender, &ev.receiver, ev.amount, &ev.nonce, ev.timestamp).unwrap();
        let history: HashSet<String> = [txid].into();
        assert!(is_replay(&ev, &history).unwrap());
    }

    #[test]
    fn different_nonce_is_not_replay() {
        let ev1 = TransferEvent {
            asset_id: "asset1".into(), sender: "alice".into(), receiver: "bob".into(),
            amount: 1000, nonce: "0000000000000001".into(), timestamp: 1740355200,
        };
        let ev2 = TransferEvent { nonce: "0000000000000002".into(), ..ev1.clone() };
        let txid1 = construct_tx_id(&ev1.sender, &ev1.receiver, ev1.amount, &ev1.nonce, ev1.timestamp).unwrap();
        let history: HashSet<String> = [txid1].into();
        assert!(!is_replay(&ev2, &history).unwrap());
    }

    // ── §6.12 Fee Validation ──────────────────────────────────────────────────

    #[test]
    fn valid_fee_allocation_accepted() {
        let fm = FeeModule {
            base_rate_basis_points: 100,
            allocations: vec![
                FeeAllocation { recipient: "sovereign".into(), basis_points: 2000 },
                FeeAllocation { recipient: "validator".into(),  basis_points: 3000 },
                FeeAllocation { recipient: "storage".into(),    basis_points: 2000 },
                FeeAllocation { recipient: "operator".into(),   basis_points: 2500 },
                FeeAllocation { recipient: "bridge".into(),     basis_points: 500  },
            ],
        };
        assert!(validate_fee_module(&fm).is_ok());
    }

    #[test]
    fn partial_allocation_rejected() {
        let fm = FeeModule {
            base_rate_basis_points: 100,
            allocations: vec![FeeAllocation { recipient: "only".into(), basis_points: 5000 }],
        };
        assert!(validate_fee_module(&fm).is_err());
    }
}
