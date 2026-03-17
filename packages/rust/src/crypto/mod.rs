//! L3RS-1 Cryptographic Primitives — §13.11, §10.3
use crate::L3rsError;
use hex;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// SHA-256 of concatenated parts. Returns lowercase hex.
pub fn sha256_concat(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}

/// Canonical JSON — sorted keys, no whitespace — §13.11
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, L3rsError> {
    serde_json::to_vec(&sort_keys(value)).map_err(|e| L3rsError::Serialization(e.to_string()))
}

fn sort_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<_, _> =
                map.iter().map(|(k, v)| (k.clone(), sort_keys(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_keys).collect())
        }
        other => other.clone(),
    }
}

/// §2.2 — I = H(pk_issuer || ts || nonce)
pub fn construct_asset_id(
    pubkey_hex: &str,
    timestamp: i64,
    nonce_hex: &str,
) -> Result<String, L3rsError> {
    let pk = hex::decode(pubkey_hex).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    let ts = (timestamp as u64).to_be_bytes();
    let nonce = hex::decode(nonce_hex).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    Ok(sha256_concat(&[&pk, &ts, &nonce]))
}

/// §8.3 — CID = H(I || SH || CH || GH || t)
pub fn construct_cid(
    asset_id: &str,
    state_hash: &str,
    compliance_hash: &str,
    governance_hash: &str,
    timestamp: i64,
) -> Result<String, L3rsError> {
    let decode = |s: &str| hex::decode(s).map_err(|e| L3rsError::Crypto(e.to_string()));
    let id = decode(asset_id)?;
    let sh = decode(state_hash)?;
    let ch = decode(compliance_hash)?;
    let gh = decode(governance_hash)?;
    let ts = (timestamp as u64).to_be_bytes();
    Ok(sha256_concat(&[&id, &sh, &ch, &gh, &ts]))
}

/// §9.6 — TxID = H(sender || receiver || amount || nonce || timestamp)
pub fn construct_tx_id(
    sender: &str,
    receiver: &str,
    amount: u64,
    nonce_hex: &str,
    timestamp: i64,
) -> Result<String, L3rsError> {
    let mut amount_buf = [0u8; 32];
    amount_buf[24..].copy_from_slice(&amount.to_be_bytes());
    let nonce = hex::decode(nonce_hex).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    let ts = (timestamp as u64).to_be_bytes();
    Ok(sha256_concat(&[
        sender.as_bytes(),
        receiver.as_bytes(),
        &amount_buf,
        &nonce,
        &ts,
    ]))
}

/// §5.10 — Override_Record = H(OID || AUTH || ACTION || TS)
pub fn construct_override_hash(
    override_id: &str,
    authority: &str,
    action: &str,
    ts: i64,
) -> String {
    let ts_bytes = (ts as u64).to_be_bytes();
    sha256_concat(&[
        override_id.as_bytes(),
        authority.as_bytes(),
        action.as_bytes(),
        &ts_bytes,
    ])
}
