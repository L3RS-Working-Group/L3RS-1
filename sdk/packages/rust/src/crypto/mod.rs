//! L3RS-1 Cryptographic Primitives
//! §13.10-11 Canonical Serialization · §10.3 Security Assumptions

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::L3rsError;

// ─── Core Hash Function ───────────────────────────────────────────────────────

/// H(data) — collision-resistant SHA-256 per §10.3. Returns lowercase hex.
pub fn sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// SHA-256 of concatenated parts.
pub fn sha256_concat(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    hex::encode(h.finalize())
}

// ─── §13.11 Canonical Serialization ──────────────────────────────────────────

/// ser(Y) — canonical JSON per §13.11.
/// Sorted keys, no whitespace, UTF-8.
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, L3rsError> {
    let sorted = sort_keys(value);
    serde_json::to_vec(&sorted).map_err(|e| L3rsError::Serialization(e.to_string()))
}

fn sort_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .iter()
                .map(|(k, v)| (k.clone(), sort_keys(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_keys).collect())
        }
        other => other.clone(),
    }
}

/// HY = H(ser(Y))
pub fn hash_object<T: serde::Serialize>(obj: &T) -> Result<String, L3rsError> {
    let v = serde_json::to_value(obj).map_err(|e| L3rsError::Serialization(e.to_string()))?;
    let bytes = canonicalize(&v)?;
    Ok(sha256(&bytes))
}

// ─── §2.2 Asset_ID Construction ──────────────────────────────────────────────

/// I = H(pk_issuer || ts || nonce) — §2.2
pub fn construct_asset_id(
    issuer_pubkey_hex: &str,
    timestamp_unix: i64,
    nonce_hex: &str,
) -> Result<String, L3rsError> {
    let pk    = hex::decode(issuer_pubkey_hex).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    let ts    = (timestamp_unix as u64).to_be_bytes();
    let nonce = hex::decode(nonce_hex).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    Ok(sha256_concat(&[&pk, &ts, &nonce]))
}

// ─── §3.4 Identity Hash ──────────────────────────────────────────────────────

/// HID = H(PII || salt || domain) — §3.4
pub fn construct_identity_hash(
    pii_utf8: &str,
    salt_hex: &str,
    domain: &str,
) -> Result<String, L3rsError> {
    let salt = hex::decode(salt_hex).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    Ok(sha256_concat(&[pii_utf8.as_bytes(), &salt, domain.as_bytes()]))
}

// ─── §5.7 Legal Basis Hash ───────────────────────────────────────────────────

/// BASIS = H(legal_document || jurisdiction || case_id) — §5.7
pub fn construct_legal_basis_hash(
    legal_doc_hash: &str,
    jurisdiction: &str,
    case_id: &str,
) -> Result<String, L3rsError> {
    let doc = hex::decode(legal_doc_hash).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    Ok(sha256_concat(&[&doc, jurisdiction.as_bytes(), case_id.as_bytes()]))
}

// ─── §8.3 Cross-Chain Certificate Identifier ─────────────────────────────────

/// CID = H(I || SH || CH || GH || t) — §8.3
pub fn construct_cid(
    asset_id: &str,
    state_hash: &str,
    compliance_hash: &str,
    governance_hash: &str,
    timestamp_unix: i64,
) -> Result<String, L3rsError> {
    let decode = |s: &str| hex::decode(s).map_err(|e| L3rsError::Crypto(e.to_string()));
    let id = decode(asset_id)?;
    let sh = decode(state_hash)?;
    let ch = decode(compliance_hash)?;
    let gh = decode(governance_hash)?;
    let ts = (timestamp_unix as u64).to_be_bytes();
    Ok(sha256_concat(&[&id, &sh, &ch, &gh, &ts]))
}

// ─── §9.6 Transaction ID ─────────────────────────────────────────────────────

/// TxID = H(sender || receiver || amount || nonce || timestamp) — §9.6
pub fn construct_tx_id(
    sender: &str,
    receiver: &str,
    amount: u128,
    nonce_hex: &str,
    timestamp_unix: i64,
) -> Result<String, L3rsError> {
    let amount_buf = amount.to_be_bytes(); // 16-byte; use [0u8;32] for 256-bit compat
    let mut amount_32 = [0u8; 32];
    amount_32[16..].copy_from_slice(&amount_buf);

    let nonce = hex::decode(nonce_hex).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    let ts    = (timestamp_unix as u64).to_be_bytes();
    Ok(sha256_concat(&[
        sender.as_bytes(),
        receiver.as_bytes(),
        &amount_32,
        &nonce,
        &ts,
    ]))
}

// ─── §5.10 Override Record ───────────────────────────────────────────────────

/// Override_Record = H(OID || AUTH || ACTION || TS) — §5.10
pub fn construct_override_hash(
    override_id: &str,
    authority: &str,
    action: &str,
    timestamp_unix: i64,
) -> String {
    let ts = (timestamp_unix as u64).to_be_bytes();
    sha256_concat(&[
        override_id.as_bytes(),
        authority.as_bytes(),
        action.as_bytes(),
        &ts,
    ])
}

// ─── §8.11 Chain ID ──────────────────────────────────────────────────────────

/// ChainID = H(chain_name || network_type || genesis_hash) — §8.11
pub fn construct_chain_id(
    chain_name: &str,
    network_type: &str,
    genesis_hash_hex: &str,
) -> Result<String, L3rsError> {
    let genesis = hex::decode(genesis_hash_hex).map_err(|e| L3rsError::Crypto(e.to_string()))?;
    Ok(sha256_concat(&[
        chain_name.as_bytes(),
        network_type.as_bytes(),
        &genesis,
    ]))
}

// ─── Signature Verifier ───────────────────────────────────────────────────────

/// Abstract trait for EdDSA/ECDSA signature verification per §10.3.
pub trait SignatureVerifier: Send + Sync {
    fn verify(&self, message: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<bool, L3rsError>;
}
