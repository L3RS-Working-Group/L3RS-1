"""
L3RS-1 Cryptographic Primitives — Python
§13.11 Canonical Serialization · §10.3 Security Assumptions
Pure stdlib — zero external dependencies.
"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any


# ── §10.3 Core Hash Function ─────────────────────────────────────────────────

def sha256(data: bytes) -> str:
    """H(data) — SHA-256 per §10.3. Returns lowercase hex."""
    return hashlib.sha256(data).hexdigest()


def sha256_concat(*parts: bytes) -> str:
    """SHA-256 of concatenated byte parts."""
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.hexdigest()


# ── §13.11 Canonical Serialization ───────────────────────────────────────────

def canonicalize(obj: Any) -> str:
    """ser(Y) — canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_object(obj: Any) -> str:
    """HY = H(ser(Y))"""
    return sha256(canonicalize(obj).encode("utf-8"))


# ── §2.2 Asset_ID ────────────────────────────────────────────────────────────

def construct_asset_id(
    issuer_pubkey_hex: str,
    timestamp_unix: int,
    nonce_hex: str,
) -> str:
    """I = H(pk_issuer || ts || nonce) — §2.2"""
    pk    = bytes.fromhex(issuer_pubkey_hex)
    ts    = struct.pack(">Q", timestamp_unix)
    nonce = bytes.fromhex(nonce_hex)
    return sha256_concat(pk, ts, nonce)


# ── §3.4 Identity Hash ───────────────────────────────────────────────────────

def construct_identity_hash(pii_utf8: str, salt_hex: str, domain: str) -> str:
    """HID = H(PII || salt || domain) — §3.4"""
    return sha256_concat(
        pii_utf8.encode("utf-8"),
        bytes.fromhex(salt_hex),
        domain.encode("utf-8"),
    )


# ── §8.3 Cross-Chain Certificate Identifier ──────────────────────────────────

def construct_cid(
    asset_id: str,
    state_hash: str,
    compliance_hash: str,
    governance_hash: str,
    timestamp_unix: int,
) -> str:
    """CID = H(I || SH || CH || GH || t) — §8.3"""
    return sha256_concat(
        bytes.fromhex(asset_id),
        bytes.fromhex(state_hash),
        bytes.fromhex(compliance_hash),
        bytes.fromhex(governance_hash),
        struct.pack(">Q", timestamp_unix),
    )


# ── §9.6 Transaction ID ──────────────────────────────────────────────────────

def construct_tx_id(
    sender: str,
    receiver: str,
    amount: int,
    nonce_hex: str,
    timestamp_unix: int,
) -> str:
    """TxID = H(sender || receiver || amount || nonce || timestamp) — §9.6"""
    amount_buf = amount.to_bytes(32, "big")
    return sha256_concat(
        sender.encode("utf-8"),
        receiver.encode("utf-8"),
        amount_buf,
        bytes.fromhex(nonce_hex),
        struct.pack(">Q", timestamp_unix),
    )


# ── §5.10 Override Hash ──────────────────────────────────────────────────────

def construct_override_hash(
    override_id: str,
    authority: str,
    action: str,
    timestamp_unix: int,
) -> str:
    """Override_Record = H(OID || AUTH || ACTION || TS) — §5.10"""
    return sha256_concat(
        override_id.encode("utf-8"),
        authority.encode("utf-8"),
        action.encode("utf-8"),
        struct.pack(">Q", timestamp_unix),
    )


# ── §8.11 Chain ID ───────────────────────────────────────────────────────────

def construct_chain_id(
    chain_name: str,
    network_type: str,
    genesis_hash_hex: str,
) -> str:
    """ChainID = H(chain_name || network_type || genesis_hash) — §8.11"""
    return sha256_concat(
        chain_name.encode("utf-8"),
        network_type.encode("utf-8"),
        bytes.fromhex(genesis_hash_hex),
    )


# ── Signature Verifier interface ─────────────────────────────────────────────

class SignatureVerifier:
    """Abstract interface for EdDSA/ECDSA verification per §10.3."""
    def verify(self, message: bytes, signature_hex: str, public_key_hex: str) -> bool:
        raise NotImplementedError
