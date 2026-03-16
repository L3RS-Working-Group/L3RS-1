"""
L3RS-1 Crypto Primitives — Python
§13.10-11 Canonical Serialization · §10.3 Security Assumptions
Pure stdlib — no external dependencies.
"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Protocol


# ─── Core Hash Function ───────────────────────────────────────────────────────

def sha256(data: bytes) -> str:
    """H(data) — collision-resistant SHA-256 per §10.3. Returns hex string."""
    return hashlib.sha256(data).hexdigest()


def sha256_concat(*parts: bytes) -> str:
    """SHA-256 of concatenated byte parts."""
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.hexdigest()


# ─── §13.11 Canonical Serialization ──────────────────────────────────────────

def canonicalize(obj: Any) -> str:
    """
    ser(Y) — canonical JSON per §13.11:
    - No whitespace
    - Stable key ordering (sort_keys=True)
    - UTF-8 encoding
    - ensure_ascii=False preserves Unicode
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_object(obj: Any) -> str:
    """HY = H(ser(Y))"""
    return sha256(canonicalize(obj).encode("utf-8"))


# ─── §2.2 Asset_ID Construction ───────────────────────────────────────────────

def construct_asset_id(
    issuer_pubkey_hex: str,
    timestamp_unix: int,
    nonce_hex: str,
) -> str:
    """I = H(pk_issuer || ts || nonce) — §2.2"""
    pk_buf    = bytes.fromhex(issuer_pubkey_hex)
    ts_buf    = struct.pack(">Q", timestamp_unix)   # 8-byte big-endian uint64
    nonce_buf = bytes.fromhex(nonce_hex)
    return sha256_concat(pk_buf, ts_buf, nonce_buf)


# ─── §3.4 Identity Hash ───────────────────────────────────────────────────────

def construct_identity_hash(
    pii_utf8: str,
    salt_hex: str,
    domain: str = "l3rs1-identity-v1",
) -> str:
    """HID = H(PII || salt || domain) — §3.4. PII never stored on-chain."""
    pii_buf    = pii_utf8.encode("utf-8")
    salt_buf   = bytes.fromhex(salt_hex)
    domain_buf = domain.encode("utf-8")
    return sha256_concat(pii_buf, salt_buf, domain_buf)


# ─── §5.7 Legal Basis Hash ────────────────────────────────────────────────────

def construct_legal_basis_hash(
    legal_document_hash: str,
    jurisdiction: str,
    case_id: str,
) -> str:
    """BASIS = H(legal_document || jurisdiction || case_id) — §5.7"""
    return sha256_concat(
        bytes.fromhex(legal_document_hash),
        jurisdiction.encode("utf-8"),
        case_id.encode("utf-8"),
    )


# ─── §12.3 Legal Document Hash ───────────────────────────────────────────────

def construct_legal_hash(
    document_bytes: bytes,
    jurisdiction: str,
    version: str,
) -> str:
    """LH = H(document_bytes || jurisdiction || version) — §12.3"""
    return sha256_concat(
        document_bytes,
        jurisdiction.encode("utf-8"),
        version.encode("utf-8"),
    )


# ─── §8.3 Cross-Chain Certificate Identifier ─────────────────────────────────

def construct_cid(
    asset_id: str,
    state_hash: str,
    compliance_hash: str,
    governance_hash: str,
    timestamp_unix: int,
) -> str:
    """CID = H(I || SH || CH || GH || t) — §8.3"""
    ts_buf = struct.pack(">Q", timestamp_unix)
    return sha256_concat(
        bytes.fromhex(asset_id),
        bytes.fromhex(state_hash),
        bytes.fromhex(compliance_hash),
        bytes.fromhex(governance_hash),
        ts_buf,
    )


# ─── §9.6 Transaction ID ─────────────────────────────────────────────────────

def construct_tx_id(
    sender: str,
    receiver: str,
    amount: int,
    nonce: str,
    timestamp: int,
) -> str:
    """TxID = H(sender || receiver || amount || nonce || timestamp) — §9.6"""
    # Amount: 256-bit big-endian
    amount_buf = amount.to_bytes(32, "big")
    ts_buf     = struct.pack(">Q", timestamp)
    return sha256_concat(
        sender.encode("utf-8"),
        receiver.encode("utf-8"),
        amount_buf,
        bytes.fromhex(nonce),
        ts_buf,
    )


# ─── §5.10 Override Record Hash ───────────────────────────────────────────────

def construct_override_hash(
    override_id: str,
    authority: str,
    action: str,
    timestamp: int,
) -> str:
    """Override_Record = H(OID || AUTH || ACTION || TS) — §5.10"""
    ts_buf = struct.pack(">Q", timestamp)
    return sha256_concat(
        override_id.encode("utf-8"),
        authority.encode("utf-8"),
        action.encode("utf-8"),
        ts_buf,
    )


# ─── §8.11 Chain Identifier ───────────────────────────────────────────────────

def construct_chain_id(
    chain_name: str,
    network_type: str,
    genesis_hash: str,
) -> str:
    """ChainID = H(chain_name || network_type || genesis_hash) — §8.11"""
    return sha256_concat(
        chain_name.encode("utf-8"),
        network_type.encode("utf-8"),
        bytes.fromhex(genesis_hash),
    )


# ─── Signature Verifier Interface ────────────────────────────────────────────

class SignatureVerifier(Protocol):
    """Abstract interface for EdDSA/ECDSA verification — §10.3"""
    def verify(self, message: bytes, signature_hex: str, public_key_hex: str) -> bool: ...


class NullVerifier:
    """Rejects all signatures. Use only in testing."""
    def verify(self, _message: bytes, _signature_hex: str, _public_key_hex: str) -> bool:
        return False
