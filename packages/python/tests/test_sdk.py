"""L3RS-1 Python SDK — pytest test suite"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from l3rs1.crypto import (
    sha256, canonicalize, construct_asset_id, construct_cid,
    construct_tx_id, construct_identity_hash,
)
from l3rs1.types import (
    AssetState, AssetType, IdentityLevel, IdentityStatus,
    RuleType, EnforcementAction, GovernanceAction, BackingType,
    AttestationFrequency, ReserveStatus, InsolvencyPriority,
    FeeModule, FeeAllocation, IdentityRecord, TransferEvent,
)
from l3rs1.modules import (
    apply_state_transition, validate_fee_module, is_replay,
    identity_status,
)

PUBKEY   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
TS       = 1740355200
NONCE    = "0000000000000001"
EXPECTED = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a"
NOW      = 1740355200


# ── §13.11 Canonical Serialization ───────────────────────────────────────────

def test_canonical_key_sort():
    assert canonicalize({"z": 3, "a": 1, "m": 2}) == '{"a":1,"m":2,"z":3}'

def test_canonical_nested():
    assert canonicalize({"b": {"d": 4, "c": 3}, "a": 1}) == '{"a":1,"b":{"c":3,"d":4}}'

def test_canonical_no_whitespace():
    assert " " not in canonicalize({"key": "value"})

def test_canonical_determinism():
    obj = {"jurisdiction": "US", "assetId": "abc"}
    assert canonicalize(obj) == canonicalize(obj)


# ── §2.2 Asset_ID ────────────────────────────────────────────────────────────

def test_asset_id_vector():
    assert construct_asset_id(PUBKEY, TS, NONCE) == EXPECTED

def test_asset_id_length():
    assert len(construct_asset_id(PUBKEY, TS, NONCE)) == 64

def test_asset_id_deterministic():
    assert construct_asset_id(PUBKEY, TS, NONCE) == construct_asset_id(PUBKEY, TS, NONCE)

def test_asset_id_nonce_sensitive():
    assert construct_asset_id(PUBKEY, TS, NONCE) != construct_asset_id(PUBKEY, TS, "0000000000000002")

def test_asset_id_timestamp_sensitive():
    assert construct_asset_id(PUBKEY, TS, NONCE) != construct_asset_id(PUBKEY, TS + 1, NONCE)


# ── §2.5 State Transitions ───────────────────────────────────────────────────

@pytest.mark.parametrize("from_s,trigger,expected", [
    (AssetState.ISSUED,     "ACTIVATION",    AssetState.ACTIVE),
    (AssetState.ACTIVE,     "BREACH",        AssetState.RESTRICTED),
    (AssetState.ACTIVE,     "FREEZE",        AssetState.FROZEN),
    (AssetState.RESTRICTED, "CLEARED",       AssetState.ACTIVE),
    (AssetState.FROZEN,     "RELEASE",       AssetState.ACTIVE),
    (AssetState.ACTIVE,     "REDEMPTION",    AssetState.REDEEMED),
    (AssetState.REDEEMED,   "FINALIZATION",  AssetState.BURNED),
    (AssetState.ACTIVE,     "SUSPENSION",    AssetState.SUSPENDED),
    (AssetState.SUSPENDED,  "REINSTATEMENT", AssetState.ACTIVE),
])
def test_valid_transition(from_s, trigger, expected):
    r = apply_state_transition(from_s, trigger)
    assert r.success and r.new_state == expected

def test_burned_is_terminal():
    assert not apply_state_transition(AssetState.BURNED, "ACTIVATION").success

def test_invalid_transition():
    assert not apply_state_transition(AssetState.ISSUED, "FREEZE").success


# ── §8.3 CID ─────────────────────────────────────────────────────────────────

def test_cid_length():
    assert len(construct_cid("a"*64, "b"*64, "c"*64, "d"*64, 1000)) == 64

def test_cid_deterministic():
    a = construct_cid("a"*64, "b"*64, "c"*64, "d"*64, 1000)
    b = construct_cid("a"*64, "b"*64, "c"*64, "d"*64, 1000)
    assert a == b

def test_cid_timestamp_sensitive():
    a = construct_cid("a"*64, "b"*64, "c"*64, "d"*64, 1000)
    b = construct_cid("a"*64, "b"*64, "c"*64, "d"*64, 1001)
    assert a != b


# ── §9.6 Replay Protection ───────────────────────────────────────────────────

def test_same_event_is_replay():
    ev = TransferEvent("a", "alice", "bob", 1000, "00"*8, TS)
    txid = construct_tx_id(ev.sender, ev.receiver, ev.amount, ev.nonce, ev.timestamp)
    assert is_replay(ev, {txid})

def test_different_nonce_not_replay():
    ev1 = TransferEvent("a", "alice", "bob", 1000, "00"*8, TS)
    ev2 = TransferEvent("a", "alice", "bob", 1000, "01"*8, TS)
    txid = construct_tx_id(ev1.sender, ev1.receiver, ev1.amount, ev1.nonce, ev1.timestamp)
    assert not is_replay(ev2, {txid})


# ── §6.12 Fee Validation ─────────────────────────────────────────────────────

def test_valid_fee_module():
    fm = FeeModule(100, (
        FeeAllocation("a", 2000), FeeAllocation("b", 3000),
        FeeAllocation("c", 2000), FeeAllocation("d", 2500),
        FeeAllocation("e", 500),
    ))
    validate_fee_module(fm)  # no raise

def test_fee_partial_rejected():
    with pytest.raises(ValueError):
        validate_fee_module(FeeModule(100, (FeeAllocation("x", 5000),)))

def test_fee_over_rejected():
    with pytest.raises(ValueError):
        validate_fee_module(FeeModule(100, (FeeAllocation("a", 6000), FeeAllocation("b", 5000))))


# ── §3.6 Identity Status ─────────────────────────────────────────────────────

def test_identity_valid():
    r = IdentityRecord("a"*64, "va", "US", 9999999999, False)
    assert identity_status(r, NOW) == IdentityStatus.VALID

def test_identity_expired():
    r = IdentityRecord("a"*64, "va", "US", 1000000000, False)
    assert identity_status(r, NOW) == IdentityStatus.EXPIRED

def test_identity_revoked():
    r = IdentityRecord("a"*64, "va", "US", 9999999999, True)
    assert identity_status(r, NOW) == IdentityStatus.REVOKED

def test_revoked_beats_expired():
    r = IdentityRecord("a"*64, "va", "US", 1000000000, True)
    assert identity_status(r, NOW) == IdentityStatus.REVOKED
