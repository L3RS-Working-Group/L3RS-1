"""
L3RS-1 Python SDK Test Suite
pytest tests covering all spec sections.
Run: pytest tests/ -v
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from l3rs1.crypto import (
    sha256, sha256_concat, canonicalize, construct_asset_id,
    construct_cid, construct_tx_id, construct_identity_hash,
)
from l3rs1.types import (
    AssetState, AssetType, IdentityLevel, RuleType,
    EnforcementAction, GovernanceAction, FeeModule, FeeAllocation,
    IdentityRecord, TransferEvent,
)
from l3rs1.modules import (
    apply_state_transition, validate_fee_module, is_replay,
    identity_status, IdentityStatus,
)

# ══════════════════════════════════════════════════════════════════════════════
# §13.11 Canonical Serialization
# ══════════════════════════════════════════════════════════════════════════════

class TestCanonicalSerialization:
    def test_keys_sorted_alphabetically(self):
        assert canonicalize({"z": 3, "a": 1, "m": 2}) == '{"a":1,"m":2,"z":3}'

    def test_nested_objects_sorted(self):
        assert canonicalize({"b": {"d": 4, "c": 3}, "a": 1}) == '{"a":1,"b":{"c":3,"d":4}}'

    def test_no_insignificant_whitespace(self):
        assert canonicalize({"key": "value"}) == '{"key":"value"}'

    def test_arrays_preserve_order(self):
        assert canonicalize({"arr": [3, 1, 2]}) == '{"arr":[3,1,2]}'

    def test_deterministic_across_calls(self):
        obj = {"jurisdiction": "US", "assetId": "abc", "state": "ACTIVE"}
        assert canonicalize(obj) == canonicalize(obj)

    def test_key_insertion_order_irrelevant(self):
        assert canonicalize({"b": 2, "a": 1}) == canonicalize({"a": 1, "b": 2})

# ══════════════════════════════════════════════════════════════════════════════
# §2.2 Asset_ID Construction
# ══════════════════════════════════════════════════════════════════════════════

PUBKEY   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
TS       = 1740355200
NONCE    = "0000000000000001"
EXPECTED = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a"

class TestAssetIdConstruction:
    def test_matches_canonical_vector(self):
        assert construct_asset_id(PUBKEY, TS, NONCE) == EXPECTED

    def test_length_is_64_hex_chars(self):
        assert len(construct_asset_id(PUBKEY, TS, NONCE)) == 64

    def test_is_deterministic(self):
        assert construct_asset_id(PUBKEY, TS, NONCE) == construct_asset_id(PUBKEY, TS, NONCE)

    def test_different_nonce_gives_different_id(self):
        assert construct_asset_id(PUBKEY, TS, NONCE) != construct_asset_id(PUBKEY, TS, "0000000000000002")

    def test_different_timestamp_gives_different_id(self):
        assert construct_asset_id(PUBKEY, TS, NONCE) != construct_asset_id(PUBKEY, TS + 1, NONCE)

# ══════════════════════════════════════════════════════════════════════════════
# §2.5 State Transition Matrix
# ══════════════════════════════════════════════════════════════════════════════

VALID_TRANSITIONS = [
    (AssetState.ISSUED,     "ACTIVATION",    AssetState.ACTIVE),
    (AssetState.ACTIVE,     "BREACH",        AssetState.RESTRICTED),
    (AssetState.ACTIVE,     "FREEZE",        AssetState.FROZEN),
    (AssetState.RESTRICTED, "CLEARED",       AssetState.ACTIVE),
    (AssetState.FROZEN,     "RELEASE",       AssetState.ACTIVE),
    (AssetState.ACTIVE,     "REDEMPTION",    AssetState.REDEEMED),
    (AssetState.REDEEMED,   "FINALIZATION",  AssetState.BURNED),
    (AssetState.ACTIVE,     "SUSPENSION",    AssetState.SUSPENDED),
    (AssetState.SUSPENDED,  "REINSTATEMENT", AssetState.ACTIVE),
]

class TestStateTransitions:
    @pytest.mark.parametrize("from_state,trigger,expected", VALID_TRANSITIONS)
    def test_valid_transitions(self, from_state, trigger, expected):
        result = apply_state_transition(from_state, trigger)
        assert result.success
        assert result.new_state == expected

    def test_burned_is_terminal(self):
        result = apply_state_transition(AssetState.BURNED, "ACTIVATION")
        assert not result.success

    def test_invalid_transition_rejected(self):
        assert not apply_state_transition(AssetState.ISSUED, "FREEZE").success

    def test_no_unknown_triggers(self):
        assert not apply_state_transition(AssetState.ACTIVE, "INVALID_TRIGGER").success

# ══════════════════════════════════════════════════════════════════════════════
# §8.3 Cross-Chain CID
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossChainCID:
    A, B, C, D = "a" * 64, "b" * 64, "c" * 64, "d" * 64

    def test_cid_is_64_hex_chars(self):
        assert len(construct_cid(self.A, self.B, self.C, self.D, 1000)) == 64

    def test_cid_is_deterministic(self):
        assert construct_cid(self.A, self.B, self.C, self.D, 1000) == \
               construct_cid(self.A, self.B, self.C, self.D, 1000)

    def test_state_hash_change_changes_cid(self):
        assert construct_cid(self.A, self.B, self.C, self.D, 1000) != \
               construct_cid(self.A, "c" * 64, self.C, self.D, 1000)

    def test_compliance_hash_change_changes_cid(self):
        assert construct_cid(self.A, self.B, self.C, self.D, 1000) != \
               construct_cid(self.A, self.B, "d" * 64, self.D, 1000)

    def test_governance_hash_change_changes_cid(self):
        assert construct_cid(self.A, self.B, self.C, self.D, 1000) != \
               construct_cid(self.A, self.B, self.C, "e" * 64, 1000)

    def test_timestamp_change_changes_cid(self):
        assert construct_cid(self.A, self.B, self.C, self.D, 1000) != \
               construct_cid(self.A, self.B, self.C, self.D, 1001)

# ══════════════════════════════════════════════════════════════════════════════
# §9.6 TxID and Replay Protection
# ══════════════════════════════════════════════════════════════════════════════

class TestTxIdAndReplay:
    SENDER   = "alice"
    RECEIVER = "bob"
    AMOUNT   = 1000
    NONCE    = "00" * 8
    TS       = 1740355200

    def _ev(self, nonce=None, amount=None):
        return TransferEvent(
            "asset1", self.SENDER, self.RECEIVER,
            amount or self.AMOUNT,
            nonce or self.NONCE,
            self.TS,
        )

    def test_txid_is_64_hex_chars(self):
        assert len(construct_tx_id(self.SENDER, self.RECEIVER, self.AMOUNT, self.NONCE, self.TS)) == 64

    def test_txid_is_deterministic(self):
        assert construct_tx_id(self.SENDER, self.RECEIVER, self.AMOUNT, self.NONCE, self.TS) == \
               construct_tx_id(self.SENDER, self.RECEIVER, self.AMOUNT, self.NONCE, self.TS)

    def test_same_event_is_replay(self):
        ev = self._ev()
        txid = construct_tx_id(ev.sender, ev.receiver, ev.amount, ev.nonce, ev.timestamp)
        assert is_replay(ev, {txid})

    def test_different_nonce_is_not_replay(self):
        ev1 = self._ev()
        ev2 = self._ev(nonce="01" * 8)
        txid1 = construct_tx_id(ev1.sender, ev1.receiver, ev1.amount, ev1.nonce, ev1.timestamp)
        assert not is_replay(ev2, {txid1})

    def test_different_amount_is_not_replay(self):
        ev1 = self._ev()
        ev2 = self._ev(amount=2000)
        txid1 = construct_tx_id(ev1.sender, ev1.receiver, ev1.amount, ev1.nonce, ev1.timestamp)
        assert not is_replay(ev2, {txid1})

# ══════════════════════════════════════════════════════════════════════════════
# §6.12 Fee Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestFeeValidation:
    def _module(self, *bps_values):
        allocs = tuple(FeeAllocation(f"addr{i}", bp) for i, bp in enumerate(bps_values))
        return FeeModule(100, allocs)

    def test_valid_five_way_split(self):
        validate_fee_module(self._module(2000, 3000, 2000, 2500, 500))  # no raise

    def test_single_full_allocation(self):
        validate_fee_module(self._module(10000))  # no raise

    def test_under_allocation_rejected(self):
        with pytest.raises(ValueError):
            validate_fee_module(self._module(5000))

    def test_over_allocation_rejected(self):
        with pytest.raises(ValueError):
            validate_fee_module(self._module(6000, 5000))

    def test_negative_allocation_rejected(self):
        with pytest.raises(ValueError):
            validate_fee_module(self._module(11000, -1000))

# ══════════════════════════════════════════════════════════════════════════════
# §3.4 Identity Hash
# ══════════════════════════════════════════════════════════════════════════════

class TestIdentityHash:
    PII    = "John Doe | 1990-01-01"
    SALT   = "deadbeef" * 4
    DOMAIN = "l3rs1-identity-v1"

    def test_hash_is_64_chars(self):
        assert len(construct_identity_hash(self.PII, self.SALT, self.DOMAIN)) == 64

    def test_hash_is_deterministic(self):
        assert construct_identity_hash(self.PII, self.SALT, self.DOMAIN) == \
               construct_identity_hash(self.PII, self.SALT, self.DOMAIN)

    def test_different_pii_different_hash(self):
        assert construct_identity_hash(self.PII, self.SALT, self.DOMAIN) != \
               construct_identity_hash("Jane Doe | 1985-06-15", self.SALT, self.DOMAIN)

    def test_different_salt_different_hash(self):
        assert construct_identity_hash(self.PII, self.SALT, self.DOMAIN) != \
               construct_identity_hash(self.PII, "cafebabe" * 4, self.DOMAIN)

# ══════════════════════════════════════════════════════════════════════════════
# §3.6 Identity Status
# ══════════════════════════════════════════════════════════════════════════════

class TestIdentityStatus:
    NOW    = 1_740_355_200
    HASH   = "a" * 64

    def test_valid_status(self):
        rec = IdentityRecord(self.HASH, "va", "US", 9_999_999_999, False)
        assert identity_status(rec, self.NOW) == IdentityStatus.VALID

    def test_expired_status(self):
        rec = IdentityRecord(self.HASH, "va", "US", 1_000_000_000, False)
        assert identity_status(rec, self.NOW) == IdentityStatus.EXPIRED

    def test_revoked_status(self):
        rec = IdentityRecord(self.HASH, "va", "US", 9_999_999_999, True)
        assert identity_status(rec, self.NOW) == IdentityStatus.REVOKED

    def test_revoked_takes_precedence_over_expiry(self):
        # Revoked + expired: REVOKED takes precedence (checked first)
        rec = IdentityRecord(self.HASH, "va", "US", 1_000_000_000, True)
        assert identity_status(rec, self.NOW) == IdentityStatus.REVOKED
