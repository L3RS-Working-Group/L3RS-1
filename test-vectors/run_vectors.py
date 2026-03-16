#!/usr/bin/env python3
"""
L3RS-1 Canonical Test Vector Runner
§11.5 — All implementations MUST reproduce these outputs exactly.

Run: python sdk/test-vectors/run_vectors.py
"""
import json
import sys
import struct
import hashlib
from pathlib import Path

# Load the SDK
sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "python"))
from l3rs1.crypto import (
    sha256, sha256_concat, canonicalize, construct_asset_id,
    construct_tx_id, construct_cid, construct_identity_hash,
    construct_override_hash,
)
from l3rs1.types import (
    AssetState, AssetType, IdentityLevel, RuleType,
    EnforcementAction, GovernanceAction, BackingType,
    AttestationFrequency, ReserveStatus, InsolvencyPriority,
)
from l3rs1.modules import (
    apply_state_transition, validate_fee_module, is_replay,
    identity_status, IdentityStatus,
)
from l3rs1.types import (
    FeeModule, FeeAllocation, IdentityRecord, TransferEvent,
)

# ─── Load canonical vectors ───────────────────────────────────────────────────

vectors_path = Path(__file__).parent / "canonical.json"
with open(vectors_path) as f:
    VECTORS = json.load(f)

passed = 0
failed = 0
results = []


def check(name: str, actual, expected, note: str = ""):
    global passed, failed
    ok = actual == expected
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
        results.append(f"  FAIL  {name}")
        results.append(f"        expected: {expected}")
        results.append(f"        actual:   {actual}")
        if note:
            results.append(f"        note:     {note}")
        return
    results.append(f"  PASS  {name}")


def check_true(name: str, condition: bool, note: str = ""):
    check(name, condition, True, note)


# ─── §2.2 Asset_ID construction ──────────────────────────────────────────────

v = VECTORS["vectors"]["asset_id_construction"]
asset_id = construct_asset_id(
    v["inputs"]["issuer_pubkey_hex"],
    v["inputs"]["timestamp_unix"],
    v["inputs"]["nonce_hex"],
)
check("§2.2 Asset_ID hex output", asset_id, v["expected"]["asset_id_hex"])
check("§2.2 Asset_ID length", len(asset_id), 64)

# ─── §2.3 Asset types ────────────────────────────────────────────────────────

for t in VECTORS["vectors"]["asset_types"]["valid_values"]:
    check_true(f"§2.3 AssetType.{t}", t in [e.value for e in AssetType])

# ─── §2.4 Asset states ───────────────────────────────────────────────────────

for s in VECTORS["vectors"]["asset_states"]["valid_values"]:
    check_true(f"§2.4 AssetState.{s}", s in [e.value for e in AssetState])

# ─── §2.5 State transitions — valid ──────────────────────────────────────────

for t in VECTORS["vectors"]["state_transitions"]["valid_transitions"]:
    from_state = AssetState(t["from"])
    result = apply_state_transition(from_state, t["trigger"])
    check(
        f"§2.5 {t['from']} --{t['trigger']}--> {t['to']}",
        result.new_state.value if result.new_state else None,
        t["to"],
    )

# ─── §2.5 State transitions — invalid ────────────────────────────────────────

for t in VECTORS["vectors"]["state_transitions"]["invalid_transitions"]:
    if t["from"] == "BURNED":
        result = apply_state_transition(AssetState.BURNED, "ACTIVATION")
        check_true(f"§2.5 BURNED terminal state blocked", not result.success)
    elif t["from"] == "ISSUED" and t["trigger"] == "FREEZE":
        result = apply_state_transition(AssetState.ISSUED, "FREEZE")
        check_true(f"§2.5 ISSUED cannot FREEZE (invalid)", not result.success)

# ─── §3.2 Identity levels ────────────────────────────────────────────────────

for level in VECTORS["vectors"]["identity_requirement_levels"]["valid_values"]:
    check_true(f"§3.2 IdentityLevel {level}", level in [e.value for e in IdentityLevel])

# ─── §3.6 Identity status ────────────────────────────────────────────────────

dummy_hash = "a" * 64
valid_rec   = IdentityRecord(dummy_hash, "va", "US", 9_999_999_999, False)
expired_rec = IdentityRecord(dummy_hash, "va", "US", 1_000_000_000, False)
revoked_rec = IdentityRecord(dummy_hash, "va", "US", 9_999_999_999, True)

now = 1_740_355_200

check("§3.6 VALID identity status",   identity_status(valid_rec,   now), IdentityStatus.VALID)
check("§3.6 EXPIRED identity status", identity_status(expired_rec, now), IdentityStatus.EXPIRED)
check("§3.6 REVOKED identity status", identity_status(revoked_rec, now), IdentityStatus.REVOKED)

# ─── §4.4 Compliance rule types ──────────────────────────────────────────────

for rt in VECTORS["vectors"]["compliance_rule_types"]["valid_values"]:
    check_true(f"§4.4 RuleType.{rt}", rt in [e.value for e in RuleType])

# ─── §4.7 Enforcement actions ────────────────────────────────────────────────

for ea in VECTORS["vectors"]["enforcement_actions"]["valid_values"]:
    check_true(f"§4.7 EnforcementAction.{ea}", ea in [e.value for e in EnforcementAction])

# ─── §5.3 Governance actions ─────────────────────────────────────────────────

for ga in VECTORS["vectors"]["governance_actions"]["valid_values"]:
    check_true(f"§5.3 GovernanceAction.{ga}", ga in [e.value for e in GovernanceAction])

# ─── §6.4 Fee allocation ─────────────────────────────────────────────────────

v = VECTORS["vectors"]["fee_allocation"]
allocs = [
    FeeAllocation("sovereign",  v["valid_example"]["sovereign"]),
    FeeAllocation("validation", v["valid_example"]["validation"]),
    FeeAllocation("storage",    v["valid_example"]["storage"]),
    FeeAllocation("operator",   v["valid_example"]["operator"]),
    FeeAllocation("bridge",     v["valid_example"]["bridge"]),
]
fm = FeeModule(100, tuple(allocs))
try:
    validate_fee_module(fm)
    check_true("§6.4 Valid fee allocation accepted", True)
except ValueError:
    check_true("§6.4 Valid fee allocation accepted", False)

fm_bad = FeeModule(100, (FeeAllocation("only", 5000),))
try:
    validate_fee_module(fm_bad)
    check_true("§6.4 Invalid fee allocation rejected", False)
except ValueError:
    check_true("§6.4 Invalid fee allocation rejected", True)

# ─── §7.5 Backing types ──────────────────────────────────────────────────────

for bt in VECTORS["vectors"]["reserve_backing_types"]["valid_values"]:
    check_true(f"§7.5 BackingType.{bt}", bt in [e.value for e in BackingType])

# ─── §7.7 Attestation frequencies ───────────────────────────────────────────

for af in VECTORS["vectors"]["attestation_frequencies"]["valid_values"]:
    check_true(f"§7.7 AttestationFrequency.{af}", af in [e.value for e in AttestationFrequency])

# ─── §7.8 Reserve status ─────────────────────────────────────────────────────

for rs in VECTORS["vectors"]["reserve_status_values"]["valid_values"]:
    check_true(f"§7.8 ReserveStatus.{rs}", rs in [e.value for e in ReserveStatus])

# ─── §8.3 Cross-chain CID ────────────────────────────────────────────────────

cid1 = construct_cid("a" * 64, "b" * 64, "c" * 64, "d" * 64, 1_000)
cid2 = construct_cid("a" * 64, "b" * 64, "c" * 64, "d" * 64, 1_000)
cid3 = construct_cid("a" * 64, "b" * 64, "c" * 64, "d" * 64, 1_001)

check("§8.3 CID determinism (same inputs)", cid1, cid2)
check_true("§8.3 CID sensitivity (timestamp change)", cid1 != cid3)
check("§8.3 CID length (SHA-256 hex)", len(cid1), 64)

# ─── §9.6 TxID replay protection ─────────────────────────────────────────────

ev1 = TransferEvent("asset1", "alice", "bob", 1000, "00" * 8, 1_740_355_200)
ev2 = TransferEvent("asset1", "alice", "bob", 1000, "00" * 8, 1_740_355_200)  # same
ev3 = TransferEvent("asset1", "alice", "bob", 1000, "01" * 8, 1_740_355_200)  # diff nonce

txid1 = construct_tx_id(ev1.sender, ev1.receiver, ev1.amount, ev1.nonce, ev1.timestamp)
history = {txid1}

check_true("§9.6 Identical event is replay",          is_replay(ev2, history))
check_true("§9.6 Different nonce is not replay",      not is_replay(ev3, history))
check("§9.6 TxID length (SHA-256 hex)",               len(txid1), 64)

# ─── §13.11 Canonical serialization ──────────────────────────────────────────

# Key ordering
check("§13.11 Keys sorted alphabetically",
      canonicalize({"z": 3, "a": 1, "m": 2}),
      '{"a":1,"m":2,"z":3}')

# Nested objects
check("§13.11 Nested object key ordering",
      canonicalize({"b": {"d": 4, "c": 3}, "a": 1}),
      '{"a":1,"b":{"c":3,"d":4}}')

# No whitespace
check("§13.11 No insignificant whitespace",
      canonicalize({"key": "value"}),
      '{"key":"value"}')

# Arrays preserved
check("§13.11 Array order preserved",
      canonicalize({"arr": [3, 1, 2]}),
      '{"arr":[3,1,2]}')

# Determinism — same object, two calls
obj = {"jurisdiction": "US", "assetId": "abc", "state": "ACTIVE"}
check("§13.11 Serialization is deterministic",
      canonicalize(obj), canonicalize(obj))

# ─── §10 Invariants — presence check ─────────────────────────────────────────

invariants = VECTORS["vectors"]["invariants"]
for key in [f"I{i}" for i in range(1, 12)]:
    check_true(f"§10 Invariant {key} defined in vectors", key in invariants)

# ─── Print results ────────────────────────────────────────────────────────────

print()
print("=== L3RS-1 Canonical Test Vector Suite ===")
print()
for line in results:
    print(line)
print()
print(f"Results: {passed} passed, {failed} failed")
print(f"SDK version: L3RS-1.0.0 | Conformance: CROSSCHAIN")
print()

if failed > 0:
    print(f"CONFORMANCE FAILURE: {failed} vector(s) did not match.")
    sys.exit(1)
else:
    print("ALL VECTORS PASS — implementation is conformant.")
    sys.exit(0)
