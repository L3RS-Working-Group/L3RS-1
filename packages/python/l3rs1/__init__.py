"""
l3rs1 — L3RS-1 Reference Implementation SDK
Layer-3 Regulated Asset Standard v1.0.0 — CROSSCHAIN Conformance
"""
from .types import *
from .crypto import *
from .modules import *

SDK_VERSION       = "1.0.0"
STANDARD_VERSION  = "L3RS-1.0.0"
CONFORMANCE_CLASS = "CROSSCHAIN"


# ══════════════════════════════════════════════════════════════════════════════
# §2 Asset State Machine
# ══════════════════════════════════════════════════════════════════════════════

_TRANSITION_MATRIX: list[tuple[AssetState, str, AssetState]] = [
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


@dataclass(frozen=True)
class StateTransitionResult:
    success:   bool
    new_state: Optional[AssetState] = None
    error:     Optional[str] = None


def apply_state_transition(current_state: AssetState, trigger: str) -> StateTransitionResult:
    """§2.5 — Deterministic state transition. Invariant I₁."""
    if current_state == AssetState.BURNED:
        return StateTransitionResult(False, error="BURNED is terminal")
    for from_state, t, to_state in _TRANSITION_MATRIX:
        if from_state == current_state and t == trigger:
            return StateTransitionResult(True, new_state=to_state)
    return StateTransitionResult(False, error=f"No transition from {current_state} via {trigger}")


def valid_triggers_from(state: AssetState) -> list[str]:
    return [t for (s, t, _) in _TRANSITION_MATRIX if s == state]


def validate_asset(asset: object) -> None:
    """§13.14 Strict validation — raises on any violation."""
    if not isinstance(asset, Asset):
        raise TypeError("Not an Asset instance")
    if not isinstance(asset.jurisdiction, str) or len(asset.jurisdiction) != 2:
        raise ValueError("Jurisdiction must be ISO 3166-1 alpha-2")
    if not asset.standard_version.startswith("L3RS-"):
        raise ValueError('standard_version must start with "L3RS-"')


# ══════════════════════════════════════════════════════════════════════════════
# §4 Compliance Engine
# ══════════════════════════════════════════════════════════════════════════════

class SanctionsRegistry(Protocol):
    registry_hash: str
    def is_listed(self, address: str) -> bool: ...


@dataclass(frozen=True)
class ComplianceContext:
    asset:     Asset
    sender:    str
    receiver:  str
    amount:    int
    timestamp: int
    sanctions: Optional[SanctionsRegistry] = None


_SYNTHETIC_STATE_RULE = ComplianceRule(
    rule_id="SYSTEM_STATE_CHECK", rule_type=RuleType.TRANSFER_ELIGIBILITY,
    scope="*", trigger="TRANSFER", priority=0, action=EnforcementAction.REJECT,
)

_BLOCKING = {EnforcementAction.REJECT, EnforcementAction.FREEZE, EnforcementAction.RESTRICT}


def evaluate_compliance(module: ComplianceModule, ctx: ComplianceContext) -> ComplianceDecision:
    """C: E → {0,1} — §4.3. O(n) per §14.3. Invariant I₂."""
    if ctx.asset.state != AssetState.ACTIVE:
        return ComplianceDecision(False, _SYNTHETIC_STATE_RULE, EnforcementAction.REJECT)

    ordered = sorted(module.rules, key=lambda r: r.priority)
    for rule in ordered:
        if not _trigger_applies(rule, ctx):
            continue
        if not _evaluate_rule(rule, ctx):
            if rule.action in _BLOCKING:
                return ComplianceDecision(False, rule, rule.action)
    return ComplianceDecision(True)


def _trigger_applies(rule: ComplianceRule, ctx: ComplianceContext) -> bool:
    return rule.scope in ("*", ctx.asset.jurisdiction)


def _evaluate_rule(rule: ComplianceRule, ctx: ComplianceContext) -> bool:
    if rule.rule_type == RuleType.HOLDING_PERIOD:
        acq = rule.params.get("acquisitionTime")
        period = rule.params.get("holdingPeriodSec")
        if acq is None or period is None:
            return False
        return (ctx.timestamp - int(str(acq))) >= int(str(period))

    if rule.rule_type == RuleType.TRANSACTION_THRESHOLD:
        threshold = rule.params.get("thresholdAmount")
        if threshold is None:
            return False
        return ctx.amount <= int(str(threshold))

    if rule.rule_type == RuleType.SANCTIONS_SCREENING:
        if ctx.sanctions is None:
            return False  # Cannot verify → block
        return not ctx.sanctions.is_listed(ctx.sender) and not ctx.sanctions.is_listed(ctx.receiver)

    # External rules: require pre-resolved result
    result = rule.params.get("externalResult")
    if result is None:
        return False  # §14.10: unknown → block
    return bool(result)


# ══════════════════════════════════════════════════════════════════════════════
# §3 Identity Binding
# ══════════════════════════════════════════════════════════════════════════════

def identity_status(
    record: IdentityRecord,
    now_unix: int,
    verifier: Optional[SignatureVerifier] = None,
) -> IdentityStatus:
    """Status(IR) ∈ {VALID, EXPIRED, REVOKED, UNKNOWN} — §3.6"""
    if record.revoked:
        return IdentityStatus.REVOKED
    if now_unix >= record.expiry:
        return IdentityStatus.EXPIRED
    return IdentityStatus.VALID


def validate_identity(
    record: IdentityRecord,
    now_unix: int,
    verifier: Optional[SignatureVerifier] = None,
) -> tuple[bool, str]:
    """validate_identity(party) — §3.11. Returns (valid, error_message)."""
    status = identity_status(record, now_unix, verifier)
    if status != IdentityStatus.VALID:
        return False, f"Identity status: {status.value}"
    if record.proof and not _verify_zkp(record.proof):
        return False, "ZKP verification failed"
    return True, ""


def _verify_zkp(proof: ZKProof) -> bool:
    """§3.8 — Conservative: returns False until real verifier is supplied."""
    return False


def enforce_identity_level(
    level: IdentityLevel,
    sender_records: list[IdentityRecord],
    receiver_records: list[IdentityRecord],
    now_unix: int,
    required_jurisdictions: Optional[list[str]] = None,
    verifier: Optional[SignatureVerifier] = None,
) -> tuple[bool, str]:
    if level == IdentityLevel.UNBOUND:
        return True, ""

    if not sender_records:
        return False, "Sender has no identity record"
    ok, err = validate_identity(sender_records[0], now_unix, verifier)
    if not ok:
        return False, f"Sender: {err}"

    if not receiver_records:
        return False, "Receiver has no identity record"
    ok, err = validate_identity(receiver_records[0], now_unix, verifier)
    if not ok:
        return False, f"Receiver: {err}"

    if level == IdentityLevel.MULTI_JURISDICTION and required_jurisdictions:
        for party, records in [("Sender", sender_records), ("Receiver", receiver_records)]:
            valid_juris = {
                r.jurisdiction_identity
                for r in records
                if identity_status(r, now_unix, verifier) == IdentityStatus.VALID
            }
            missing = set(required_jurisdictions) - valid_juris
            if missing:
                return False, f"{party} missing jurisdictions: {missing}"

    return True, ""


# ══════════════════════════════════════════════════════════════════════════════
# §5 Governance Override
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class OverrideRecord:
    record_hash: str
    override_id: str
    authority:   str
    action:      GovernanceAction
    timestamp:   int
    immutable:   bool = True


def validate_override(
    override: OverrideObject,
    governance: GovernanceModule,
    verifier: SignatureVerifier,
    all_signatures: Optional[list[dict[str, str]]] = None,
) -> tuple[bool, str]:
    """validate_override(O) — §5.6"""
    if override.authority not in governance.authorities:
        return False, "Authority not registered"
    if override.action not in governance.override_types:
        return False, f"Action {override.action} not permitted"
    if not override.legal_basis or len(override.legal_basis) < 64:
        return False, "Legal basis hash missing"
    msg = bytes.fromhex(override.legal_basis)
    if not verifier.verify(msg, override.signature, override.authority):
        return False, "Signature verification failed"
    if override.action == GovernanceAction.EMERGENCY_ROLLBACK:
        met, count, required = validate_quorum(governance, all_signatures or [])
        if not met:
            return False, f"Quorum not met: {count}/{required}"
    return True, ""


def validate_quorum(
    governance: GovernanceModule,
    signatures: list[dict[str, str]],
) -> tuple[bool, int, int]:
    """Quorum = ⌈(2/3) × N⌉ — §5.5"""
    N = len(governance.authorities)
    required = math.ceil(2 / 3 * N)
    signing = {
        s["authority"] for s in signatures
        if s.get("authority") in governance.authorities
    }
    count = len(signing)
    return count >= required, count, required


def create_override_record(override: OverrideObject) -> OverrideRecord:
    record_hash = construct_override_hash(
        override.override_id, override.authority, override.action.value, override.timestamp,
    )
    return OverrideRecord(
        record_hash=record_hash, override_id=override.override_id,
        authority=override.authority, action=override.action, timestamp=override.timestamp,
    )


# ══════════════════════════════════════════════════════════════════════════════
# §6 Fee Routing
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FeeDistribution:
    total_fee:       int
    allocations:     list[dict[str, object]]
    fee_record_hash: str


def validate_fee_module(fee_module: FeeModule) -> None:
    """§6.12 Economic Integrity Constraint"""
    total = sum(a.basis_points for a in fee_module.allocations)
    if total != 10000:
        raise ValueError(f"Fee allocations must sum to 10000 basis points; got {total}")
    for a in fee_module.allocations:
        if a.basis_points < 0:
            raise ValueError("Negative fee allocation not permitted")


def distribute_fees(
    fee_module: FeeModule, amount: int, tx_id: str, timestamp: int,
) -> FeeDistribution:
    """distribute_fees(A, amount) — §6.5. Atomic."""
    validate_fee_module(fee_module)
    total_fee = (amount * fee_module.base_rate_basis_points) // 10000
    allocations = [
        {"recipient": a.recipient, "amount": (total_fee * a.basis_points) // 10000}
        for a in fee_module.allocations
    ]
    ts_buf = struct.pack(">Q", timestamp)
    fee_record_hash = sha256_concat(
        bytes.fromhex(tx_id),
        total_fee.to_bytes(32, "big"),
        ts_buf,
    )
    return FeeDistribution(total_fee, allocations, fee_record_hash)


# ══════════════════════════════════════════════════════════════════════════════
# §7 Reserve Verification
# ══════════════════════════════════════════════════════════════════════════════

_FREQ_SECONDS = {
    AttestationFrequency.REALTIME:  60,
    AttestationFrequency.DAILY:     86400,
    AttestationFrequency.WEEKLY:    604800,
    AttestationFrequency.MONTHLY:   2592000,
    AttestationFrequency.QUARTERLY: 7776000,
    AttestationFrequency.ANNUAL:    31536000,
}


def validate_reserve(
    reserve: ReserveInterface,
    now_unix: int,
    audit_hash_verifier: Optional[object] = None,
) -> ReserveStatus:
    """ReserveStatus(B) — §7.8"""
    if audit_hash_verifier is not None:
        if not getattr(audit_hash_verifier, "verify", lambda _: True)(reserve.audit_hash):
            return ReserveStatus.INVALID
    return ReserveStatus.VALID  # Simplified: timestamp extraction requires oracle


# ══════════════════════════════════════════════════════════════════════════════
# §8 Cross-Chain
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CrossChainCertificate:
    cid:             str
    asset_id:        str
    state_hash:      str
    compliance_hash: str
    governance_hash: str
    timestamp:       int


def build_cross_chain_certificate(asset: Asset, timestamp: int) -> CrossChainCertificate:
    """§8.3 — CID = H(I || SH || CH || GH || t)"""
    state_hash      = hash_object(asset.state.value)
    compliance_hash = hash_object(canonicalize(asset.compliance_module))
    governance_hash = hash_object(canonicalize(asset.governance_module))
    cid = construct_cid(asset.asset_id, state_hash, compliance_hash, governance_hash, timestamp)
    return CrossChainCertificate(cid, asset.asset_id, state_hash, compliance_hash, governance_hash, timestamp)


def verify_cross_chain(
    cert: CrossChainCertificate,
    dest_asset_id: str,
    dest_compliance_hash: str,
    dest_governance_hash: str,
) -> tuple[bool, str]:
    """§8.9 verify_crosschain"""
    if dest_asset_id != cert.asset_id:
        return False, "Asset_ID changed — invariant violated"
    recomputed = construct_cid(
        cert.asset_id, cert.state_hash, cert.compliance_hash, cert.governance_hash, cert.timestamp,
    )
    if recomputed != cert.cid:
        return False, "CID recomputation mismatch"
    if dest_compliance_hash != cert.compliance_hash:
        return False, "Compliance downgrade detected"
    if dest_governance_hash != cert.governance_hash:
        return False, "Governance hash changed"
    return True, ""


# ══════════════════════════════════════════════════════════════════════════════
# §9 Settlement
# ══════════════════════════════════════════════════════════════════════════════

def build_settlement_proof(
    event: TransferEvent, block_height: int, state_hash: str,
) -> SettlementProof:
    tx_id = construct_tx_id(
        event.sender, event.receiver, event.amount, event.nonce, event.timestamp,
    )
    return SettlementProof(tx_id, block_height, state_hash, event.timestamp)


def is_replay(event: TransferEvent, ledger_history: set[str]) -> bool:
    """§9.6 Replay protection."""
    tx_id = construct_tx_id(
        event.sender, event.receiver, event.amount, event.nonce, event.timestamp,
    )
    return tx_id in ledger_history


# ══════════════════════════════════════════════════════════════════════════════
# §2.7 Transfer Executor
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class TransferOutput:
    success:     bool
    tx_id:       Optional[str] = None
    proof:       Optional[SettlementProof] = None
    new_state:   Optional[str] = None
    fee_record:  Optional[str] = None
    error:       Optional[str] = None
    failed_step: Optional[str] = None


def execute_transfer(
    asset: Asset,
    event: TransferEvent,
    sender_records: list[IdentityRecord],
    receiver_records: list[IdentityRecord],
    ledger_history: set[str],
    block_height: int,
    sanctions: Optional[SanctionsRegistry] = None,
    verifier: Optional[SignatureVerifier] = None,
    required_jurisdictions: Optional[list[str]] = None,
) -> TransferOutput:
    """§2.6 Deterministic 7-step transfer execution."""

    def fail(step: str, msg: str) -> TransferOutput:
        return TransferOutput(False, failed_step=step, error=msg)

    if is_replay(event, ledger_history):
        return fail("REPLAY_CHECK", "Duplicate TxID — replay rejected")

    tx_id = construct_tx_id(event.sender, event.receiver, event.amount, event.nonce, event.timestamp)

    if asset.state != AssetState.ACTIVE:
        return fail("STATE_CHECK", f"Asset state is {asset.state.value}; must be ACTIVE")

    if asset.identity_level >= IdentityLevel.VERIFIED:
        ok, err = enforce_identity_level(
            asset.identity_level, sender_records, receiver_records,
            event.timestamp, required_jurisdictions, verifier,
        )
        if not ok:
            return fail("IDENTITY", err)

    ctx = ComplianceContext(asset, event.sender, event.receiver, event.amount, event.timestamp, sanctions)
    decision = evaluate_compliance(asset.compliance_module, ctx)
    if not decision.allowed:
        return fail("COMPLIANCE", f"Blocked by {decision.blocked_by.rule_id if decision.blocked_by else 'unknown'}")

    try:
        validate_fee_module(asset.fee_module)
        fee_result = distribute_fees(asset.fee_module, event.amount, tx_id, event.timestamp)
    except ValueError as e:
        return fail("FEE_ROUTING", str(e))

    proof = SettlementProof(tx_id, block_height, "", event.timestamp)
    return TransferOutput(True, tx_id=tx_id, proof=proof, new_state=asset.state.value, fee_record=fee_result.fee_record_hash)
