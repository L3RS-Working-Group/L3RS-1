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
```


# ─── §2.3 Asset Type ──────────────────────────────────────────────────────────

class AssetType(str, Enum):
    CBDC               = "CBDC"
    INDUSTRY_STABLE    = "INDUSTRY_STABLE"
    REGULATED_SECURITY = "REGULATED_SECURITY"
    UTILITY            = "UTILITY"
    GOVERNANCE         = "GOVERNANCE"
    STORAGE_BACKED     = "STORAGE_BACKED"


# ─── §2.4 Asset State ─────────────────────────────────────────────────────────

class AssetState(str, Enum):
    ISSUED     = "ISSUED"
    ACTIVE     = "ACTIVE"
    RESTRICTED = "RESTRICTED"
    FROZEN     = "FROZEN"
    SUSPENDED  = "SUSPENDED"
    REDEEMED   = "REDEEMED"
    BURNED     = "BURNED"


# ─── §3.2 Identity Requirement Level ─────────────────────────────────────────

class IdentityLevel(int, Enum):
    UNBOUND             = 0
    VERIFIED            = 1
    SOVEREIGN_VALIDATED = 2
    MULTI_JURISDICTION  = 3


# ─── §3.6 Identity Status ─────────────────────────────────────────────────────

class IdentityStatus(str, Enum):
    VALID   = "VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


# ─── §4.4 Rule Types ──────────────────────────────────────────────────────────

class RuleType(str, Enum):
    TRANSFER_ELIGIBILITY    = "TRANSFER_ELIGIBILITY"
    INVESTOR_CLASSIFICATION = "INVESTOR_CLASSIFICATION"
    HOLDING_PERIOD          = "HOLDING_PERIOD"
    GEOGRAPHIC_RESTRICTION  = "GEOGRAPHIC_RESTRICTION"
    SANCTIONS_SCREENING     = "SANCTIONS_SCREENING"
    TRANSACTION_THRESHOLD   = "TRANSACTION_THRESHOLD"
    AML_TRIGGER             = "AML_TRIGGER"
    MARKET_RESTRICTION      = "MARKET_RESTRICTION"
    REDEMPTION_ELIGIBILITY  = "REDEMPTION_ELIGIBILITY"


# ─── §4.7 Enforcement Actions ─────────────────────────────────────────────────

class EnforcementAction(str, Enum):
    REJECT             = "REJECT"
    FREEZE             = "FREEZE"
    RESTRICT           = "RESTRICT"
    FLAG               = "FLAG"
    REQUIRE_DISCLOSURE = "REQUIRE_DISCLOSURE"


# ─── §5.3 Governance Actions ──────────────────────────────────────────────────

class GovernanceAction(str, Enum):
    FREEZE_BALANCE     = "FREEZE_BALANCE"
    UNFREEZE_BALANCE   = "UNFREEZE_BALANCE"
    RESTRICT_TRANSFER  = "RESTRICT_TRANSFER"
    SEIZE_ASSET        = "SEIZE_ASSET"
    FORCE_REDEMPTION   = "FORCE_REDEMPTION"
    EMERGENCY_ROLLBACK = "EMERGENCY_ROLLBACK"


# ─── §7.5 Backing Types ───────────────────────────────────────────────────────

class BackingType(str, Enum):
    FIAT        = "FIAT"
    TREASURY    = "TREASURY"
    COMMODITY   = "COMMODITY"
    REAL_ESTATE = "REAL_ESTATE"
    EQUITY      = "EQUITY"
    DEBT        = "DEBT"
    MIXED       = "MIXED"


# ─── §7.7 Attestation Frequency ──────────────────────────────────────────────

class AttestationFrequency(str, Enum):
    REALTIME  = "REALTIME"
    DAILY     = "DAILY"
    WEEKLY    = "WEEKLY"
    MONTHLY   = "MONTHLY"
    QUARTERLY = "QUARTERLY"
    ANNUAL    = "ANNUAL"


# ─── §7.8 Reserve Status ──────────────────────────────────────────────────────

class ReserveStatus(str, Enum):
    VALID   = "VALID"
    STALE   = "STALE"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


# ─── §7.11 Insolvency Priority ────────────────────────────────────────────────

class InsolvencyPriority(str, Enum):
    SENIOR       = "SENIOR"
    SECURED      = "SECURED"
    UNSECURED    = "UNSECURED"
    SUBORDINATED = "SUBORDINATED"


# ─── §3.8 ZK Proof ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ZKProof:
    scheme:             str
    statement:          str
    witness_commitment: str
    proof_bytes:        str  # hex
    nonce:              str


# ─── §3.3 Identity Record ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class IdentityRecord:
    """IR = (HID, VA, JI, EXP, REV, ATTR, PROOF) — §3.3"""
    identity_hash:            str               # HID
    verification_authority:   str               # VA
    jurisdiction_identity:    str               # JI: ISO 3166-1 alpha-2
    expiry:                   int               # EXP: UTC Unix timestamp
    revoked:                  bool              # REV
    attribute_commitments:    tuple[str, ...] = field(default_factory=tuple)
    proof:                    Optional[ZKProof] = None


# ─── §12.2 Legal Mirror ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class LegalMirror:
    """L = (J, LH, LV, TS, SIGN) — §12.2"""
    jurisdiction:       str           # ISO 3166-1 alpha-2
    legal_hash:         str           # LH
    legal_version:      str           # LV: MAJOR.MINOR
    timestamp:          int           # UTC Unix
    authority_signature: Optional[str] = None


# ─── §13.5 Compliance Rule ────────────────────────────────────────────────────

@dataclass(frozen=True)
class ComplianceRule:
    rule_id:   str
    rule_type: RuleType
    scope:     str
    trigger:   str
    priority:  int
    action:    EnforcementAction
    params:    dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ComplianceModule:
    rules: tuple[ComplianceRule, ...]


# ─── §13.6 Governance Module ─────────────────────────────────────────────────

@dataclass(frozen=True)
class GovernanceModule:
    authorities:      tuple[str, ...]
    quorum_threshold: int                          # integer percentage e.g. 67
    override_types:   tuple[GovernanceAction, ...]


# ─── §5.2 Override Object ────────────────────────────────────────────────────

@dataclass(frozen=True)
class OverrideObject:
    """O = (OID, AUTH, ACTION, TARGET, BASIS, TS, SIG) — §5.2"""
    override_id:  str
    authority:    str
    action:       GovernanceAction
    target:       str
    legal_basis:  str
    timestamp:    int
    signature:    str


# ─── §13.7 Fee Module ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FeeAllocation:
    recipient:    str
    basis_points: int


@dataclass(frozen=True)
class FeeModule:
    base_rate_basis_points: int
    allocations:            tuple[FeeAllocation, ...]


# ─── §13.8 Reserve Interface ─────────────────────────────────────────────────

@dataclass(frozen=True)
class RedemptionLogic:
    eligibility:    str
    procedure:      str
    settlement:     str
    timeframe_sec:  int


@dataclass(frozen=True)
class ReserveInterface:
    """B = (CID, ABT, AH, FREQ, RLOG, PRIORITY) — §7.3"""
    custodian_id:           str
    backing_type:           BackingType
    audit_hash:             str
    attestation_frequency:  AttestationFrequency
    insolvency_priority:    InsolvencyPriority
    redemption_logic:       RedemptionLogic


# ─── §13.9 Cross-Chain Metadata ──────────────────────────────────────────────

@dataclass(frozen=True)
class CrossChainMetadata:
    certificate_id:   str
    origin_chain_id:  str
    compliance_hash:  str
    governance_hash:  str
    state_hash:       str
    timestamp:        int


# ─── §13.2 Canonical Asset Object ────────────────────────────────────────────

@dataclass(frozen=True)
class Asset:
    """A = (I, T, J, L, ID, C, R, G, F, B, X, S) — §2.1"""
    asset_id:           str
    asset_type:         AssetType
    jurisdiction:       str
    legal_mirror:       LegalMirror
    identity_level:     IdentityLevel
    compliance_module:  ComplianceModule
    governance_module:  GovernanceModule
    fee_module:         FeeModule
    crosschain_metadata: CrossChainMetadata
    state:              AssetState
    standard_version:   str
    reserve_interface:  Optional[ReserveInterface] = None


# ─── Transfer ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TransferEvent:
    asset_id:  str
    sender:    str
    receiver:  str
    amount:    int        # use int for arbitrary precision (equivalent to bigint)
    nonce:     str        # hex
    timestamp: int        # UTC Unix


@dataclass(frozen=True)
class SettlementProof:
    tx_id:        str
    block_height: int
    state_hash:   str
    timestamp:    int


# ─── Compliance Decision ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class ComplianceDecision:
    allowed:    bool
    blocked_by: Optional[ComplianceRule] = None
    action:     Optional[EnforcementAction] = None
