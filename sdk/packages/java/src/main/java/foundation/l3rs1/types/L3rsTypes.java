package foundation.l3rs1.types;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Optional;

// ─── §3.6 Identity Status ─────────────────────────────────────────────────────
// (separate enum, declared inline for SDK conciseness — move to own file in production)

/** §4.4 Rule Type */
enum RuleType {
    TRANSFER_ELIGIBILITY, INVESTOR_CLASSIFICATION, HOLDING_PERIOD,
    GEOGRAPHIC_RESTRICTION, SANCTIONS_SCREENING, TRANSACTION_THRESHOLD,
    AML_TRIGGER, MARKET_RESTRICTION, REDEMPTION_ELIGIBILITY
}

/** §4.7 Enforcement Action */
enum EnforcementAction {
    REJECT, FREEZE, RESTRICT, FLAG, REQUIRE_DISCLOSURE;
    public boolean isBlocking() {
        return this == REJECT || this == FREEZE || this == RESTRICT;
    }
}

/** §5.3 Governance Action */
enum GovernanceAction {
    FREEZE_BALANCE, UNFREEZE_BALANCE, RESTRICT_TRANSFER,
    SEIZE_ASSET, FORCE_REDEMPTION, EMERGENCY_ROLLBACK
}

/** §7.5 Asset Backing Type */
enum BackingType { FIAT, TREASURY, COMMODITY, REAL_ESTATE, EQUITY, DEBT, MIXED }

/** §7.7 Attestation Frequency */
enum AttestationFrequency {
    REALTIME, DAILY, WEEKLY, MONTHLY, QUARTERLY, ANNUAL;
    public long toSeconds() {
        return switch (this) {
            case REALTIME  -> 60L;
            case DAILY     -> 86_400L;
            case WEEKLY    -> 604_800L;
            case MONTHLY   -> 2_592_000L;
            case QUARTERLY -> 7_776_000L;
            case ANNUAL    -> 31_536_000L;
        };
    }
}

/** §7.8 Reserve Status */
enum ReserveStatus { VALID, STALE, INVALID, UNKNOWN }

/** §7.11 Insolvency Priority */
enum InsolvencyPriority { SENIOR, SECURED, UNSECURED, SUBORDINATED }

// ─── §3.8 ZK Proof ────────────────────────────────────────────────────────────
record ZKProof(String scheme, String statement, String witnessCommitment,
               String proofBytes, String nonce) {}

// ─── §3.3 Identity Record ─────────────────────────────────────────────────────
/** IR = (HID, VA, JI, EXP, REV, ATTR, PROOF) — §3.3 */
record IdentityRecord(
    String identityHash,
    String verificationAuthority,
    String jurisdictionIdentity,
    long expiry,
    boolean revoked,
    List<String> attributeCommitments,
    Optional<ZKProof> proof
) {}

// ─── §12.2 Legal Mirror ───────────────────────────────────────────────────────
/** L = (J, LH, LV, TS, SIGN) — §12.2 */
record LegalMirror(
    String jurisdiction, String legalHash, String legalVersion,
    long timestamp, Optional<String> authoritySignature
) {}

// ─── §13.5 Compliance Rule ────────────────────────────────────────────────────
record ComplianceRule(
    String ruleId, RuleType ruleType, String scope, String trigger,
    int priority, EnforcementAction action, Map<String, Object> params
) {}

record ComplianceModule(List<ComplianceRule> rules) {}

// ─── §13.6 Governance Module ─────────────────────────────────────────────────
record GovernanceModule(
    List<String> authorities, int quorumThreshold, List<GovernanceAction> overrideTypes
) {}

// ─── §5.2 Override Object ────────────────────────────────────────────────────
/** O = (OID, AUTH, ACTION, TARGET, BASIS, TS, SIG) — §5.2 */
record OverrideObject(
    String overrideId, String authority, GovernanceAction action,
    String target, String legalBasis, long timestamp, String signature
) {}

// ─── §13.7 Fee Module ────────────────────────────────────────────────────────
record FeeAllocation(String recipient, int basisPoints) {}
record FeeModule(int baseRateBasisPoints, List<FeeAllocation> allocations) {}

// ─── §13.8 Reserve Interface ─────────────────────────────────────────────────
record RedemptionLogic(String eligibility, String procedure, String settlement, long timeframeSec) {}
/** B = (CID, ABT, AH, FREQ, RLOG, PRIORITY) — §7.3 */
record ReserveInterface(
    String custodianId, BackingType backingType, String auditHash,
    AttestationFrequency attestationFrequency, InsolvencyPriority insolvencyPriority,
    RedemptionLogic redemptionLogic
) {}

// ─── §13.9 Cross-Chain Metadata ──────────────────────────────────────────────
record CrossChainMetadata(
    String certificateId, String originChainId, String complianceHash,
    String governanceHash, String stateHash, long timestamp
) {}

// ─── §13.2 Canonical Asset Object ────────────────────────────────────────────
/** A = (I, T, J, L, ID, C, R, G, F, B, X, S) — §2.1 */
record Asset(
    String assetId, AssetType assetType, String jurisdiction,
    LegalMirror legalMirror, IdentityLevel identityLevel,
    ComplianceModule complianceModule, GovernanceModule governanceModule,
    FeeModule feeModule, Optional<ReserveInterface> reserveInterface,
    CrossChainMetadata crossChainMetadata, AssetState state, String standardVersion
) {}

// ─── Transfer ─────────────────────────────────────────────────────────────────
record TransferEvent(
    String assetId, String sender, String receiver,
    BigInteger amount, String nonce, long timestamp
) {}

record SettlementProof(String txId, BigInteger blockHeight, String stateHash, long timestamp) {}
