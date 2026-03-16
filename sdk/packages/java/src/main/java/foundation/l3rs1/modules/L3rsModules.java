package foundation.l3rs1.modules;

import foundation.l3rs1.crypto.L3rsCrypto;
import foundation.l3rs1.types.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * L3RS-1 Core Modules — Java
 * asset · compliance · identity · governance · settlement · transfer
 * Pure JDK 21 — zero external dependencies.
 */
public final class L3rsModules {

    private L3rsModules() {}

    // ══════════════════════════════════════════════════════════════════════════
    // §2 Asset State Machine
    // ══════════════════════════════════════════════════════════════════════════

    private static final String[][] TRANSITION_MATRIX = {
        {"ISSUED",     "ACTIVATION",    "ACTIVE"},
        {"ACTIVE",     "BREACH",        "RESTRICTED"},
        {"ACTIVE",     "FREEZE",        "FROZEN"},
        {"RESTRICTED", "CLEARED",       "ACTIVE"},
        {"FROZEN",     "RELEASE",       "ACTIVE"},
        {"ACTIVE",     "REDEMPTION",    "REDEEMED"},
        {"REDEEMED",   "FINALIZATION",  "BURNED"},
        {"ACTIVE",     "SUSPENSION",    "SUSPENDED"},
        {"SUSPENDED",  "REINSTATEMENT", "ACTIVE"},
    };

    /** §2.5 — Deterministic state transition. Invariant I₁. */
    public static AssetState applyStateTransition(AssetState current, String trigger) {
        if (current.isTerminal()) throw new IllegalStateException("BURNED is terminal");
        for (var row : TRANSITION_MATRIX) {
            if (current.name().equals(row[0]) && trigger.equals(row[1])) {
                return AssetState.valueOf(row[2]);
            }
        }
        throw new IllegalArgumentException("No transition from " + current + " via " + trigger);
    }

    /** §13.14 Strict asset validation. */
    public static void validateAsset(Asset asset) {
        if (asset.jurisdiction() == null || asset.jurisdiction().length() != 2)
            throw new IllegalArgumentException("Jurisdiction must be ISO 3166-1 alpha-2");
        if (!asset.standardVersion().startsWith("L3RS-"))
            throw new IllegalArgumentException("standardVersion must start with L3RS-");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §4 Compliance Engine
    // ══════════════════════════════════════════════════════════════════════════

    public interface SanctionsRegistry {
        String registryHash();
        boolean isListed(String address);
    }

    public record ComplianceContext(
        Asset asset, String sender, String receiver,
        BigInteger amount, long timestamp, SanctionsRegistry sanctions
    ) {}

    public record ComplianceDecision(boolean allowed, ComplianceRule blockedBy, String action) {
        public static ComplianceDecision allow() { return new ComplianceDecision(true, null, null); }
        public static ComplianceDecision block(ComplianceRule r) {
            return new ComplianceDecision(false, r, r.action().name());
        }
    }

    /** C: E → {allow, block} — §4.3. O(n) per §14.3. Invariant I₂. */
    public static ComplianceDecision evaluateCompliance(ComplianceModule module, ComplianceContext ctx) {
        if (ctx.asset().state() != AssetState.ACTIVE) {
            return ComplianceDecision.block(syntheticStateRule());
        }
        var sorted = new ArrayList<>(module.rules());
        sorted.sort(Comparator.comparingInt(ComplianceRule::priority));
        for (var rule : sorted) {
            if (!triggerApplies(rule, ctx)) continue;
            if (!evaluateRule(rule, ctx) && rule.action().isBlocking()) {
                return ComplianceDecision.block(rule);
            }
        }
        return ComplianceDecision.allow();
    }

    private static boolean triggerApplies(ComplianceRule rule, ComplianceContext ctx) {
        return "*".equals(rule.scope()) || rule.scope().equals(ctx.asset().jurisdiction());
    }

    @SuppressWarnings("unchecked")
    private static boolean evaluateRule(ComplianceRule rule, ComplianceContext ctx) {
        return switch (rule.ruleType()) {
            case HOLDING_PERIOD -> {
                var acq = rule.params().get("acquisitionTime");
                var period = rule.params().get("holdingPeriodSec");
                if (acq == null || period == null) yield false;
                yield (ctx.timestamp() - toLong(acq)) >= toLong(period);
            }
            case TRANSACTION_THRESHOLD -> {
                var threshold = rule.params().get("thresholdAmount");
                if (threshold == null) yield false;
                yield ctx.amount().compareTo(new BigInteger(threshold.toString())) <= 0;
            }
            case SANCTIONS_SCREENING -> {
                if (ctx.sanctions() == null) yield false;
                yield !ctx.sanctions().isListed(ctx.sender()) && !ctx.sanctions().isListed(ctx.receiver());
            }
            default -> {
                var result = rule.params().get("externalResult");
                yield result instanceof Boolean b && b;
            }
        };
    }

    private static long toLong(Object v) {
        if (v instanceof Number n) return n.longValue();
        return Long.parseLong(v.toString());
    }

    private static ComplianceRule syntheticStateRule() {
        return new ComplianceRule("SYSTEM_STATE_CHECK", RuleType.TRANSFER_ELIGIBILITY,
            "*", "TRANSFER", 0, EnforcementAction.REJECT, Map.of());
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §3 Identity Binding
    // ══════════════════════════════════════════════════════════════════════════

    public enum IdentityStatusResult { VALID, EXPIRED, REVOKED, UNKNOWN }

    /** Status(IR) — §3.6. */
    public static IdentityStatusResult identityStatus(IdentityRecord record, long nowUnix) {
        if (record.revoked()) return IdentityStatusResult.REVOKED;
        if (nowUnix >= record.expiry()) return IdentityStatusResult.EXPIRED;
        return IdentityStatusResult.VALID;
    }

    /** validate_identity(party) — §3.11. */
    public static void validateIdentity(IdentityRecord record, long nowUnix) {
        var status = identityStatus(record, nowUnix);
        if (status != IdentityStatusResult.VALID)
            throw new IllegalStateException("Identity status: " + status);
        if (record.proof().isPresent())
            throw new IllegalStateException("ZKP verification not implemented");
    }

    /** §3.2 Identity level enforcement. */
    public static void enforceIdentityLevel(
        IdentityLevel level,
        List<IdentityRecord> senderRecords,
        List<IdentityRecord> receiverRecords,
        long nowUnix,
        List<String> requiredJurisdictions
    ) {
        if (level == IdentityLevel.UNBOUND) return;
        if (senderRecords.isEmpty()) throw new IllegalStateException("Sender has no identity record");
        validateIdentity(senderRecords.get(0), nowUnix);
        if (receiverRecords.isEmpty()) throw new IllegalStateException("Receiver has no identity record");
        validateIdentity(receiverRecords.get(0), nowUnix);
        if (level == IdentityLevel.MULTI_JURISDICTION && requiredJurisdictions != null) {
            for (var party : List.of(Map.entry("sender", senderRecords), Map.entry("receiver", receiverRecords))) {
                var valid = party.getValue().stream()
                    .filter(r -> identityStatus(r, nowUnix) == IdentityStatusResult.VALID)
                    .map(IdentityRecord::jurisdictionIdentity)
                    .collect(java.util.stream.Collectors.toSet());
                for (var j : requiredJurisdictions) {
                    if (!valid.contains(j))
                        throw new IllegalStateException(party.getKey() + " missing jurisdiction: " + j);
                }
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §5 Governance Override
    // ══════════════════════════════════════════════════════════════════════════

    public record OverrideRecord(String recordHash, String overrideId, String authority,
                                  GovernanceAction action, long timestamp) {}

    /** validate_override(O) — §5.6. Invariant I₄. */
    public static void validateOverride(
        OverrideObject override,
        GovernanceModule governance,
        L3rsCrypto.SignatureVerifier verifier,
        List<String[]> allSignatures
    ) {
        if (!governance.authorities().contains(override.authority()))
            throw new IllegalStateException("Authority not registered");
        if (!governance.overrideTypes().contains(override.action()))
            throw new IllegalStateException("Action not permitted");
        if (override.legalBasis() == null || override.legalBasis().length() < 64)
            throw new IllegalStateException("Legal basis hash missing");
        var msg = L3rsCrypto.hexToBytes(override.legalBasis());
        if (!verifier.verify(msg, override.signature(), override.authority()))
            throw new IllegalStateException("Signature verification failed");
        if (override.action() == GovernanceAction.EMERGENCY_ROLLBACK)
            validateQuorum(governance, allSignatures);
    }

    private static void validateQuorum(GovernanceModule gov, List<String[]> sigs) {
        int n = gov.authorities().size();
        int required = (int) Math.ceil(2.0 * n / 3.0);
        var signed = sigs.stream()
            .filter(s -> gov.authorities().contains(s[0]))
            .map(s -> s[0])
            .collect(java.util.stream.Collectors.toSet());
        if (signed.size() < required)
            throw new IllegalStateException("Quorum not met: " + signed.size() + "/" + required);
    }

    public static OverrideRecord createOverrideRecord(OverrideObject o) {
        return new OverrideRecord(
            L3rsCrypto.constructOverrideHash(o.overrideId(), o.authority(), o.action().name(), o.timestamp()),
            o.overrideId(), o.authority(), o.action(), o.timestamp()
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §6 Fee Routing
    // ══════════════════════════════════════════════════════════════════════════

    public record FeeDistribution(BigInteger totalFee, List<FeeAlloc> allocations, String feeRecordHash) {}
    public record FeeAlloc(String recipient, BigInteger amount) {}

    /** §6.12 Economic Integrity Constraint. */
    public static void validateFeeModule(FeeModule fee) {
        int total = fee.allocations().stream().mapToInt(FeeAllocation::basisPoints).sum();
        if (total != 10_000)
            throw new IllegalArgumentException("Fee basis points must sum to 10000; got " + total);
        for (var a : fee.allocations())
            if (a.basisPoints() < 0) throw new IllegalArgumentException("Negative allocation");
    }

    /** distribute_fees(A, amount) — §6.5. Atomic. */
    public static FeeDistribution distributeFees(FeeModule fee, BigInteger amount, String txId, long timestamp) {
        validateFeeModule(fee);
        var totalFee = amount.multiply(BigInteger.valueOf(fee.baseRateBasisPoints())).divide(BigInteger.valueOf(10_000));
        var allocs = fee.allocations().stream()
            .map(a -> new FeeAlloc(a.recipient(),
                totalFee.multiply(BigInteger.valueOf(a.basisPoints())).divide(BigInteger.valueOf(10_000))))
            .toList();
        var feeRecord = L3rsCrypto.sha256(
            L3rsCrypto.hexToBytes(txId),
            to32Bytes(totalFee),
            L3rsCrypto.longToBytes(timestamp)
        );
        return new FeeDistribution(totalFee, allocs, feeRecord);
    }

    private static byte[] to32Bytes(BigInteger v) {
        var b = v.toByteArray();
        var buf = new byte[32];
        System.arraycopy(b, 0, buf, 32 - b.length, b.length);
        return buf;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §8 Cross-Chain
    // ══════════════════════════════════════════════════════════════════════════

    public record CrossChainCertificate(String cid, String assetId, String stateHash,
                                         String complianceHash, String governanceHash, long timestamp) {}

    /** §8.3 — CID = H(I || SH || CH || GH || t) */
    public static CrossChainCertificate buildCrossChainCertificate(Asset asset, long timestamp) {
        var stateHash      = L3rsCrypto.hashObject(asset.state().name());
        var complianceHash = L3rsCrypto.hashObject(L3rsCrypto.canonicalize(asset.complianceModule()));
        var governanceHash = L3rsCrypto.hashObject(L3rsCrypto.canonicalize(asset.governanceModule()));
        var cid = L3rsCrypto.constructCID(asset.assetId(), stateHash, complianceHash, governanceHash, timestamp);
        return new CrossChainCertificate(cid, asset.assetId(), stateHash, complianceHash, governanceHash, timestamp);
    }

    /** §8.9 verify_crosschain */
    public static void verifyCrossChain(CrossChainCertificate cert, String destAssetId,
                                         String destComplianceHash, String destGovernanceHash) {
        if (!cert.assetId().equals(destAssetId))
            throw new IllegalStateException("Asset_ID changed");
        var recomputed = L3rsCrypto.constructCID(cert.assetId(), cert.stateHash(),
            cert.complianceHash(), cert.governanceHash(), cert.timestamp());
        if (!recomputed.equals(cert.cid()))
            throw new IllegalStateException("CID mismatch");
        if (!destComplianceHash.equals(cert.complianceHash()))
            throw new IllegalStateException("Compliance downgrade");
        if (!destGovernanceHash.equals(cert.governanceHash()))
            throw new IllegalStateException("Governance hash changed");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §9 Settlement + §2.7 Transfer Executor
    // ══════════════════════════════════════════════════════════════════════════

    public record TransferOutput(boolean success, String txId, SettlementProof proof,
                                  String feeRecord, String error, String failedStep) {
        public static TransferOutput fail(String step, String msg) {
            return new TransferOutput(false, null, null, null, msg, step);
        }
    }

    public static boolean isReplay(TransferEvent event, Set<String> ledgerHistory) {
        var txId = L3rsCrypto.constructTxId(event.sender(), event.receiver(),
            event.amount(), event.nonce(), event.timestamp());
        return ledgerHistory.contains(txId);
    }

    /** §2.6 Deterministic 7-step transfer execution. */
    public static TransferOutput executeTransfer(
        Asset asset, TransferEvent event,
        List<IdentityRecord> senderRecords, List<IdentityRecord> receiverRecords,
        Set<String> ledgerHistory, BigInteger blockHeight,
        SanctionsRegistry sanctions, List<String> requiredJurisdictions
    ) {
        if (isReplay(event, ledgerHistory))
            return TransferOutput.fail("REPLAY_CHECK", "Duplicate TxID");

        var txId = L3rsCrypto.constructTxId(event.sender(), event.receiver(),
            event.amount(), event.nonce(), event.timestamp());

        if (asset.state() != AssetState.ACTIVE)
            return TransferOutput.fail("STATE_CHECK", "Asset not ACTIVE: " + asset.state());

        if (asset.identityLevel().value >= 1) {
            try {
                enforceIdentityLevel(asset.identityLevel(), senderRecords, receiverRecords,
                    event.timestamp(), requiredJurisdictions);
            } catch (Exception e) {
                return TransferOutput.fail("IDENTITY", e.getMessage());
            }
        }

        var ctx = new ComplianceContext(asset, event.sender(), event.receiver(),
            event.amount(), event.timestamp(), sanctions);
        var decision = evaluateCompliance(asset.complianceModule(), ctx);
        if (!decision.allowed())
            return TransferOutput.fail("COMPLIANCE", "Blocked by: " +
                (decision.blockedBy() != null ? decision.blockedBy().ruleId() : "unknown"));

        FeeDistribution feeResult;
        try {
            feeResult = distributeFees(asset.feeModule(), event.amount(), txId, event.timestamp());
        } catch (Exception e) {
            return TransferOutput.fail("FEE_ROUTING", e.getMessage());
        }

        var proof = new SettlementProof(txId, blockHeight, "", event.timestamp());
        return new TransferOutput(true, txId, proof, feeResult.feeRecordHash(), null, null);
    }
}
