package foundation.l3rs1.modules;

import foundation.l3rs1.crypto.L3rsCrypto;
import java.math.BigInteger;
import java.util.*;

/** L3RS-1 Core Modules — asset · compliance · identity · fees · replay */
public final class L3rsModules {
    private L3rsModules() {}

    // ── Enums ──────────────────────────────────────────────────────────────────

    public enum AssetState {
        ISSUED, ACTIVE, RESTRICTED, FROZEN, SUSPENDED, REDEEMED, BURNED;
        public boolean isTerminal() { return this == BURNED; }
    }

    public enum IdentityStatus { VALID, EXPIRED, REVOKED, UNKNOWN }
    public enum EnforcementAction {
        REJECT, FREEZE, RESTRICT, FLAG, REQUIRE_DISCLOSURE;
        public boolean isBlocking() { return this==REJECT||this==FREEZE||this==RESTRICT; }
    }
    public enum GovernanceAction {
        FREEZE_BALANCE, UNFREEZE_BALANCE, RESTRICT_TRANSFER,
        SEIZE_ASSET, FORCE_REDEMPTION, EMERGENCY_ROLLBACK
    }
    public enum RuleType {
        TRANSFER_ELIGIBILITY, INVESTOR_CLASSIFICATION, HOLDING_PERIOD,
        GEOGRAPHIC_RESTRICTION, SANCTIONS_SCREENING, TRANSACTION_THRESHOLD,
        AML_TRIGGER, MARKET_RESTRICTION, REDEMPTION_ELIGIBILITY
    }

    // ── Records ────────────────────────────────────────────────────────────────

    public record ComplianceRule(String ruleId, RuleType ruleType, String scope,
        String trigger, int priority, EnforcementAction action, Map<String,Object> params) {}
    public record ComplianceModule(List<ComplianceRule> rules) {}
    public record FeeAllocation(String recipient, int basisPoints) {}
    public record FeeModule(int baseRateBasisPoints, List<FeeAllocation> allocations) {}
    public record IdentityRecord(String identityHash, String verificationAuthority,
        String jurisdictionIdentity, long expiry, boolean revoked) {}
    public record TransferEvent(String assetId, String sender, String receiver,
        BigInteger amount, String nonce, long timestamp) {}
    public record StateTransitionResult(boolean success, AssetState newState, String error) {}
    public record ComplianceDecision(boolean allowed, ComplianceRule blockedBy) {}

    // ── §2.5 State Machine ────────────────────────────────────────────────────

    private static final String[][] TRANSITIONS = {
        {"ISSUED","ACTIVATION","ACTIVE"}, {"ACTIVE","BREACH","RESTRICTED"},
        {"ACTIVE","FREEZE","FROZEN"}, {"RESTRICTED","CLEARED","ACTIVE"},
        {"FROZEN","RELEASE","ACTIVE"}, {"ACTIVE","REDEMPTION","REDEEMED"},
        {"REDEEMED","FINALIZATION","BURNED"}, {"ACTIVE","SUSPENSION","SUSPENDED"},
        {"SUSPENDED","REINSTATEMENT","ACTIVE"},
    };

    public static StateTransitionResult applyStateTransition(AssetState current, String trigger) {
        if (current.isTerminal())
            return new StateTransitionResult(false, null, "BURNED is terminal");
        for (var row : TRANSITIONS)
            if (current.name().equals(row[0]) && trigger.equals(row[1]))
                return new StateTransitionResult(true, AssetState.valueOf(row[2]), null);
        return new StateTransitionResult(false, null, "No transition from "+current+" via "+trigger);
    }

    // ── §6.12 Fee Validation ──────────────────────────────────────────────────

    public static void validateFeeModule(FeeModule fee) {
        int total = fee.allocations().stream().mapToInt(FeeAllocation::basisPoints).sum();
        if (total != 10_000)
            throw new IllegalArgumentException("Fee allocations must sum to 10000; got " + total);
        for (var a : fee.allocations())
            if (a.basisPoints() < 0) throw new IllegalArgumentException("Negative allocation");
    }

    // ── §3.6 Identity Status ──────────────────────────────────────────────────

    public static IdentityStatus identityStatus(IdentityRecord record, long nowUnix) {
        if (record.revoked()) return IdentityStatus.REVOKED;
        if (nowUnix >= record.expiry()) return IdentityStatus.EXPIRED;
        return IdentityStatus.VALID;
    }

    // ── §9.6 Replay Protection ────────────────────────────────────────────────

    public static boolean isReplay(TransferEvent event, Set<String> ledgerHistory) {
        var txId = L3rsCrypto.constructTxId(
            event.sender(), event.receiver(), event.amount(), event.nonce(), event.timestamp());
        return ledgerHistory.contains(txId);
    }
}
