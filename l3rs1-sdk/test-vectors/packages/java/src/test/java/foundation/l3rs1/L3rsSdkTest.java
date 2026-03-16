package foundation.l3rs1;

import foundation.l3rs1.crypto.L3rsCrypto;
import foundation.l3rs1.modules.L3rsModules;
import foundation.l3rs1.types.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import java.math.BigInteger;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * L3RS-1 Java SDK Test Suite
 * JUnit 5 — covers §2, §3, §4, §6, §8, §9, §13
 */
class L3rsSdkTest {

    // ══════════════════════════════════════════════════════════════════════════
    // §13.11 Canonical Serialization
    // ══════════════════════════════════════════════════════════════════════════

    @Test @DisplayName("§13.11 Keys sorted alphabetically")
    void canonicalKeysSorted() {
        var obj = new java.util.TreeMap<>(Map.of("z", 3, "a", 1, "m", 2));
        // Note: L3rsCrypto.canonicalize sorts keys
        var result = L3rsCrypto.canonicalize(Map.of("z", 3, "a", 1, "m", 2));
        assertEquals("{\"a\":1,\"m\":2,\"z\":3}", result);
    }

    @Test @DisplayName("§13.11 Serialization is deterministic")
    void canonicalDeterminism() {
        var obj = Map.of("jurisdiction", "US", "assetId", "abc", "state", "ACTIVE");
        assertEquals(L3rsCrypto.canonicalize(obj), L3rsCrypto.canonicalize(obj));
    }

    @Test @DisplayName("§13.11 No insignificant whitespace")
    void canonicalNoWhitespace() {
        var result = L3rsCrypto.canonicalize(Map.of("key", "value"));
        assertFalse(result.contains(" "));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §2.2 Asset_ID Construction
    // ══════════════════════════════════════════════════════════════════════════

    static final String PUBKEY   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    static final long   TS       = 1740355200L;
    static final String NONCE    = "0000000000000001";
    static final String EXPECTED = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a";

    @Test @DisplayName("§2.2 Asset_ID matches canonical vector")
    void assetIdMatchesVector() {
        assertEquals(EXPECTED, L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE));
    }

    @Test @DisplayName("§2.2 Asset_ID is 64 hex characters")
    void assetIdIs64Chars() {
        assertEquals(64, L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE).length());
    }

    @Test @DisplayName("§2.2 Asset_ID is deterministic")
    void assetIdDeterministic() {
        assertEquals(
            L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE),
            L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE)
        );
    }

    @Test @DisplayName("§2.2 Different nonce gives different ID")
    void assetIdNonceSensitive() {
        assertNotEquals(
            L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE),
            L3rsCrypto.constructAssetId(PUBKEY, TS, "0000000000000002")
        );
    }

    @Test @DisplayName("§2.2 Different timestamp gives different ID")
    void assetIdTimestampSensitive() {
        assertNotEquals(
            L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE),
            L3rsCrypto.constructAssetId(PUBKEY, TS + 1, NONCE)
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §2.5 State Transition Matrix
    // ══════════════════════════════════════════════════════════════════════════

    @ParameterizedTest(name = "{0} --{1}--> {2}")
    @CsvSource({
        "ISSUED,     ACTIVATION,    ACTIVE",
        "ACTIVE,     BREACH,        RESTRICTED",
        "ACTIVE,     FREEZE,        FROZEN",
        "RESTRICTED, CLEARED,       ACTIVE",
        "FROZEN,     RELEASE,       ACTIVE",
        "ACTIVE,     REDEMPTION,    REDEEMED",
        "REDEEMED,   FINALIZATION,  BURNED",
        "ACTIVE,     SUSPENSION,    SUSPENDED",
        "SUSPENDED,  REINSTATEMENT, ACTIVE",
    })
    @DisplayName("§2.5 Valid transition")
    void validTransition(String from, String trigger, String expected) {
        var result = L3rsModules.applyStateTransition(AssetState.valueOf(from.trim()), trigger.trim());
        assertEquals(AssetState.valueOf(expected.trim()), result);
    }

    @Test @DisplayName("§2.5 BURNED is terminal")
    void burnedIsTerminal() {
        assertThrows(IllegalStateException.class,
            () -> L3rsModules.applyStateTransition(AssetState.BURNED, "ACTIVATION"));
    }

    @Test @DisplayName("§2.5 Invalid transition is rejected")
    void invalidTransitionRejected() {
        assertThrows(IllegalArgumentException.class,
            () -> L3rsModules.applyStateTransition(AssetState.ISSUED, "FREEZE"));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §8.3 Cross-Chain CID
    // ══════════════════════════════════════════════════════════════════════════

    static final String A = "a".repeat(64);
    static final String B = "b".repeat(64);
    static final String C = "c".repeat(64);
    static final String D = "d".repeat(64);

    @Test @DisplayName("§8.3 CID is 64 hex characters")
    void cidIs64Chars() {
        assertEquals(64, L3rsCrypto.constructCID(A, B, C, D, 1000L).length());
    }

    @Test @DisplayName("§8.3 CID is deterministic")
    void cidDeterministic() {
        assertEquals(
            L3rsCrypto.constructCID(A, B, C, D, 1000L),
            L3rsCrypto.constructCID(A, B, C, D, 1000L)
        );
    }

    @Test @DisplayName("§8.3 CID changes when stateHash changes (I₁₁)")
    void cidStateHashSensitive() {
        assertNotEquals(
            L3rsCrypto.constructCID(A, B, C, D, 1000L),
            L3rsCrypto.constructCID(A, "e".repeat(64), C, D, 1000L)
        );
    }

    @Test @DisplayName("§8.3 CID changes when timestamp changes (I₁₁)")
    void cidTimestampSensitive() {
        assertNotEquals(
            L3rsCrypto.constructCID(A, B, C, D, 1000L),
            L3rsCrypto.constructCID(A, B, C, D, 1001L)
        );
    }

    @Test @DisplayName("§8.3 All components affect CID (I₁₁)")
    void cidAllComponentsSensitive() {
        var base = L3rsCrypto.constructCID(A, B, C, D, 1000L);
        assertNotEquals(base, L3rsCrypto.constructCID("e".repeat(64), B, C, D, 1000L));
        assertNotEquals(base, L3rsCrypto.constructCID(A, "e".repeat(64), C, D, 1000L));
        assertNotEquals(base, L3rsCrypto.constructCID(A, B, "e".repeat(64), D, 1000L));
        assertNotEquals(base, L3rsCrypto.constructCID(A, B, C, "e".repeat(64), 1000L));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §9.6 TxID and Replay Protection
    // ══════════════════════════════════════════════════════════════════════════

    @Test @DisplayName("§9.6 TxID is 64 hex characters")
    void txIdIs64Chars() {
        var txId = L3rsCrypto.constructTxId("alice", "bob", BigInteger.valueOf(1000L), "00".repeat(8), 1740355200L);
        assertEquals(64, txId.length());
    }

    @Test @DisplayName("§9.6 TxID is deterministic")
    void txIdDeterministic() {
        var a = L3rsCrypto.constructTxId("alice", "bob", BigInteger.valueOf(1000L), "00".repeat(8), 1740355200L);
        var b = L3rsCrypto.constructTxId("alice", "bob", BigInteger.valueOf(1000L), "00".repeat(8), 1740355200L);
        assertEquals(a, b);
    }

    @Test @DisplayName("§9.6 Same event detected as replay")
    void sameEventIsReplay() {
        var ev = new TransferEvent("asset1", "alice", "bob", BigInteger.valueOf(1000L), "00".repeat(8), 1740355200L);
        var txId = L3rsCrypto.constructTxId(ev.sender(), ev.receiver(), ev.amount(), ev.nonce(), ev.timestamp());
        var history = new HashSet<>(Set.of(txId));
        assertTrue(L3rsModules.isReplay(ev, history));
    }

    @Test @DisplayName("§9.6 Different nonce is not a replay")
    void differentNonceIsNotReplay() {
        var ev1 = new TransferEvent("asset1", "alice", "bob", BigInteger.valueOf(1000L), "00".repeat(8), 1740355200L);
        var ev2 = new TransferEvent("asset1", "alice", "bob", BigInteger.valueOf(1000L), "01".repeat(8), 1740355200L);
        var txId1 = L3rsCrypto.constructTxId(ev1.sender(), ev1.receiver(), ev1.amount(), ev1.nonce(), ev1.timestamp());
        var history = new HashSet<>(Set.of(txId1));
        assertFalse(L3rsModules.isReplay(ev2, history));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §6.12 Fee Validation
    // ══════════════════════════════════════════════════════════════════════════

    @Test @DisplayName("§6.12 Valid 5-way fee split accepted")
    void validFeeSplitAccepted() {
        var fm = new FeeModule(100, List.of(
            new FeeAllocation("sovereign",  2000),
            new FeeAllocation("validation", 3000),
            new FeeAllocation("storage",    2000),
            new FeeAllocation("operator",   2500),
            new FeeAllocation("bridge",     500)
        ));
        assertDoesNotThrow(() -> L3rsModules.validateFeeModule(fm));
    }

    @Test @DisplayName("§6.12 Partial allocation rejected")
    void partialAllocationRejected() {
        var fm = new FeeModule(100, List.of(new FeeAllocation("only", 5000)));
        assertThrows(IllegalArgumentException.class, () -> L3rsModules.validateFeeModule(fm));
    }

    @Test @DisplayName("§6.12 Over-allocation rejected")
    void overAllocationRejected() {
        var fm = new FeeModule(100, List.of(
            new FeeAllocation("a", 6000),
            new FeeAllocation("b", 5000)
        ));
        assertThrows(IllegalArgumentException.class, () -> L3rsModules.validateFeeModule(fm));
    }

    @Test @DisplayName("§6.12 Negative allocation rejected")
    void negativeAllocationRejected() {
        var fm = new FeeModule(100, List.of(
            new FeeAllocation("a", 11000),
            new FeeAllocation("b", -1000)
        ));
        assertThrows(IllegalArgumentException.class, () -> L3rsModules.validateFeeModule(fm));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // §3.6 Identity Status
    // ══════════════════════════════════════════════════════════════════════════

    static final long NOW = 1_740_355_200L;
    static final String HASH = "a".repeat(64);

    @Test @DisplayName("§3.6 VALID status")
    void identityValidStatus() {
        var rec = new IdentityRecord(HASH, "va", "US", 9_999_999_999L, false, List.of(), Optional.empty());
        assertEquals(L3rsModules.IdentityStatusResult.VALID, L3rsModules.identityStatus(rec, NOW));
    }

    @Test @DisplayName("§3.6 EXPIRED status")
    void identityExpiredStatus() {
        var rec = new IdentityRecord(HASH, "va", "US", 1_000_000_000L, false, List.of(), Optional.empty());
        assertEquals(L3rsModules.IdentityStatusResult.EXPIRED, L3rsModules.identityStatus(rec, NOW));
    }

    @Test @DisplayName("§3.6 REVOKED status")
    void identityRevokedStatus() {
        var rec = new IdentityRecord(HASH, "va", "US", 9_999_999_999L, true, List.of(), Optional.empty());
        assertEquals(L3rsModules.IdentityStatusResult.REVOKED, L3rsModules.identityStatus(rec, NOW));
    }

    @Test @DisplayName("§3.6 REVOKED takes precedence over EXPIRED")
    void revokedPrecedence() {
        var rec = new IdentityRecord(HASH, "va", "US", 1_000_000_000L, true, List.of(), Optional.empty());
        assertEquals(L3rsModules.IdentityStatusResult.REVOKED, L3rsModules.identityStatus(rec, NOW));
    }
}
