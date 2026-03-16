package foundation.l3rs1.types;
import java.math.BigInteger;
/** §9.10 Settlement Proof */
public record SettlementProof(
    String txId, BigInteger blockHeight, String stateHash, long timestamp
) {}
