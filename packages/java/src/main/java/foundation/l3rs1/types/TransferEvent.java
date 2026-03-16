package foundation.l3rs1.types;
import java.math.BigInteger;
/** §9.6 Transfer Event */
public record TransferEvent(
    String assetId, String sender, String receiver,
    BigInteger amount, String nonce, long timestamp
) {}
