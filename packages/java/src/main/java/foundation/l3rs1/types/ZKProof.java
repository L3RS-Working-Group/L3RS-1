package foundation.l3rs1.types;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** §3.8 ZK Proof */
public record ZKProof(
    String scheme,
    String statement,
    String witnessCommitment,
    String proofBytes,
    String nonce
) {}
