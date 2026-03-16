package foundation.l3rs1.types;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** §3.3 IR = (HID, VA, JI, EXP, REV, ATTR, PROOF) */
public record IdentityRecord(
    String identityHash,
    String verificationAuthority,
    String jurisdictionIdentity,
    long expiry,
    boolean revoked,
    List<String> attributeCommitments,
    Optional<ZKProof> proof
) {}
