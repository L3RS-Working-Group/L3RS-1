package foundation.l3rs1.types;
/** §5.2 O = (OID, AUTH, ACTION, TARGET, BASIS, TS, SIG) */
public record OverrideObject(
    String overrideId, String authority, GovernanceAction action,
    String target, String legalBasis, long timestamp, String signature
) {}
