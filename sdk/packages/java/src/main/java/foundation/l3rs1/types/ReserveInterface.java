package foundation.l3rs1.types;
/** §7.3 B = (CID, ABT, AH, FREQ, RLOG, PRIORITY) */
public record ReserveInterface(
    String custodianId, BackingType backingType, String auditHash,
    AttestationFrequency attestationFrequency, InsolvencyPriority insolvencyPriority,
    RedemptionLogic redemptionLogic
) {}
