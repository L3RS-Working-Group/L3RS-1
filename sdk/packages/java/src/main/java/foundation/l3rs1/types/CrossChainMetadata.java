package foundation.l3rs1.types;
/** §13.9 Cross-Chain Metadata */
public record CrossChainMetadata(
    String certificateId, String originChainId, String complianceHash,
    String governanceHash, String stateHash, long timestamp
) {}
