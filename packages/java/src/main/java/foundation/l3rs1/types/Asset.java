package foundation.l3rs1.types;
import java.util.Optional;
/** §2.1 A = (I, T, J, L, ID, C, R, G, F, B, X, S) */
public record Asset(
    String assetId, AssetType assetType, String jurisdiction,
    LegalMirror legalMirror, IdentityLevel identityLevel,
    ComplianceModule complianceModule, GovernanceModule governanceModule,
    FeeModule feeModule, Optional<ReserveInterface> reserveInterface,
    CrossChainMetadata crossChainMetadata, AssetState state, String standardVersion
) {}
