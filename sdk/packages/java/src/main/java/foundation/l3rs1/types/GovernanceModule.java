package foundation.l3rs1.types;
import java.util.List;
/** §13.6 Governance Module */
public record GovernanceModule(
    List<String> authorities, int quorumThreshold, List<GovernanceAction> overrideTypes
) {}
