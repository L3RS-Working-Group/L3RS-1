package foundation.l3rs1.types;
import java.util.List;
/** §13.7 Fee Module */
public record FeeModule(int baseRateBasisPoints, List<FeeAllocation> allocations) {}
