package foundation.l3rs1.types;
import java.util.Map;
/** §13.5 Compliance Rule */
public record ComplianceRule(
    String ruleId, RuleType ruleType, String scope, String trigger,
    int priority, EnforcementAction action, Map<String, Object> params
) {}
