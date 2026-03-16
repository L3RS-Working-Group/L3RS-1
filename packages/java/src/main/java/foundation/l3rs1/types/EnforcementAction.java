package foundation.l3rs1.types;
/** §4.7 Enforcement Actions */
public enum EnforcementAction {
    REJECT, FREEZE, RESTRICT, FLAG, REQUIRE_DISCLOSURE;
    public boolean isBlocking() {
        return this == REJECT || this == FREEZE || this == RESTRICT;
    }
}
