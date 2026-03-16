package foundation.l3rs1.types;

/** §3.2 Identity Requirement Level */
public enum IdentityLevel {
    UNBOUND(0), VERIFIED(1), SOVEREIGN_VALIDATED(2), MULTI_JURISDICTION(3);
    public final int value;
    IdentityLevel(int v) { this.value = v; }
}
