package foundation.l3rs1.types;

/** §2.4 Asset State Machine */
public enum AssetState {
    ISSUED, ACTIVE, RESTRICTED, FROZEN, SUSPENDED, REDEEMED, BURNED;

    public boolean isTerminal() { return this == BURNED; }
}
