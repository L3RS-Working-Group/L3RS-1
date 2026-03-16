package foundation.l3rs1.types;
/** §7.7 Attestation Frequency */
public enum AttestationFrequency {
    REALTIME, DAILY, WEEKLY, MONTHLY, QUARTERLY, ANNUAL;
    public long toSeconds() {
        return switch (this) {
            case REALTIME  -> 60L;
            case DAILY     -> 86_400L;
            case WEEKLY    -> 604_800L;
            case MONTHLY   -> 2_592_000L;
            case QUARTERLY -> 7_776_000L;
            case ANNUAL    -> 31_536_000L;
        };
    }
}
