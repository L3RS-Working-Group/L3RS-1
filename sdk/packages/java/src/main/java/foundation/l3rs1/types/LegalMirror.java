package foundation.l3rs1.types;
import java.util.Optional;
/** §12.2 L = (J, LH, LV, TS, SIGN) */
public record LegalMirror(
    String jurisdiction, String legalHash, String legalVersion,
    long timestamp, Optional<String> authoritySignature
) {}
