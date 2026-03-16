package foundation.l3rs1.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * L3RS-1 Cryptographic Primitives — Java
 * §13.10-11 Canonical Serialization · §10.3 Security Assumptions
 * Pure JDK — zero external dependencies.
 */
public final class L3rsCrypto {

    private L3rsCrypto() {}

    // ─── Core Hash Function ───────────────────────────────────────────────────

    /** H(data) — SHA-256 per §10.3. Returns lowercase hex. */
    public static String sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) md.update(part);
            return bytesToHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // ─── §13.11 Canonical Serialization ──────────────────────────────────────

    /**
     * ser(Y) — canonical JSON: no whitespace, sorted keys, UTF-8.
     * Sufficient for Map/List/primitive objects.
     */
    public static String canonicalize(Object obj) {
        return canonicalJson(obj);
    }

    @SuppressWarnings("unchecked")
    private static String canonicalJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof Map<?, ?> map) {
            var sorted = new TreeMap<>((Map<String, Object>) map);
            var sb = new StringBuilder("{");
            boolean first = true;
            for (var entry : sorted.entrySet()) {
                if (!first) sb.append(',');
                sb.append('"').append(entry.getKey()).append('"');
                sb.append(':');
                sb.append(canonicalJson(entry.getValue()));
                first = false;
            }
            return sb.append('}').toString();
        }
        if (obj instanceof List<?> list) {
            var sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(canonicalJson(list.get(i)));
            }
            return sb.append(']').toString();
        }
        if (obj instanceof String s) return "\"" + s.replace("\"", "\\\"") + "\"";
        if (obj instanceof Boolean || obj instanceof Number) return obj.toString();
        return "\"" + obj + "\"";
    }

    /** HY = H(ser(Y)) */
    public static String hashObject(Object obj) {
        return sha256(canonicalize(obj).getBytes(StandardCharsets.UTF_8));
    }

    // ─── §2.2 Asset_ID ───────────────────────────────────────────────────────

    /** I = H(pk_issuer || ts || nonce) — §2.2 */
    public static String constructAssetId(String issuerPubkeyHex, long timestampUnix, String nonceHex) {
        byte[] pk    = hexToBytes(issuerPubkeyHex);
        byte[] ts    = longToBytes(timestampUnix);
        byte[] nonce = hexToBytes(nonceHex);
        return sha256(pk, ts, nonce);
    }

    // ─── §3.4 Identity Hash ──────────────────────────────────────────────────

    /** HID = H(PII || salt || domain) — §3.4 */
    public static String constructIdentityHash(String piiUtf8, String saltHex, String domain) {
        return sha256(
            piiUtf8.getBytes(StandardCharsets.UTF_8),
            hexToBytes(saltHex),
            domain.getBytes(StandardCharsets.UTF_8)
        );
    }

    // ─── §8.3 CID ────────────────────────────────────────────────────────────

    /** CID = H(I || SH || CH || GH || t) — §8.3 */
    public static String constructCID(String assetId, String stateHash,
                                       String complianceHash, String governanceHash,
                                       long timestampUnix) {
        return sha256(
            hexToBytes(assetId), hexToBytes(stateHash),
            hexToBytes(complianceHash), hexToBytes(governanceHash),
            longToBytes(timestampUnix)
        );
    }

    // ─── §9.6 TxID ───────────────────────────────────────────────────────────

    /** TxID = H(sender || receiver || amount || nonce || timestamp) — §9.6 */
    public static String constructTxId(String sender, String receiver,
                                        BigInteger amount, String nonceHex, long timestamp) {
        byte[] amountBuf = new byte[32];
        byte[] amountBytes = amount.toByteArray();
        System.arraycopy(amountBytes, 0, amountBuf, 32 - amountBytes.length, amountBytes.length);
        return sha256(
            sender.getBytes(StandardCharsets.UTF_8),
            receiver.getBytes(StandardCharsets.UTF_8),
            amountBuf, hexToBytes(nonceHex), longToBytes(timestamp)
        );
    }

    // ─── §5.10 Override Record ───────────────────────────────────────────────

    /** Override_Record = H(OID || AUTH || ACTION || TS) — §5.10 */
    public static String constructOverrideHash(String overrideId, String authority,
                                                String action, long timestamp) {
        return sha256(
            overrideId.getBytes(StandardCharsets.UTF_8),
            authority.getBytes(StandardCharsets.UTF_8),
            action.getBytes(StandardCharsets.UTF_8),
            longToBytes(timestamp)
        );
    }

    // ─── §8.11 Chain ID ──────────────────────────────────────────────────────

    /** ChainID = H(chain_name || network_type || genesis_hash) — §8.11 */
    public static String constructChainId(String chainName, String networkType, String genesisHashHex) {
        return sha256(
            chainName.getBytes(StandardCharsets.UTF_8),
            networkType.getBytes(StandardCharsets.UTF_8),
            hexToBytes(genesisHashHex)
        );
    }

    // ─── Utilities ───────────────────────────────────────────────────────────

    public static byte[] longToBytes(long v) {
        return ByteBuffer.allocate(8).putLong(v).array();
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        var sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Abstract interface for EdDSA/ECDSA verification — §10.3 */
    public interface SignatureVerifier {
        boolean verify(byte[] message, String signatureHex, String publicKeyHex);
    }
}
