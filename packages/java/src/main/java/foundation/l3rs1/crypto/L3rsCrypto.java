package foundation.l3rs1.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/** L3RS-1 Cryptographic Primitives — pure JDK, zero external dependencies. */
public final class L3rsCrypto {
    private L3rsCrypto() {}

    // ── SHA-256 ───────────────────────────────────────────────────────────────

    public static String sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) md.update(p);
            return bytesToHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // ── §13.11 Canonical JSON ─────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static String canonicalize(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof Map<?, ?> m) {
            var sorted = new TreeMap<>((Map<String, Object>) m);
            var sb = new StringBuilder("{");
            boolean first = true;
            for (var e : sorted.entrySet()) {
                if (!first) sb.append(',');
                sb.append('"').append(e.getKey()).append("\":").append(canonicalize(e.getValue()));
                first = false;
            }
            return sb.append('}').toString();
        }
        if (obj instanceof List<?> l) {
            var sb = new StringBuilder("[");
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(canonicalize(l.get(i)));
            }
            return sb.append(']').toString();
        }
        if (obj instanceof String s) return "\"" + s.replace("\"", "\\\"") + "\"";
        if (obj instanceof Boolean || obj instanceof Number) return obj.toString();
        return "\"" + obj + "\"";
    }

    // ── §2.2 Asset_ID ─────────────────────────────────────────────────────────

    public static String constructAssetId(String issuerPubkeyHex, long timestampUnix, String nonceHex) {
        return sha256(hexToBytes(issuerPubkeyHex), longToBytes(timestampUnix), hexToBytes(nonceHex));
    }

    // ── §8.3 CID ─────────────────────────────────────────────────────────────

    public static String constructCID(String assetId, String stateHash,
                                       String complianceHash, String governanceHash, long ts) {
        return sha256(hexToBytes(assetId), hexToBytes(stateHash),
                      hexToBytes(complianceHash), hexToBytes(governanceHash), longToBytes(ts));
    }

    // ── §9.6 TxID ────────────────────────────────────────────────────────────

    public static String constructTxId(String sender, String receiver,
                                        BigInteger amount, String nonceHex, long ts) {
        byte[] amtBuf = new byte[32];
        byte[] amtBytes = amount.toByteArray();
        int len = Math.min(amtBytes.length, 32);
        System.arraycopy(amtBytes, amtBytes.length - len, amtBuf, 32 - len, len);
        return sha256(sender.getBytes(StandardCharsets.UTF_8),
                      receiver.getBytes(StandardCharsets.UTF_8),
                      amtBuf, hexToBytes(nonceHex), longToBytes(ts));
    }

    // ── §5.10 Override Hash ───────────────────────────────────────────────────

    public static String constructOverrideHash(String overrideId, String authority,
                                                String action, long ts) {
        return sha256(overrideId.getBytes(StandardCharsets.UTF_8),
                      authority.getBytes(StandardCharsets.UTF_8),
                      action.getBytes(StandardCharsets.UTF_8), longToBytes(ts));
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    public static byte[] longToBytes(long v) {
        return ByteBuffer.allocate(8).putLong(v).array();
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte)((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        var sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
