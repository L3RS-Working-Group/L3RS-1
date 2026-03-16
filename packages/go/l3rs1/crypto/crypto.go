// Package crypto implements L3RS-1 hash constructions — §13.10-11, §10.3
package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// SHA256 returns lowercase hex of SHA-256 over concatenated parts.
func SHA256(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Canonicalize returns ser(Y) per §13.11: sorted keys, no whitespace, UTF-8.
func Canonicalize(v any) ([]byte, error) {
	sorted := sortKeys(v)
	return json.Marshal(sorted)
}

func sortKeys(v any) any {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(val))
		for _, k := range keys {
			out[k] = sortKeys(val[k])
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = sortKeys(item)
		}
		return out
	default:
		return v
	}
}

// HashObject returns H(ser(obj)).
func HashObject(v any) (string, error) {
	b, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	return SHA256(b), nil
}

// ConstructAssetID — §2.2: I = H(pk_issuer || ts || nonce)
func ConstructAssetID(issuerPubkeyHex string, timestampUnix int64, nonceHex string) (string, error) {
	pk, err := hex.DecodeString(issuerPubkeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid pubkey: %w", err)
	}
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestampUnix))
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce: %w", err)
	}
	return SHA256(pk, ts, nonce), nil
}

// ConstructCID — §8.3: CID = H(I || SH || CH || GH || t)
func ConstructCID(assetID, stateHash, complianceHash, governanceHash string, ts int64) (string, error) {
	decode := func(s string) ([]byte, error) { return hex.DecodeString(s) }
	id, err := decode(assetID)
	if err != nil { return "", err }
	sh, err := decode(stateHash)
	if err != nil { return "", err }
	ch, err := decode(complianceHash)
	if err != nil { return "", err }
	gh, err := decode(governanceHash)
	if err != nil { return "", err }
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts))
	return SHA256(id, sh, ch, gh, tsBuf), nil
}

// ConstructTxID — §9.6: TxID = H(sender || receiver || amount || nonce || ts)
func ConstructTxID(sender, receiver string, amount uint64, nonceHex string, ts int64) (string, error) {
	amtBuf := make([]byte, 32)
	binary.BigEndian.PutUint64(amtBuf[24:], amount)
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce: %w", err)
	}
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts))
	return SHA256([]byte(sender), []byte(receiver), amtBuf, nonce, tsBuf), nil
}

// ConstructOverrideHash — §5.10
func ConstructOverrideHash(overrideID, authority, action string, ts int64) string {
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts))
	return SHA256([]byte(overrideID), []byte(authority), []byte(action), tsBuf)
}
