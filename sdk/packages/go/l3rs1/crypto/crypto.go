// Package crypto implements L3RS-1 cryptographic primitives per §10.3 and §13.10-11.
// Pure stdlib — no external dependencies.
package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
)

// ─── Core Hash Function ───────────────────────────────────────────────────────

// SHA256 computes H(data) per §10.3. Returns lowercase hex string.
func SHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SHA256Concat hashes the concatenation of all parts.
func SHA256Concat(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ─── §13.11 Canonical Serialization ─────────────────────────────────────────

// Canonicalize produces canonical JSON per §13.11:
// no whitespace, stable key ordering, UTF-8.
func Canonicalize(v any) ([]byte, error) {
	// Marshal then re-sort keys recursively
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize marshal: %w", err)
	}
	var obj any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("canonicalize unmarshal: %w", err)
	}
	return marshalCanonical(obj)
}

func marshalCanonical(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := []byte{'{'}
		for i, k := range keys {
			keyBytes, _ := json.Marshal(k)
			valBytes, err := marshalCanonical(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, keyBytes...)
			buf = append(buf, ':')
			buf = append(buf, valBytes...)
			if i < len(keys)-1 {
				buf = append(buf, ',')
			}
		}
		return append(buf, '}'), nil
	case []any:
		buf := []byte{'['}
		for i, item := range val {
			b, err := marshalCanonical(item)
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
			if i < len(val)-1 {
				buf = append(buf, ',')
			}
		}
		return append(buf, ']'), nil
	default:
		return json.Marshal(v)
	}
}

// HashObject computes HY = H(ser(Y)).
func HashObject(v any) (string, error) {
	b, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	return SHA256(b), nil
}

// ─── §2.2 Asset_ID ───────────────────────────────────────────────────────────

// ConstructAssetID computes I = H(pk_issuer || ts || nonce) per §2.2.
func ConstructAssetID(issuerPubkeyHex string, timestampUnix int64, nonceHex string) (string, error) {
	pk, err := hex.DecodeString(issuerPubkeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid issuer pubkey: %w", err)
	}
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestampUnix))
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce: %w", err)
	}
	return SHA256Concat(pk, ts, nonce), nil
}

// ─── §3.4 Identity Hash ──────────────────────────────────────────────────────

// ConstructIdentityHash computes HID = H(PII || salt || domain) per §3.4.
func ConstructIdentityHash(piiUTF8, saltHex, domain string) (string, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", fmt.Errorf("invalid salt: %w", err)
	}
	return SHA256Concat([]byte(piiUTF8), salt, []byte(domain)), nil
}

// ─── §8.3 Cross-Chain Certificate Identifier ─────────────────────────────────

// ConstructCID computes CID = H(I || SH || CH || GH || t) per §8.3.
func ConstructCID(assetID, stateHash, complianceHash, governanceHash string, timestampUnix int64) (string, error) {
	decode := func(s string) ([]byte, error) { return hex.DecodeString(s) }
	id, err := decode(assetID)
	if err != nil {
		return "", fmt.Errorf("invalid assetID: %w", err)
	}
	sh, err := decode(stateHash)
	if err != nil {
		return "", fmt.Errorf("invalid stateHash: %w", err)
	}
	ch, err := decode(complianceHash)
	if err != nil {
		return "", fmt.Errorf("invalid complianceHash: %w", err)
	}
	gh, err := decode(governanceHash)
	if err != nil {
		return "", fmt.Errorf("invalid governanceHash: %w", err)
	}
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestampUnix))
	return SHA256Concat(id, sh, ch, gh, ts), nil
}

// ─── §9.6 Transaction ID ─────────────────────────────────────────────────────

// ConstructTxID computes TxID = H(sender || receiver || amount || nonce || timestamp) per §9.6.
func ConstructTxID(sender, receiver string, amount *big.Int, nonceHex string, timestampUnix int64) (string, error) {
	amountBuf := make([]byte, 32)
	amount.FillBytes(amountBuf) // 256-bit big-endian
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce: %w", err)
	}
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestampUnix))
	return SHA256Concat([]byte(sender), []byte(receiver), amountBuf, nonce, ts), nil
}

// ─── §5.10 Override Record ───────────────────────────────────────────────────

// ConstructOverrideHash computes Override_Record = H(OID || AUTH || ACTION || TS) per §5.10.
func ConstructOverrideHash(overrideID, authority, action string, timestampUnix int64) string {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestampUnix))
	return SHA256Concat([]byte(overrideID), []byte(authority), []byte(action), ts)
}

// ─── §8.11 Chain ID ──────────────────────────────────────────────────────────

// ConstructChainID computes ChainID = H(chain_name || network_type || genesis_hash) per §8.11.
func ConstructChainID(chainName, networkType, genesisHashHex string) (string, error) {
	genesis, err := hex.DecodeString(genesisHashHex)
	if err != nil {
		return "", fmt.Errorf("invalid genesis hash: %w", err)
	}
	return SHA256Concat([]byte(chainName), []byte(networkType), genesis), nil
}

// ─── Signature Verifier Interface ────────────────────────────────────────────

// SignatureVerifier is the abstract interface for EdDSA/ECDSA verification per §10.3.
type SignatureVerifier interface {
	Verify(message []byte, signatureHex, publicKeyHex string) (bool, error)
}
