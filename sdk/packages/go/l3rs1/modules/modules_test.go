package modules_test

import (
	"math/big"
	"testing"

	"github.com/L3RS-Working-Group/L3RS-1/sdk/go/l3rs1/crypto"
	"github.com/L3RS-Working-Group/L3RS-1/sdk/go/l3rs1/modules"
	"github.com/L3RS-Working-Group/L3RS-1/sdk/go/l3rs1/types"
)

// ══════════════════════════════════════════════════════════════════════════════
// §13.11 Canonical Serialization
// ══════════════════════════════════════════════════════════════════════════════

func TestCanonicalSerialization(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"keys sorted alphabetically", map[string]any{"z": 3, "a": 1, "m": 2}, `{"a":1,"m":2,"z":3}`},
		{"no whitespace", map[string]any{"key": "value"}, `{"key":"value"}`},
		{"nested keys sorted", map[string]any{"b": map[string]any{"d": 4, "c": 3}, "a": 1}, `{"a":1,"b":{"c":3,"d":4}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := crypto.Canonicalize(tt.input)
			if err != nil {
				t.Fatalf("Canonicalize error: %v", err)
			}
			if string(got) != tt.expected {
				t.Errorf("got %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestCanonicalizeDeterminism(t *testing.T) {
	obj := map[string]any{"jurisdiction": "US", "assetId": "abc", "state": "ACTIVE"}
	a, _ := crypto.Canonicalize(obj)
	b, _ := crypto.Canonicalize(obj)
	if string(a) != string(b) {
		t.Error("Canonicalize is not deterministic")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// §2.2 Asset_ID Construction
// ══════════════════════════════════════════════════════════════════════════════

const (
	testPubkey   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	testTS       = int64(1740355200)
	testNonce    = "0000000000000001"
	expectedAssetId = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a"
)

func TestAssetIDConstruction(t *testing.T) {
	t.Run("matches canonical test vector", func(t *testing.T) {
		got, err := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got != expectedAssetId {
			t.Errorf("got %s, want %s", got, expectedAssetId)
		}
	})

	t.Run("output is 64 hex chars", func(t *testing.T) {
		got, _ := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
		if len(got) != 64 {
			t.Errorf("length %d, want 64", len(got))
		}
	})

	t.Run("is deterministic", func(t *testing.T) {
		a, _ := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
		b, _ := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
		if a != b {
			t.Error("not deterministic")
		}
	})

	t.Run("different nonce produces different ID", func(t *testing.T) {
		a, _ := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
		b, _ := crypto.ConstructAssetID(testPubkey, testTS, "0000000000000002")
		if a == b {
			t.Error("different nonce should produce different ID")
		}
	})
}

// ══════════════════════════════════════════════════════════════════════════════
// §2.5 State Transition Matrix
// ══════════════════════════════════════════════════════════════════════════════

func TestStateTransitions(t *testing.T) {
	validTransitions := []struct {
		from    types.AssetState
		trigger string
		to      types.AssetState
	}{
		{types.AssetStateIssued,     "ACTIVATION",    types.AssetStateActive},
		{types.AssetStateActive,     "BREACH",        types.AssetStateRestricted},
		{types.AssetStateActive,     "FREEZE",        types.AssetStateFrozen},
		{types.AssetStateRestricted, "CLEARED",       types.AssetStateActive},
		{types.AssetStateFrozen,     "RELEASE",       types.AssetStateActive},
		{types.AssetStateActive,     "REDEMPTION",    types.AssetStateRedeemed},
		{types.AssetStateRedeemed,   "FINALIZATION",  types.AssetStateBurned},
		{types.AssetStateActive,     "SUSPENSION",    types.AssetStateSuspended},
		{types.AssetStateSuspended,  "REINSTATEMENT", types.AssetStateActive},
	}

	for _, tt := range validTransitions {
		t.Run(string(tt.from)+"--"+tt.trigger+"-->"+string(tt.to), func(t *testing.T) {
			got, err := modules.ApplyStateTransition(tt.from, tt.trigger)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.to {
				t.Errorf("got %s, want %s", got, tt.to)
			}
		})
	}

	t.Run("BURNED is terminal", func(t *testing.T) {
		_, err := modules.ApplyStateTransition(types.AssetStateBurned, "ACTIVATION")
		if err == nil {
			t.Error("expected error for terminal state")
		}
	})

	t.Run("invalid transition is rejected", func(t *testing.T) {
		_, err := modules.ApplyStateTransition(types.AssetStateIssued, "FREEZE")
		if err == nil {
			t.Error("expected error for invalid transition")
		}
	})
}

// ══════════════════════════════════════════════════════════════════════════════
// §8.3 Cross-Chain CID
// ══════════════════════════════════════════════════════════════════════════════

func TestCrossChainCID(t *testing.T) {
	a, b, c, d := "aa" + "aa"[0:0], "bb", "cc", "dd" // placeholders
	_ = a; _ = b; _ = c; _ = d

	fill := func(ch byte) string {
		s := make([]byte, 64)
		for i := range s { s[i] = ch }
		return string(s)
	}
	A, B, C, D := fill('a'), fill('b'), fill('c'), fill('d')

	cid1, err := crypto.ConstructCID(A, B, C, D, 1000)
	if err != nil {
		t.Fatalf("ConstructCID error: %v", err)
	}

	t.Run("CID is 64 hex chars", func(t *testing.T) {
		if len(cid1) != 64 {
			t.Errorf("length %d, want 64", len(cid1))
		}
	})

	t.Run("CID is deterministic", func(t *testing.T) {
		cid2, _ := crypto.ConstructCID(A, B, C, D, 1000)
		if cid1 != cid2 {
			t.Error("not deterministic")
		}
	})

	t.Run("CID changes when stateHash changes (I₁₁)", func(t *testing.T) {
		cid2, _ := crypto.ConstructCID(A, fill('e'), C, D, 1000)
		if cid1 == cid2 {
			t.Error("CID should change when stateHash changes")
		}
	})

	t.Run("CID changes when timestamp changes (I₁₁)", func(t *testing.T) {
		cid2, _ := crypto.ConstructCID(A, B, C, D, 1001)
		if cid1 == cid2 {
			t.Error("CID should change when timestamp changes")
		}
	})
}

// ══════════════════════════════════════════════════════════════════════════════
// §9.6 TxID Replay Protection
// ══════════════════════════════════════════════════════════════════════════════

func TestTxIDAndReplay(t *testing.T) {
	sender, receiver := "alice", "bob"
	amount := big.NewInt(1000)
	nonce := "0000000000000001"
	ts := int64(1740355200)

	txid1, err := crypto.ConstructTxID(sender, receiver, amount, nonce, ts)
	if err != nil {
		t.Fatalf("ConstructTxID error: %v", err)
	}

	t.Run("TxID is 64 hex chars", func(t *testing.T) {
		if len(txid1) != 64 {
			t.Errorf("length %d, want 64", len(txid1))
		}
	})

	t.Run("TxID is deterministic", func(t *testing.T) {
		txid2, _ := crypto.ConstructTxID(sender, receiver, amount, nonce, ts)
		if txid1 != txid2 {
			t.Error("not deterministic")
		}
	})

	t.Run("same event is a replay", func(t *testing.T) {
		ev := &types.TransferEvent{Sender: sender, Receiver: receiver, Amount: amount, Nonce: nonce, Timestamp: ts}
		history := map[string]bool{txid1: true}
		replay, err := modules.IsReplay(ev, history)
		if err != nil {
			t.Fatalf("IsReplay error: %v", err)
		}
		if !replay {
			t.Error("same event should be detected as replay")
		}
	})

	t.Run("different nonce is not a replay", func(t *testing.T) {
		ev := &types.TransferEvent{Sender: sender, Receiver: receiver, Amount: amount, Nonce: "0000000000000002", Timestamp: ts}
		history := map[string]bool{txid1: true}
		replay, _ := modules.IsReplay(ev, history)
		if replay {
			t.Error("different nonce should not be a replay")
		}
	})
}

// ══════════════════════════════════════════════════════════════════════════════
// §6.12 Fee Validation
// ══════════════════════════════════════════════════════════════════════════════

func TestFeeValidation(t *testing.T) {
	t.Run("valid 5-way split", func(t *testing.T) {
		fm := &types.FeeModule{
			BaseRateBasisPoints: 100,
			Allocations: []types.FeeAllocation{
				{Recipient: "sovereign",  BasisPoints: 2000},
				{Recipient: "validator",  BasisPoints: 3000},
				{Recipient: "storage",    BasisPoints: 2000},
				{Recipient: "operator",   BasisPoints: 2500},
				{Recipient: "bridge",     BasisPoints: 500},
			},
		}
		if err := modules.ValidateFeeModule(fm); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("partial allocation rejected", func(t *testing.T) {
		fm := &types.FeeModule{
			BaseRateBasisPoints: 100,
			Allocations: []types.FeeAllocation{{Recipient: "only", BasisPoints: 5000}},
		}
		if err := modules.ValidateFeeModule(fm); err == nil {
			t.Error("expected error for partial allocation")
		}
	})

	t.Run("over-allocation rejected", func(t *testing.T) {
		fm := &types.FeeModule{
			BaseRateBasisPoints: 100,
			Allocations: []types.FeeAllocation{
				{Recipient: "a", BasisPoints: 6000},
				{Recipient: "b", BasisPoints: 5000},
			},
		}
		if err := modules.ValidateFeeModule(fm); err == nil {
			t.Error("expected error for over-allocation")
		}
	})
}
