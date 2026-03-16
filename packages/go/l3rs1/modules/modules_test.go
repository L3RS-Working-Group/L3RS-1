package modules_test

import (
	"testing"

	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/crypto"
	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/modules"
	"github.com/L3RS-Foundation/L3RS-1/packages/go/l3rs1/types"
)

const (
	testPubkey  = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	testTS      = int64(1740355200)
	testNonce   = "0000000000000001"
	expectedID  = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a"
)

func TestAssetIDVector(t *testing.T) {
	id, err := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
	if err != nil { t.Fatal(err) }
	if id != expectedID { t.Errorf("got %s want %s", id, expectedID) }
}

func TestAssetIDDeterministic(t *testing.T) {
	a, _ := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
	b, _ := crypto.ConstructAssetID(testPubkey, testTS, testNonce)
	if a != b { t.Error("not deterministic") }
}

func TestCanonicalize(t *testing.T) {
	b, err := crypto.Canonicalize(map[string]any{"z": 3, "a": 1, "m": 2})
	if err != nil { t.Fatal(err) }
	if string(b) != `{"a":1,"m":2,"z":3}` { t.Errorf("got %s", b) }
}

func TestStateTransitions(t *testing.T) {
	cases := [][2]string{
		{"ISSUED", "ACTIVATION"}, {"ACTIVE", "BREACH"}, {"ACTIVE", "FREEZE"},
		{"RESTRICTED", "CLEARED"}, {"FROZEN", "RELEASE"}, {"ACTIVE", "REDEMPTION"},
		{"REDEEMED", "FINALIZATION"}, {"ACTIVE", "SUSPENSION"}, {"SUSPENDED", "REINSTATEMENT"},
	}
	expected := []string{
		"ACTIVE","RESTRICTED","FROZEN","ACTIVE","ACTIVE",
		"REDEEMED","BURNED","SUSPENDED","ACTIVE",
	}
	for i, c := range cases {
		r := modules.ApplyStateTransition(types.AssetState(c[0]), c[1])
		if !r.Success { t.Errorf("case %d failed: %s", i, r.Error) }
		if string(r.NewState) != expected[i] {
			t.Errorf("case %d: got %s want %s", i, r.NewState, expected[i])
		}
	}
}

func TestBurnedTerminal(t *testing.T) {
	r := modules.ApplyStateTransition(types.AssetStateBurned, "ACTIVATION")
	if r.Success { t.Error("BURNED should be terminal") }
}

func TestInvalidTransition(t *testing.T) {
	r := modules.ApplyStateTransition(types.AssetStateIssued, "FREEZE")
	if r.Success { t.Error("ISSUED->FREEZE should fail") }
}

func TestCIDDeterministic(t *testing.T) {
	fill := func(c string) string { return c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c + c }
	a, _ := crypto.ConstructCID(fill("a"), fill("b"), fill("c"), fill("d"), 1000)
	b, _ := crypto.ConstructCID(fill("a"), fill("b"), fill("c"), fill("d"), 1000)
	if a != b { t.Error("CID not deterministic") }
}

func TestCIDTimestampSensitive(t *testing.T) {
	fill := func(c string) string {
		s := ""
		for i := 0; i < 64; i++ { s += c }
		return s
	}
	a, _ := crypto.ConstructCID(fill("a"), fill("b"), fill("c"), fill("d"), 1000)
	b, _ := crypto.ConstructCID(fill("a"), fill("b"), fill("c"), fill("d"), 1001)
	if a == b { t.Error("CID should differ for different timestamps") }
}

func TestFeeValidation(t *testing.T) {
	valid := &types.FeeModule{
		BaseRateBasisPoints: 100,
		Allocations: []types.FeeAllocation{
			{Recipient: "a", BasisPoints: 2000},
			{Recipient: "b", BasisPoints: 3000},
			{Recipient: "c", BasisPoints: 2000},
			{Recipient: "d", BasisPoints: 2500},
			{Recipient: "e", BasisPoints: 500},
		},
	}
	if err := modules.ValidateFeeModule(valid); err != nil {
		t.Errorf("valid fee rejected: %v", err)
	}
	invalid := &types.FeeModule{
		Allocations: []types.FeeAllocation{{Recipient: "x", BasisPoints: 5000}},
	}
	if err := modules.ValidateFeeModule(invalid); err == nil {
		t.Error("partial allocation should be rejected")
	}
}

func TestIdentityStatus(t *testing.T) {
	now := int64(1740355200)
	valid   := &types.IdentityRecord{Expiry: 9999999999, Revoked: false}
	expired := &types.IdentityRecord{Expiry: 1000000000, Revoked: false}
	revoked := &types.IdentityRecord{Expiry: 9999999999, Revoked: true}
	if modules.IdentityStatus(valid, now)   != types.IdentityStatusValid   { t.Error("should be VALID") }
	if modules.IdentityStatus(expired, now) != types.IdentityStatusExpired { t.Error("should be EXPIRED") }
	if modules.IdentityStatus(revoked, now) != types.IdentityStatusRevoked { t.Error("should be REVOKED") }
}

func TestReplayProtection(t *testing.T) {
	ev := &types.TransferEvent{Sender: "alice", Receiver: "bob", Amount: 1000,
		Nonce: "0000000000000001", Timestamp: testTS}
	txID, _ := crypto.ConstructTxID(ev.Sender, ev.Receiver, ev.Amount, ev.Nonce, ev.Timestamp)
	history := map[string]bool{txID: true}

	replay, _ := modules.IsReplay(ev, history)
	if !replay { t.Error("should be replay") }

	ev2 := &types.TransferEvent{Sender: "alice", Receiver: "bob", Amount: 1000,
		Nonce: "0000000000000002", Timestamp: testTS}
	notReplay, _ := modules.IsReplay(ev2, history)
	if notReplay { t.Error("different nonce should not be replay") }
}
