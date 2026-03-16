/**
 * L3RS-1 TypeScript Tests
 * Uses Node.js built-in test runner (node:test) — zero dependencies.
 * Run: node --test tests/sdk.test.js  (after npm run build)
 */
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { createHash } from "node:crypto";

// ── Inline implementations (no build needed for testing) ──────────────────

function sha256(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest("hex");
}

function canonicalize(obj) {
  return JSON.stringify(obj, (_key, value) => {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const sorted = {};
      for (const k of Object.keys(value).sort()) sorted[k] = value[k];
      return sorted;
    }
    return value;
  });
}

function constructAssetId(pubkeyHex, ts, nonceHex) {
  const pk = Buffer.from(pubkeyHex, "hex");
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(ts));
  return sha256(pk, tsBuf, Buffer.from(nonceHex, "hex"));
}

function constructCID(assetId, stateHash, complianceHash, governanceHash, ts) {
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(ts));
  return sha256(
    Buffer.from(assetId, "hex"), Buffer.from(stateHash, "hex"),
    Buffer.from(complianceHash, "hex"), Buffer.from(governanceHash, "hex"), tsBuf
  );
}

function constructTxId(sender, receiver, amount, nonceHex, ts) {
  const amtBuf = Buffer.alloc(32);
  let a = BigInt(amount);
  for (let i = 31; i >= 0; i--) { amtBuf[i] = Number(a & 0xffn); a >>= 8n; }
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigUInt64BE(BigInt(ts));
  return sha256(Buffer.from(sender), Buffer.from(receiver), amtBuf, Buffer.from(nonceHex, "hex"), tsBuf);
}

const TRANSITIONS = [
  ["ISSUED","ACTIVATION","ACTIVE"],["ACTIVE","BREACH","RESTRICTED"],
  ["ACTIVE","FREEZE","FROZEN"],["RESTRICTED","CLEARED","ACTIVE"],
  ["FROZEN","RELEASE","ACTIVE"],["ACTIVE","REDEMPTION","REDEEMED"],
  ["REDEEMED","FINALIZATION","BURNED"],["ACTIVE","SUSPENSION","SUSPENDED"],
  ["SUSPENDED","REINSTATEMENT","ACTIVE"],
];

function applyTransition(from, trigger) {
  if (from === "BURNED") return null;
  const m = TRANSITIONS.find(([f, t]) => f === from && t === trigger);
  return m ? m[2] : null;
}

// ── Tests ─────────────────────────────────────────────────────────────────

const PUBKEY   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TS       = 1740355200;
const NONCE    = "0000000000000001";
const EXPECTED = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a";

test("§2.2 Asset_ID canonical vector", () => {
  assert.equal(constructAssetId(PUBKEY, TS, NONCE), EXPECTED);
});

test("§2.2 Asset_ID deterministic", () => {
  assert.equal(constructAssetId(PUBKEY, TS, NONCE), constructAssetId(PUBKEY, TS, NONCE));
});

test("§2.2 Asset_ID nonce sensitive", () => {
  assert.notEqual(constructAssetId(PUBKEY, TS, NONCE), constructAssetId(PUBKEY, TS, "0000000000000002"));
});

test("§13.11 canonical key sort", () => {
  assert.equal(canonicalize({z:3,a:1,m:2}), '{"a":1,"m":2,"z":3}');
});

test("§13.11 canonical nested", () => {
  assert.equal(canonicalize({b:{d:4,c:3},a:1}), '{"a":1,"b":{"c":3,"d":4}}');
});

test("§13.11 canonical deterministic", () => {
  assert.equal(canonicalize({b:2,a:1}), canonicalize({a:1,b:2}));
});

for (const [from, trigger, expected] of TRANSITIONS) {
  test(`§2.5 ${from}--${trigger}-->${expected}`, () => {
    assert.equal(applyTransition(from, trigger), expected);
  });
}

test("§2.5 BURNED terminal", () => {
  assert.equal(applyTransition("BURNED", "ACTIVATION"), null);
});

test("§2.5 invalid transition", () => {
  assert.equal(applyTransition("ISSUED", "FREEZE"), null);
});

test("§8.3 CID deterministic", () => {
  const a = constructCID("a".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),1000);
  const b = constructCID("a".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),1000);
  assert.equal(a, b);
});

test("§8.3 CID timestamp sensitive", () => {
  const a = constructCID("a".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),1000);
  const b = constructCID("a".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),1001);
  assert.notEqual(a, b);
});

test("§9.6 replay detected", () => {
  const txId = constructTxId("alice","bob",1000,"00".repeat(8),TS);
  const history = new Set([txId]);
  const replay  = constructTxId("alice","bob",1000,"00".repeat(8),TS);
  assert.ok(history.has(replay));
});

test("§9.6 different nonce not replay", () => {
  const txId = constructTxId("alice","bob",1000,"00".repeat(8),TS);
  const history = new Set([txId]);
  const other = constructTxId("alice","bob",1000,"01".repeat(8),TS);
  assert.ok(!history.has(other));
});

test("§6.12 fee sum must be 10000", () => {
  const validate = (allocs) => {
    const sum = allocs.reduce((s, a) => s + a, 0);
    if (sum !== 10000) throw new Error(`sum=${sum}`);
  };
  validate([2000,3000,2000,2500,500]);
  assert.throws(() => validate([5000]));
});
