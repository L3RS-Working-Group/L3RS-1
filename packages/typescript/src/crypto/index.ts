/**
 * @module crypto
 * @description L3RS-1 cryptographic primitives — §13.10–11, §10.3.
 *
 * Pure TypeScript SHA-256 implementation — zero external dependencies,
 * runs in Node.js, browsers, and edge runtimes without `@types/node`.
 */

// ── Utilities ─────────────────────────────────────────────────────────────────

/** Decode a lowercase hex string to a Uint8Array. */
export function fromHex(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    arr[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return arr;
}

/** Encode a string to UTF-8 bytes without TextEncoder. */
export function fromUtf8(s: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) bytes.push(c);
    else if (c < 0x800) bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  return new Uint8Array(bytes);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function toBigEndian8(n: number): Uint8Array {
  const buf = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) { buf[i] = Number(v & 0xffn); v >>= 8n; }
  return buf;
}

function amountTo32(amount: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let a = amount;
  for (let i = 31; i >= 0; i--) { buf[i] = Number(a & 0xffn); a >>= 8n; }
  return buf;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

// ── SHA-256 (FIPS 180-4) ─────────────────────────────────────────────────────

const K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]);

function rotr(x: number, n: number): number { return (x >>> n) | (x << (32 - n)); }

/** Raw SHA-256 — returns 32-byte Uint8Array. */
export function sha256raw(data: Uint8Array): Uint8Array {
  const msgLen = data.length;
  const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[msgLen] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(paddedLen - 4, (msgLen * 8) & 0xffffffff, false);
  dv.setUint32(paddedLen - 8, Math.floor((msgLen * 8) / 2 ** 32), false);

  let [h0,h1,h2,h3,h4,h5,h6,h7] = [
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
  ];

  for (let i = 0; i < paddedLen; i += 64) {
    const w = new Uint32Array(64);
    for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);
    for (let j = 16; j < 64; j++) {
      const s0 = rotr(w[j-15]!,7) ^ rotr(w[j-15]!,18) ^ (w[j-15]! >>> 3);
      const s1 = rotr(w[j-2]!,17) ^ rotr(w[j-2]!,19)  ^ (w[j-2]!  >>> 10);
      w[j] = (w[j-16]! + s0 + w[j-7]! + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = [h0,h1,h2,h3,h4,h5,h6,h7];
    for (let j = 0; j < 64; j++) {
      const S1  = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch  = (e & f) ^ (~e & g);
      const t1  = (h + S1 + ch + K[j]! + w[j]!) >>> 0;
      const S0  = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2  = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
    h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
  }
  const result = new Uint8Array(32);
  const rv = new DataView(result.buffer);
  [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i) => rv.setUint32(i*4, v, false));
  return result;
}

/**
 * SHA-256 of concatenated parts. Returns lowercase hex.
 * @example sha256(fromHex(pubkey), ts, nonce)
 */
export function sha256(...parts: Uint8Array[]): string {
  return toHex(sha256raw(concat(...parts)));
}

/**
 * §13.11 — Canonical JSON serialization: recursively sorted keys, no whitespace.
 * @example canonicalize({ z: 3, a: 1 }) // → '{"a":1,"z":3}'
 */
export function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, (_key, value: unknown) => {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as object).sort())
        sorted[k] = (value as Record<string, unknown>)[k];
      return sorted;
    }
    return value;
  });
}

/** H(ser(obj)) — hash of canonical JSON representation. */
export function hashObject(obj: unknown): string {
  return sha256(fromUtf8(canonicalize(obj)));
}

/**
 * §2.2 — Asset_ID construction.
 * `I = H(pk_issuer ∥ ts ∥ nonce)`
 * @param pubkeyHex - Compressed public key (hex)
 * @param timestampUnix - Issuance Unix timestamp
 * @param nonceHex - 8-byte nonce (hex)
 */
export function constructAssetId(pubkeyHex: string, timestampUnix: number, nonceHex: string): string {
  return sha256(fromHex(pubkeyHex), toBigEndian8(timestampUnix), fromHex(nonceHex));
}

/**
 * §8.3 — Cross-Chain Certificate Identifier.
 * `CID = H(I ∥ SH ∥ CH ∥ GH ∥ t)`
 */
export function constructCID(
  assetId: string, stateHash: string, complianceHash: string,
  governanceHash: string, timestampUnix: number,
): string {
  return sha256(
    fromHex(assetId), fromHex(stateHash), fromHex(complianceHash),
    fromHex(governanceHash), toBigEndian8(timestampUnix),
  );
}

/**
 * §9.6 — Transaction ID.
 * `TxID = H(sender ∥ receiver ∥ amount ∥ nonce ∥ timestamp)`
 */
export function constructTxId(
  sender: string, receiver: string, amount: bigint,
  nonceHex: string, timestampUnix: number,
): string {
  return sha256(
    fromUtf8(sender), fromUtf8(receiver),
    amountTo32(amount), fromHex(nonceHex), toBigEndian8(timestampUnix),
  );
}

/** §3.4 — Identity hash. `HID = H(PII ∥ salt ∥ domain)` */
export function constructIdentityHash(piiUtf8: string, saltHex: string, domain: string): string {
  return sha256(fromUtf8(piiUtf8), fromHex(saltHex), fromUtf8(domain));
}

/** §5.10 — Override record hash. */
export function constructOverrideHash(
  overrideId: string, authority: string, action: string, timestampUnix: number,
): string {
  return sha256(
    fromUtf8(overrideId), fromUtf8(authority),
    fromUtf8(action), toBigEndian8(timestampUnix),
  );
}

/** Abstract interface for EdDSA/ECDSA signature verification per §10.3. */
export interface SignatureVerifier {
  verify(message: Uint8Array, signatureHex: string, publicKeyHex: string): boolean;
}
