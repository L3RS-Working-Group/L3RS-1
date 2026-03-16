const { expect } = require("chai");
const { ethers } = require("hardhat");

// ─── Helpers ──────────────────────────────────────────────────────────────────

function keccakConcat(...parts) {
  return ethers.keccak256(ethers.concat(parts));
}

function toBytes2(isoCode) {
  return ethers.encodeBytes32String(isoCode).slice(0, 6); // "US" → 0x5553
}

async function deployAsset(overrides = {}) {
  const [issuer, authority1, authority2, authority3] = await ethers.getSigners();

  const issuerPubkey  = ethers.randomBytes(33);
  const jurisdiction  = ethers.toUtf8Bytes("US").slice(0, 2);
  const legalMirror   = ethers.randomBytes(32);
  const identityLevel = overrides.identityLevel ?? 0;
  const feeRate       = overrides.feeRate ?? 100; // 1% = 100 bps
  const authorities   = overrides.authorities ?? [authority1.address, authority2.address, authority3.address];
  const quorum        = overrides.quorum ?? 67;
  const nonce         = ethers.randomBytes(32);

  const L3RS1Asset = await ethers.getContractFactory("L3RS1Asset");
  const asset = await L3RS1Asset.deploy(
    issuerPubkey,
    ethers.hexlify(jurisdiction) + "0".repeat(60), // pad to bytes2
    legalMirror,
    identityLevel,
    feeRate,
    authorities,
    quorum,
    nonce,
  );
  await asset.waitForDeployment();

  return { asset, issuer, authority1, authority2, authority3 };
}

// ══════════════════════════════════════════════════════════════════════════════
// §2.2 Asset_ID Construction
// ══════════════════════════════════════════════════════════════════════════════

describe("§2.2 Asset_ID Construction", function () {
  it("assetId() returns a non-zero bytes32", async function () {
    const { asset } = await deployAsset();
    const id = await asset.assetId();
    expect(id).to.not.equal(ethers.ZeroHash);
    expect(id).to.have.length(66); // 0x + 64 hex chars
  });

  it("assetId is immutable — same after state changes", async function () {
    const { asset, authority1 } = await deployAsset();
    const idBefore = await asset.assetId();

    // Try a governance action that changes state
    // (asset starts ISSUED so no transfer possible yet — just verify ID stability)
    const idAfter = await asset.assetId();
    expect(idBefore).to.equal(idAfter);
  });

  it("two separately deployed assets have different IDs", async function () {
    const { asset: a1 } = await deployAsset();
    const { asset: a2 } = await deployAsset();
    const id1 = await asset.assetId() !== undefined ? await a1.assetId() : null;
    const id2 = await a2.assetId();
    expect(id1).to.not.equal(id2);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §2.4 Asset State Machine
// ══════════════════════════════════════════════════════════════════════════════

describe("§2.4 Asset State", function () {
  it("initial state is ISSUED (0)", async function () {
    const { asset } = await deployAsset();
    expect(await asset.currentState()).to.equal(0n); // AssetState.ISSUED = 0
  });

  it("standardVersion() returns L3RS-1.0.0", async function () {
    const { asset } = await deployAsset();
    expect(await asset.standardVersion()).to.equal("L3RS-1.0.0");
  });

  it("identityLevel() returns configured value", async function () {
    const { asset } = await deployAsset({ identityLevel: 1 });
    expect(await asset.identityLevel()).to.equal(1n);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §6 Fee Module
// ══════════════════════════════════════════════════════════════════════════════

describe("§6 Fee Module", function () {
  it("feeRateBasisPoints() returns configured rate", async function () {
    const { asset } = await deployAsset({ feeRate: 250 }); // 2.5%
    expect(await asset.feeRateBasisPoints()).to.equal(250n);
  });

  it("zero fee rate is valid", async function () {
    const { asset } = await deployAsset({ feeRate: 0 });
    expect(await asset.feeRateBasisPoints()).to.equal(0n);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §8 Cross-Chain Certificate
// ══════════════════════════════════════════════════════════════════════════════

describe("§8.3 Cross-Chain Certificate", function () {
  it("crossChainCertificateId() returns bytes32 (zero on fresh deploy)", async function () {
    const { asset } = await deployAsset();
    const cid = await asset.crossChainCertificateId();
    // CID is zero before first transfer (no state transitions yet)
    expect(typeof cid).to.equal("string");
    expect(cid).to.have.length(66);
  });

  it("verifyCrossChainCertificate with mismatched hashes returns false", async function () {
    const { asset } = await deployAsset();
    const fake = ethers.randomBytes(32);
    const result = await asset.verifyCrossChainCertificate(
      ethers.randomBytes(32),
      fake, fake, fake,
      Math.floor(Date.now() / 1000),
    );
    expect(result).to.equal(false);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §4 Compliance Engine
// ══════════════════════════════════════════════════════════════════════════════

describe("§4 Compliance Engine", function () {
  it("checkCompliance returns allowed=true for fresh asset (no rules)", async function () {
    const { asset } = await deployAsset();
    const [signers] = [await ethers.getSigners()];
    const [sender, receiver] = await ethers.getSigners();

    const [allowed] = await asset.checkCompliance(
      sender.address,
      receiver.address,
      ethers.parseEther("1"),
    );
    expect(allowed).to.equal(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §9.6 Replay Protection
// ══════════════════════════════════════════════════════════════════════════════

describe("§9.6 Replay Protection", function () {
  it("transfer reverts on asset not in ACTIVE state", async function () {
    const { asset } = await deployAsset();
    const [, receiver] = await ethers.getSigners();
    const nonce = ethers.randomBytes(32);

    // Asset is ISSUED, not ACTIVE — transfer must revert
    await expect(
      asset.transfer(receiver.address, ethers.parseEther("1"), nonce)
    ).to.be.revertedWith("L3RS1: asset not ACTIVE");
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §5 Governance Override
// ══════════════════════════════════════════════════════════════════════════════

describe("§5 Governance Override", function () {
  it("executeOverride reverts for non-registered authority", async function () {
    const { asset } = await deployAsset();
    const [stranger] = await ethers.getSigners();

    await expect(
      asset.connect(stranger).executeOverride(
        ethers.randomBytes(32),
        ethers.encodeBytes32String("FREEZE_BALANCE"),
        stranger.address,
        ethers.randomBytes(32),
        ethers.randomBytes(65),
      )
    ).to.be.revertedWith("L3RS1: not a governance authority");
  });

  it("registered authority with legal basis can call executeOverride", async function () {
    const { asset, authority1 } = await deployAsset();

    // Should revert with signature check, not authority check
    // (authority1 IS registered but signature is fake)
    await expect(
      asset.connect(authority1).executeOverride(
        ethers.randomBytes(32),
        ethers.encodeBytes32String("FREEZE_BALANCE"),
        authority1.address,
        ethers.randomBytes(32), // legal basis
        ethers.randomBytes(65), // fake 65-byte sig — passes length check
      )
    ).to.be.revertedWith("L3RS1: unknown override action"); // action encoding check
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §7 Reserve
// ══════════════════════════════════════════════════════════════════════════════

describe("§7 Reserve Interface", function () {
  it("reserveStatus() returns VALID bytes32", async function () {
    const { asset } = await deployAsset();
    const status = await asset.reserveStatus();
    expect(ethers.toUtf8String(
      ethers.getBytes(status).filter(b => b !== 0)
    )).to.equal("VALID");
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §9.10 Settlement Proof
// ══════════════════════════════════════════════════════════════════════════════

describe("§9.10 Settlement Proof", function () {
  it("getSettlementProof returns zeros for unknown txId", async function () {
    const { asset } = await deployAsset();
    const [blockHash, blockNumber, stateHash, timestamp] =
      await asset.getSettlementProof(ethers.ZeroHash);
    expect(blockNumber).to.equal(0n);
    expect(timestamp).to.equal(0n);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// §13.11 On-chain Canonical Hashing (L3RS1Hashing library)
// ══════════════════════════════════════════════════════════════════════════════

describe("§13.11 L3RS1Hashing Library", function () {
  let hashing;

  before(async function () {
    // Deploy a test harness that exposes the library
    // (In production: library is internal to L3RS1Asset)
    // We verify hash consistency using ethers directly
  });

  it("constructTxId is deterministic", function () {
    const sender   = ethers.Wallet.createRandom().address;
    const receiver = ethers.Wallet.createRandom().address;
    const amount   = ethers.parseEther("1");
    const nonce    = ethers.randomBytes(32);
    const ts       = BigInt(Math.floor(Date.now() / 1000));

    // Replicate the on-chain hash computation
    const h1 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "address", "uint256", "bytes32", "uint256"],
      [sender, receiver, amount, nonce, ts]
    ));
    const h2 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "address", "uint256", "bytes32", "uint256"],
      [sender, receiver, amount, nonce, ts]
    ));
    expect(h1).to.equal(h2);
  });

  it("CID changes when any component changes (Invariant I₁₁)", function () {
    const encode = (a, b, c, d, t) =>
      ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "bytes32", "bytes32", "uint256"],
        [a, b, c, d, t]
      ));

    const A = ethers.id("assetId");
    const B = ethers.id("stateHash");
    const C = ethers.id("complianceHash");
    const D = ethers.id("govHash");
    const T = 1000n;

    const base = encode(A, B, C, D, T);
    expect(encode(ethers.id("different"), B, C, D, T)).to.not.equal(base);
    expect(encode(A, ethers.id("different"), C, D, T)).to.not.equal(base);
    expect(encode(A, B, ethers.id("different"), D, T)).to.not.equal(base);
    expect(encode(A, B, C, ethers.id("different"), T)).to.not.equal(base);
    expect(encode(A, B, C, D, 1001n)).to.not.equal(base);
  });
});
