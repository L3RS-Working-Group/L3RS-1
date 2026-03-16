const { expect }  = require("chai");
const { ethers }  = require("hardhat");

describe("L3RS1Asset", function () {

  async function deploy() {
    const [owner, user1, user2, auth1, auth2, auth3] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("L3RS1Asset");
    const asset   = await Factory.deploy(
      ethers.randomBytes(33),  // issuerPubkey
      100,                     // 1% fee in bps
      [auth1.address, auth2.address, auth3.address],
      2,                       // quorum
      ethers.randomBytes(32),  // nonce
    );
    await asset.waitForDeployment();
    return { asset, owner, user1, user2 };
  }

  // ── §2.2 Asset_ID ───────────────────────────────────────────────────────────

  it("assetId() returns non-zero bytes32", async function () {
    const { asset } = await deploy();
    expect(await asset.assetId()).to.not.equal(ethers.ZeroHash);
  });

  it("two deployments produce different assetIds", async function () {
    const { asset: a1 } = await deploy();
    const { asset: a2 } = await deploy();
    expect(await a1.assetId()).to.not.equal(await a2.assetId());
  });

  // ── §2.4 State ──────────────────────────────────────────────────────────────

  it("initial state is ISSUED (0)", async function () {
    const { asset } = await deploy();
    expect(await asset.currentState()).to.equal(0n);
  });

  it("activate() transitions to ACTIVE (1)", async function () {
    const { asset } = await deploy();
    await asset.activate();
    expect(await asset.currentState()).to.equal(1n);
  });

  it("standardVersion() returns L3RS-1.0.0", async function () {
    const { asset } = await deploy();
    expect(await asset.standardVersion()).to.equal("L3RS-1.0.0");
  });

  // ── §6 Fees ─────────────────────────────────────────────────────────────────

  it("feeRateBasisPoints() returns configured value", async function () {
    const { asset } = await deploy();
    expect(await asset.feeRateBasisPoints()).to.equal(100n);
  });

  // ── §9.6 Transfer & Replay ───────────────────────────────────────────────────

  it("transfer reverts when not ACTIVE", async function () {
    const { asset, user1, user2 } = await deploy();
    await expect(
      asset.transfer(user2.address, 100n, ethers.randomBytes(32))
    ).to.be.revertedWith("L3RS1: not ACTIVE");
  });

  it("transfer succeeds when ACTIVE and emits event", async function () {
    const { asset, owner, user1, user2 } = await deploy();
    await asset.activate();
    await asset.mint(owner.address, 1000n);

    const nonce = ethers.randomBytes(32);
    await expect(asset.transfer(user2.address, 100n, nonce))
      .to.emit(asset, "Transfer");
  });

  it("replay is rejected", async function () {
    const { asset, owner, user2 } = await deploy();
    await asset.activate();
    await asset.mint(owner.address, 1000n);

    const nonce = ethers.randomBytes(32);
    await asset.transfer(user2.address, 100n, nonce);
    await expect(
      asset.transfer(user2.address, 100n, nonce)
    ).to.be.revertedWith("L3RS1: replay");
  });

  // ── §4 Compliance ────────────────────────────────────────────────────────────

  it("checkCompliance returns false when not ACTIVE", async function () {
    const { asset, user1, user2 } = await deploy();
    const [allowed] = await asset.checkCompliance(user1.address, user2.address, 100n);
    expect(allowed).to.equal(false);
  });

  it("checkCompliance returns true when ACTIVE", async function () {
    const { asset, user1, user2 } = await deploy();
    await asset.activate();
    const [allowed] = await asset.checkCompliance(user1.address, user2.address, 100n);
    expect(allowed).to.equal(true);
  });

  // ── §8.3 CID ────────────────────────────────────────────────────────────────

  it("crossChainCertificateId() updates after transfer", async function () {
    const { asset, owner, user2 } = await deploy();
    await asset.activate();
    await asset.mint(owner.address, 1000n);
    const cidBefore = await asset.crossChainCertificateId();
    await asset.transfer(user2.address, 100n, ethers.randomBytes(32));
    const cidAfter  = await asset.crossChainCertificateId();
    expect(cidAfter).to.not.equal(cidBefore);
  });

  // ── L3RS1Hashing library ─────────────────────────────────────────────────────

  it("CID changes when inputs change (Invariant I₁₁)", function () {
    const encode = (a, b, c, d, t) =>
      ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32","bytes32","bytes32","bytes32","uint256"], [a,b,c,d,t]
      ));
    const A = ethers.id("assetId"), B = ethers.id("sh"),
          C = ethers.id("ch"),     D = ethers.id("gh"), T = 1000n;
    const base = encode(A,B,C,D,T);
    expect(encode(ethers.id("x"),B,C,D,T)).to.not.equal(base);
    expect(encode(A,B,C,D,1001n)).to.not.equal(base);
  });
});
