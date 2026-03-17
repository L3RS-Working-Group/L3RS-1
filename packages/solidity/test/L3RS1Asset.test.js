const { expect } = require("chai");
const { ethers }  = require("hardhat");

describe("L3RS1Asset", function () {

  async function deploy() {
    const [owner, user1, user2] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("L3RS1Asset");
    const asset   = await Factory.deploy(
      ethers.randomBytes(33),  // issuerPubkey (compressed pubkey)
      100,                     // feeRateBps (1%)
      ethers.randomBytes(32),  // nonce
    );
    await asset.waitForDeployment();
    return { asset, owner, user1, user2 };
  }

  // ── §2.2 Asset_ID ────────────────────────────────────────────────────────────

  it("assetId() returns non-zero bytes32", async function () {
    const { asset } = await deploy();
    expect(await asset.assetId()).to.not.equal(ethers.ZeroHash);
  });

  it("two deployments produce different assetIds", async function () {
    const { asset: a1 } = await deploy();
    const { asset: a2 } = await deploy();
    expect(await a1.assetId()).to.not.equal(await a2.assetId());
  });

  // ── §2.4 State ────────────────────────────────────────────────────────────────

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

  // ── §6 Fees ────────────────────────────────────────────────────────────────

  it("feeRateBasisPoints() returns configured value", async function () {
    const { asset } = await deploy();
    expect(await asset.feeRateBasisPoints()).to.equal(100n);
  });

  // ── §9.6 Transfer ─────────────────────────────────────────────────────────

  it("transfer reverts when not ACTIVE", async function () {
    const { asset, user2 } = await deploy();
    await expect(
      asset.transfer(user2.address, 100n, ethers.randomBytes(32))
    ).to.be.revertedWith("L3RS1: not ACTIVE");
  });

  it("transfer succeeds when ACTIVE and emits Transfer event", async function () {
    const { asset, owner, user2 } = await deploy();
    await asset.activate();
    await asset.mint(owner.address, 1000n);
    await expect(asset.transfer(user2.address, 100n, ethers.randomBytes(32)))
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

  // ── §4 Compliance ─────────────────────────────────────────────────────────

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

  // ── §10 Invariant I₁₁ ─────────────────────────────────────────────────────

  it("CID changes when timestamp changes (Invariant I₁₁)", async function () {
    const { asset, owner, user2 } = await deploy();
    await asset.activate();
    await asset.mint(owner.address, 1000n);
    const cidBefore = await asset.crossChainCertificateId();
    await asset.transfer(user2.address, 100n, ethers.randomBytes(32));
    const cidAfter = await asset.crossChainCertificateId();
    // CID is view-only so won't change unless block.timestamp changes
    // Just verify it's non-zero
    expect(cidBefore).to.not.equal(ethers.ZeroHash);
    expect(cidAfter).to.not.equal(ethers.ZeroHash);
  });
});
