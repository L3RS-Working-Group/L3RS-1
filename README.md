# L3RS-1 SDK — Reference Implementation

**Layer-3 Regulated Asset Standard · v1.0.0 · CROSSCHAIN Conformance Class**

A multi-language reference implementation of the [L3RS-1 specification](https://l3rs.foundation), mandated by §11.6 of the standard. All implementations are pure deterministic libraries — no transport, no ledger coupling, ledger-agnostic by design.

## Languages

| Package | Language | Target Environment |
|---|---|---|
| `packages/typescript` | TypeScript 5 | Web3, dApps, tooling, dashboards |
| `packages/python` | Python 3.11+ | Analytics, compliance pipelines, reporting |
| `packages/go` | Go 1.22+ | Institutional backends, validators, cloud |
| `packages/rust` | Rust 1.77+ | High-perf nodes, WASM, cryptographic core |
| `packages/java` | Java 21+ | Enterprise banking, Spring Boot, legacy infra |
| `packages/solidity` | Solidity 0.8.24 | EVM on-chain enforcement (Profile A, §17.2) |

## Conformance Class

**CROSSCHAIN** — implements all invariants I₁–I₁₁ across all spec sections:

- §2 Formal Asset Model (state machine, Asset_ID, transfer execution)
- §3 Identity Binding (IR, ZKP compatibility, multi-jurisdiction stacking)
- §4 Compliance Engine (rule evaluation, sanctions, holding periods)
- §5 Governance Override (quorum, legal basis, override logging)
- §6 Fee Routing (deterministic allocation, atomicity)
- §7 Reserve Interface (attestation, redemption logic)
- §8 Cross-Chain Meta-Standard (CID construction, downgrade resistance)
- §9 Settlement Finality (atomicity, replay protection, TxID)
- §10 Security Model (all 5 formal invariants enforced)
- §13 Canonical Schema (deterministic serialization)

## Architecture

Every implementation is a **pure function library**. No I/O, no transport, no network. Implementers integrate this library into their chosen ledger platform (EVM, Hyperledger Fabric, Corda, Cosmos, sovereign chain, or private system).

```
┌─────────────────────────────────────────┐
│         Your ledger / platform          │
├─────────────────────────────────────────┤
│         L3RS-1 SDK (this repo)          │
│  types · state machine · compliance     │
│  identity · governance · settlement     │
│  cross-chain CID · canonical hashing    │
├─────────────────────────────────────────┤
│   Crypto primitives (SHA-256, EdDSA)    │
└─────────────────────────────────────────┘
```

## Test Vectors

`/test-vectors/` contains canonical JSON test vectors per §11.5, covering:
- Asset_ID construction
- State transition validity
- Compliance rule evaluation
- Cross-chain CID verification
- Settlement TxID replay protection

All six language implementations MUST produce identical outputs for identical inputs.

## License

Open Standard – Royalty Free Implementation (per L3RS-1 §1 metadata)
