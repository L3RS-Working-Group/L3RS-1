# Contributing to L3RS-1

Thank you for your interest in contributing to L3RS-1.

L3RS-1 is a deterministic, compliance-first standard for regulated digital assets. Contributions must preserve structural integrity, protocol invariants, and canonical behavior.

---

## Guiding Principles

All contributions MUST:

- Preserve protocol invariants (𝓘₁–𝓘₁₁)
- Maintain deterministic compliance behavior
- Respect canonical serialization rules
- Avoid weakening downgrade resistance guarantees
- Remain ledger-agnostic and vendor-neutral

Proposals that introduce ambiguity or non-determinism will not be accepted.

---

## Contribution Process

1. Open a GitHub Issue describing the proposal.
2. Clearly state:
   - What is being modified
   - Whether invariants are affected
   - Implementation implications
   - Backward compatibility impact
3. Submit a Pull Request referencing the Issue.

All normative changes MUST be reflected in versioning and release notes.

---

## Types of Contributions

The following contributions are welcome:

- Clarifications and specification corrections
- Formalization improvements
- Additional conformance test vectors
- Implementation profile definitions
- Security analysis refinements

The following are out of scope:

- Marketing language
- Commercial integrations
- Product-specific extensions
- Changes that weaken invariant guarantees

---

## Review Policy

During the Working Group phase:

- The Steward (original author) reviews and approves changes.
- Public technical feedback is encouraged.
- Major changes require explicit version increment.

---

## Invariant Protection

Protocol invariants (𝓘₁–𝓘₁₁) are mandatory and non-negotiable.

Any proposal that weakens invariants SHALL be rejected.

---

## Code of Conduct

All contributors are expected to engage professionally and constructively.

Technical critique is encouraged.
Personal attacks are not tolerated.
