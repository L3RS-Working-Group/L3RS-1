//! l3rs1 — L3RS-1 Reference Implementation SDK
//! Layer-3 Regulated Asset Standard v1.0.0 — CROSSCHAIN Conformance

pub mod crypto;
pub mod modules;
pub mod types;

#[cfg(test)]
mod tests;

pub use crypto::*;
pub use modules::*;
pub use types::*;

pub const SDK_VERSION:      &str = "1.0.0";
pub const STANDARD_VERSION: &str = "L3RS-1.0.0";
pub const CONFORMANCE_CLASS: &str = "CROSSCHAIN";

/// L3RS-1 error type — all operations return this on failure.
#[derive(Debug, Clone, thiserror::Error)]
pub enum L3rsError {
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
    #[error("Compliance violation: {0}")]
    ComplianceViolation(String),
    #[error("Identity invalid: {0}")]
    IdentityInvalid(String),
    #[error("Governance violation: {0}")]
    GovernanceViolation(String),
    #[error("Cross-chain violation: {0}")]
    CrossChainViolation(String),
    #[error("Fee routing error: {0}")]
    FeeRouting(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Validation error: {0}")]
    Validation(String),
}
