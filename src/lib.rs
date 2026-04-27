//! LLM Security Library
//!
//! This library provides comprehensive security features for Large Language Model (LLM) interactions,
//! including prompt injection detection, output validation, and secure code generation.

pub mod constants;
pub mod detection;
pub mod patterns;
pub mod sanitization;
pub mod types;
pub mod validation;

// Re-export main types and functions
pub use constants::*;
pub use detection::*;
pub use patterns::*;
pub use sanitization::*;
pub use types::*;
pub use validation::*;

// Explicit re-export for the documented facade name (already covered by the
// glob above, but making it explicit keeps the public API obvious).
pub use types::{LLMSecurity, LLMSecurityLayer};