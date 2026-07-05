//! LLM Security Library
//!
//! This library provides comprehensive security features for Large Language Model (LLM) interactions,
//! including prompt injection detection, output validation, and secure code generation.

pub mod adversarial_ml;
pub mod agentic;
pub mod confusables;
pub mod constants;
pub mod content_safety;
pub mod context;
pub mod decode;
pub mod detection;
pub mod events;
pub mod failsafe;
pub mod grounding;
pub mod i18n;
pub mod indirect;
pub mod layer;
pub mod patterns;
pub mod multimodal;
pub mod output_sink;
pub mod pii;
pub mod policy;
pub mod rate_limit;
pub mod sanitization;
pub mod semantic;
pub mod supply_chain;
pub mod types;
pub mod validation;

// Re-export main types and functions
pub use constants::*;
pub use detection::*;
pub use patterns::*;
pub use sanitization::*;
pub use types::*;
pub use validation::*;

// Re-export the main LLMSecurity struct
pub use types::LLMSecurity;

// Re-export the LLMSecurityLayer facade (see layer.rs for why this is new, not moved).
pub use layer::LLMSecurityLayer;