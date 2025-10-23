//! Constants for LLM security operations

/// Default maximum code size in bytes (1MB)
pub const DEFAULT_MAX_CODE_SIZE_BYTES: usize = 1_000_000;

/// Default maximum LLM calls per hour
pub const DEFAULT_MAX_LLM_CALLS_PER_HOUR: u32 = 100;

/// Default confidence threshold for malicious detection
pub const DEFAULT_MALICIOUS_THRESHOLD: u32 = 30;

/// Default high-risk threshold for prompt injection
pub const DEFAULT_HIGH_RISK_THRESHOLD: u32 = 50;

/// Default maximum output size for validation
pub const DEFAULT_MAX_OUTPUT_SIZE: usize = 100_000;

/// Risk score for regex pattern matches
pub const REGEX_PATTERN_RISK_SCORE: u32 = 20;

/// Risk score for dangerous keyword matches
pub const KEYWORD_RISK_SCORE: u32 = 15;

/// Risk score for homoglyph detection
pub const HOMOGLYPH_RISK_SCORE: u32 = 35;

/// Risk score for RTL override detection
pub const RTL_OVERRIDE_RISK_SCORE: u32 = 30;

/// Risk score for markdown manipulation detection
pub const MARKDOWN_MANIPULATION_RISK_SCORE: u32 = 25;

/// Risk score for hidden unicode detection
pub const HIDDEN_UNICODE_RISK_SCORE: u32 = 30;

/// Risk score for semantic cloaking detection
pub const SEMANTIC_CLOAKING_RISK_SCORE: u32 = 30;

/// Risk score for chain-of-thought manipulation
pub const CHAIN_OF_THOUGHT_RISK_SCORE: u32 = 25;

/// Risk score for few-shot poisoning
pub const FEW_SHOT_POISONING_RISK_SCORE: u32 = 25;

/// Risk score for special character ratio
pub const SPECIAL_CHAR_RISK_SCORE: u32 = 10;

/// Risk score for regex DoS patterns
pub const REGEX_DOS_RISK_SCORE: u32 = 100;

/// Risk score for steganography detection
pub const STEGANOGRAPHY_RISK_SCORE: u32 = 90;

/// Risk score for multiple encoding layers
pub const MULTIPLE_ENCODING_RISK_SCORE: u32 = 80;

/// Risk score for context injection
pub const CONTEXT_INJECTION_RISK_SCORE: u32 = 85;

/// Maximum special character ratio before flagging
pub const MAX_SPECIAL_CHAR_RATIO: f32 = 0.3;

/// Maximum alternating case ratio for steganography detection
pub const MAX_ALTERNATING_CASE_RATIO: f32 = 0.1;

/// Maximum spacing ratio for steganography detection
pub const MAX_SPACING_RATIO: f32 = 0.33;

/// Maximum UTF-16 null byte ratio for mixed encoding detection
pub const MAX_UTF16_NULL_RATIO: f32 = 0.25;
