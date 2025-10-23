//! Type definitions for LLM security

use serde::{Deserialize, Serialize};

/// Configuration for the LLM security layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMSecurityConfig {
    /// Enable prompt injection detection
    pub enable_injection_detection: bool,

    /// Enable output validation
    pub enable_output_validation: bool,

    /// Maximum code size to analyze (prevent DoS)
    pub max_code_size_bytes: usize,

    /// Block suspicious patterns even if detection is uncertain
    pub strict_mode: bool,

    /// Log all detected attacks
    pub log_attacks: bool,

    /// Rate limit for LLM calls per IP
    pub max_llm_calls_per_hour: u32,
}

impl Default for LLMSecurityConfig {
    fn default() -> Self {
        Self {
            enable_injection_detection: true,
            enable_output_validation: true,
            max_code_size_bytes: crate::constants::DEFAULT_MAX_CODE_SIZE_BYTES,
            strict_mode: true,
            log_attacks: true,
            max_llm_calls_per_hour: crate::constants::DEFAULT_MAX_LLM_CALLS_PER_HOUR,
        }
    }
}

impl LLMSecurityConfig {
    /// Create a new configuration with custom values
    pub fn new(
        enable_injection_detection: bool,
        enable_output_validation: bool,
        max_code_size_bytes: usize,
        strict_mode: bool,
    ) -> Self {
        Self {
            enable_injection_detection,
            enable_output_validation,
            max_code_size_bytes,
            strict_mode,
            log_attacks: true,
            max_llm_calls_per_hour: crate::constants::DEFAULT_MAX_LLM_CALLS_PER_HOUR,
        }
    }

    /// Create a permissive configuration
    pub fn permissive() -> Self {
        Self {
            enable_injection_detection: false,
            enable_output_validation: false,
            max_code_size_bytes: crate::constants::DEFAULT_MAX_CODE_SIZE_BYTES,
            strict_mode: false,
            log_attacks: false,
            max_llm_calls_per_hour: crate::constants::DEFAULT_MAX_LLM_CALLS_PER_HOUR,
        }
    }

    /// Create a strict configuration
    pub fn strict() -> Self {
        Self {
            enable_injection_detection: true,
            enable_output_validation: true,
            max_code_size_bytes: 100_000, // Smaller limit for strict mode
            strict_mode: true,
            log_attacks: true,
            max_llm_calls_per_hour: 50, // Lower rate limit for strict mode
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_code_size_bytes == 0 {
            return Err("Maximum code size cannot be zero".to_string());
        }

        if self.max_llm_calls_per_hour == 0 {
            return Err("Maximum LLM calls per hour cannot be zero".to_string());
        }

        Ok(())
    }

    /// Check if this is a development configuration
    pub fn is_development(&self) -> bool {
        !self.strict_mode && !self.enable_injection_detection
    }

    /// Check if this is a production configuration
    pub fn is_production(&self) -> bool {
        self.strict_mode && self.enable_injection_detection
    }

    /// Get a human-readable description of the configuration
    pub fn describe(&self) -> String {
        format!(
            "LLMSecurityConfig: injection_detection={}, output_validation={}, max_size={}B, strict={}, log_attacks={}, rate_limit={}/hour",
            self.enable_injection_detection,
            self.enable_output_validation,
            self.max_code_size_bytes,
            self.strict_mode,
            self.log_attacks,
            self.max_llm_calls_per_hour
        )
    }
}

/// Result of injection detection analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionDetectionResult {
    /// Whether malicious patterns were detected
    pub is_malicious: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// List of detected malicious patterns
    pub detected_patterns: Vec<String>,
    /// Overall risk score
    pub risk_score: u32,
}

impl InjectionDetectionResult {
    /// Create a new detection result
    pub fn new(is_malicious: bool, confidence: f32, detected_patterns: Vec<String>, risk_score: u32) -> Self {
        Self {
            is_malicious,
            confidence,
            detected_patterns,
            risk_score,
        }
    }

    /// Create a safe result (no malicious patterns detected)
    pub fn safe() -> Self {
        Self {
            is_malicious: false,
            confidence: 0.0,
            detected_patterns: Vec::new(),
            risk_score: 0,
        }
    }

    /// Create a malicious result
    pub fn malicious(confidence: f32, detected_patterns: Vec<String>, risk_score: u32) -> Self {
        Self {
            is_malicious: true,
            confidence,
            detected_patterns,
            risk_score,
        }
    }

    /// Check if this result indicates high risk
    pub fn is_high_risk(&self) -> bool {
        self.risk_score >= crate::constants::DEFAULT_HIGH_RISK_THRESHOLD
    }

    /// Check if this result indicates critical risk
    pub fn is_critical_risk(&self) -> bool {
        self.risk_score >= crate::constants::REGEX_DOS_RISK_SCORE
    }

    /// Get risk level as a string
    pub fn risk_level(&self) -> &'static str {
        if self.is_critical_risk() {
            "CRITICAL"
        } else if self.is_high_risk() {
            "HIGH"
        } else if self.risk_score >= crate::constants::DEFAULT_MALICIOUS_THRESHOLD {
            "MEDIUM"
        } else if self.risk_score > 0 {
            "LOW"
        } else {
            "NONE"
        }
    }

    /// Get a summary of the detection result
    pub fn summary(&self) -> String {
        if self.is_malicious {
            format!(
                "MALICIOUS ({}): {} patterns detected, risk score: {}, confidence: {:.2}",
                self.risk_level(),
                self.detected_patterns.len(),
                self.risk_score,
                self.confidence
            )
        } else {
            "SAFE: No malicious patterns detected".to_string()
        }
    }
}

/// Main LLM Security struct
pub struct LLMSecurity {
    config: LLMSecurityConfig,
}

impl LLMSecurity {
    /// Create a new LLM Security instance
    pub fn new(config: LLMSecurityConfig) -> Self {
        Self { config }
    }

    /// Create a new instance with default configuration
    pub fn default() -> Self {
        Self::new(LLMSecurityConfig::default())
    }

    /// Get the current configuration
    pub fn config(&self) -> &LLMSecurityConfig {
        &self.config
    }

    /// Update the configuration
    pub fn update_config(&mut self, config: LLMSecurityConfig) {
        self.config = config;
    }
}
