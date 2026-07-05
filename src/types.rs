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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = LLMSecurityConfig::default();
        assert!(cfg.enable_injection_detection);
        assert!(cfg.enable_output_validation);
        assert_eq!(cfg.max_code_size_bytes, crate::constants::DEFAULT_MAX_CODE_SIZE_BYTES);
        assert!(cfg.strict_mode);
        assert!(cfg.log_attacks);
        assert_eq!(cfg.max_llm_calls_per_hour, crate::constants::DEFAULT_MAX_LLM_CALLS_PER_HOUR);
    }

    #[test]
    fn permissive_config_disables_detection() {
        let cfg = LLMSecurityConfig::permissive();
        assert!(!cfg.enable_injection_detection);
        assert!(!cfg.enable_output_validation);
        assert!(!cfg.strict_mode);
        assert!(!cfg.log_attacks);
    }

    #[test]
    fn strict_config_has_smaller_limits() {
        let cfg = LLMSecurityConfig::strict();
        assert!(cfg.strict_mode);
        assert_eq!(cfg.max_code_size_bytes, 100_000);
        assert_eq!(cfg.max_llm_calls_per_hour, 50);
    }

    #[test]
    fn new_constructor_sets_fields() {
        let cfg = LLMSecurityConfig::new(true, false, 1234, true);
        assert!(cfg.enable_injection_detection);
        assert!(!cfg.enable_output_validation);
        assert_eq!(cfg.max_code_size_bytes, 1234);
        assert!(cfg.strict_mode);
    }

    #[test]
    fn validate_rejects_zero_size() {
        let mut cfg = LLMSecurityConfig::default();
        cfg.max_code_size_bytes = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_rate_limit() {
        let mut cfg = LLMSecurityConfig::default();
        cfg.max_llm_calls_per_hour = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_default() {
        assert!(LLMSecurityConfig::default().validate().is_ok());
    }

    #[test]
    fn is_development_and_is_production_are_mutually_exclusive_for_defaults() {
        assert!(LLMSecurityConfig::default().is_production());
        assert!(LLMSecurityConfig::permissive().is_development());
    }

    #[test]
    fn describe_contains_key_fields() {
        let desc = LLMSecurityConfig::default().describe();
        assert!(desc.contains("injection_detection=true"));
        assert!(desc.contains("rate_limit="));
    }

    #[test]
    fn safe_result_is_not_malicious() {
        let r = InjectionDetectionResult::safe();
        assert!(!r.is_malicious);
        assert_eq!(r.risk_score, 0);
        assert_eq!(r.risk_level(), "NONE");
    }

    #[test]
    fn malicious_result_reports_risk_level() {
        let r = InjectionDetectionResult::malicious(0.9, vec!["x".to_string()], 60);
        assert!(r.is_malicious);
        assert!(r.is_high_risk());
        assert!(!r.is_critical_risk());
        assert_eq!(r.risk_level(), "HIGH");
    }

    #[test]
    fn critical_risk_threshold() {
        let r = InjectionDetectionResult::malicious(1.0, vec![], crate::constants::REGEX_DOS_RISK_SCORE);
        assert!(r.is_critical_risk());
        assert_eq!(r.risk_level(), "CRITICAL");
    }

    #[test]
    fn summary_reports_safe_and_malicious() {
        assert_eq!(InjectionDetectionResult::safe().summary(), "SAFE: No malicious patterns detected");
        let r = InjectionDetectionResult::malicious(0.5, vec!["a".to_string()], 40);
        assert!(r.summary().starts_with("MALICIOUS"));
    }

    #[test]
    fn llm_security_new_and_default_use_given_config() {
        let sec = LLMSecurity::new(LLMSecurityConfig::strict());
        assert!(sec.config().strict_mode);
        let sec2 = LLMSecurity::default();
        assert!(sec2.config().enable_injection_detection);
    }

    #[test]
    fn llm_security_update_config_replaces_config() {
        let mut sec = LLMSecurity::default();
        sec.update_config(LLMSecurityConfig::permissive());
        assert!(!sec.config().strict_mode);
    }
}
