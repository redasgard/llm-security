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

/// Main LLM security facade.
///
/// Wraps the detection, sanitization, and validation engines behind a single
/// surface that matches the documented public API in `README.md` and
/// `docs/architecture.md`.
pub struct LLMSecurityLayer {
    config: LLMSecurityConfig,
}

/// Backwards-compatible alias for the previous name of [`LLMSecurityLayer`].
pub type LLMSecurity = LLMSecurityLayer;

impl LLMSecurityLayer {
    pub fn new(config: LLMSecurityConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &LLMSecurityConfig {
        &self.config
    }

    pub fn update_config(&mut self, config: LLMSecurityConfig) {
        self.config = config;
    }

    /// Analyze input for prompt-injection patterns without modifying it.
    pub fn detect_prompt_injection(&self, code: &str) -> InjectionDetectionResult {
        crate::detection::DetectionEngine::new(self.config.clone())
            .detect_prompt_injection_safe(code)
    }

    /// Sanitize and wrap code for safe LLM processing.
    pub fn sanitize_code_for_llm(&self, code: &str) -> Result<String, String> {
        crate::sanitization::SanitizationEngine::new(self.config.clone())
            .sanitize_comprehensive(code)
    }

    /// Wrap a base prompt with hardened anti-injection instructions.
    pub fn generate_secure_system_prompt(&self, base_prompt: &str) -> String {
        crate::sanitization::SanitizationEngine::new(self.config.clone())
            .generate_secure_system_prompt(base_prompt)
    }

    /// Validate an LLM response for signs of compromise.
    pub fn validate_llm_output(&self, output: &str) -> Result<(), String> {
        crate::validation::ValidationEngine::new(self.config.clone())
            .validate_llm_output(output)
    }

    /// Comprehensive pre-flight check: detect injection, then sanitize+wrap.
    ///
    /// In strict mode a malicious result is rejected outright; otherwise the
    /// caller still receives a sanitized payload they can choose to send.
    pub fn pre_llm_security_check(&self, code: &str) -> Result<String, String> {
        if self.config.enable_injection_detection {
            let result = self.detect_prompt_injection(code);
            if result.is_malicious && self.config.strict_mode {
                return Err(format!(
                    "Input rejected by pre-flight security check: {}",
                    result.summary()
                ));
            }
        }
        self.sanitize_code_for_llm(code)
    }

    /// Post-flight check: validate the LLM's output.
    pub fn post_llm_security_check(&self, output: &str) -> Result<(), String> {
        self.validate_llm_output(output)
    }
}

impl Default for LLMSecurityLayer {
    fn default() -> Self {
        Self::new(LLMSecurityConfig::default())
    }
}
