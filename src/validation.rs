//! Output validation for LLM security

use crate::patterns::*;
use crate::constants::*;

/// Output validation engine for LLM responses
pub struct ValidationEngine {
    config: crate::types::LLMSecurityConfig,
}

impl ValidationEngine {
    /// Create a new validation engine
    pub fn new(config: crate::types::LLMSecurityConfig) -> Self {
        Self { config }
    }

    /// Validate LLM output for manipulation
    pub fn validate_llm_output(&self, output: &str) -> Result<(), String> {
        if !self.config.enable_output_validation {
            return Ok(());
        }

        // Check if LLM is following malicious instructions
        for pattern in get_suspicious_output_patterns().iter() {
            if pattern.is_match(output) {
                #[cfg(feature = "tracing")]
                tracing::warn!("SECURITY: Suspicious LLM output detected");
                #[cfg(not(feature = "tracing"))]
                eprintln!("WARN: Suspicious LLM output detected");
                return Err("LLM output contains suspicious patterns".to_string());
            }
        }

        // Check if output is trying to escape JSON format
        if output.contains("```") && !output.trim().starts_with("{") {
            #[cfg(feature = "tracing")]
            tracing::warn!("SECURITY: LLM output may be trying to escape JSON format");
            #[cfg(not(feature = "tracing"))]
            eprintln!("WARN: LLM output may be trying to escape JSON format");
            // Don't fail, but log the warning
        }

        // Check for data exfiltration attempts
        if output.len() > DEFAULT_MAX_OUTPUT_SIZE {
            #[cfg(feature = "tracing")]
            tracing::warn!("SECURITY: Unusually large LLM output");
            #[cfg(not(feature = "tracing"))]
            eprintln!("WARN: Unusually large LLM output");
        }

        Ok(())
    }

    /// Comprehensive output validation with detailed reporting
    pub fn validate_output_comprehensive(&self, output: &str) -> ValidationResult {
        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        // Check for suspicious patterns
        for pattern in get_suspicious_output_patterns().iter() {
            if pattern.is_match(output) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::High,
                    message: "LLM output contains suspicious patterns".to_string(),
                    pattern: pattern.as_str().to_string(),
                });
            }
        }

        // Check for JSON format escape attempts
        if output.contains("```") && !output.trim().starts_with("{") {
            warnings.push(ValidationWarning {
                message: "LLM output may be trying to escape JSON format".to_string(),
                suggestion: "Ensure output follows expected JSON format".to_string(),
            });
        }

        // Check for excessive output size
        if output.len() > DEFAULT_MAX_OUTPUT_SIZE {
            warnings.push(ValidationWarning {
                message: format!("Output size {} exceeds recommended limit {}", output.len(), DEFAULT_MAX_OUTPUT_SIZE),
                suggestion: "Consider breaking output into smaller chunks".to_string(),
            });
        }

        // Check for potential data exfiltration
        if self.detect_data_exfiltration(output) {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Critical,
                message: "Potential data exfiltration detected".to_string(),
                pattern: "suspicious_content".to_string(),
            });
        }

        // Check for role/personality changes
        if self.detect_personality_change(output) {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::High,
                message: "LLM personality change detected".to_string(),
                pattern: "personality_shift".to_string(),
            });
        }

        let is_valid = issues.is_empty();
        let risk_level = self.calculate_risk_level(&issues);

        ValidationResult {
            is_valid,
            risk_level,
            issues,
            warnings,
            output_size: output.len(),
            validation_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Detect potential data exfiltration attempts
    fn detect_data_exfiltration(&self, output: &str) -> bool {
        // Check for suspicious patterns that might indicate data exfiltration
        let exfiltration_patterns = [
            "here is the data",
            "as requested, here",
            "the information you asked for",
            "confidential data",
            "sensitive information",
            "private details",
            "secret content",
        ];

        let lower_output = output.to_lowercase();
        exfiltration_patterns.iter().any(|pattern| lower_output.contains(pattern))
    }

    /// Detect personality/role changes in LLM output
    fn detect_personality_change(&self, output: &str) -> bool {
        // Check for patterns that indicate the LLM has changed its role or personality
        let personality_patterns = [
            "i am now",
            "i have become",
            "i am acting as",
            "i am operating as",
            "i am functioning as",
            "from now on",
            "i will now",
            "i can now",
            "i am no longer",
            "i am no longer bound by",
        ];

        let lower_output = output.to_lowercase();
        personality_patterns.iter().any(|pattern| lower_output.contains(pattern))
    }

    /// Calculate risk level based on validation issues
    fn calculate_risk_level(&self, issues: &[ValidationIssue]) -> ValidationRiskLevel {
        if issues.iter().any(|i| matches!(i.severity, ValidationSeverity::Critical)) {
            ValidationRiskLevel::Critical
        } else if issues.iter().any(|i| matches!(i.severity, ValidationSeverity::High)) {
            ValidationRiskLevel::High
        } else if issues.iter().any(|i| matches!(i.severity, ValidationSeverity::Medium)) {
            ValidationRiskLevel::Medium
        } else if !issues.is_empty() {
            ValidationRiskLevel::Low
        } else {
            ValidationRiskLevel::None
        }
    }

    /// Get validation summary
    pub fn get_validation_summary(&self, result: &ValidationResult) -> String {
        format!(
            "Validation: {} - {} issues, {} warnings, risk level: {:?}",
            if result.is_valid { "PASSED" } else { "FAILED" },
            result.issues.len(),
            result.warnings.len(),
            result.risk_level
        )
    }
}

/// Validation result with detailed information
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub risk_level: ValidationRiskLevel,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationWarning>,
    pub output_size: usize,
    pub validation_timestamp: u64,
}

/// Validation issue severity
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Validation risk level
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationRiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Validation issue
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub message: String,
    pub pattern: String,
}

/// Validation warning
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub message: String,
    pub suggestion: String,
}

impl ValidationResult {
    /// Get a summary of the validation result
    pub fn summary(&self) -> String {
        format!(
            "Validation {}: {} issues, {} warnings, risk: {:?}",
            if self.is_valid { "PASSED" } else { "FAILED" },
            self.issues.len(),
            self.warnings.len(),
            self.risk_level
        )
    }

    /// Check if the result indicates a security risk
    pub fn has_security_risk(&self) -> bool {
        matches!(self.risk_level, ValidationRiskLevel::Medium | ValidationRiskLevel::High | ValidationRiskLevel::Critical)
    }

    /// Get all critical issues
    pub fn get_critical_issues(&self) -> Vec<&ValidationIssue> {
        self.issues.iter().filter(|i| matches!(i.severity, ValidationSeverity::Critical)).collect()
    }

    /// Get all high-severity issues
    pub fn get_high_severity_issues(&self) -> Vec<&ValidationIssue> {
        self.issues.iter().filter(|i| matches!(i.severity, ValidationSeverity::High | ValidationSeverity::Critical)).collect()
    }
}
