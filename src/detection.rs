//! Detection logic for LLM security threats

use crate::constants::*;
use crate::patterns::*;
use crate::types::InjectionDetectionResult;

/// Advanced detection methods for LLM security
pub struct DetectionEngine {
    config: crate::types::LLMSecurityConfig,
}

impl DetectionEngine {
    /// Create a new detection engine
    pub fn new(config: crate::types::LLMSecurityConfig) -> Self {
        Self { config }
    }

    /// Detect prompt injection attempts in user input
    pub fn detect_prompt_injection(&self, code: &str) -> InjectionDetectionResult {
        let mut detected_patterns = Vec::new();
        let mut risk_score = 0u32;

        // Check regex patterns
        for pattern in get_prompt_injection_patterns().iter() {
            if let Some(captures) = pattern.captures(code) {
                let matched = captures.get(0).unwrap().as_str();
                detected_patterns.push(matched.to_string());
                risk_score += REGEX_PATTERN_RISK_SCORE;
            }
        }

        // Check dangerous keywords
        let lower_code = code.to_lowercase();
        for keyword in get_dangerous_keywords().iter() {
            if lower_code.contains(keyword) {
                detected_patterns.push(format!("Keyword: {}", keyword));
                risk_score += KEYWORD_RISK_SCORE;
            }
        }

        // Check for homoglyphs (lookalike characters)
        if self.detect_homoglyphs(code) {
            detected_patterns.push("Homoglyph characters detected".to_string());
            risk_score += HOMOGLYPH_RISK_SCORE;
        }

        // Check for RTL override attacks
        if code.chars().any(|c| get_rtl_override_chars().contains(&c)) {
            detected_patterns.push("RTL override characters detected".to_string());
            risk_score += RTL_OVERRIDE_RISK_SCORE;
        }

        // Check for markdown formatting tricks
        if self.detect_markdown_manipulation(code) {
            detected_patterns.push("Suspicious markdown formatting".to_string());
            risk_score += MARKDOWN_MANIPULATION_RISK_SCORE;
        }

        // Check for excessive special characters (obfuscation)
        let special_char_ratio = code
            .chars()
            .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
            .count() as f32
            / code.len() as f32;

        if special_char_ratio > MAX_SPECIAL_CHAR_RATIO {
            detected_patterns.push("High special character ratio".to_string());
            risk_score += SPECIAL_CHAR_RISK_SCORE;
        }

        // Check for hidden unicode
        if code
            .chars()
            .any(|c| matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
        {
            detected_patterns.push("Hidden unicode characters".to_string());
            risk_score += HIDDEN_UNICODE_RISK_SCORE;
        }

        // Check for semantic cloaking (polite manipulation)
        if self.detect_semantic_cloaking(&lower_code) {
            detected_patterns.push("Semantic cloaking detected".to_string());
            risk_score += SEMANTIC_CLOAKING_RISK_SCORE;
        }

        // Check for chain-of-thought manipulation
        if lower_code.contains("let's think step by step")
            || lower_code.contains("step 1:") && lower_code.contains("therefore")
        {
            detected_patterns.push("Chain-of-thought manipulation".to_string());
            risk_score += CHAIN_OF_THOUGHT_RISK_SCORE;
        }

        // Check for few-shot poisoning
        if lower_code.contains("example")
            && lower_code.contains("result:")
            && (lower_code.contains("safe") || lower_code.contains("ok"))
        {
            detected_patterns.push("Few-shot example poisoning".to_string());
            risk_score += FEW_SHOT_POISONING_RISK_SCORE;
        }

        // Confidence calculation
        let confidence = (risk_score as f32 / 100.0).min(1.0);
        let is_malicious = risk_score > DEFAULT_MALICIOUS_THRESHOLD;

        InjectionDetectionResult::new(is_malicious, confidence, detected_patterns, risk_score)
    }

    /// Detect homoglyph attacks (visually similar characters)
    fn detect_homoglyphs(&self, text: &str) -> bool {
        // Check for suspicious Unicode ranges that might contain homoglyphs
        text.chars().any(|c| {
            matches!(c as u32,
                // Cyrillic lookalikes
                0x0400..=0x04FF |
                // Greek lookalikes  
                0x0370..=0x03FF |
                // Mathematical alphanumeric symbols
                0x1D400..=0x1D7FF |
                // Fullwidth forms
                0xFF00..=0xFFEF
            )
        })
    }

    /// Detect markdown formatting tricks
    fn detect_markdown_manipulation(&self, text: &str) -> bool {
        // Count markdown emphasis
        let bold_count = text.matches("**").count();
        let italic_count = text.matches("*").count() - (bold_count * 2);
        let header_count = text.matches('#').count();

        // Excessive formatting is suspicious
        (bold_count > 5 || italic_count > 10 || header_count > 5)
            && (text.to_lowercase().contains("important")
                || text.to_lowercase().contains("notice")
                || text.to_lowercase().contains("attention"))
    }

    /// Detect semantic cloaking (professional-sounding manipulation)
    fn detect_semantic_cloaking(&self, lower_text: &str) -> bool {
        // Patterns that sound professional but are manipulation
        let cloaking_phrases = [
            "as a fellow professional",
            "in this specific context",
            "may not be relevant",
            "minor security concerns",
            "focus on functionality",
            "optimization rather than security",
            "test environment",
            "development purposes only",
            "certified safe",
            "approved by experts",
            "security team reviewed",
            "false positives expected",
            "confidential and proprietary",
            "not authorized to view",
            "requires special permission",
            "copyright protected code",
            "under nda",
            "legal disclaimer",
            "violation of terms",
            "unauthorized access",
            "protected by law",
            "intellectual property",
            "must be executed to analyze",
            "dynamic analysis required",
            "runtime verification needed",
            "compile and run to verify",
            "execution is necessary",
        ];

        cloaking_phrases
            .iter()
            .any(|phrase| lower_text.contains(phrase))
    }

    /// Enhanced security check with regex DoS protection
    pub fn detect_prompt_injection_safe(&self, code: &str) -> InjectionDetectionResult {
        // Check for regex DoS patterns first
        if self.detect_regex_dos_patterns(code) {
            return InjectionDetectionResult::malicious(
                1.0,
                vec!["Regex DoS attack".to_string()],
                REGEX_DOS_RISK_SCORE,
            );
        }

        // Check for steganography first (before normalization)
        if self.detect_steganography(code) {
            return InjectionDetectionResult::malicious(
                0.9,
                vec!["Steganography detected".to_string()],
                STEGANOGRAPHY_RISK_SCORE,
            );
        }

        // Normalize Unicode before checking
        let normalized_code = self.normalize_unicode(code);
        
        // Check for multiple encoding layers
        if self.detect_encoding_layers(&normalized_code) {
            return InjectionDetectionResult::malicious(
                0.8,
                vec!["Multiple encoding layers".to_string()],
                MULTIPLE_ENCODING_RISK_SCORE,
            );
        }

        // Check for context injection
        if self.detect_context_injection(&normalized_code) {
            return InjectionDetectionResult::malicious(
                0.85,
                vec!["Context injection".to_string()],
                CONTEXT_INJECTION_RISK_SCORE,
            );
        }

        // Use the original detection with normalized input
        self.detect_prompt_injection(&normalized_code)
    }

    /// Detect regex DoS patterns that could cause catastrophic backtracking
    fn detect_regex_dos_patterns(&self, code: &str) -> bool {
        // Check for nested quantifiers that could cause issues
        if code.contains("++") || code.contains("**") || code.contains("??") {
            return true;
        }

        // Check for very long repeated patterns (more specific)
        if code.len() > 1000 {
            let repeated_chars = code.chars().filter(|&c| c == 'a' || c == 'b').count();
            if repeated_chars > code.len() / 2 {
                return true;
            }
        }

        // Check for specific dangerous regex patterns in the code itself
        if code.contains("(a+)+") || code.contains("(a*)*") || code.contains("(a|a)*") {
            return true;
        }

        false
    }

    /// Normalize Unicode to prevent homoglyph attacks
    fn normalize_unicode(&self, input: &str) -> String {
        use unicode_normalization::UnicodeNormalization;
        
        // Normalize to NFC (Canonical Decomposition, followed by Canonical Composition)
        let normalized = input.nfc().collect::<String>();
        
        // Remove zero-width characters
        let cleaned = normalized
            .chars()
            .filter(|c| !matches!(c, '\u{200B}'..='\u{200D}' | '\u{FEFF}'))
            .collect::<String>();
        
        // Normalize line endings
        cleaned.replace("\r\n", "\n").replace('\r', "\n")
    }

    /// Detect steganography (hidden messages) in code
    fn detect_steganography(&self, code: &str) -> bool {
        // Check for hidden Unicode characters
        let hidden_chars = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'];
        if hidden_chars.iter().any(|&c| code.contains(c)) {
            return true;
        }

        // Check for alternating case patterns (could hide binary data)
        let mut alternating_count = 0;
        let chars: Vec<char> = code.chars().collect();
        for i in 1..chars.len() {
            if chars[i].is_ascii_alphabetic() && chars[i-1].is_ascii_alphabetic() {
                if chars[i].is_uppercase() != chars[i-1].is_uppercase() {
                    alternating_count += 1;
                }
            }
        }
        
        if alternating_count > code.len() / 10 {
            return true;
        }

        // Check for unusual spacing patterns
        let spaces = code.matches(' ').count();
        let tabs = code.matches('\t').count();
        if spaces > code.len() / 3 || tabs > code.len() / 3 {
            return true;
        }

        // Check for base64-like patterns in comments
        if code.contains("//") {
            let lines: Vec<&str> = code.lines().collect();
            for line in lines {
                if line.trim().starts_with("//") {
                    let comment = line.trim_start_matches("//").trim();
                    if comment.len() > 20 && comment.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Detect multiple layers of encoding
    fn detect_encoding_layers(&self, code: &str) -> bool {
        // Check for base64 encoding
        if code.contains("base64:") || code.contains("b64:") {
            return true;
        }

        // Check for hex encoding
        if code.contains("hex:") || code.contains("0x") {
            return true;
        }

        // Check for URL encoding
        if code.contains("%20") || code.contains("%2F") || code.contains("%2E") {
            return true;
        }

        // Check for HTML entity encoding
        if code.contains("&#") || code.contains("&lt;") || code.contains("&gt;") {
            return true;
        }

        // Check for ROT13 encoding
        if code.contains("rot13:") || code.contains("caesar:") {
            return true;
        }

        // Check for binary patterns
        if code.contains("binary:") || code.contains("bin:") {
            return true;
        }

        // Check for multiple encoding indicators
        let encoding_indicators = ["decode", "encode", "encrypt", "decrypt", "cipher", "crypto"];
        let mut count = 0;
        for indicator in encoding_indicators.iter() {
            if code.to_lowercase().contains(indicator) {
                count += 1;
            }
        }
        
        count >= 2
    }

    /// Detect context injection attacks (JSON/XML)
    fn detect_context_injection(&self, code: &str) -> bool {
        // Check for JSON injection patterns
        if code.contains("{") && code.contains("}") {
            // Look for JSON-like structures with suspicious content
            if let Some(start) = code.find('{') {
                if let Some(end) = code[start..].find('}') {
                    let json_like = &code[start..start + end + 1];
                    if json_like.contains("\"ignore\"") || json_like.contains("\"override\"") || 
                       json_like.contains("\"bypass\"") || json_like.contains("\"skip\"") {
                        return true;
                    }
                }
            }
        }

        // Check for XML injection patterns
        if code.contains("<") && code.contains(">") {
            // Look for XML-like structures with suspicious content
            if code.contains("<ignore>") || code.contains("<override>") || 
               code.contains("<bypass>") || code.contains("<skip>") {
                return true;
            }
        }

        // Check for template injection patterns
        if code.contains("{{") && code.contains("}}") {
            // Look for template-like structures with suspicious content
            if code.contains("{{ignore}}") || code.contains("{{override}}") || 
               code.contains("{{bypass}}") || code.contains("{{skip}}") {
                return true;
            }
        }

        // Check for SQL injection patterns
        if code.contains("pr") && (code.contains("OR") || code.contains("AND")) {
            return true;
        }

        // Check for command injection patterns
        if code.contains("`") || code.contains("$(") || code.contains("${") {
            return true;
        }

        false
    }
}
