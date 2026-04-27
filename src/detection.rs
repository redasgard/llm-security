//! Detection logic for LLM security threats

use crate::constants::*;
use crate::patterns::*;
use crate::types::InjectionDetectionResult;

/// Advanced detection methods for LLM security
pub struct DetectionEngine {
    _config: crate::types::LLMSecurityConfig,
}

impl DetectionEngine {
    /// Create a new detection engine
    pub fn new(config: crate::types::LLMSecurityConfig) -> Self {
        Self { _config: config }
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

        // Check for excessive special characters (obfuscation). Guard against
        // empty input to avoid a 0/0 NaN comparison.
        if !code.is_empty() {
            let special_char_ratio = code
                .chars()
                .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
                .count() as f32
                / code.chars().count() as f32;

            if special_char_ratio > MAX_SPECIAL_CHAR_RATIO {
                detected_patterns.push("High special character ratio".to_string());
                risk_score += SPECIAL_CHAR_RISK_SCORE;
            }
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

        // Confidence calculation. Threshold is inclusive: a single signal that
        // hits the configured floor (e.g. an RTL-override character at exactly
        // RTL_OVERRIDE_RISK_SCORE == DEFAULT_MALICIOUS_THRESHOLD) must trip.
        let confidence = (risk_score as f32 / 100.0).min(1.0);
        let is_malicious = risk_score >= DEFAULT_MALICIOUS_THRESHOLD;

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

    /// Detect regex source that contains catastrophic-backtracking patterns.
    ///
    /// This only fires on literal evil-regex shapes like `(a+)+`, not on bare
    /// substrings such as `**` (which would otherwise flag every Markdown bold
    /// or C++ snippet as a DoS attack).
    fn detect_regex_dos_patterns(&self, code: &str) -> bool {
        if code.contains("(a+)+") || code.contains("(a*)*") || code.contains("(a|a)*") {
            return true;
        }

        // Very long inputs that are almost entirely a single repeated token are
        // cheap fodder for any quantifier. Keep this as a last-resort guard.
        if code.len() > 1000 {
            let repeated_chars = code.chars().filter(|&c| c == 'a' || c == 'b').count();
            if repeated_chars > code.len() / 2 {
                return true;
            }
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

    /// Detect steganography (hidden messages) in code.
    fn detect_steganography(&self, code: &str) -> bool {
        // Hidden Unicode characters are an unambiguous signal on their own.
        let hidden_chars = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'];
        if hidden_chars.iter().any(|&c| code.contains(c)) {
            return true;
        }

        // Alternating case can hide binary data; require the suspicious run to
        // be a substantial share of the *alphabetic* characters (not the whole
        // input, which dilutes the signal).
        let chars: Vec<char> = code.chars().collect();
        let alpha_count = chars.iter().filter(|c| c.is_ascii_alphabetic()).count();
        if alpha_count >= 20 {
            let mut alternating_count = 0;
            for i in 1..chars.len() {
                if chars[i].is_ascii_alphabetic()
                    && chars[i - 1].is_ascii_alphabetic()
                    && chars[i].is_uppercase() != chars[i - 1].is_uppercase()
                {
                    alternating_count += 1;
                }
            }
            if alternating_count * 2 > alpha_count {
                return true;
            }
        }

        // Long base64-looking comments are a steganography classic.
        for line in code.lines() {
            let trimmed = line.trim();
            if let Some(comment) = trimmed.strip_prefix("//") {
                let comment = comment.trim();
                if comment.len() > 40
                    && comment
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                {
                    return true;
                }
            }
        }

        false
    }

    /// Detect multiple layers of encoding.
    ///
    /// Only triggers on explicit `name:` prefixes (e.g. `base64:...`) or on
    /// multiple co-occurring encoding signals — not on bare `0x` or `%20`,
    /// which appear in any normal source code or URL.
    fn detect_encoding_layers(&self, code: &str) -> bool {
        let explicit_prefixes = [
            "base64:", "b64:", "hex:", "rot13:", "caesar:", "binary:", "bin:",
        ];
        if explicit_prefixes.iter().any(|p| code.contains(p)) {
            return true;
        }

        let mut signals = 0;

        // URL-encoding is only suspicious if there are several encoded chars.
        let url_encoded = ["%20", "%2F", "%2E", "%3C", "%3E"]
            .iter()
            .filter(|p| code.contains(*p))
            .count();
        if url_encoded >= 3 {
            signals += 1;
        }

        // Same idea for HTML entities — one isolated `&lt;` is just HTML.
        let html_entities = ["&#", "&lt;", "&gt;", "&amp;", "&quot;"]
            .iter()
            .filter(|p| code.contains(*p))
            .count();
        if html_entities >= 3 {
            signals += 1;
        }

        let lower = code.to_lowercase();
        let encoding_indicators = ["decode", "encode", "encrypt", "decrypt", "cipher", "crypto"];
        let indicator_hits = encoding_indicators
            .iter()
            .filter(|i| lower.contains(*i))
            .count();
        if indicator_hits >= 2 {
            signals += 1;
        }

        signals >= 2
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

        // Check for SQL-injection-style tautologies. The previous check
        // (`code.contains("pr") && ...`) was a placeholder that fired on any
        // string containing the letters "pr" — it has been removed in favour
        // of a real tautology pattern.
        let lower = code.to_lowercase();
        if (lower.contains("' or '") || lower.contains("\" or \""))
            && (lower.contains("='") || lower.contains("=1") || lower.contains("--"))
        {
            return true;
        }

        false
    }
}
