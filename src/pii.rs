//! PII/secret detection & redaction, cross-tenant tag bleed, and privacy-compliance
//! classification. The crate previously had zero detectors for emails, SSNs, keys,
//! tokens, or credentials in inputs or outputs.
//!
//! Built-in rules use validation gates specifically to control false positives:
//! credit-card matches require a passing Luhn checksum; generic high-entropy
//! secrets require a three-way gate (shape + entropy + a nearby marker word) rather
//! than flagging any long random-looking string.

use lazy_static::lazy_static;
use regex::Regex;

/// The kind of sensitive value a `PiiMatch` represents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PiiKind {
    Email,
    Phone,
    Ssn,
    CreditCard,
    IpAddress,
    AwsAccessKey,
    GenericApiKey,
    PrivateKeyBlock,
    JwtToken,
    Custom(String),
}

/// One matched span of sensitive content.
#[derive(Debug, Clone)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
    /// A redacted preview (never the raw matched text) safe to log.
    pub matched_text_redacted: String,
}

#[derive(Debug, Clone)]
pub struct PiiScanResult {
    pub matches: Vec<PiiMatch>,
    pub redacted_text: String,
}

lazy_static! {
    static ref EMAIL_RE: Regex = Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap();
    static ref PHONE_RE: Regex = Regex::new(r"\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap();
    // The `regex` crate has no lookahead support, so invalid-range exclusion
    // (000/666/9xx area numbers, 00 group, 0000 serial) is applied in `is_valid_ssn`
    // after this plain shape match, not in the pattern itself.
    static ref SSN_RE: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    static ref CREDIT_CARD_RE: Regex = Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap();
    static ref IPV4_RE: Regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b").unwrap();
    static ref AWS_KEY_RE: Regex = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    static ref PRIVATE_KEY_RE: Regex = Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap();
    static ref JWT_RE: Regex = Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
    static ref GENERIC_SECRET_RE: Regex = Regex::new(r"[A-Za-z0-9+/_-]{24,}").unwrap();
    static ref SECRET_MARKER_RE: Regex = Regex::new(r"(?i)(key|token|secret|api)").unwrap();
}

fn luhn_checksum_valid(digits: &str) -> bool {
    let cleaned: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if cleaned.len() < 13 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in cleaned.iter().rev() {
        let mut value = d;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum % 10 == 0
}

/// Excludes structurally-invalid SSNs (000/666/9xx area, 00 group number, 0000
/// serial) that the plain `\d{3}-\d{2}-\d{4}` shape match can't rule out itself.
fn is_valid_ssn(candidate: &str) -> bool {
    let parts: Vec<&str> = candidate.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area = parts[0];
    let group = parts[1];
    let serial = parts[2];
    if area == "000" || area == "666" || area.starts_with('9') {
        return false;
    }
    if group == "00" {
        return false;
    }
    if serial == "0000" {
        return false;
    }
    true
}

fn shannon_entropy(text: &str) -> f32 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in text.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    let len = text.chars().count() as f32;
    counts
        .values()
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn redact_preview(kind: &PiiKind, matched: &str) -> String {
    match kind {
        PiiKind::Email => format!("[REDACTED_EMAIL:{} chars]", matched.len()),
        PiiKind::Phone => "[REDACTED_PHONE]".to_string(),
        PiiKind::Ssn => "[REDACTED_SSN]".to_string(),
        PiiKind::CreditCard => "[REDACTED_CREDIT_CARD]".to_string(),
        PiiKind::IpAddress => "[REDACTED_IP]".to_string(),
        PiiKind::AwsAccessKey => "[REDACTED_AWS_KEY]".to_string(),
        PiiKind::GenericApiKey => "[REDACTED_SECRET]".to_string(),
        PiiKind::PrivateKeyBlock => "[REDACTED_PRIVATE_KEY]".to_string(),
        PiiKind::JwtToken => "[REDACTED_JWT]".to_string(),
        PiiKind::Custom(name) => format!("[REDACTED_{}]", name.to_uppercase()),
    }
}

pub struct PiiScanner {
    custom_rules: Vec<(PiiKind, Regex)>,
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiScanner {
    pub fn new() -> Self {
        Self { custom_rules: Vec::new() }
    }

    pub fn with_custom_rule(mut self, kind: PiiKind, pattern: Regex) -> Self {
        self.custom_rules.push((kind, pattern));
        self
    }

    /// Scan `text` for known PII/secret shapes, returning matches ordered by
    /// position (overlaps resolved by longest-match-wins, keeping the first).
    pub fn scan(&self, text: &str) -> PiiScanResult {
        let mut matches: Vec<PiiMatch> = Vec::new();

        for m in AWS_KEY_RE.find_iter(text) {
            matches.push(PiiMatch { kind: PiiKind::AwsAccessKey, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::AwsAccessKey, m.as_str()) });
        }
        for m in PRIVATE_KEY_RE.find_iter(text) {
            matches.push(PiiMatch { kind: PiiKind::PrivateKeyBlock, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::PrivateKeyBlock, m.as_str()) });
        }
        for m in JWT_RE.find_iter(text) {
            matches.push(PiiMatch { kind: PiiKind::JwtToken, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::JwtToken, m.as_str()) });
        }
        for m in EMAIL_RE.find_iter(text) {
            matches.push(PiiMatch { kind: PiiKind::Email, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::Email, m.as_str()) });
        }
        for m in SSN_RE.find_iter(text) {
            if is_valid_ssn(m.as_str()) {
                matches.push(PiiMatch { kind: PiiKind::Ssn, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::Ssn, m.as_str()) });
            }
        }
        for m in PHONE_RE.find_iter(text) {
            matches.push(PiiMatch { kind: PiiKind::Phone, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::Phone, m.as_str()) });
        }
        for m in IPV4_RE.find_iter(text) {
            matches.push(PiiMatch { kind: PiiKind::IpAddress, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::IpAddress, m.as_str()) });
        }
        for m in CREDIT_CARD_RE.find_iter(text) {
            if luhn_checksum_valid(m.as_str()) {
                matches.push(PiiMatch { kind: PiiKind::CreditCard, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::CreditCard, m.as_str()) });
            }
        }
        for m in GENERIC_SECRET_RE.find_iter(text) {
            let window_start = m.start().saturating_sub(20);
            let context = &text[window_start..m.start()];
            let entropy = shannon_entropy(m.as_str());
            if SECRET_MARKER_RE.is_match(context) && entropy > 3.5 {
                matches.push(PiiMatch { kind: PiiKind::GenericApiKey, start: m.start(), end: m.end(), matched_text_redacted: redact_preview(&PiiKind::GenericApiKey, m.as_str()) });
            }
        }
        for (kind, pattern) in &self.custom_rules {
            for m in pattern.find_iter(text) {
                matches.push(PiiMatch { kind: kind.clone(), start: m.start(), end: m.end(), matched_text_redacted: redact_preview(kind, m.as_str()) });
            }
        }

        matches.sort_by_key(|m| (m.start, std::cmp::Reverse(m.end)));
        let mut deduped: Vec<PiiMatch> = Vec::new();
        let mut last_end = 0usize;
        for m in matches {
            if m.start >= last_end {
                last_end = m.end;
                deduped.push(m);
            }
        }

        let redacted_text = self.redact_with_matches(text, &deduped);

        PiiScanResult { matches: deduped, redacted_text }
    }

    fn redact_with_matches(&self, text: &str, matches: &[PiiMatch]) -> String {
        let mut out = String::with_capacity(text.len());
        let mut last = 0usize;
        for m in matches {
            out.push_str(&text[last..m.start]);
            out.push_str(&m.matched_text_redacted);
            last = m.end;
        }
        out.push_str(&text[last..]);
        out
    }

    pub fn redact(&self, text: &str) -> String {
        self.scan(text).redacted_text
    }
}

/// Recommended handling posture for content containing detected PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionHint {
    Ephemeral,
    ShortTerm,
    RequiresReview,
}

#[derive(Debug, Clone)]
pub struct DataHandlingTag {
    pub contains_pii: bool,
    pub pii_kinds: Vec<PiiKind>,
    pub recommended_retention: RetentionHint,
}

pub fn classify_data_handling(scan: &PiiScanResult) -> DataHandlingTag {
    let pii_kinds: Vec<PiiKind> = scan.matches.iter().map(|m| m.kind.clone()).collect();
    let has_high_sensitivity = pii_kinds
        .iter()
        .any(|k| matches!(k, PiiKind::Ssn | PiiKind::CreditCard | PiiKind::PrivateKeyBlock | PiiKind::AwsAccessKey));

    let recommended_retention = if pii_kinds.is_empty() {
        RetentionHint::Ephemeral
    } else if has_high_sensitivity {
        RetentionHint::RequiresReview
    } else {
        RetentionHint::ShortTerm
    };

    DataHandlingTag {
        contains_pii: !pii_kinds.is_empty(),
        pii_kinds,
        recommended_retention,
    }
}

/// Tags a piece of output with the tenant it should belong to, for detecting
/// cross-tenant data bleed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantTag(pub String);

/// Scan `output` for any tenant tag (from `known`) other than `expected` — a coarse
/// signal that content from a different tenant's context leaked into this
/// response.
pub fn scan_for_foreign_tenant_tags(output: &str, expected: &TenantTag, known: &[TenantTag]) -> Vec<TenantTag> {
    known
        .iter()
        .filter(|tag| *tag != expected && output.contains(&tag.0))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_detected_and_redacted() {
        let scanner = PiiScanner::new();
        let result = scanner.scan("Contact me at jane.doe@example.com for details");
        assert!(result.matches.iter().any(|m| m.kind == PiiKind::Email));
        assert!(!result.redacted_text.contains("jane.doe@example.com"));
    }

    #[test]
    fn ssn_is_detected() {
        let scanner = PiiScanner::new();
        let result = scanner.scan("SSN: 123-45-6789");
        assert!(result.matches.iter().any(|m| m.kind == PiiKind::Ssn));
    }

    #[test]
    fn valid_credit_card_passes_luhn_and_is_detected() {
        let scanner = PiiScanner::new();
        // 4111111111111111 is a well-known Luhn-valid test Visa number.
        let result = scanner.scan("Card number: 4111111111111111");
        assert!(result.matches.iter().any(|m| m.kind == PiiKind::CreditCard));
    }

    #[test]
    fn invalid_luhn_digit_string_is_not_flagged_as_credit_card() {
        let scanner = PiiScanner::new();
        let result = scanner.scan("Reference number: 1234567890123456");
        assert!(!result.matches.iter().any(|m| m.kind == PiiKind::CreditCard));
    }

    #[test]
    fn aws_access_key_is_detected() {
        let scanner = PiiScanner::new();
        let result = scanner.scan("key = AKIAIOSFODNN7EXAMPLE");
        assert!(result.matches.iter().any(|m| m.kind == PiiKind::AwsAccessKey));
    }

    #[test]
    fn private_key_block_is_detected() {
        let scanner = PiiScanner::new();
        let result = scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----");
        assert!(result.matches.iter().any(|m| m.kind == PiiKind::PrivateKeyBlock));
    }

    #[test]
    fn generic_secret_requires_marker_word_nearby() {
        let scanner = PiiScanner::new();
        // High-entropy string with no nearby "key/token/secret/api" marker should NOT match.
        let no_marker = scanner.scan("Reference: aB3xQ9zL2kM8pR4tV7wY1nH6sD0fG5j");
        assert!(!no_marker.matches.iter().any(|m| m.kind == PiiKind::GenericApiKey));

        let with_marker = scanner.scan("api_secret_token = aB3xQ9zL2kM8pR4tV7wY1nH6sD0fG5j");
        assert!(with_marker.matches.iter().any(|m| m.kind == PiiKind::GenericApiKey));
    }

    #[test]
    fn ordinary_text_has_no_matches() {
        let scanner = PiiScanner::new();
        let result = scanner.scan("The quick brown fox jumps over the lazy dog");
        assert!(result.matches.is_empty());
        assert_eq!(result.redacted_text, "The quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn overlapping_matches_are_deduplicated() {
        let scanner = PiiScanner::new();
        // A JWT-like string could also match the generic secret pattern; ensure we
        // don't double-count/double-redact the same span.
        let result = scanner.scan("token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ");
        let jwt_matches: Vec<_> = result.matches.iter().filter(|m| m.kind == PiiKind::JwtToken).collect();
        assert_eq!(jwt_matches.len(), 1);
    }

    #[test]
    fn classify_data_handling_flags_high_sensitivity() {
        let scanner = PiiScanner::new();
        let scan = scanner.scan("SSN: 123-45-6789");
        let tag = classify_data_handling(&scan);
        assert!(tag.contains_pii);
        assert_eq!(tag.recommended_retention, RetentionHint::RequiresReview);
    }

    #[test]
    fn classify_data_handling_reports_ephemeral_for_clean_text() {
        let scanner = PiiScanner::new();
        let scan = scanner.scan("nothing sensitive here");
        let tag = classify_data_handling(&scan);
        assert!(!tag.contains_pii);
        assert_eq!(tag.recommended_retention, RetentionHint::Ephemeral);
    }

    #[test]
    fn custom_rule_is_applied() {
        let scanner = PiiScanner::new().with_custom_rule(
            PiiKind::Custom("employee_id".to_string()),
            Regex::new(r"EMP-\d{6}").unwrap(),
        );
        let result = scanner.scan("Employee record EMP-123456 was updated");
        assert!(result.matches.iter().any(|m| m.kind == PiiKind::Custom("employee_id".to_string())));
    }

    #[test]
    fn foreign_tenant_tag_is_detected() {
        let expected = TenantTag("tenant-a".to_string());
        let known = vec![TenantTag("tenant-a".to_string()), TenantTag("tenant-b".to_string())];
        let leaked = scan_for_foreign_tenant_tags("data belonging to tenant-b was included", &expected, &known);
        assert_eq!(leaked, vec![TenantTag("tenant-b".to_string())]);
    }

    #[test]
    fn no_foreign_tenant_tag_when_output_matches_expected_only() {
        let expected = TenantTag("tenant-a".to_string());
        let known = vec![TenantTag("tenant-a".to_string()), TenantTag("tenant-b".to_string())];
        let leaked = scan_for_foreign_tenant_tags("data belonging to tenant-a", &expected, &known);
        assert!(leaked.is_empty());
    }
}
