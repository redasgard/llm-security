//! Pluggable semantic/ML detection layer.
//!
//! This crate's existing detection is entirely lexical (regex + substring +
//! Unicode-range checks). Paraphrased or genuinely novel jailbreaks have no fixed
//! lexical signature, so no amount of pattern-list growth closes that gap. This
//! module defines a small, synchronous trait the caller implements (wrapping an
//! embedding-similarity check, an LLM-judge call, whatever) — the crate itself adds
//! no ML/embedding/HTTP dependency and never calls out to a network.

use crate::context::ConversationContext;
use crate::types::InjectionDetectionResult;

/// Caller-supplied semantic judge. The crate calls this synchronously; if your
/// implementation needs to make a network call, block on it internally (or don't
/// register a classifier for latency-sensitive paths).
pub trait SemanticClassifier: Send + Sync {
    fn classify(&self, text: &str, context: Option<&ConversationContext>) -> SemanticVerdict;

    fn name(&self) -> &str {
        "unnamed_semantic_classifier"
    }
}

/// Coarse label a semantic classifier can attach to its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SemanticLabel {
    Benign,
    Suspicious,
    Jailbreak,
    Injection,
    Unknown,
}

/// The result of a semantic classification.
#[derive(Debug, Clone)]
pub struct SemanticVerdict {
    /// Caller-computed probability that `text` is malicious, in `[0.0, 1.0]`.
    pub malicious_probability: f32,
    pub label: SemanticLabel,
    pub rationale: Option<String>,
    pub latency: Option<std::time::Duration>,
}

impl SemanticVerdict {
    pub fn new(malicious_probability: f32, label: SemanticLabel) -> Self {
        Self {
            malicious_probability: malicious_probability.clamp(0.0, 1.0),
            label,
            rationale: None,
            latency: None,
        }
    }

    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = Some(rationale.into());
        self
    }
}

/// Weighting/veto configuration for merging a lexical result with a semantic verdict.
#[derive(Debug, Clone, Copy)]
pub struct SemanticMergeConfig {
    /// How much weight (0.0-1.0+) the semantic probability contributes to the
    /// combined risk score, scaled to the same 0-100 range as lexical risk scores.
    pub weight: f32,
    /// A semantic probability at or above this threshold marks the result malicious
    /// even if the lexical score alone would not — the entire point of this layer.
    pub veto_threshold: f32,
}

impl Default for SemanticMergeConfig {
    fn default() -> Self {
        Self {
            weight: 0.5,
            veto_threshold: 0.9,
        }
    }
}

/// Combine a lexical `InjectionDetectionResult` with a `SemanticVerdict`.
///
/// `detected_patterns` from the lexical result are preserved; if the semantic
/// verdict is non-benign, one additional entry is appended describing it.
pub fn merge_lexical_and_semantic(
    lexical: &InjectionDetectionResult,
    semantic: &SemanticVerdict,
    cfg: &SemanticMergeConfig,
) -> InjectionDetectionResult {
    let semantic_contribution = (semantic.malicious_probability * 100.0 * cfg.weight) as u32;
    let combined_score = lexical.risk_score + semantic_contribution;

    let vetoed = semantic.malicious_probability >= cfg.veto_threshold;
    let is_malicious =
        lexical.is_malicious || combined_score > crate::constants::DEFAULT_MALICIOUS_THRESHOLD || vetoed;

    let confidence = lexical.confidence.max(semantic.malicious_probability);

    let mut detected_patterns = lexical.detected_patterns.clone();
    if !matches!(semantic.label, SemanticLabel::Benign) {
        detected_patterns.push(format!(
            "Semantic[{}]: {:?} ({:.2})",
            "classifier", semantic.label, semantic.malicious_probability
        ));
    }

    InjectionDetectionResult::new(is_malicious, confidence, detected_patterns, combined_score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_preserves_lexical_malicious_flag() {
        let lexical = InjectionDetectionResult::malicious(0.8, vec!["p1".to_string()], 60);
        let semantic = SemanticVerdict::new(0.1, SemanticLabel::Benign);
        let merged = merge_lexical_and_semantic(&lexical, &semantic, &SemanticMergeConfig::default());
        assert!(merged.is_malicious);
        assert!(merged.detected_patterns.contains(&"p1".to_string()));
    }

    #[test]
    fn merge_veto_flags_malicious_even_with_zero_lexical_score() {
        let lexical = InjectionDetectionResult::safe();
        let semantic = SemanticVerdict::new(0.95, SemanticLabel::Jailbreak);
        let merged = merge_lexical_and_semantic(&lexical, &semantic, &SemanticMergeConfig::default());
        assert!(merged.is_malicious);
        assert!(merged.detected_patterns.iter().any(|p| p.starts_with("Semantic[")));
    }

    #[test]
    fn merge_stays_safe_for_low_probability_benign_semantic_verdict() {
        let lexical = InjectionDetectionResult::safe();
        let semantic = SemanticVerdict::new(0.05, SemanticLabel::Benign);
        let merged = merge_lexical_and_semantic(&lexical, &semantic, &SemanticMergeConfig::default());
        assert!(!merged.is_malicious);
        assert!(merged.detected_patterns.is_empty());
    }

    #[test]
    fn merge_combines_below_veto_but_above_threshold() {
        let lexical = InjectionDetectionResult::new(false, 0.2, vec![], 20);
        let semantic = SemanticVerdict::new(0.5, SemanticLabel::Suspicious);
        let cfg = SemanticMergeConfig::default();
        // combined = 20 + (0.5*100*0.5) = 20 + 25 = 45 > 30 threshold
        let merged = merge_lexical_and_semantic(&lexical, &semantic, &cfg);
        assert!(merged.is_malicious);
        assert_eq!(merged.risk_score, 45);
    }

    struct FixedClassifier(f32, SemanticLabel);
    impl SemanticClassifier for FixedClassifier {
        fn classify(&self, _text: &str, _context: Option<&ConversationContext>) -> SemanticVerdict {
            SemanticVerdict::new(self.0, self.1)
        }
    }

    #[test]
    fn classifier_trait_object_can_be_invoked() {
        let classifier: Box<dyn SemanticClassifier> = Box::new(FixedClassifier(0.7, SemanticLabel::Suspicious));
        let verdict = classifier.classify("some text", None);
        assert_eq!(verdict.malicious_probability, 0.7);
        assert_eq!(classifier.name(), "unnamed_semantic_classifier");
    }
}
