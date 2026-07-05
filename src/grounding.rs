//! Honest extension point for misinformation/hallucination detection.
//!
//! The crate has no source of truth to check an LLM's claims against — that's an
//! application-specific retrieval/citation-checking concern. This defines the
//! interface a caller implements against their own grounding source (a knowledge
//! base, a search index, a citation database) rather than a heuristic that would
//! give false confidence about factual accuracy.

/// Caller-supplied grounding/fact-checking judge.
pub trait GroundingChecker: Send + Sync {
    /// Check whether `claim` is supported by `sources` (whatever source-of-truth
    /// representation the caller's implementation understands — document IDs, raw
    /// text, URLs, …).
    fn check(&self, claim: &str, sources: &[String]) -> GroundingVerdict;
}

#[derive(Debug, Clone)]
pub struct GroundingVerdict {
    pub supported: bool,
    pub confidence: f32,
    pub unsupported_claims: Vec<String>,
}

impl GroundingVerdict {
    pub fn supported(confidence: f32) -> Self {
        Self {
            supported: true,
            confidence: confidence.clamp(0.0, 1.0),
            unsupported_claims: Vec::new(),
        }
    }

    pub fn unsupported(claims: Vec<String>) -> Self {
        Self {
            supported: false,
            confidence: 0.0,
            unsupported_claims: claims,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysSupported;
    impl GroundingChecker for AlwaysSupported {
        fn check(&self, _claim: &str, _sources: &[String]) -> GroundingVerdict {
            GroundingVerdict::supported(0.9)
        }
    }

    #[test]
    fn grounding_checker_trait_object_can_be_invoked() {
        let checker: Box<dyn GroundingChecker> = Box::new(AlwaysSupported);
        let verdict = checker.check("the sky is blue", &["source-1".to_string()]);
        assert!(verdict.supported);
        assert_eq!(verdict.confidence, 0.9);
    }

    #[test]
    fn unsupported_verdict_lists_claims() {
        let verdict = GroundingVerdict::unsupported(vec!["claim A".to_string()]);
        assert!(!verdict.supported);
        assert_eq!(verdict.unsupported_claims, vec!["claim A".to_string()]);
    }

    #[test]
    fn supported_verdict_clamps_confidence() {
        let verdict = GroundingVerdict::supported(1.5);
        assert_eq!(verdict.confidence, 1.0);
    }
}
