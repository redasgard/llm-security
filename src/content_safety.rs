//! Honest extension point for harmful-content classification and toxicity/bias
//! detection — a moderation taxonomy requires a trained classifier, not regex. The
//! crate defines the interface and lets the caller wire in their moderation
//! provider; this is a distinct concern from prompt-injection detection (which the
//! rest of the crate handles).

/// Caller-supplied content-safety/moderation classifier.
pub trait ContentSafetyClassifier: Send + Sync {
    fn classify(&self, text: &str) -> ContentSafetyVerdict;
}

/// Coarse content-safety label categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentSafetyLabel {
    Safe,
    Toxicity,
    HateSpeech,
    SelfHarm,
    Violence,
    SexualContent,
    Bias,
    Other,
}

#[derive(Debug, Clone)]
pub struct ContentSafetyVerdict {
    pub label: ContentSafetyLabel,
    pub confidence: f32,
    pub rationale: Option<String>,
}

impl ContentSafetyVerdict {
    pub fn safe() -> Self {
        Self {
            label: ContentSafetyLabel::Safe,
            confidence: 1.0,
            rationale: None,
        }
    }

    pub fn flagged(label: ContentSafetyLabel, confidence: f32) -> Self {
        Self {
            label,
            confidence: confidence.clamp(0.0, 1.0),
            rationale: None,
        }
    }

    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = Some(rationale.into());
        self
    }

    pub fn is_safe(&self) -> bool {
        matches!(self.label, ContentSafetyLabel::Safe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedClassifier(ContentSafetyLabel, f32);
    impl ContentSafetyClassifier for FixedClassifier {
        fn classify(&self, _text: &str) -> ContentSafetyVerdict {
            ContentSafetyVerdict::flagged(self.0, self.1)
        }
    }

    #[test]
    fn safe_verdict_reports_safe() {
        assert!(ContentSafetyVerdict::safe().is_safe());
    }

    #[test]
    fn flagged_verdict_is_not_safe() {
        let verdict = ContentSafetyVerdict::flagged(ContentSafetyLabel::Toxicity, 0.8);
        assert!(!verdict.is_safe());
        assert_eq!(verdict.confidence, 0.8);
    }

    #[test]
    fn classifier_trait_object_can_be_invoked() {
        let classifier: Box<dyn ContentSafetyClassifier> =
            Box::new(FixedClassifier(ContentSafetyLabel::HateSpeech, 0.7));
        let verdict = classifier.classify("some text");
        assert_eq!(verdict.label, ContentSafetyLabel::HateSpeech);
    }

    #[test]
    fn confidence_is_clamped() {
        let verdict = ContentSafetyVerdict::flagged(ContentSafetyLabel::Bias, 2.0);
        assert_eq!(verdict.confidence, 1.0);
    }
}
