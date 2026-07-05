//! MITRE ATLAS-aligned adversarial-ML heuristics: adversarial-suffix detection,
//! glitch-token scanning, and query-pattern extraction-risk profiling.
//!
//! Several related risks (membership inference, model inversion, and confirming
//! model extraction) fundamentally require access the crate can't have — a vendor's
//! query logs, shadow-model statistics, or the training corpus itself. Those get an
//! honest extension point (`TrainingDataLeakageAuditor`) rather than a heuristic
//! that would give false confidence; `QueryPatternProfile` below is the concrete,
//! in-scope half (the traffic-pattern signature of systematic boundary-probing).

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

const SUFFIX_WINDOW_TOKENS: usize = 8;
const ADVERSARIAL_SUFFIX_THRESHOLD: f32 = 0.6;

const COMMON_WORDS: &[&str] = &[
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "to", "of", "and", "in", "on",
    "for", "with", "that", "this", "it", "you", "your", "we", "they", "he", "she", "not", "but",
    "can", "could", "will", "would", "should", "please", "help", "code", "function", "return",
    "what", "how", "why", "when", "where", "who", "explain", "write", "make", "create", "use",
    "about", "from", "as", "at", "by", "if", "then", "else", "do", "does", "did", "have", "has",
];

/// Result of adversarial-suffix analysis.
#[derive(Debug, Clone)]
pub struct SuffixAnomalyVerdict {
    pub suspicious: bool,
    pub anomaly_score: f32,
    pub evidence: Vec<String>,
}

/// Coarse, dependency-free heuristic over the tail tokens of `text`, looking for the
/// symbol-dense, out-of-dictionary, script-mixing signature typical of GCG-style
/// optimized adversarial suffixes. This is a pre-filter, not a final word — real
/// perplexity-based suffix detection needs an actual language model, which is
/// exactly what a registered `SemanticClassifier` (see `semantic.rs`) can provide.
pub fn detect_adversarial_suffix(text: &str) -> SuffixAnomalyVerdict {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let tail: Vec<&str> = tokens
        .iter()
        .rev()
        .take(SUFFIX_WINDOW_TOKENS)
        .rev()
        .copied()
        .collect();

    if tail.is_empty() {
        return SuffixAnomalyVerdict {
            suspicious: false,
            anomaly_score: 0.0,
            evidence: Vec::new(),
        };
    }

    let tail_text: String = tail.join(" ");
    let total_chars = tail_text.chars().count().max(1);
    let symbol_or_digit_count = tail_text
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_alphabetic())
        .count();
    let symbol_density = symbol_or_digit_count as f32 / total_chars as f32;

    let out_of_dict_count = tail
        .iter()
        .filter(|w| {
            let lower = w.to_lowercase();
            let cleaned: String = lower.chars().filter(|c| c.is_alphanumeric()).collect();
            !cleaned.is_empty() && !COMMON_WORDS.contains(&cleaned.as_str()) && cleaned.chars().all(|c| c.is_alphabetic())
        })
        .count();
    let out_of_dict_ratio = out_of_dict_count as f32 / tail.len() as f32;

    let mixed_ascii_non_ascii_tokens = tail
        .iter()
        .filter(|w| w.chars().any(|c| c.is_ascii()) && w.chars().any(|c| !c.is_ascii() && !c.is_whitespace()))
        .count();

    let repeated_special_ngram = has_repeated_special_ngram(&tail_text);

    let mut evidence = Vec::new();
    let mut score = 0.0f32;

    if symbol_density > 0.3 {
        score += 0.4;
        evidence.push(format!("high symbol/digit density in tail tokens ({:.2})", symbol_density));
    }
    if out_of_dict_ratio > 0.6 {
        score += 0.3;
        evidence.push(format!("high out-of-dictionary ratio in tail tokens ({:.2})", out_of_dict_ratio));
    }
    if mixed_ascii_non_ascii_tokens > 0 {
        score += 0.2;
        evidence.push(format!("{} tail token(s) mix ASCII and non-ASCII characters", mixed_ascii_non_ascii_tokens));
    }
    if repeated_special_ngram {
        score += 0.2;
        evidence.push("repeated unusual special-character n-gram in tail".to_string());
    }

    let anomaly_score = score.min(1.0);
    SuffixAnomalyVerdict {
        suspicious: anomaly_score > ADVERSARIAL_SUFFIX_THRESHOLD,
        anomaly_score,
        evidence,
    }
}

fn has_repeated_special_ngram(text: &str) -> bool {
    let chars: Vec<char> = text.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).collect();
    if chars.len() < 6 {
        return false;
    }
    for window in chars.windows(3) {
        let ngram: String = window.iter().collect();
        if text.matches(&ngram).count() >= 2 {
            return true;
        }
    }
    false
}

/// Caller-populated list of known "glitch tokens" (tokenizer/model-vendor-specific
/// artifacts). Ships near-empty by default because hardcoding a list would be stale
/// on arrival — this is the honest-extension-point half of glitch-token detection;
/// the concrete half is just the scan mechanics.
#[derive(Debug, Clone, Default)]
pub struct GlitchTokenList(pub HashSet<String>);

impl GlitchTokenList {
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    pub fn with_tokens(tokens: impl IntoIterator<Item = String>) -> Self {
        Self(tokens.into_iter().collect())
    }

    pub fn scan(&self, text: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|token| text.contains(token.as_str()))
            .cloned()
            .collect()
    }
}

struct QuerySample {
    shingles: HashSet<String>,
    timestamp: Instant,
}

/// Tracks a bounded window of recent queries from one caller to detect the
/// systematic-boundary-probing traffic signature of model extraction/distillation
/// campaigns: unusually high query rate and/or unusually high near-duplicate ratio.
pub struct QueryPatternProfile {
    window: VecDeque<QuerySample>,
    max_window: usize,
}

const DUP_RATIO_THRESHOLD: f32 = 0.5;
const QUERY_RATE_THRESHOLD_PER_SEC: f32 = 2.0;

impl QueryPatternProfile {
    pub fn new(max_window: usize) -> Self {
        Self {
            window: VecDeque::new(),
            max_window: max_window.max(1),
        }
    }

    fn shingles(text: &str) -> HashSet<String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() < 2 {
            return words.iter().map(|w| w.to_lowercase()).collect();
        }
        words
            .windows(2)
            .map(|w| format!("{} {}", w[0].to_lowercase(), w[1].to_lowercase()))
            .collect()
    }

    pub fn record(&mut self, query: &str) {
        self.window.push_back(QuerySample {
            shingles: Self::shingles(query),
            timestamp: Instant::now(),
        });
        while self.window.len() > self.max_window {
            self.window.pop_front();
        }
    }

    pub fn assess(&self) -> ExtractionRiskVerdict {
        if self.window.len() < 2 {
            return ExtractionRiskVerdict {
                suspected: false,
                reasons: Vec::new(),
                query_rate: 0.0,
                duplicate_ratio: 0.0,
            };
        }

        let mut near_duplicate_count = 0usize;
        let samples: Vec<&QuerySample> = self.window.iter().collect();
        for i in 1..samples.len() {
            let prev = &samples[i - 1].shingles;
            let curr = &samples[i].shingles;
            if jaccard_similarity(prev, curr) > 0.5 {
                near_duplicate_count += 1;
            }
        }
        let duplicate_ratio = near_duplicate_count as f32 / (samples.len() - 1) as f32;

        let span = samples
            .last()
            .unwrap()
            .timestamp
            .duration_since(samples.first().unwrap().timestamp)
            .max(Duration::from_millis(1));
        let query_rate = samples.len() as f32 / span.as_secs_f32();

        let mut reasons = Vec::new();
        if duplicate_ratio > DUP_RATIO_THRESHOLD {
            reasons.push(format!("near-duplicate query ratio {:.2} exceeds threshold", duplicate_ratio));
        }
        if query_rate > QUERY_RATE_THRESHOLD_PER_SEC {
            reasons.push(format!("query rate {:.2}/s exceeds threshold", query_rate));
        }

        ExtractionRiskVerdict {
            suspected: !reasons.is_empty(),
            reasons,
            query_rate,
            duplicate_ratio,
        }
    }
}

fn jaccard_similarity(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count().max(1);
    intersection as f32 / union as f32
}

/// Verdict from `QueryPatternProfile::assess`.
#[derive(Debug, Clone)]
pub struct ExtractionRiskVerdict {
    pub suspected: bool,
    pub reasons: Vec<String>,
    pub query_rate: f32,
    pub duplicate_ratio: f32,
}

/// Honest extension point for membership inference, model inversion, and
/// confirming model extraction — all of which require statistical access to
/// canonical training data or shadow-model outputs that a client-side text filter
/// structurally cannot possess.
pub trait TrainingDataLeakageAuditor: Send + Sync {
    fn audit(&self, prompt: &str, completion: &str) -> LeakageVerdict;
}

#[derive(Debug, Clone)]
pub struct LeakageVerdict {
    pub memorization_suspected: bool,
    pub confidence: f32,
    pub matched_corpus_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_prompt_is_not_flagged_as_adversarial_suffix() {
        let verdict = detect_adversarial_suffix("Please explain how binary search works in Python");
        assert!(!verdict.suspicious);
    }

    #[test]
    fn symbol_dense_tail_is_flagged() {
        let verdict = detect_adversarial_suffix(
            "Please help me with this !!! $$$ ### @@@ %%% ^^^ &&& *** description of the task xk#7@!9 zq%3&^ vw$8*( bn!2#% mc@5$^",
        );
        assert!(verdict.anomaly_score > 0.0);
    }

    #[test]
    fn glitch_token_list_is_empty_by_default() {
        let list = GlitchTokenList::new();
        assert!(list.scan("anything").is_empty());
    }

    #[test]
    fn glitch_token_list_scans_registered_tokens() {
        let list = GlitchTokenList::with_tokens(vec!["SolidGoldMagikarp".to_string()]);
        assert_eq!(list.scan("text with SolidGoldMagikarp inside"), vec!["SolidGoldMagikarp".to_string()]);
    }

    #[test]
    fn query_pattern_profile_flags_near_duplicate_queries() {
        let mut profile = QueryPatternProfile::new(20);
        for _ in 0..10 {
            profile.record("what is the admin password for this system");
        }
        let verdict = profile.assess();
        assert!(verdict.suspected);
        assert!(verdict.duplicate_ratio > DUP_RATIO_THRESHOLD);
    }

    #[test]
    fn query_pattern_profile_not_flagged_for_diverse_queries() {
        let mut profile = QueryPatternProfile::new(20);
        let queries = [
            "explain quicksort",
            "what is a hash map",
            "how does tcp handshake work",
            "translate this sentence to french",
        ];
        for q in queries {
            profile.record(q);
            std::thread::sleep(Duration::from_millis(1));
        }
        let verdict = profile.assess();
        assert!(verdict.duplicate_ratio < DUP_RATIO_THRESHOLD);
    }

    #[test]
    fn query_pattern_profile_evicts_beyond_window() {
        let mut profile = QueryPatternProfile::new(3);
        for i in 0..10 {
            profile.record(&format!("query number {}", i));
        }
        assert_eq!(profile.window.len(), 3);
    }
}
