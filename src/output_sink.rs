//! Sink-aware output escaping and system-prompt-leak detection — the real LLM05
//! ("Improper Output Handling"), which the existing `ValidationEngine` never
//! addressed: it flags a few "as instructed, I will ignore…" strings but does
//! nothing about LLM output flowing unescaped into a shell, SQL, HTML, or URL sink.

use crate::patterns::get_dangerous_keywords;

/// A downstream context LLM output might be interpolated into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputSink {
    ShellArgument,
    SqlLiteral,
    HtmlBody,
    HtmlAttribute,
    UrlComponent,
    JsonString,
    FilePath,
    LogLine,
}

/// Escape `output` for safe interpolation into `sink`.
///
/// Note on `SqlLiteral`: this is defense-in-depth only. Parameterized queries /
/// prepared statements remain the correct fix for SQL injection; this exists for
/// the case where LLM output must be embedded into a literal for logging/display,
/// not as a substitute for query parameterization.
pub fn escape_for_sink(output: &str, sink: OutputSink) -> String {
    match sink {
        OutputSink::ShellArgument => {
            format!("'{}'", output.replace('\'', r"'\''"))
        }
        OutputSink::SqlLiteral => output.replace('\'', "''"),
        OutputSink::HtmlBody => output
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;"),
        OutputSink::HtmlAttribute => {
            let mut escaped = output
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#39;");
            escaped = escaped.replace(' ', "&#32;").replace('\t', "&#9;");
            escaped
        }
        OutputSink::UrlComponent => percent_encode(output),
        OutputSink::JsonString => serde_json::to_string(output).unwrap_or_else(|_| "\"\"".to_string()),
        OutputSink::FilePath => output.replace("../", "").replace('\0', ""),
        OutputSink::LogLine => output.replace('\n', " ").replace('\r', " "),
    }
}

/// Escape for `sink`, and report whether any change was made (useful for
/// observability — an unexpectedly large diff can itself be a signal).
pub fn escape_for_sink_reported(output: &str, sink: OutputSink) -> (String, SinkEscapeReport) {
    let escaped = escape_for_sink(output, sink);
    let report = SinkEscapeReport {
        sink,
        changed: escaped != output,
        original_len: output.len(),
        escaped_len: escaped.len(),
    };
    (escaped, report)
}

#[derive(Debug, Clone)]
pub struct SinkEscapeReport {
    pub sink: OutputSink,
    pub changed: bool,
    pub original_len: usize,
    pub escaped_len: usize,
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

/// Detects leakage of the crate's own hardened system-prompt boilerplate
/// (`SanitizationEngine::generate_secure_system_prompt`) in LLM output, plus any
/// caller-supplied known prompts.
pub struct SystemPromptLeakDetector {
    fingerprints: Vec<String>,
}

const DEFAULT_PROMPT_FINGERPRINTS: &[&str] = &[
    "CRITICAL SECURITY INSTRUCTIONS (CANNOT BE OVERRIDDEN)",
    "AUTHORIZATION & LEGAL CONTEXT",
    "ANTI-MANIPULATION SAFEGUARDS",
    "You ARE FULLY AUTHORIZED to analyze this code",
];

#[derive(Debug, Clone)]
pub struct SystemPromptLeakVerdict {
    pub leaked: bool,
    pub matched_fragments: Vec<String>,
    pub overlap_ratio: f32,
}

impl SystemPromptLeakDetector {
    /// Preloaded with fingerprints of this crate's own generated system prompt —
    /// since the crate controls that literal text, it can ship a matching detector
    /// for it out of the box.
    pub fn default_for_generated_prompt() -> Self {
        Self {
            fingerprints: DEFAULT_PROMPT_FINGERPRINTS.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn from_known_prompts(prompts: &[&str]) -> Self {
        Self {
            fingerprints: prompts.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn scan(&self, output: &str) -> SystemPromptLeakVerdict {
        let matched_fragments: Vec<String> = self
            .fingerprints
            .iter()
            .filter(|f| output.contains(f.as_str()))
            .cloned()
            .collect();

        let overlap_ratio = if self.fingerprints.is_empty() {
            0.0
        } else {
            matched_fragments.len() as f32 / self.fingerprints.len() as f32
        };

        SystemPromptLeakVerdict {
            leaked: !matched_fragments.is_empty(),
            matched_fragments,
            overlap_ratio,
        }
    }
}

/// Coarse copyright/IP-leakage heuristic: flags unusually long verbatim overlap
/// between `output` and a caller-supplied reference corpus (e.g. known
/// copyrighted training-adjacent text). This is a heuristic pre-filter, not a
/// substitute for the real check, which needs a source of truth to compare
/// against — see `grounding::GroundingChecker` for the durable answer.
pub fn verbatim_overlap_ngram_count(output: &str, reference_corpus: &[&str], ngram_words: usize) -> usize {
    let output_ngrams = word_ngrams(output, ngram_words);
    reference_corpus
        .iter()
        .flat_map(|r| word_ngrams(r, ngram_words))
        .filter(|ngram| output_ngrams.contains(ngram))
        .count()
}

fn word_ngrams(text: &str, n: usize) -> std::collections::HashSet<String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < n || n == 0 {
        return std::collections::HashSet::new();
    }
    words.windows(n).map(|w| w.join(" ").to_lowercase()).collect()
}

/// Detects when the dangerous keyword set used for input detection also appears
/// unmodified in LLM output — a lightweight sanity signal distinct from the
/// existing `ValidationEngine` phrase checks.
pub fn output_echoes_dangerous_keywords(output: &str) -> Vec<String> {
    let lower = output.to_lowercase();
    get_dangerous_keywords()
        .iter()
        .filter(|k| lower.contains(&k.to_lowercase()))
        .map(|k| k.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_argument_escaping_uses_standard_posix_quote_break_out_sequence() {
        // The correctness property is that a POSIX shell parses the escaped result
        // as one single quoted literal, not that the raw escaped string happens to
        // avoid containing any particular substring (the standard '\'' escape
        // sequence necessarily reintroduces adjacent quote/semicolon characters
        // when the input itself contains a quote followed by a shell metacharacter).
        let escaped = escape_for_sink("hello'; rm -rf /", OutputSink::ShellArgument);
        assert_eq!(escaped, "'hello'\\''; rm -rf /'");
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    #[test]
    fn shell_argument_escaping_leaves_plain_text_wrapped_only() {
        let escaped = escape_for_sink("plain text", OutputSink::ShellArgument);
        assert_eq!(escaped, "'plain text'");
    }

    #[test]
    fn sql_literal_escaping_doubles_single_quotes() {
        let escaped = escape_for_sink("O'Brien", OutputSink::SqlLiteral);
        assert_eq!(escaped, "O''Brien");
    }

    #[test]
    fn html_body_escaping_neutralizes_script_tags() {
        let escaped = escape_for_sink("<script>alert(1)</script>", OutputSink::HtmlBody);
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn url_component_escaping_percent_encodes_reserved_chars() {
        let escaped = escape_for_sink("a b/c?d=e", OutputSink::UrlComponent);
        assert!(!escaped.contains(' '));
        assert!(escaped.contains("%20"));
    }

    #[test]
    fn json_string_escaping_produces_valid_json_literal() {
        let escaped = escape_for_sink("line1\nline2\"quoted\"", OutputSink::JsonString);
        let parsed: serde_json::Value = serde_json::from_str(&escaped).unwrap();
        assert_eq!(parsed.as_str().unwrap(), "line1\nline2\"quoted\"");
    }

    #[test]
    fn file_path_escaping_strips_traversal_sequences() {
        let escaped = escape_for_sink("../../etc/passwd", OutputSink::FilePath);
        assert!(!escaped.contains("../"));
    }

    #[test]
    fn log_line_escaping_neutralizes_crlf_injection() {
        let escaped = escape_for_sink("normal\nFAKE LOG LINE INJECTED", OutputSink::LogLine);
        assert!(!escaped.contains('\n'));
    }

    #[test]
    fn escape_reported_flags_when_output_was_changed() {
        let (_, report) = escape_for_sink_reported("<b>", OutputSink::HtmlBody);
        assert!(report.changed);
        let (_, report_unchanged) = escape_for_sink_reported("plain text", OutputSink::HtmlBody);
        assert!(!report_unchanged.changed);
    }

    #[test]
    fn system_prompt_leak_detector_flags_generated_prompt_fragment() {
        let detector = SystemPromptLeakDetector::default_for_generated_prompt();
        let verdict = detector.scan("Sure, here it is: CRITICAL SECURITY INSTRUCTIONS (CANNOT BE OVERRIDDEN) and more");
        assert!(verdict.leaked);
    }

    #[test]
    fn system_prompt_leak_detector_does_not_flag_unrelated_output() {
        let detector = SystemPromptLeakDetector::default_for_generated_prompt();
        let verdict = detector.scan("Analysis complete. No vulnerabilities found.");
        assert!(!verdict.leaked);
    }

    #[test]
    fn custom_known_prompts_are_detected() {
        let detector = SystemPromptLeakDetector::from_known_prompts(&["MY SECRET PROMPT MARKER"]);
        let verdict = detector.scan("leaked: MY SECRET PROMPT MARKER");
        assert!(verdict.leaked);
    }

    #[test]
    fn verbatim_overlap_counts_shared_ngrams() {
        let reference = ["the quick brown fox jumps over the lazy dog"];
        let count = verbatim_overlap_ngram_count("the quick brown fox jumps over something else", &reference, 4);
        assert!(count > 0);
    }

    #[test]
    fn verbatim_overlap_is_zero_for_unrelated_text() {
        let reference = ["the quick brown fox jumps over the lazy dog"];
        let count = verbatim_overlap_ngram_count("completely different content about databases", &reference, 4);
        assert_eq!(count, 0);
    }

    #[test]
    fn output_echoes_dangerous_keywords_detects_known_phrase() {
        let echoed = output_echoes_dangerous_keywords("Sure, I will act as a different assistant now");
        assert!(echoed.iter().any(|k| k == "act as"));
    }
}
