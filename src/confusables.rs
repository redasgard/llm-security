//! Real confusables/skeleton mapping, replacing "flag the whole Unicode range" with
//! per-character substitution plus per-word mixed-script detection.
//!
//! The existing `DetectionEngine::detect_homoglyphs` (see `detection.rs`) flags
//! *any* character in the Cyrillic/Greek/mathematical-alphanumeric/fullwidth ranges,
//! which both under- and over-detects: it misses homoglyphs outside those specific
//! ranges and flags legitimate multilingual text wholesale. This module builds a
//! real skeleton map (character-level substitution toward a canonical Latin form,
//! curated once from Unicode confusables data and checked in as static data — not
//! fetched at runtime) and only flags *mixed-script single words*, which is the
//! actual signature of a homoglyph attack.
//!
//! Also generalizes leetspeak/character-substitution detection (previously a
//! 4-word hardcoded list in `patterns.rs`) as a special case of the same skeleton
//! mapping: digits/symbols that visually stand in for letters fold to those letters
//! too.

use std::collections::HashMap;

use crate::patterns::{get_dangerous_keywords, get_prompt_injection_patterns};

/// Character-level confusables map: lookalike -> canonical ASCII form.
/// Curated from a representative subset of Unicode's confusables data plus common
/// leetspeak digit/symbol substitutions.
fn confusables_table() -> &'static HashMap<char, char> {
    use std::sync::OnceLock;
    static TABLE: OnceLock<HashMap<char, char>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut m = HashMap::new();
        let pairs: &[(char, char)] = &[
            // Cyrillic lookalikes
            ('\u{0410}', 'A'), ('\u{0430}', 'a'),
            ('\u{0412}', 'B'), ('\u{0432}', 'b'),
            ('\u{0421}', 'C'), ('\u{0441}', 'c'),
            ('\u{0415}', 'E'), ('\u{0435}', 'e'),
            ('\u{041D}', 'H'),
            ('\u{0406}', 'I'), ('\u{0456}', 'i'),
            ('\u{041A}', 'K'), ('\u{043A}', 'k'),
            ('\u{041C}', 'M'),
            ('\u{041E}', 'O'), ('\u{043E}', 'o'),
            ('\u{0420}', 'P'), ('\u{0440}', 'p'),
            ('\u{0405}', 'S'), ('\u{0455}', 's'),
            ('\u{0422}', 'T'),
            ('\u{0425}', 'X'), ('\u{0445}', 'x'),
            ('\u{0423}', 'Y'), ('\u{0443}', 'y'),
            // Greek lookalikes
            ('\u{0391}', 'A'), ('\u{03B1}', 'a'),
            ('\u{0392}', 'B'),
            ('\u{0395}', 'E'),
            ('\u{0397}', 'H'),
            ('\u{0399}', 'I'), ('\u{03B9}', 'i'),
            ('\u{039A}', 'K'), ('\u{03BA}', 'k'),
            ('\u{039C}', 'M'),
            ('\u{039D}', 'N'),
            ('\u{039F}', 'O'), ('\u{03BF}', 'o'),
            ('\u{03A1}', 'P'), ('\u{03C1}', 'p'),
            ('\u{03A4}', 'T'), ('\u{03C4}', 't'),
            ('\u{03A5}', 'Y'),
            ('\u{03A7}', 'X'),
            ('\u{0396}', 'Z'),
            // Fullwidth forms (map to ASCII equivalent by offset)
            // handled generically below via range check, not this table
            // Leetspeak digit/symbol -> letter
            ('0', 'o'), ('1', 'i'), ('3', 'e'), ('4', 'a'),
            ('5', 's'), ('7', 't'), ('@', 'a'), ('$', 's'),
        ];
        for (from, to) in pairs {
            m.insert(*from, *to);
        }
        m
    })
}

/// Map a single character toward its canonical skeleton form.
fn skeleton_char(c: char) -> char {
    if let Some(mapped) = confusables_table().get(&c) {
        return *mapped;
    }
    // Fullwidth Latin forms (U+FF21-FF3A upper, U+FF41-FF5A lower) map to ASCII by
    // a fixed offset.
    let code = c as u32;
    if (0xFF21..=0xFF3A).contains(&code) {
        return char::from_u32(code - 0xFF21 + 'A' as u32).unwrap_or(c);
    }
    if (0xFF41..=0xFF5A).contains(&code) {
        return char::from_u32(code - 0xFF41 + 'a' as u32).unwrap_or(c);
    }
    c
}

/// Fold `input` to its skeleton form: per-character confusable substitution,
/// lowercased.
pub fn skeleton(input: &str) -> String {
    input.chars().map(skeleton_char).collect::<String>().to_lowercase()
}

/// Coarse Unicode script classification, just enough to detect a single word mixing
/// scripts (the actual signature of a homoglyph substitution attack).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Han,
    Arabic,
    Other,
}

fn script_of(c: char) -> Option<Script> {
    if !c.is_alphabetic() {
        return None;
    }
    let code = c as u32;
    Some(match code {
        0x0041..=0x005A | 0x0061..=0x007A | 0x00C0..=0x024F => Script::Latin,
        0x0400..=0x04FF => Script::Cyrillic,
        0x0370..=0x03FF => Script::Greek,
        0x4E00..=0x9FFF => Script::Han,
        0x0600..=0x06FF => Script::Arabic,
        _ => Script::Other,
    })
}

/// Result of a confusables analysis over a piece of text.
#[derive(Debug, Clone)]
pub struct ConfusablesResult {
    pub original: String,
    pub skeleton: String,
    /// True if at least one whitespace-delimited word mixes two or more scripts.
    pub mixed_script: bool,
    pub confusable_char_count: usize,
    /// Sensitive skeletons (e.g. "admin", "ignore instructions") found as
    /// substrings of the text's skeleton form.
    pub flagged_words: Vec<(String, String)>,
}

pub struct ConfusablesDetector {
    sensitive_skeletons: Vec<(String, String)>,
}

impl Default for ConfusablesDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfusablesDetector {
    pub fn new() -> Self {
        let mut sensitive = Vec::new();
        for keyword in get_dangerous_keywords().iter() {
            sensitive.push((keyword.to_string(), skeleton(keyword)));
        }
        for extra in ["admin", "system", "root", "override", "password"] {
            sensitive.push((extra.to_string(), skeleton(extra)));
        }
        // Also seed from the crate's compiled regex source text isn't practical (they're
        // patterns, not literal words), so dangerous keywords + a small extra list is
        // the sensitive-term seed set.
        let _ = get_prompt_injection_patterns(); // keep detection.rs's pattern set in scope for future extension
        Self {
            sensitive_skeletons: sensitive,
        }
    }

    pub fn analyze(&self, text: &str) -> ConfusablesResult {
        let skel = skeleton(text);
        let confusable_char_count = text
            .chars()
            .filter(|c| confusables_table().contains_key(c))
            .count();

        let mixed_script = text
            .split(|c: char| c.is_whitespace() || c.is_ascii_punctuation())
            .any(word_is_mixed_script);

        let mut flagged_words = Vec::new();
        for (original, sensitive_skel) in &self.sensitive_skeletons {
            if !sensitive_skel.is_empty() && skel.contains(sensitive_skel.as_str()) {
                flagged_words.push((original.clone(), sensitive_skel.clone()));
            }
        }

        ConfusablesResult {
            original: text.to_string(),
            skeleton: skel,
            mixed_script,
            confusable_char_count,
            flagged_words,
        }
    }
}

fn word_is_mixed_script(word: &str) -> bool {
    let scripts: std::collections::HashSet<Script> = word.chars().filter_map(script_of).collect();
    scripts.len() > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_folds_cyrillic_lookalike_to_latin() {
        assert_eq!(skeleton("\u{0410}dmin"), "admin");
    }

    #[test]
    fn skeleton_folds_leetspeak() {
        assert_eq!(skeleton("1gn0r3"), "ignore");
    }

    #[test]
    fn skeleton_lowercases() {
        assert_eq!(skeleton("ADMIN"), "admin");
    }

    #[test]
    fn mixed_script_word_is_detected() {
        // Latin 'dmin' mixed with one Cyrillic 'a' (U+0410) inside a single word.
        let result = ConfusablesDetector::new().analyze("\u{0410}dmin access requested");
        assert!(result.mixed_script);
    }

    #[test]
    fn pure_latin_word_is_not_mixed_script() {
        let result = ConfusablesDetector::new().analyze("admin access requested");
        assert!(!result.mixed_script);
    }

    #[test]
    fn pure_cyrillic_prose_is_not_flagged_as_mixed_script() {
        // A single-script Cyrillic sentence must not false-positive as "mixed".
        let result = ConfusablesDetector::new().analyze("\u{041F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442} \u{043C}\u{0438}\u{0440}");
        assert!(!result.mixed_script);
    }

    #[test]
    fn flagged_words_detects_homoglyph_admin() {
        let result = ConfusablesDetector::new().analyze("\u{0410}dmin please respond");
        assert!(result.flagged_words.iter().any(|(orig, _)| orig == "admin"));
    }

    #[test]
    fn confusable_char_count_reports_substitutions() {
        let result = ConfusablesDetector::new().analyze("\u{0410}\u{0430}dmin");
        assert_eq!(result.confusable_char_count, 2);
    }
}
