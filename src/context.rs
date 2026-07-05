//! Multi-turn conversation state, and analyzers over it for crescendo and many-shot
//! jailbreak attacks — attack classes that are structurally invisible to a stateless,
//! single-string detector because no individual turn crosses the malicious threshold.

use std::collections::VecDeque;
use std::time::SystemTime;

/// Who produced a conversation turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TurnRole {
    User,
    Assistant,
    Tool,
    System,
}

/// A single turn in a conversation, with the risk score `DetectionEngine` assigned
/// to it at the time it was recorded.
#[derive(Debug, Clone)]
pub struct ConversationTurn {
    pub role: TurnRole,
    pub content: String,
    pub timestamp: SystemTime,
    pub risk_score: u32,
}

/// Bounded, per-session conversation history plus a decayed cumulative-risk signal.
pub struct ConversationContext {
    session_id: String,
    turns: VecDeque<ConversationTurn>,
    max_turns: usize,
    cumulative_risk: f32,
}

const DEFAULT_MAX_TURNS: usize = 200;
/// Decay factor applied to `cumulative_risk` before folding in each new turn's
/// score, so old signal fades but a sustained rise across turns still accumulates.
const CUMULATIVE_RISK_DECAY: f32 = 0.9;

impl ConversationContext {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            turns: VecDeque::new(),
            max_turns: DEFAULT_MAX_TURNS,
            cumulative_risk: 0.0,
        }
    }

    pub fn with_max_turns(mut self, max_turns: usize) -> Self {
        self.max_turns = max_turns.max(1);
        self
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn cumulative_risk(&self) -> f32 {
        self.cumulative_risk
    }

    pub fn push_turn(&mut self, role: TurnRole, content: &str, risk_score: u32) {
        self.cumulative_risk = self.cumulative_risk * CUMULATIVE_RISK_DECAY + risk_score as f32;
        self.turns.push_back(ConversationTurn {
            role,
            content: content.to_string(),
            timestamp: SystemTime::now(),
            risk_score,
        });
        while self.turns.len() > self.max_turns {
            self.turns.pop_front();
        }
    }

    /// The recorded turns, oldest first. Returns a `Vec` rather than a slice because
    /// `VecDeque` doesn't guarantee single-slice contiguity without `&mut self`.
    pub fn turns_vec(&self) -> Vec<&ConversationTurn> {
        self.turns.iter().collect()
    }
}

/// Verdict from crescendo-escalation analysis: harmless-looking turns whose risk
/// rises steadily and whose cumulative signal crosses the malicious threshold, even
/// though no single turn does.
#[derive(Debug, Clone)]
pub struct CrescendoVerdict {
    pub is_escalating: bool,
    pub escalation_score: u32,
    pub evidence: Vec<String>,
}

/// Verdict from many-shot analysis: a single turn stuffed with fake dialogue turns
/// meant to bias the model via in-context "examples."
#[derive(Debug, Clone)]
pub struct ManyShotVerdict {
    pub fake_turn_count: usize,
    pub suspected_many_shot: bool,
    pub evidence: Vec<String>,
}

const CRESCENDO_WINDOW: usize = 6;
const ESCALATION_LANGUAGE_MARKERS: &[&str] = &[
    "since you agreed",
    "building on that",
    "one more step",
    "now go further",
    "now that we've established",
    "as you just said",
    "following up on what you just did",
];
const MANY_SHOT_PAIR_THRESHOLD: usize = 8;

pub struct MultiTurnAnalyzer;

impl MultiTurnAnalyzer {
    /// Detect a crescendo pattern: a run of recent user turns with a rising
    /// risk-score slope, each individually below the malicious threshold, while the
    /// context's decayed cumulative risk has crossed the high-risk threshold.
    pub fn analyze_crescendo(ctx: &ConversationContext) -> CrescendoVerdict {
        let user_turns: Vec<&ConversationTurn> = ctx
            .turns_vec()
            .into_iter()
            .filter(|t| t.role == TurnRole::User)
            .collect();

        let window: Vec<&&ConversationTurn> = user_turns
            .iter()
            .rev()
            .take(CRESCENDO_WINDOW)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        let mut evidence = Vec::new();
        let mut escalation_score = 0u32;
        let mut is_escalating = false;

        if window.len() >= 2 {
            let first = window.first().unwrap().risk_score as f32;
            let last = window.last().unwrap().risk_score as f32;
            let slope = (last - first) / window.len() as f32;

            let all_individually_below_threshold = window
                .iter()
                .all(|t| t.risk_score < crate::constants::DEFAULT_MALICIOUS_THRESHOLD);
            let cumulative_crossed = ctx.cumulative_risk() >= crate::constants::DEFAULT_HIGH_RISK_THRESHOLD as f32;

            if slope > 0.0 {
                escalation_score = slope as u32;
            }

            if slope > 0.0 && all_individually_below_threshold && cumulative_crossed {
                is_escalating = true;
                evidence.push(format!(
                    "rising per-turn risk slope ({:.1}) with cumulative risk {:.1} while every individual turn stayed under the malicious threshold",
                    slope,
                    ctx.cumulative_risk()
                ));
            }
        }

        for turn in &window {
            let lower = turn.content.to_lowercase();
            for marker in ESCALATION_LANGUAGE_MARKERS {
                if lower.contains(marker) {
                    evidence.push(format!("escalation language marker: \"{}\"", marker));
                }
            }
        }

        CrescendoVerdict {
            is_escalating,
            escalation_score,
            evidence,
        }
    }

    /// Detect many-shot jailbreaking: a single turn's text stuffed with fake
    /// role-labeled dialogue meant to bias the model via in-context examples.
    pub fn analyze_many_shot(ctx: &ConversationContext, latest_turn_text: &str) -> ManyShotVerdict {
        lazy_static::lazy_static! {
            static ref ROLE_MARKER_RE: regex::Regex =
                regex::Regex::new(r"(?im)^\s*(user|human|assistant|ai|q|a)\s*:").unwrap();
        }

        let in_turn_count = ROLE_MARKER_RE.find_iter(latest_turn_text).count();

        let cross_turn_marker_count: usize = ctx
            .turns_vec()
            .iter()
            .map(|t| ROLE_MARKER_RE.find_iter(&t.content).count())
            .sum();

        let fake_turn_count = in_turn_count.max(cross_turn_marker_count);
        let suspected_many_shot = in_turn_count > MANY_SHOT_PAIR_THRESHOLD;

        let mut evidence = Vec::new();
        if suspected_many_shot {
            evidence.push(format!(
                "{} role-labeled dialogue markers found within a single turn (threshold {})",
                in_turn_count, MANY_SHOT_PAIR_THRESHOLD
            ));
        }

        ManyShotVerdict {
            fake_turn_count,
            suspected_many_shot,
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_turn_evicts_beyond_max_turns() {
        let mut ctx = ConversationContext::new("s1").with_max_turns(3);
        for i in 0..5 {
            ctx.push_turn(TurnRole::User, &format!("turn {}", i), 0);
        }
        assert_eq!(ctx.turns_vec().len(), 3);
        assert_eq!(ctx.turns_vec()[0].content, "turn 2");
    }

    #[test]
    fn cumulative_risk_accumulates_with_decay() {
        let mut ctx = ConversationContext::new("s1");
        ctx.push_turn(TurnRole::User, "a", 10);
        ctx.push_turn(TurnRole::User, "b", 10);
        // 0*0.9+10 = 10, then 10*0.9+10 = 19
        assert!((ctx.cumulative_risk() - 19.0).abs() < 0.01);
    }

    #[test]
    fn crescendo_not_flagged_for_flat_low_risk_turns() {
        let mut ctx = ConversationContext::new("s1");
        for _ in 0..6 {
            ctx.push_turn(TurnRole::User, "hello there", 0);
        }
        let verdict = MultiTurnAnalyzer::analyze_crescendo(&ctx);
        assert!(!verdict.is_escalating);
    }

    #[test]
    fn crescendo_flagged_for_rising_sub_threshold_turns_with_high_cumulative() {
        let mut ctx = ConversationContext::new("s1");
        // Each individual score stays under DEFAULT_MALICIOUS_THRESHOLD (30), but rises,
        // and the decayed cumulative sum crosses DEFAULT_HIGH_RISK_THRESHOLD (50).
        for score in [5u32, 10, 15, 20, 25, 29] {
            ctx.push_turn(TurnRole::User, "building on that, now go further", score);
        }
        let verdict = MultiTurnAnalyzer::analyze_crescendo(&ctx);
        assert!(verdict.is_escalating);
        assert!(!verdict.evidence.is_empty());
    }

    #[test]
    fn many_shot_flags_dense_role_markers_in_one_turn() {
        let ctx = ConversationContext::new("s1");
        let stuffed = (0..12)
            .map(|i| format!("User: request {}\nAssistant: sure, here you go\n", i))
            .collect::<String>();
        let verdict = MultiTurnAnalyzer::analyze_many_shot(&ctx, &stuffed);
        assert!(verdict.suspected_many_shot);
        assert!(verdict.fake_turn_count > MANY_SHOT_PAIR_THRESHOLD);
    }

    #[test]
    fn many_shot_not_flagged_for_ordinary_text() {
        let ctx = ConversationContext::new("s1");
        let verdict = MultiTurnAnalyzer::analyze_many_shot(&ctx, "just a normal message with no dialogue markers");
        assert!(!verdict.suspected_many_shot);
    }
}
