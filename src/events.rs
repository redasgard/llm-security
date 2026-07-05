//! Structured security-event schema for observability.
//!
//! Every new module that reaches a block/deny/redact/trip decision constructs one
//! `SecurityEvent` and forwards it to an optional caller-registered sink. This
//! generalizes (and does not replace) the crate's existing ad-hoc `eprintln!`/
//! `tracing::warn!` calls in `validation.rs`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The kind of security-relevant event being reported.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityEventType {
    InjectionDetected,
    OutputBlocked,
    RateLimitExceeded,
    ToolCallDenied,
    ToolPoisoningSuspected,
    PiiRedacted,
    SystemPromptLeak,
    PolicyReloaded,
    CircuitBreakerTripped,
    SemanticVeto,
    Other(String),
}

/// Severity of a security event, for downstream alerting/triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single structured security event.
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp_unix: u64,
    pub event_type: SecurityEventType,
    pub severity: EventSeverity,
    pub session_id: Option<String>,
    pub risk_score: u32,
    pub detected_patterns: Vec<String>,
    pub source_module: &'static str,
    pub message: String,
}

impl SecurityEvent {
    /// Construct an event stamped with the current time.
    pub fn new(
        event_type: SecurityEventType,
        severity: EventSeverity,
        source_module: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            event_type,
            severity,
            session_id: None,
            risk_score: 0,
            detected_patterns: Vec::new(),
            source_module,
            message: message.into(),
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn with_risk_score(mut self, risk_score: u32) -> Self {
        self.risk_score = risk_score;
        self
    }

    pub fn with_detected_patterns(mut self, patterns: Vec<String>) -> Self {
        self.detected_patterns = patterns;
        self
    }
}

/// A destination for security events. Implement this to forward events to your own
/// logging/SIEM/metrics pipeline.
pub trait SecurityEventSink: Send + Sync {
    fn emit(&self, event: &SecurityEvent);
}

/// Always-available sink that writes to stderr, mirroring the crate's existing
/// `eprintln!` convention in `validation.rs`.
pub struct StdErrEventSink;

impl SecurityEventSink for StdErrEventSink {
    fn emit(&self, event: &SecurityEvent) {
        eprintln!(
            "[{:?}] {} ({}): {}",
            event.severity, event.source_module, format!("{:?}", event.event_type), event.message
        );
    }
}

/// Sink that forwards to the `tracing` crate, only available with the `tracing` feature.
#[cfg(feature = "tracing")]
pub struct TracingEventSink;

#[cfg(feature = "tracing")]
impl SecurityEventSink for TracingEventSink {
    fn emit(&self, event: &SecurityEvent) {
        match event.severity {
            EventSeverity::Critical | EventSeverity::High => {
                tracing::error!(event = ?event.event_type, message = %event.message, "security event")
            }
            EventSeverity::Medium => {
                tracing::warn!(event = ?event.event_type, message = %event.message, "security event")
            }
            EventSeverity::Low | EventSeverity::Info => {
                tracing::info!(event = ?event.event_type, message = %event.message, "security event")
            }
        }
    }
}

/// Fan a single event out to multiple sinks.
pub struct MultiSink(pub Vec<Arc<dyn SecurityEventSink>>);

impl SecurityEventSink for MultiSink {
    fn emit(&self, event: &SecurityEvent) {
        for sink in &self.0 {
            sink.emit(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct CapturingSink(Mutex<Vec<String>>);

    impl SecurityEventSink for CapturingSink {
        fn emit(&self, event: &SecurityEvent) {
            self.0.lock().unwrap().push(event.message.clone());
        }
    }

    #[test]
    fn builder_methods_set_fields() {
        let event = SecurityEvent::new(
            SecurityEventType::InjectionDetected,
            EventSeverity::High,
            "detection",
            "test message",
        )
        .with_session_id("s1")
        .with_risk_score(80)
        .with_detected_patterns(vec!["p1".to_string()]);

        assert_eq!(event.session_id.as_deref(), Some("s1"));
        assert_eq!(event.risk_score, 80);
        assert_eq!(event.detected_patterns, vec!["p1".to_string()]);
    }

    #[test]
    fn multi_sink_forwards_to_all() {
        let sink1 = Arc::new(CapturingSink(Mutex::new(Vec::new())));
        let sink2 = Arc::new(CapturingSink(Mutex::new(Vec::new())));
        let multi = MultiSink(vec![sink1.clone(), sink2.clone()]);

        let event = SecurityEvent::new(
            SecurityEventType::RateLimitExceeded,
            EventSeverity::Medium,
            "rate_limit",
            "hit",
        );
        multi.emit(&event);

        assert_eq!(sink1.0.lock().unwrap().len(), 1);
        assert_eq!(sink2.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn severity_ordering_is_meaningful() {
        assert!(EventSeverity::Critical > EventSeverity::High);
        assert!(EventSeverity::High > EventSeverity::Medium);
        assert!(EventSeverity::Medium > EventSeverity::Low);
        assert!(EventSeverity::Low > EventSeverity::Info);
    }
}
