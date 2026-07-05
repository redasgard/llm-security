//! Fail-safe posture for optional, pluggable components.
//!
//! Pluggable components (a `SemanticClassifier`, a `PolicyPack` reload, …) can fail —
//! panic, return an error, or simply not be configured. This module defines the single
//! place that decides what happens next, so the posture is explicit and consistent
//! rather than accidental per call site.

/// Whether an internal failure of an optional component should be treated as
/// "assume clean" (fail open) or "assume not cleared" (fail closed).
///
/// This is about failures of the *mechanism* (a plugin panicking, a regex failing to
/// compile), never about a legitimate "malicious detected" result, which is not a
/// failure at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailurePolicy {
    /// Treat an internal failure as if the check could not clear the input.
    /// This is the safer default: an unavailable/misbehaving optional component
    /// should not silently widen what gets through.
    FailClosed,
    /// Treat an internal failure as if the check passed.
    FailOpen,
}

impl Default for FailurePolicy {
    fn default() -> Self {
        FailurePolicy::FailClosed
    }
}

/// Resolve a fallible result from an optional component according to `policy`.
///
/// - `FailClosed`: an `Err` is preserved as an `Err` (callers should treat this as
///   "not cleared", i.e. block/quarantine/deny).
/// - `FailOpen`: an `Err` is replaced with `fallback`, i.e. treated as if it had
///   succeeded with a benign result.
pub fn resolve<T, E: std::fmt::Display>(
    policy: FailurePolicy,
    result: Result<T, E>,
    fallback: T,
) -> Result<T, String> {
    match (policy, result) {
        (_, Ok(value)) => Ok(value),
        (FailurePolicy::FailOpen, Err(_)) => Ok(fallback),
        (FailurePolicy::FailClosed, Err(e)) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_fail_closed() {
        assert_eq!(FailurePolicy::default(), FailurePolicy::FailClosed);
    }

    #[test]
    fn fail_closed_propagates_error() {
        let result: Result<u32, &str> = Err("boom");
        assert!(resolve(FailurePolicy::FailClosed, result, 0).is_err());
    }

    #[test]
    fn fail_open_substitutes_fallback() {
        let result: Result<u32, &str> = Err("boom");
        assert_eq!(resolve(FailurePolicy::FailOpen, result, 42).unwrap(), 42);
    }

    #[test]
    fn ok_passes_through_regardless_of_policy() {
        let result: Result<u32, &str> = Ok(7);
        assert_eq!(resolve(FailurePolicy::FailClosed, result, 0).unwrap(), 7);
    }
}
