//! Real enforcement of call/token/cost budgets.
//!
//! `LLMSecurityConfig::max_llm_calls_per_hour` (`src/types.rs`) has always been
//! validated as non-zero but never actually enforced anywhere in the crate — no
//! counter, no clock, no limiter existed. This module is the first real consumer of
//! that field, plus optional token- and cost-budget caps.
//!
//! State lives in a `RateLimiter` (a new, separate, stateful type), since the
//! existing engines (`DetectionEngine`, `SanitizationEngine`, `ValidationEngine`) are
//! stateless `&self` structs and must stay that way for backward compatibility.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::types::LLMSecurityConfig;

/// Configuration for a [`RateLimiter`].
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub max_calls_per_hour: u32,
    pub max_tokens_per_hour: Option<u64>,
    pub max_cost_per_hour_micros: Option<u64>,
    /// Maximum instantaneous burst of calls allowed; defaults to `max_calls_per_hour`.
    pub burst_capacity: Option<u32>,
}

impl RateLimiterConfig {
    pub fn new(max_calls_per_hour: u32) -> Self {
        Self {
            max_calls_per_hour,
            max_tokens_per_hour: None,
            max_cost_per_hour_micros: None,
            burst_capacity: None,
        }
    }

    pub fn with_token_budget(mut self, max_tokens_per_hour: u64) -> Self {
        self.max_tokens_per_hour = Some(max_tokens_per_hour);
        self
    }

    pub fn with_cost_budget_micros(mut self, max_cost_per_hour_micros: u64) -> Self {
        self.max_cost_per_hour_micros = Some(max_cost_per_hour_micros);
        self
    }

    pub fn with_burst_capacity(mut self, burst_capacity: u32) -> Self {
        self.burst_capacity = Some(burst_capacity);
        self
    }

    fn burst(&self) -> f64 {
        self.burst_capacity.unwrap_or(self.max_calls_per_hour).max(1) as f64
    }
}

#[derive(Debug)]
struct Bucket {
    call_tokens: f64,
    token_budget: f64,
    cost_budget_micros: f64,
    last_refill: Instant,
}

/// A request to consume some capacity from the rate limiter.
#[derive(Debug, Clone, Default)]
pub struct ConsumptionRequest {
    pub caller_id: String,
    pub estimated_tokens: Option<u64>,
    pub estimated_cost_micros: Option<u64>,
}

impl ConsumptionRequest {
    pub fn for_caller(caller_id: impl Into<String>) -> Self {
        Self {
            caller_id: caller_id.into(),
            ..Default::default()
        }
    }
}

/// Why a rate-limit check was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateLimitDenyReason {
    CallRateExceeded,
    TokenBudgetExceeded,
    CostBudgetExceeded,
}

/// The outcome of a rate-limit check.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RateLimitVerdict {
    Allowed { remaining_calls: u32 },
    Denied { reason: RateLimitDenyReason, retry_after: Duration },
}

impl RateLimitVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitVerdict::Allowed { .. })
    }
}

/// Token-bucket rate limiter, keyed per caller (use `""` for a single global bucket).
pub struct RateLimiter {
    cfg: RateLimiterConfig,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new(cfg: RateLimiterConfig) -> Self {
        Self {
            cfg,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Seed a limiter's call-rate cap from the crate's existing (previously unused)
    /// `LLMSecurityConfig::max_llm_calls_per_hour` field.
    pub fn from_security_config(config: &LLMSecurityConfig) -> Self {
        Self::new(RateLimiterConfig::new(config.max_llm_calls_per_hour))
    }

    fn fresh_bucket(&self) -> Bucket {
        Bucket {
            call_tokens: self.cfg.burst(),
            token_budget: self.cfg.max_tokens_per_hour.unwrap_or(0) as f64,
            cost_budget_micros: self.cfg.max_cost_per_hour_micros.unwrap_or(0) as f64,
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume capacity for `req`. Lazily refills the bucket based on
    /// elapsed time since its last refill (classic token-bucket algorithm).
    pub fn try_acquire(&self, req: &ConsumptionRequest) -> RateLimitVerdict {
        let mut buckets = self.buckets.lock().unwrap();
        let has_fresh_entry = !buckets.contains_key(&req.caller_id);
        let bucket = buckets
            .entry(req.caller_id.clone())
            .or_insert_with(|| self.fresh_bucket());

        let now = Instant::now();
        if !has_fresh_entry {
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            let call_refill_rate = self.cfg.max_calls_per_hour as f64 / 3600.0;
            bucket.call_tokens = (bucket.call_tokens + elapsed * call_refill_rate).min(self.cfg.burst());

            if let Some(max_tokens) = self.cfg.max_tokens_per_hour {
                let rate = max_tokens as f64 / 3600.0;
                bucket.token_budget = (bucket.token_budget + elapsed * rate).min(max_tokens as f64);
            }
            if let Some(max_cost) = self.cfg.max_cost_per_hour_micros {
                let rate = max_cost as f64 / 3600.0;
                bucket.cost_budget_micros =
                    (bucket.cost_budget_micros + elapsed * rate).min(max_cost as f64);
            }
        }
        bucket.last_refill = now;

        let requested_tokens = req.estimated_tokens.unwrap_or(0) as f64;
        let requested_cost = req.estimated_cost_micros.unwrap_or(0) as f64;

        if bucket.call_tokens < 1.0 {
            let call_refill_rate = self.cfg.max_calls_per_hour as f64 / 3600.0;
            let shortfall = 1.0 - bucket.call_tokens;
            let retry_secs = if call_refill_rate > 0.0 { shortfall / call_refill_rate } else { 3600.0 };
            return RateLimitVerdict::Denied {
                reason: RateLimitDenyReason::CallRateExceeded,
                retry_after: Duration::from_secs_f64(retry_secs.max(0.0)),
            };
        }

        if let Some(max_tokens) = self.cfg.max_tokens_per_hour {
            if requested_tokens > bucket.token_budget {
                let rate = max_tokens as f64 / 3600.0;
                let shortfall = requested_tokens - bucket.token_budget;
                let retry_secs = if rate > 0.0 { shortfall / rate } else { 3600.0 };
                return RateLimitVerdict::Denied {
                    reason: RateLimitDenyReason::TokenBudgetExceeded,
                    retry_after: Duration::from_secs_f64(retry_secs.max(0.0)),
                };
            }
        }

        if let Some(max_cost) = self.cfg.max_cost_per_hour_micros {
            if requested_cost > bucket.cost_budget_micros {
                let rate = max_cost as f64 / 3600.0;
                let shortfall = requested_cost - bucket.cost_budget_micros;
                let retry_secs = if rate > 0.0 { shortfall / rate } else { 3600.0 };
                return RateLimitVerdict::Denied {
                    reason: RateLimitDenyReason::CostBudgetExceeded,
                    retry_after: Duration::from_secs_f64(retry_secs.max(0.0)),
                };
            }
        }

        bucket.call_tokens -= 1.0;
        if self.cfg.max_tokens_per_hour.is_some() {
            bucket.token_budget -= requested_tokens;
        }
        if self.cfg.max_cost_per_hour_micros.is_some() {
            bucket.cost_budget_micros -= requested_cost;
        }

        RateLimitVerdict::Allowed {
            remaining_calls: bucket.call_tokens as u32,
        }
    }

    /// Record actual (post-hoc) usage against a caller's budget, e.g. once the real
    /// token/cost of a completed LLM call is known (as opposed to the estimate passed
    /// to `try_acquire`).
    pub fn record_actual_usage(&self, caller_id: &str, tokens: u64, cost_micros: u64) {
        let mut buckets = self.buckets.lock().unwrap();
        if let Some(bucket) = buckets.get_mut(caller_id) {
            if self.cfg.max_tokens_per_hour.is_some() {
                bucket.token_budget = (bucket.token_budget - tokens as f64).max(0.0);
            }
            if self.cfg.max_cost_per_hour_micros.is_some() {
                bucket.cost_budget_micros = (bucket.cost_budget_micros - cost_micros as f64).max(0.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_within_burst_is_allowed() {
        let limiter = RateLimiter::new(RateLimiterConfig::new(60));
        let verdict = limiter.try_acquire(&ConsumptionRequest::for_caller("a"));
        assert!(verdict.is_allowed());
    }

    #[test]
    fn exceeding_burst_capacity_denies_immediately() {
        let limiter = RateLimiter::new(RateLimiterConfig::new(3600).with_burst_capacity(1));
        let first = limiter.try_acquire(&ConsumptionRequest::for_caller("a"));
        assert!(first.is_allowed());
        let second = limiter.try_acquire(&ConsumptionRequest::for_caller("a"));
        assert!(!second.is_allowed());
        match second {
            RateLimitVerdict::Denied { reason, .. } => assert_eq!(reason, RateLimitDenyReason::CallRateExceeded),
            _ => panic!("expected denial"),
        }
    }

    #[test]
    fn separate_callers_have_separate_buckets() {
        let limiter = RateLimiter::new(RateLimiterConfig::new(3600).with_burst_capacity(1));
        assert!(limiter.try_acquire(&ConsumptionRequest::for_caller("a")).is_allowed());
        assert!(limiter.try_acquire(&ConsumptionRequest::for_caller("b")).is_allowed());
    }

    #[test]
    fn token_budget_denies_when_estimate_exceeds_remaining() {
        let limiter = RateLimiter::new(RateLimiterConfig::new(3600).with_token_budget(100));
        let mut req = ConsumptionRequest::for_caller("a");
        req.estimated_tokens = Some(1000);
        let verdict = limiter.try_acquire(&req);
        match verdict {
            RateLimitVerdict::Denied { reason, .. } => assert_eq!(reason, RateLimitDenyReason::TokenBudgetExceeded),
            _ => panic!("expected token budget denial"),
        }
    }

    #[test]
    fn cost_budget_denies_when_estimate_exceeds_remaining() {
        let limiter = RateLimiter::new(RateLimiterConfig::new(3600).with_cost_budget_micros(100));
        let mut req = ConsumptionRequest::for_caller("a");
        req.estimated_cost_micros = Some(1000);
        let verdict = limiter.try_acquire(&req);
        match verdict {
            RateLimitVerdict::Denied { reason, .. } => assert_eq!(reason, RateLimitDenyReason::CostBudgetExceeded),
            _ => panic!("expected cost budget denial"),
        }
    }

    #[test]
    fn from_security_config_seeds_call_rate_from_existing_field() {
        let mut cfg = LLMSecurityConfig::default();
        cfg.max_llm_calls_per_hour = 1;
        let limiter = RateLimiter::from_security_config(&cfg);
        assert!(limiter.try_acquire(&ConsumptionRequest::for_caller("")).is_allowed());
        assert!(!limiter.try_acquire(&ConsumptionRequest::for_caller("")).is_allowed());
    }

    #[test]
    fn record_actual_usage_reduces_remaining_token_budget() {
        let limiter = RateLimiter::new(RateLimiterConfig::new(3600).with_token_budget(1000));
        let mut req = ConsumptionRequest::for_caller("a");
        req.estimated_tokens = Some(10);
        assert!(limiter.try_acquire(&req).is_allowed());
        limiter.record_actual_usage("a", 500, 0);

        let mut req2 = ConsumptionRequest::for_caller("a");
        req2.estimated_tokens = Some(600);
        let verdict = limiter.try_acquire(&req2);
        assert!(!verdict.is_allowed());
    }
}
