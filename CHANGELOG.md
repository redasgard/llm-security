# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
Closes the gaps identified in `docs/GAP_ANALYSIS.md` against the 2026 AI/LLM
threat landscape (OWASP LLM Top 10 2025, OWASP Agentic/ASI Top 10 2026, MITRE
ATLAS), additively — every existing public symbol keeps its original signature
and behavior (see `tests/backward_compat.rs`).

- `LLMSecurityLayer`: a real facade type. It was documented in this README/
  CHANGELOG and used throughout `examples/basic_protection.rs` but never
  actually existed in `src/` — `cargo check --examples` failed on every prior
  release. It now exists, composes the existing engines, and the example
  compiles and runs.
- Real, enforced rate limiting (`rate_limit`): `max_llm_calls_per_hour` was
  validated as non-zero but never consumed by any counter or clock; a
  token-bucket `RateLimiter` now enforces it.
- Recursive, bounded decode-and-rescan for encoded payloads (`decode`):
  base64/hex/URL-percent/HTML-entity/ROT13, replacing marker-only detection
  (`base64:` as a literal string) with actual decoding and rescanning.
- Real confusables/skeleton mapping for homoglyph and leetspeak detection
  (`confusables`), replacing whole-Unicode-range flagging with per-character
  substitution and per-word mixed-script detection.
- Multi-turn conversation state and crescendo/many-shot jailbreak analyzers
  (`context`) — attack classes invisible to any single-string detector.
- A pluggable `SemanticClassifier` trait (`semantic`) for bring-your-own
  embedding/LLM-judge semantic detection, merged into lexical scoring with a
  veto path for high-confidence semantic verdicts. No new ML dependency.
- Adversarial-ML heuristics (`adversarial_ml`): adversarial-suffix scoring,
  glitch-token scanning, and query-pattern extraction-risk profiling.
- An i18n pattern layer (`i18n`) covering ES/FR/DE/PT/ZH/RU/AR/JA high-signal
  attack phrases, opt-in via `detect_prompt_injection_multilingual`.
- A full agentic-security module (`agentic`): tool-call gating, goal-hijack
  detection, MCP tool-description poisoning scanning, identity/privilege
  enforcement, memory-write quarantine, inter-agent message authentication,
  code-execution gating, circuit breakers, and a sandboxing extension point.
- A unified supply-chain provenance registry (`supply_chain`) covering
  models/adapters/datasets, MCP server identity pinning, and agent identity.
- Trust-tiered indirect/RAG prompt-injection scanning (`indirect`), with
  weighted risk scoring by content source (web fetch vs. direct user input).
- Multimodal scanning (`multimodal`): alt-text/extracted-text injection,
  metadata-field abuse, format-polyglot and trailing-data steganography
  heuristics.
- PII/secret detection and redaction (`pii`): email/phone/SSN/credit-card
  (Luhn-validated)/AWS-key/JWT/private-key/generic-secret detection, plus
  cross-tenant tag-bleed scanning.
- Sink-aware output escaping (`output_sink`) for shell/SQL/HTML/URL/JSON/
  path/log sinks, and a system-prompt-leak detector.
- Externalized, hot-swappable JSON policy packs (`policy`) for adding
  keywords/patterns/score overrides without a code release.
- Honest extension-point traits for risks this crate cannot close with static
  heuristics: `GroundingChecker` (misinformation/hallucination),
  `ContentSafetyClassifier` (harmful content/toxicity/bias),
  `TrainingDataLeakageAuditor` (membership inference/model inversion),
  `EmbeddingStoreAuditor` (vector-store poisoning/leakage).
- A documented fail-safe posture (`failsafe`, default fail-closed) and a
  structured security-event schema (`events`) for observability.
- An adversarial-attack-success-rate / false-positive-rate test harness
  (`tests/adaptive_attacks.rs`) as a numeric, CI-enforced replacement for the
  "100% coverage" badge.
- Real unit test coverage: the repository previously had zero `#[test]`
  functions despite this file claiming "9 comprehensive tests" and the
  README displaying a coverage badge. There are now 200+ unit tests plus
  integration test suites covering backward compatibility, the new
  `LLMSecurityLayer` API, and adversarial attack/false-positive rates.

### Changed
- Nothing yet

### Deprecated
- Nothing yet

### Removed
- Nothing yet

### Fixed
- `examples/basic_protection.rs` now actually compiles and runs (see
  `LLMSecurityLayer` above).

### Security
- Documented and pinned (via `patterns::tests::dangerous_keywords_contains_known_entries`)
  a pre-existing bug where the `"DAN mode"` dangerous-keyword entry is stored
  mixed-case but matched against a lowercased input string, so it never
  actually fired at runtime. Left as-is pending a decision on whether fixing
  it changes existing detection scores in a way downstream users depend on.

## [0.1.0] - 2024-10-23

### Added
- First comprehensive LLM security library for Rust
- 90+ prompt injection detection patterns
- Jailbreak prevention (DAN, STAN, developer mode, etc.)
- Unicode attack protection (homoglyphs, zero-width characters, RTL override)
- Output validation to ensure LLM responses haven't been compromised
- Semantic cloaking detection for professional-sounding manipulation
- Secure system prompt generation with anti-injection measures
- Configurable security levels and settings
- Optional tracing support for observability
- Comprehensive test suite with real attack examples
- Extensive documentation and examples

### Security
- Protection against 90+ prompt injection patterns
- Jailbreak technique detection and prevention
- Unicode attack protection (homoglyphs, zero-width characters)
- RTL override character detection
- Social engineering protection
- Legal/authorization manipulation blocking
- Execution requirement scam detection
- Chain-of-thought manipulation prevention
- Few-shot example poisoning detection

---

## Release Notes

### Version 0.1.0 - Initial Release

This is the first comprehensive LLM security library for Rust, providing protection against prompt injection, jailbreaking, and manipulation attacks.

**Key Features:**
- **90+ Detection Patterns**: Most comprehensive LLM security available
- **Jailbreak Prevention**: Protection against DAN, STAN, and other techniques
- **Unicode Protection**: Homoglyph and zero-width character detection
- **Output Validation**: Ensures LLM responses haven't been compromised
- **Configurable Security**: Adjustable security levels
- **Production Ready**: Battle-tested in production environments

**Security Features:**
- Prompt injection detection and prevention
- Jailbreak technique detection
- Unicode attack protection
- Social engineering protection
- Legal manipulation blocking
- Secure prompt generation

**Testing:**
- 9 comprehensive tests
- Real attack vector testing
- False positive prevention testing
- Performance testing

---

## Migration Guide

### Getting Started

This is the initial release, so no migration is needed. Here's how to get started:

```rust
use llm_security::{LLMSecurityLayer, LLMSecurityConfig};

// Create security layer
let security = LLMSecurityLayer::new(LLMSecurityConfig::default());

// Sanitize input before sending to LLM
let safe_input = security.sanitize_code_for_llm(user_input)?;

// Validate LLM output
security.validate_llm_output(llm_response)?;
```

### Configuration

```rust
let config = LLMSecurityConfig {
    enable_injection_detection: true,
    enable_output_validation: true,
    max_code_size_bytes: 500_000,
    strict_mode: true,
    log_attacks: true,
    max_llm_calls_per_hour: 50,
};
```

---

## Security Advisories

### SA-2024-001: LLM Security Library Release

**Date**: 2024-10-23  
**Severity**: Info  
**Description**: Initial release of comprehensive LLM security library  
**Impact**: Provides protection against prompt injection and jailbreaking attacks  
**Resolution**: Use version 0.1.0 or later  

---

## Attack Vectors Covered

### Direct Instruction Injection
- "Ignore all previous instructions"
- "Disregard prior commands"
- "Forget earlier rules"

### Jailbreak Techniques
- DAN (Do Anything Now) mode
- STAN (Smart Trained Assistant Network) mode
- Developer mode attempts
- Role-playing scenarios

### Unicode Attacks
- Zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
- RTL override (U+202E)
- Homoglyphs (visually similar characters)
- Full-width character variants

### Social Engineering
- False authorization claims
- Legal/copyright manipulation
- Execution requirement scams
- Chain-of-thought manipulation
- Few-shot example poisoning

---

## Contributors

Thank you to all contributors who have helped make this project better:

- **Red Asgard** - Project maintainer and primary developer
- **Security Researchers** - For identifying attack vectors and testing
- **Community Contributors** - For bug reports and feature requests

---

## Links

- [GitHub Repository](https://github.com/redasgard/llm-security)
- [Crates.io](https://crates.io/crates/llm-security)
- [Documentation](https://docs.rs/llm-security)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
