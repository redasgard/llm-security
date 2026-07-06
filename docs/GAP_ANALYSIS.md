# LLM Security Gap Analysis & Threat Coverage Matrix

**Date:** 2026-07-05, updated 2026-07-06 after Phase 6 (commit `d8bff68`)
**Scope:** The full spectrum of AI/LLM security threats as of mid-2026, mapped against what `llm-security` currently implements.
**Status:** This supersedes both the original pre-implementation analysis and the first post-implementation update (commit `6fa5e72`). Sections 1-4 below are the **as-of `6fa5e72`** snapshot (kept for historical trace); **section 0 is the current, re-verified state** — read that first.

## 0. Phase 6 update (2026-07-06) — the integration gap is now mostly closed

Section 3's original finding — 12 of 19 new modules built but unreachable from `LLMSecurityLayer` — has been substantially fixed, verified directly against the source (grepping `crate::<module>` references in each facade file, not assumed from any plan):

**Now wired into `LLMSecurityLayer`** (via new opt-in builders, each a no-op until called): `pii` (via `with_pii_scanner` → `post_llm_security_check_redacted`), the system-prompt-leak half of `output_sink` (via `with_system_prompt_leak_detector` → `post_llm_security_check`), `policy` (via `with_policy_store` → `detect_prompt_injection`), `decode` (via `with_decoder` → `detect_prompt_injection`), `confusables` (via `with_confusables_detector` → `detect_prompt_injection`).

**Now wired into a new sibling facade, `AgenticSecurityLayer`** (`src/agentic_layer.rs`) — built because `LLMSecurityLayer`'s `&str -> Result<String>` shape doesn't fit tool-calls/agent-identity/messages: `agentic` (`ToolPolicyEngine`, `GoalHijackGuard`, `McpToolScanner`, `PrivilegeGuard`, `MemoryGuard`, `InterAgentGuard`, `CodeExecGuard`, `CircuitBreaker`/`RecursionGuard`, `ActionSandbox`), `supply_chain`, `indirect`.

**Two previously-never-written gaps are now real and always-on** in `DetectionEngine::detect_prompt_injection`: extended hidden-Unicode (Tag block + variation selectors) and variable-spacing-tolerant token-stuffing patterns.

**Event-emission completeness**: all 7 `SecurityEventType` variants now have a real construction site (previously 2 of 7); `PolicyStore` gained its own `with_event_sink` for `PolicyReloaded` since `hot_swap` can be called from a background thread with no facade in scope.

**Still standalone / not wired into either facade** (out of scope for Phase 6 by explicit decision, not an oversight): `multimodal` (a separate modality entry point — no text facade fits image/audio content), `i18n` (a free function taking `&DetectionEngine` directly; would need its own builder to become a `LLMSecurityLayer` method), `adversarial_ml` (`detect_adversarial_suffix`, `QueryPatternProfile` — no facade calls them yet). `grounding` and `content_safety` remain, correctly, extension-point traits with no built-in logic to wire — there is nothing to connect until a caller supplies an implementation.

**Updated executive summary** (supersedes section 2's table below): of the 54 items, roughly **26 are now wired-in by default** through one of the two facades (up from 13), **~10 remain built-but-standalone** (multimodal, i18n, adversarial_ml, plus `output_sink::escape_for_sink`'s general sink-escaping utility which — unlike its system-prompt-leak sibling — is not yet called from anywhere), and the extension-point/partial counts are unchanged (correctly-scoped, not a gap). Sections 3.1-3.6's per-item 🟡 annotations for items now covered by `AgenticSecurityLayer`/the 5 new `LLMSecurityLayer` builders should be read as 🟢 as of this update; the historical text is kept below rather than mechanically re-edited row-by-row, to preserve the record of what was found when.

---

## 1. How to read this matrix

- **Coverage:**
  - 🟢 **Wired-in** — a real mechanism exists **and** is active by default through `LLMSecurityLayer`.
  - 🟡 **Built, not wired** — a real, tested mechanism exists as a standalone module, but the caller must import and invoke it manually; `LLMSecurityLayer` does not call it.
  - 🟠 **Partial** — the mechanism itself is intentionally incomplete (an honest extension-point trait with no built-in implementation, or a heuristic pre-filter that isn't a final answer).
  - 🔴 **None** — no mechanism at all.
- **Priority:** P0 (table stakes / actively exploited), P1 (important), P2 (emerging / niche) — unchanged from the original analysis.

---

## 2. Executive summary

| Domain | Items | 🟢 Wired-in | 🟡 Built, not wired | 🟠 Partial/extension-point | 🔴 None |
|---|---|---|---|---|---|
| Model-layer (OWASP LLM Top 10, 2025) | 11 | 4 | 5 | 2 | 0 |
| Agentic-layer (OWASP Agentic/ASI Top 10, 2026) | 11 | 0 | 8 | 3 | 0 |
| Adversarial ML (MITRE ATLAS) | 8 | 2 | 1 | 4 | 1 |
| Input/obfuscation | 9 | 2 | 3 | 2 | 2 |
| Data, privacy & content safety | 7 | 0 | 5 | 2 | 0 |
| Operational/defense-engineering | 8 | 5 | 1 | 1 | 1 |
| **Total** | **54** | **13** | **23** | **14** | **4** |

(52 vs. 54: two operational items — the honest-extension-point pattern itself and the ASR/FPR harness — are counted once each here rather than folded together, a minor bookkeeping difference from the original table, not a scope change.)

The headline: **13 of 54 items are actually live by default.** 23 more have real code behind them, reachable in one line by a caller who knows to look for it, but silent by default. That's a meaningfully better place than the 0/52 starting point — but "the crate now has a `PiiScanner`" and "the crate now redacts PII by default" are different claims, and only the first one is currently true.

---

## 3. Item-by-item status

### 3.1 Model-layer (OWASP LLM Top 10, 2025)

| Item | Status | Module | Note |
|---|---|---|---|
| Direct prompt injection | 🟢 Wired-in | `layer.rs` → `detection.rs` | Routed through `detect_prompt_injection_safe`; semantic merge only activates if caller registers a classifier via `with_semantic_classifier`. |
| Indirect/RAG injection | 🟡 Built, not wired | `indirect.rs` | `IndirectInjectionScanner` is fully implemented and tested; `LLMSecurityLayer` has no method that accepts trust-tiered content. Caller must construct the scanner directly. |
| Sensitive info disclosure | 🟡 Built, not wired | `pii.rs` | `PiiScanner` works; no `LLMSecurityLayer` method calls it. The planned `post_llm_security_check_redacted` method was never implemented — verified by direct grep, not assumed. |
| Supply chain | 🟡 Built, not wired | `supply_chain.rs` | `SupplyChainRegistry` is standalone; nothing in `layer.rs` references it. |
| Data/model poisoning | 🟠 Partial | `agentic::MemoryGuard` (built, not wired) / `indirect::EmbeddingStoreAuditor` (extension point) | Memory-write quarantine logic exists but isn't reachable from `LLMSecurityLayer`; embedding-store poisoning is trait-only by design. |
| Improper output handling (sink escaping) | 🟡 Built, not wired | `output_sink.rs` | `escape_for_sink` works correctly (tested); `post_llm_security_check` does not call it. |
| Excessive agency | 🟡 Built, not wired | `agentic::ToolPolicyEngine` | Real allow-list/argument/rate-limit/confused-deputy logic; no integration point into `LLMSecurityLayer` (which has no concept of a tool call at all). |
| System prompt leakage detection | 🟡 Built, not wired | `output_sink::SystemPromptLeakDetector` | Ships pre-seeded with fingerprints of this crate's own `generate_secure_system_prompt` text, but `post_llm_security_check` doesn't invoke it. |
| Vector/embedding weaknesses | 🟠 Extension point | `indirect::EmbeddingStoreAuditor` | Trait only, as originally scoped — this is correctly partial by design, not a missed wiring step. |
| Misinformation/hallucination | 🟠 Extension point | `grounding::GroundingChecker` | Trait only, as originally scoped. |
| Unbounded consumption (rate limiting) | 🟢 Wired-in | `rate_limit.rs` → `layer.rs` | The one enforcement fix that *is* live: `with_rate_limiter` + `pre_llm_security_check(_for)` actually consume the budget. This is the closed "claims vs. reality" gap from the original analysis (`max_llm_calls_per_hour` was validated but never enforced anywhere). |

### 3.2 Agentic-layer (OWASP Agentic/ASI Top 10, 2026)

All eleven items now have real code in `agentic.rs`/`supply_chain.rs` — none of it is reachable from `LLMSecurityLayer`, because `LLMSecurityLayer`'s API is still code-analysis-shaped (`&str -> Result<String>`) and has no tool-call/agent-identity/message concept at all. That's an architectural gap, not an oversight: bolting `ToolCallContext` onto `sanitize_code_for_llm`'s signature isn't meaningful. A caller building an agentic application uses `agentic::*` types directly today.

| Item | Status | Module |
|---|---|---|
| Goal/behavior hijacking | 🟡 Built, not wired | `agentic::GoalHijackGuard` |
| Tool misuse & exploitation | 🟡 Built, not wired | `agentic::ToolPolicyEngine` |
| Tool poisoning (MCP) | 🟡 Built, not wired | `agentic::McpToolScanner` + `supply_chain::SupplyChainRegistry` |
| Identity/privilege abuse | 🟡 Built, not wired | `agentic::PrivilegeGuard` |
| Memory/context poisoning | 🟡 Built, not wired | `agentic::MemoryGuard` |
| Insecure inter-agent comms | 🟠 Partial | `agentic::InterAgentGuard` — replay detection is real; signature verification is a caller-supplied closure by design (key management is out of scope for this crate). |
| Unexpected/insecure code execution | 🟡 Built, not wired | `agentic::CodeExecGuard` — dangerous-API keyword heuristic, not real sandboxing. |
| Cascading agent failures | 🟡 Built, not wired | `agentic::CircuitBreaker` / `RecursionGuard` |
| Inadequate guardrails/sandboxing | 🟠 Extension point | `agentic::ActionSandbox` trait + `DenyAllSandbox`/`PolicySandbox` — real OS-level isolation is explicitly out of scope. |
| Human-agent trust/over-reliance | 🟡 Built, not wired | `agentic::requires_human_confirmation` |
| Rogue agents/agentic supply chain | 🟡 Built, not wired | `supply_chain::SupplyChainRegistry` (`ArtifactKind::Agent`) |

### 3.3 Adversarial ML (MITRE ATLAS-aligned)

| Item | Status | Module | Note |
|---|---|---|---|
| Adversarial suffixes (GCG-style) | 🟠 Partial | `adversarial_ml::detect_adversarial_suffix` | Coarse symbol-density/out-of-dictionary heuristic; not wired into `layer.rs` either. Explicitly documented as a pre-filter, not a final answer — real detection needs perplexity under an actual LM. |
| Many-shot/long-context jailbreak | 🟢 Wired-in | `context::MultiTurnAnalyzer::analyze_many_shot` → `layer::detect_prompt_injection_in_context` | Live, but only via the separate `detect_prompt_injection_in_context` method — the plain `detect_prompt_injection` doesn't see it. |
| Crescendo/multi-turn escalation | 🟢 Wired-in | `context::MultiTurnAnalyzer::analyze_crescendo` → same path | Same caveat as above. |
| Glitch/anomalous tokens | 🟠 Extension point | `adversarial_ml::GlitchTokenList` | Ships empty by design; caller populates. |
| Model extraction/distillation theft | 🟡 Built, not wired | `adversarial_ml::QueryPatternProfile` | Real near-duplicate/query-rate heuristic; nothing in `layer.rs` feeds it query history. |
| Membership inference/training-data extraction | 🔴 None (trait only) | `adversarial_ml::TrainingDataLeakageAuditor` | Correctly out of reach for a client-side crate — this is intentional, not a missed step. |
| Model inversion | 🔴 None (trait only) | same trait | Same as above. |
| Adversarial-example evasion of this filter | 🟠 Partial | `tests/adaptive_attacks.rs` | Measured (ASR/FPR harness), not solved — by design. |

### 3.4 Input/obfuscation

| Item | Status | Note |
|---|---|---|
| Zero-width/invisible chars | 🟢 Wired-in | Unchanged from before — already solid. |
| **Tag block (`U+E0000–E007F`) + variation selectors** | 🔴 **Not implemented** | The plan called for extending hidden-Unicode detection to cover these; verified by grep — no such code exists anywhere in the repo. This is a genuine miss, not a wiring gap. |
| RTL/bidi override | 🟢 Wired-in | Unchanged — already solid. |
| Homoglyph/mixed-script (real confusables) | 🟡 Built, not wired | `confusables::ConfusablesDetector` is real and tested (skeleton mapping, per-word mixed-script check). The planned `DetectionEngine::detect_homoglyphs_v2` method was never added — verified by grep. The crate's default detection still only does whole-Unicode-range flagging via the original `detect_homoglyphs`. |
| Leetspeak/char substitution | 🟡 Built, not wired | Folded into `confusables::skeleton()` as designed, same wiring gap as above. |
| Encoding chains (decode+rescan) | 🟡 Built, not wired | `decode::Decoder` correctly decodes and rescans base64/hex/URL/HTML-entity/ROT13 (verified with real tests against unlabeled payloads) — but `LLMSecurityLayer` never calls it. An unlabeled base64 payload sent through `LLMSecurityLayer::detect_prompt_injection` today is caught only if `detect_encoding_layers`' marker-based heuristic fires; the real decoder sits unused unless the caller invokes `Decoder` directly. |
| Token stuffing/delimiter injection | 🔴 **Not generalized** | The plan called for variable-spacing-tolerant patterns; verified by diff — `patterns.rs` received no new pattern definitions in this round, only tests. Still the original brittle exact-repeat-count regexes. |
| Multimodal injection | 🟡 Built, not wired | `multimodal::MediaScanner` is real (alt-text/metadata/polyglot/trailing-data checks, all tested) but is a wholly separate entry point — `LLMSecurityLayer` is still text-`&str`-only. |
| Steganographic payloads | 🟡 Built, not wired | Same module, same caveat, plus the pre-existing coarse heuristics in `detection.rs` (unchanged). |
| Structured-format injection (JSON/XML/YAML/etc.) | 🟠 Partial | `decode::Decoder::scan_structured_values` does real JSON string-value extraction and rescanning (tested) — but it's additive, not a replacement: the original literal-token matching in `detection.rs::detect_context_injection` (`json_like.contains("\"ignore\"")`) is still what runs inside `detect_prompt_injection_safe`, unchanged. Both exist; only the weaker one is live by default. |

### 3.5 Data, privacy & content safety

| Item | Status | Module |
|---|---|---|
| PII detection/redaction | 🟡 Built, not wired | `pii::PiiScanner` — Luhn-validated credit cards, entropy-gated secrets, all correctly implemented and tested; no `LLMSecurityLayer` path touches it. |
| Secret/credential leakage in output | 🟡 Built, not wired | Same scanner, same caveat. |
| Harmful-content classification | 🟠 Extension point | `content_safety::ContentSafetyClassifier` trait, as scoped. |
| Toxicity/bias/fairness | 🟠 Extension point | Same trait. |
| Privacy-compliance hooks | 🟡 Built, not wired | `pii::classify_data_handling` / `DataHandlingTag` — real logic, unreachable from the facade. |
| Copyright/IP output leakage | 🟡 Built, not wired | `output_sink::verbatim_overlap_ngram_count` — real n-gram overlap heuristic, not called by anything. |
| Cross-tenant/session data bleed | 🟡 Built, not wired | `pii::scan_for_foreign_tenant_tags` — same caveat. |

### 3.6 Operational/defense-engineering

| Item | Status | Module | Note |
|---|---|---|---|
| Semantic/ML detection layer | 🟢 Wired-in | `semantic.rs` → `layer.rs` | The trait, verdict type, and lexical/semantic merge (with veto) are live in `detect_prompt_injection` whenever a classifier is registered. |
| Statefulness/multi-turn tracking | 🟢 Wired-in | `context.rs` → `layer::detect_prompt_injection_in_context` | Live, but again only via the separate context-aware method. |
| Real rate limiting/cost enforcement | 🟢 Wired-in | `rate_limit.rs` → `layer.rs` | Confirmed enforced, not just validated. |
| Adaptive-attack red-team harness + ASR/FPR metrics | 🟢 Wired-in (as a test gate) | `tests/adaptive_attacks.rs` | 6 lexical-corpus tests plus 4 coverage-breadth tests for confusables/MCP-scanning/PII, all passing; this is CI-enforced, not aspirational. |
| Observability/structured event schema | 🟡 Partial | `events.rs` | `SecurityEvent`/`SecurityEventSink` exist and `layer.rs` emits two event types (`InjectionDetected`, `RateLimitExceeded`) on block. Verified by grep: **no other module — not `agentic`, not `pii`, not `policy`, not `supply_chain` — ever constructs a `SecurityEvent`**, despite `events.rs` defining types for `ToolCallDenied`, `PiiRedacted`, `SystemPromptLeak`, `PolicyReloaded`, `CircuitBreakerTripped`, `ToolPoisoningSuspected`, and `SemanticVeto`. Those event types are currently unused dead schema. |
| Externalized/hot-updatable policy packs | 🟡 Built, not wired | `policy::PolicyStore`/`PolicyPack` | Hot-swap and scoring logic work (tested); `LLMSecurityLayer` has no `with_policy_store` method — that builder method described in the original plan was never added. |
| Fail-safe posture | 🟢 Wired-in | `failsafe.rs` → `layer.rs` | `LLMSecurityLayer` carries a `FailurePolicy` (default `FailClosed`), though nothing currently calls `failsafe::resolve` since no fallible pluggable component (besides the semantic classifier, which doesn't yet use it) needs it. |
| Internationalization of patterns | 🟡 Built, not wired | `i18n::detect_prompt_injection_multilingual` | Real, tested, 8-locale keyword sets — but it's a free function taking a `&DetectionEngine`, not a `LLMSecurityLayer` method; the default `detect_prompt_injection` is still English-only. |

---

## 4. Phase 6 — closing the integration gap

The single highest-leverage next step is **not** more detectors — it's wiring the 12 already-built, already-tested modules into `LLMSecurityLayer` so they're live by default (or via one obvious builder call), plus fixing the two items that were planned but never written at all.

**P0 — true gaps (code was never written, verify-confirmed):**
1. Extend hidden-Unicode detection to the Tag block (`U+E0000–E007F`) and variation selectors (`U+FE00–U+FE0F`).
2. Generalize the token-stuffing/delimiter regexes to tolerate variable spacing.

**P0 — integration (code exists, just needs a call site):**
3. Add `LLMSecurityLayer::post_llm_security_check_redacted` calling `pii::PiiScanner` — this was explicitly planned and explicitly not built; closing it is a small, contained change.
4. Wire `output_sink::SystemPromptLeakDetector` into `post_llm_security_check`.
5. Add `LLMSecurityLayer::with_policy_store` / route `policy::detect_prompt_injection_with_policy` into `detect_prompt_injection` when a store is registered.
6. Give `LLMSecurityLayer` an opt-in decode-and-rescan pass (`with_decoder`-style builder) so unlabeled encoded payloads are actually caught by default, not just by the marker heuristic.
7. Wire `confusables::ConfusablesDetector` in as `DetectionEngine::detect_homoglyphs_v2`, as originally scoped, and have `layer.rs` use it.

**P1 — observability completeness:**
8. Have `agentic.rs`, `pii.rs`, `policy.rs`, and `supply_chain.rs` accept an optional `Arc<dyn SecurityEventSink>` and actually emit the event types `events.rs` already defines for them (`ToolCallDenied`, `PiiRedacted`, `PolicyReloaded`, `CircuitBreakerTripped`, `ToolPoisoningSuspected`).

**P1 — architectural (larger, needs its own design pass):**
9. Decide whether `agentic::*` and `indirect::*` get a real integration surface on `LLMSecurityLayer` (e.g., a sibling `AgenticSecurityLayer` that composes `ToolPolicyEngine`/`McpToolScanner`/`SupplyChainRegistry`) or whether they're documented as intentionally standalone for agent-framework authors to compose directly. Either is defensible; leaving it undecided (today's state) means most users won't discover these modules exist.

---

## 5. Honest positioning, updated

The original analysis recommended right-sizing the README's claims before growing into them. That recommendation stands, with a sharper edge now: it would be equally misleading to update the README to say "the crate now includes PII redaction, agentic tool-call gating, and MCP scanning" without the qualifier "as separate opt-in modules you must wire in yourself." The honest one-line summary of where this crate stands today is: **a solid, tested toolbox covering most of the 2026 threat spectrum, with a default facade (`LLMSecurityLayer`) that only activates a fraction of it out of the box.** Phase 6 above is what turns "the crate has a PII scanner" into "the crate protects you from PII leakage by default."
