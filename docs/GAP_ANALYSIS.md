# LLM Security Gap Analysis & Threat Coverage Matrix

**Date:** 2026-07-05
**Scope:** The full spectrum of AI/LLM security threats as of mid-2026, mapped against what `llm-security` currently implements.
**Verdict at a glance:** The library is a competent **single-turn, English-text, regex/keyword prompt-injection filter** built for one narrow job — protecting a code-analysis LLM from manipulation. Measured against the 2026 threat landscape (agentic systems, MCP/tool use, RAG, multimodal, and adaptive attacks), it covers roughly **one of the modern risk categories, and that one only partially.** This document enumerates the whole surface so the roadmap is explicit.

---

## 1. How to read this matrix

Each threat is scored on two axes:

- **Coverage** — how much of the threat the library addresses today:
  - 🟢 **Covered** — a real, defensible mechanism exists.
  - 🟡 **Partial** — some detection exists but is shallow, evadable, or advisory-only.
  - 🔴 **None** — no mechanism at all.
- **Priority** — how much it matters for a library that markets itself as "the most comprehensive LLM security library": **P0** (table stakes / actively exploited), **P1** (important), **P2** (emerging / niche).

A recurring theme: the current engine is **lexical** (regex + substring + Unicode-range checks). Modern attacks are **semantic, multi-turn, multi-modal, and cross-component**. Published meta-analysis (2021–2026) shows lexical/static defenses are bypassed **>85% of the time** by adaptive attackers, so even the 🟢/🟡 items should be read as "raises the cost of the laziest attacks," not "solved."

---

## 2. Executive gap summary

| Domain | Categories | Covered 🟢 | Partial 🟡 | None 🔴 |
|---|---|---|---|---|
| Model-layer (OWASP LLM Top 10, 2025) | 10 | 0 | 3 | 7 |
| Agentic-layer (OWASP Agentic/ASI Top 10, 2026) | 10 | 0 | 0 | 10 |
| Adversarial ML / model theft (MITRE ATLAS) | 8 | 0 | 1 | 7 |
| Input/obfuscation techniques | 9 | 2 | 5 | 2 |
| Data, privacy & content safety | 7 | 0 | 1 | 6 |
| Operational / defense engineering | 8 | 0 | 2 | 6 |
| **Total** | **52** | **~4** | **~12** | **~36** |

The headline: **agentic security — the single fastest-growing attack surface of 2025–2026 — has zero coverage.** The library predates the tool-use/MCP era and is architected around a single `&str` in, `Result<String>` out. There is no concept of a tool, a memory store, a retrieved document, an agent identity, or a downstream sink.

---

## 3. Model-layer threats — OWASP Top 10 for LLM Applications (2025)

This is the baseline the library implicitly targets. It addresses parts of exactly one entry.

| ID | Threat | Coverage | Priority | Notes on current state & the gap |
|---|---|---|---|---|
| **LLM01** | Prompt Injection (direct) | 🟡 Partial | P0 | Regex/keyword detection of ~30 English phrases (`ignore previous instructions`, DAN/STAN, etc.). Catches naive, literal attempts. Misses paraphrase, role-play framing, obfuscated intent, and any language but English. No semantic model. |
| **LLM01** | Prompt Injection (**indirect / RAG / cross-document**) | 🔴 None | P0 | The dominant 2026 vector. Malicious instructions embedded in fetched web pages, PDFs, emails, tool descriptions, or DB rows. Library has no hook to scan retrieved/external content as a distinct trust tier — it only sees one already-assembled string. |
| **LLM02** | Sensitive Information Disclosure | 🔴 None | P0 | No PII/secret/credential detection in inputs or outputs. No system-prompt-leak detection. No redaction. |
| **LLM03** | Supply Chain | 🔴 None | P1 | No model provenance, no dependency/adapter/LoRA integrity, no dataset attestation, no MCP-server trust checks. |
| **LLM04** | Data & Model Poisoning | 🔴 None | P1 | Training/fine-tuning/RAG-store poisoning entirely out of scope. |
| **LLM05** | Improper Output Handling | 🟡 Partial | P0 | `validate_llm_output` regexes for a few "as instructed, I will ignore…" strings. Does **not** address the real risk: LLM output flowing unescaped into shells, SQL, HTML (XSS), SSRF, or file paths downstream. No output encoding/sink-awareness. |
| **LLM06** | Excessive Agency | 🔴 None | P1 | No notion of tools, permissions, or action gating. |
| **LLM07** | System Prompt Leakage | 🔴 None | P1 | `generate_secure_system_prompt` *adds* hardening text but never *detects* leakage of it in output. |
| **LLM08** | Vector & Embedding Weaknesses | 🔴 None | P1 | RAG/embedding-store attacks (poisoning, inversion, cross-tenant leakage) unaddressed. |
| **LLM09** | Misinformation / Hallucination | 🔴 None | P2 | No grounding, citation, or confidence checks. |
| **LLM10** | Unbounded Consumption (DoS/cost) | 🟡 Partial | P0 | `max_llm_calls_per_hour` and `max_code_size_bytes` exist as **config fields only** — the crate never enforces the rate limit (no counter, no clock). Size cap is real; rate limit is a no-op. Token-cost blowup, wallet-drain, and recursive amplification unhandled. |

---

## 4. Agentic-layer threats — OWASP Top 10 for Agentic Applications / ASI (2026)

Published Dec 2025; the fastest-moving area in the field. **Coverage across the board: none.** These are listed so the roadmap can prioritize — a library claiming comprehensiveness in 2026 cannot omit the agentic layer.

> Note: category numbering/titling still varies between OWASP drafts and secondary sources; the set below reflects the risks consistently named across them. Treat IDs as indicative.

| Threat | Coverage | Priority | What's needed |
|---|---|---|---|
| **Agent Goal / Behavior Hijacking** | 🔴 None | P0 | Detect objective drift; validate that planned actions match the sanctioned task. |
| **Tool Misuse & Exploitation** | 🔴 None | P0 | Tool-call allow-listing, argument validation, side-effect classification (read vs. write vs. destructive). |
| **Tool Poisoning (MCP)** | 🔴 None | P0 | Scan MCP/tool **descriptions and schemas** for injected instructions before they enter context; pin/verify server identity. |
| **Identity & Privilege Abuse** | 🔴 None | P0 | Per-agent identity, credential scoping, no ambient/inherited-credential reuse. |
| **Memory & Context Poisoning** | 🔴 None | P0 | Integrity/provenance on persistent memory and RAG writes; quarantine untrusted writes. |
| **Insecure Inter-Agent Communication** | 🔴 None | P1 | Authenticate, sign, and replay-protect agent-to-agent messages. |
| **Unexpected / Insecure Code Execution** | 🔴 None | P0 | Sandbox generated code; the library's "must execute to analyze" detection is a keyword string, not a control. |
| **Cascading Agent Failures** | 🔴 None | P1 | Circuit breakers, blast-radius limits, loop/recursion detection. |
| **Inadequate Guardrails & Sandboxing** | 🔴 None | P0 | Runtime action boundaries, not just input scanning. |
| **Human-Agent Trust / Over-reliance** | 🔴 None | P1 | Confidence signaling, human-in-the-loop gates for high-impact actions. |
| **Rogue / Misaligned Agents & Supply Chain** | 🔴 None | P1 | Behavioral attestation, agent provenance. |

---

## 5. Adversarial ML & model-theft (MITRE ATLAS-aligned)

| Threat | Coverage | Priority | Gap |
|---|---|---|---|
| Gradient/optimization suffixes (e.g. GCG adversarial suffixes) | 🔴 None | P1 | Random-looking suffix tokens defeat regex entirely; needs perplexity/anomaly scoring. |
| Many-shot / long-context jailbreak | 🔴 None | P0 | Fill the context with fake dialog turns to override alignment — invisible to per-string phrase matching. |
| Crescendo / multi-turn escalation | 🔴 None | P0 | Attack spread across turns; library is **stateless per call** and cannot see conversation history. |
| Glitch / anomalous-token attacks | 🔴 None | P2 | Tokenizer-level exploits. |
| Model extraction / distillation theft | 🔴 None | P1 | No query-pattern anomaly detection. |
| Membership inference / training-data extraction | 🔴 None | P1 | No output-similarity or memorization checks. |
| Model inversion | 🔴 None | P2 | Out of scope today. |
| Adversarial examples (classifier evasion of *this* filter) | 🟡 Partial | P0 | Unicode normalization + leetspeak handling raise the bar slightly, but the small hardcoded substitution set is trivially bypassed (spacing, synonyms, non-Latin scripts, invisible vari/selectors). |

---

## 6. Input manipulation & obfuscation (the library's home turf)

This is where the crate is strongest — but even here, most items are 🟡 because detection is shallow.

| Technique | Coverage | Priority | Assessment |
|---|---|---|---|
| Zero-width / invisible characters | 🟢 Covered | P1 | Detected and stripped in `normalize_unicode`. Solid. **Gap:** doesn't cover Unicode **Tag** block (`U+E0000–E007F`) used for invisible instruction smuggling, nor variation selectors. |
| RTL/LTR override (bidi) | 🟢 Covered | P1 | The 5 bidi control chars are detected. Good. |
| Homoglyph / mixed-script | 🟡 Partial | P1 | Flags whole Unicode *ranges* (Cyrillic/Greek/fullwidth) — high false-positive risk for legitimately multilingual input, and no actual skeleton/confusable mapping (UTS #39). |
| Leetspeak / char substitution | 🟡 Partial | P2 | Only ~4 hardcoded words (`1gn0r3`, etc.). Not generalizable. |
| Base64 / hex / ROT13 / URL / HTML-entity encoding | 🟡 Partial | P0 | **Flags the presence of encoding *keywords/markers* but never decodes and re-scans.** A payload that is simply base64 with no `base64:` label passes clean. This is a core evasion gap. |
| Token stuffing / delimiter injection | 🟡 Partial | P1 | Regex for runs of `#`/`=`/`*` and some delimiter escapes (`<\|im_end\|>`). Brittle to spacing/variants. |
| Multimodal injection (image/audio/PDF-embedded text) | 🔴 None | P0 | 2026 reality: instructions hidden in images, alt-text, audio, document metadata. Library is text-`&str` only. |
| Steganographic payloads | 🟡 Partial | P2 | Heuristics for alternating-case / spacing / comment-base64. Noisy and easily tuned around. |
| Structured-format injection (JSON/XML/YAML/template/SQL/cmd) | 🟡 Partial | P1 | `detect_context_injection` looks for literal `{{ignore}}`, `<bypass>`, backticks, `$(`. Extremely narrow; real structured attacks won't use those exact tokens. The `code.contains("pr") && OR/AND` SQL heuristic is essentially a false-positive generator. |

---

## 7. Data, privacy & content safety

| Threat | Coverage | Priority | Gap |
|---|---|---|---|
| PII detection / redaction (input & output) | 🔴 None | P0 | No detector for emails, SSNs, keys, tokens, credentials. |
| Secret/credential leakage in output | 🔴 None | P0 | Nothing prevents the model echoing API keys or system-prompt secrets. |
| Harmful-content classification (CSAM, weapons, self-harm, etc.) | 🔴 None | P1 | No content-safety taxonomy — this is a moderation gap, distinct from injection. |
| Toxicity / bias / fairness | 🔴 None | P2 | Out of scope. |
| Privacy compliance hooks (GDPR/CCPA right-to-delete, data residency) | 🔴 None | P2 | No data-handling metadata. |
| Copyright/IP output leakage | 🟡 Partial | P2 | Ironically, it *detects* attacker phrases like "copyright protected" as manipulation, but does nothing about the model actually **reproducing** copyrighted training data. |
| Cross-tenant / session data bleed | 🔴 None | P1 | No isolation primitives. |

---

## 8. Operational & defense-engineering gaps

These are about *how the library defends*, not individual attacks — and they cap the ceiling of everything above.

| Concern | Coverage | Priority | Gap |
|---|---|---|---|
| Detection method: **semantic** (embeddings/ML classifier/LLM-judge) | 🔴 None | P0 | Purely lexical. The entire field has moved to model-based guardrails because regex cannot generalize. This is the single highest-leverage upgrade. |
| Statefulness (multi-turn / session context) | 🔴 None | P0 | Stateless per call → structurally blind to crescendo, many-shot, and cross-turn attacks. |
| Rate limiting / cost control (actual enforcement) | 🔴 None | P0 | Config field exists; **no enforcement code**. Misleading as-is. |
| Adaptive-attack resistance / red-team test harness | 🔴 None | P1 | No benchmark suite (e.g. against known jailbreak corpora), no ASR measurement, no false-positive metrics despite the README's "100% coverage" badge. |
| Observability / audit trail / SIEM integration | 🟡 Partial | P1 | `tracing` feature exists but there's no structured security event schema, no severity taxonomy for downstream alerting. |
| Configurable policy / allow-deny lists / severity tuning | 🟡 Partial | P1 | Some config (strict mode, thresholds) but no externalized, updatable policy/pattern set — new attacks require a code release. |
| Fail-safe posture & bypass on error | 🔴 None | P1 | No documented fail-closed vs. fail-open behavior; error paths return raw strings. |
| Internationalization | 🔴 None | P1 | English-only pattern set; non-English injections sail through. |

---

## 9. Structural limitations (root causes)

Most gaps above trace to four architectural facts:

1. **Lexical, not semantic.** Regex + substring + Unicode-range checks. Cannot understand intent, paraphrase, or novel phrasing. Documented adaptive-bypass rates exceed 85%.
2. **Stateless & single-string.** The API is `&str → Result<String>`. There is no session, no conversation, no trust tiers (user vs. retrieved vs. tool), no downstream sink. This forecloses indirect injection, multi-turn attacks, and all agentic controls by construction.
3. **Text-only, English-only.** No multimodal input, no decode-and-rescan, no i18n.
4. **Detection-only, no runtime control.** It scans strings; it cannot sandbox code, gate a tool call, scope a credential, or enforce a rate limit. Agentic security is fundamentally about *action control*, which this library has no surface for.

---

## 10. Prioritized remediation roadmap

**P0 — close the credibility gaps (the claims-vs-reality items):**
1. **Actually enforce** the rate limit / consumption controls, or remove the field and the DoS claim.
2. **Decode-then-rescan** for base64/hex/URL/entity layers (recursively, bounded depth) instead of keyword-flagging.
3. **Indirect-injection surface:** add a distinct API for scanning *untrusted retrieved content* (RAG/tool output/web) as a separate trust tier.
4. **Semantic detection layer:** integrate an embedding-similarity or small-classifier/LLM-judge option behind a feature flag; keep regex as a cheap pre-filter.
5. **Multi-turn state:** accept conversation history so crescendo/many-shot attacks are visible.
6. **Output sink-awareness:** helpers for escaping LLM output bound for shell/SQL/HTML/URL sinks (the real LLM05).
7. **PII/secret detection & redaction** for inputs and outputs.

**P1 — enter the agentic era:**
8. Tool-call gating: allow-lists, argument schemas, side-effect classification.
9. MCP tool-description scanning + server-identity pinning.
10. Memory/RAG-write provenance & quarantine.
11. A red-team benchmark harness reporting ASR and false-positive rate (retire the unearned "100% coverage" badge).
12. Externalized, hot-updatable policy/pattern packs.
13. i18n pattern coverage.

**P2 — completeness:**
14. Multimodal input scanning hooks.
15. Content-safety taxonomy integration.
16. Model-extraction / anomaly-query detection.
17. Confusables mapping via UTS #39 skeletons (replace range-flagging).

---

## 11. Honest positioning

The most useful near-term change may be **narrowing the marketing to match reality**: this is a solid *lexical prompt-injection pre-filter for single-turn, English, text-only, code-analysis pipelines* — a legitimate defense-in-depth layer. The README's "most comprehensive LLM security library" and "100% coverage" claims are not defensible against the 2026 threat model documented above and invite exactly the kind of adaptive attacker who will find the 85% that gets through. Right-size the claim, then execute the P0 roadmap to grow into it.

---

### Sources / frameworks referenced
- OWASP Top 10 for LLM Applications (2025) — model-layer risk taxonomy.
- OWASP Top 10 for Agentic Applications / ASI (2026, published Dec 2025) — agentic risk taxonomy.
- MITRE ATLAS — adversarial-ML tactics & techniques (model theft, evasion, poisoning).
- Academic meta-analyses of prompt-injection & jailbreak robustness (2021–2026), reporting >85% adaptive-attack success against static defenses.
- MCP threat catalogs (tool poisoning, parasitic tool chains, indirect injection via tool descriptions), 2025–2026.
