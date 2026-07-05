//! Unified supply-chain provenance registry, covering models/adapters/datasets, MCP
//! server identity pinning, and rogue-agent/agentic-supply-chain risk — one trust/
//! pinning state machine, several call sites, rather than duplicating the same
//! "is this artifact who it claims to be" logic per risk category.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::agentic::{PolicyAction, ToolCallVerdict};

/// What kind of artifact a provenance check is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArtifactKind {
    Model,
    Adapter,
    Dataset,
    McpServer,
    Agent,
}

/// A claim about an artifact's identity and integrity, to be checked against the
/// registry's trusted publishers and pinned content hashes.
#[derive(Debug, Clone)]
pub struct ArtifactProvenance {
    pub kind: ArtifactKind,
    pub artifact_id: String,
    pub publisher: String,
    /// Caller-supplied content hash (e.g. hex SHA-256) — hashing itself is left to
    /// the caller, keeping this crate dependency-free for that.
    pub content_hash: String,
    pub signature_valid: Option<bool>,
}

/// Registry of trusted publishers and pinned artifact hashes.
pub struct SupplyChainRegistry {
    trusted_publishers: Mutex<HashSet<String>>,
    known_hashes: Mutex<HashMap<(ArtifactKind, String), String>>,
}

impl Default for SupplyChainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyChainRegistry {
    pub fn new() -> Self {
        Self {
            trusted_publishers: Mutex::new(HashSet::new()),
            known_hashes: Mutex::new(HashMap::new()),
        }
    }

    pub fn trust_publisher(&self, publisher: &str) {
        self.trusted_publishers.lock().unwrap().insert(publisher.to_string());
    }

    pub fn pin_hash(&self, kind: ArtifactKind, artifact_id: &str, hash: &str) {
        self.known_hashes
            .lock()
            .unwrap()
            .insert((kind, artifact_id.to_string()), hash.to_string());
    }

    /// Verify a provenance claim:
    /// - `Deny` if a pinned hash exists and mismatches (tampering / "rug pull").
    /// - `RequireHumanApproval` if the publisher isn't trusted, or no pin exists yet
    ///   for a first-seen artifact.
    /// - `Allow` if the publisher is trusted and the hash matches (or is unpinned).
    pub fn verify(&self, prov: &ArtifactProvenance) -> ToolCallVerdict {
        let mut reasons = Vec::new();
        let key = (prov.kind.clone(), prov.artifact_id.clone());

        if let Some(pinned) = self.known_hashes.lock().unwrap().get(&key) {
            if pinned != &prov.content_hash {
                reasons.push(format!(
                    "content hash mismatch for {:?}/{}: pinned {} but got {}",
                    prov.kind, prov.artifact_id, pinned, prov.content_hash
                ));
                return ToolCallVerdict {
                    action: PolicyAction::Deny,
                    reasons,
                    risk_score: 90,
                };
            }
        } else {
            reasons.push(format!(
                "no pinned hash on file yet for {:?}/{}",
                prov.kind, prov.artifact_id
            ));
        }

        let publisher_trusted = self.trusted_publishers.lock().unwrap().contains(&prov.publisher);
        if !publisher_trusted {
            reasons.push(format!("publisher '{}' is not in the trusted set", prov.publisher));
            return ToolCallVerdict {
                action: PolicyAction::RequireHumanApproval,
                reasons,
                risk_score: 50,
            };
        }

        if prov.signature_valid == Some(false) {
            reasons.push("signature present but failed verification".to_string());
            return ToolCallVerdict {
                action: PolicyAction::Deny,
                reasons,
                risk_score: 95,
            };
        }

        if self
            .known_hashes
            .lock()
            .unwrap()
            .get(&key)
            .is_none()
        {
            return ToolCallVerdict {
                action: PolicyAction::RequireHumanApproval,
                reasons,
                risk_score: 40,
            };
        }

        ToolCallVerdict {
            action: PolicyAction::Allow,
            reasons: Vec::new(),
            risk_score: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance(hash: &str) -> ArtifactProvenance {
        ArtifactProvenance {
            kind: ArtifactKind::Model,
            artifact_id: "model-a".to_string(),
            publisher: "acme".to_string(),
            content_hash: hash.to_string(),
            signature_valid: None,
        }
    }

    #[test]
    fn untrusted_publisher_requires_human_approval() {
        let registry = SupplyChainRegistry::new();
        let verdict = registry.verify(&provenance("hash1"));
        assert_eq!(verdict.action, PolicyAction::RequireHumanApproval);
    }

    #[test]
    fn trusted_publisher_with_no_pin_requires_approval_on_first_sight() {
        let registry = SupplyChainRegistry::new();
        registry.trust_publisher("acme");
        let verdict = registry.verify(&provenance("hash1"));
        assert_eq!(verdict.action, PolicyAction::RequireHumanApproval);
    }

    #[test]
    fn trusted_publisher_with_matching_pinned_hash_is_allowed() {
        let registry = SupplyChainRegistry::new();
        registry.trust_publisher("acme");
        registry.pin_hash(ArtifactKind::Model, "model-a", "hash1");
        let verdict = registry.verify(&provenance("hash1"));
        assert_eq!(verdict.action, PolicyAction::Allow);
    }

    #[test]
    fn mismatched_pinned_hash_is_denied_even_for_trusted_publisher() {
        let registry = SupplyChainRegistry::new();
        registry.trust_publisher("acme");
        registry.pin_hash(ArtifactKind::Model, "model-a", "hash1");
        let verdict = registry.verify(&provenance("hash2-tampered"));
        assert_eq!(verdict.action, PolicyAction::Deny);
    }

    #[test]
    fn failed_signature_is_denied() {
        let registry = SupplyChainRegistry::new();
        registry.trust_publisher("acme");
        registry.pin_hash(ArtifactKind::Model, "model-a", "hash1");
        let mut prov = provenance("hash1");
        prov.signature_valid = Some(false);
        let verdict = registry.verify(&prov);
        assert_eq!(verdict.action, PolicyAction::Deny);
    }

    #[test]
    fn mcp_server_and_agent_kinds_use_separate_hash_namespaces() {
        let registry = SupplyChainRegistry::new();
        registry.trust_publisher("acme");
        registry.pin_hash(ArtifactKind::McpServer, "server-a", "hashA");
        registry.pin_hash(ArtifactKind::Agent, "server-a", "hashB");

        let mcp_prov = ArtifactProvenance {
            kind: ArtifactKind::McpServer,
            artifact_id: "server-a".to_string(),
            publisher: "acme".to_string(),
            content_hash: "hashA".to_string(),
            signature_valid: None,
        };
        assert_eq!(registry.verify(&mcp_prov).action, PolicyAction::Allow);

        let agent_prov = ArtifactProvenance {
            kind: ArtifactKind::Agent,
            artifact_id: "server-a".to_string(),
            publisher: "acme".to_string(),
            content_hash: "hashA".to_string(), // wrong hash for this namespace
            signature_valid: None,
        };
        assert_eq!(registry.verify(&agent_prov).action, PolicyAction::Deny);
    }
}
