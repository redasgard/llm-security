---
name: Bug Report
about: Create a report to help us improve llm-security
title: '[BUG] '
labels: ['bug', 'needs-triage']
assignees: ''
---

## Bug Description
A clear and concise description of what the bug is.

## To Reproduce
Steps to reproduce the behavior:
1. Go to '...'
2. Call function '...'
3. Pass arguments '...'
4. See error

## Expected Behavior
A clear and concise description of what you expected to happen.

## Actual Behavior
A clear and concise description of what actually happened.

## Code Example
```rust
// Minimal code example that reproduces the issue
use llm_security::{LLMSecurityLayer, LLMSecurityConfig};

fn main() -> Result<(), String> {
    let security = LLMSecurityLayer::new(LLMSecurityConfig::default());
    
    // This should detect/block but doesn't (or vice versa)
    let result = security.detect_prompt_injection("your input here");
    println!("Result: {:?}", result);
    Ok(())
}
```

## Environment
- **OS**: [e.g. Ubuntu 22.04, Windows 11, macOS 13.0]
- **Rust Version**: [e.g. 1.70.0]
- **llm-security Version**: [e.g. 0.1.0]
- **LLM Model**: [e.g. GPT-4, Claude, Llama]
- **Architecture**: [e.g. x86_64, aarch64]

## Security Considerations
- [ ] This bug could be a security vulnerability
- [ ] This bug involves prompt injection attacks
- [ ] This bug involves jailbreak attempts
- [ ] This bug involves Unicode attacks
- [ ] This bug involves false positives/negatives

## Additional Context
Add any other context about the problem here.

## Checklist
- [ ] I have searched existing issues to avoid duplicates
- [ ] I have provided a minimal code example
- [ ] I have included environment details
- [ ] I have considered security implications
- [ ] I have read the [CONTRIBUTING.md](CONTRIBUTING.md) guide
