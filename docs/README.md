# LLM Security Documentation

Comprehensive security layer for Large Language Model applications that prevents prompt injection, jailbreaking, and manipulation attacks.

## Documentation Structure

- **[Architecture](./architecture.md)** - Detection system design
- **[Getting Started](./getting-started.md)** - Quick start guide
- **[User Guide](./user-guide.md)** - Comprehensive usage patterns
- **[API Reference](./api-reference.md)** - Detailed API documentation
- **[Attack Vectors](./attack-vectors.md)** - Covered attack patterns
- **[Security Model](./security-model.md)** - Security guarantees
- **[Integration Guide](./integration.md)** - LLM provider integration
- **[FAQ](./faq.md)** - Frequently asked questions

## Quick Links

- [Why LLM Security?](./why-llm-security.md)
- [Use Cases](./use-cases.md)
- [Pattern Catalog](./pattern-catalog.md)
- [Best Practices](./best-practices.md)

## Overview

LLM Security provides 90+ detection patterns to protect AI applications from prompt injection, jailbreaking, and social engineering attacks.

### Key Features

- ✅ **90+ Detection Patterns**: Comprehensive attack coverage
- ✅ **Prompt Injection Prevention**: Blocks instruction override
- ✅ **Jailbreak Detection**: DAN, STAN, and other techniques
- ✅ **Output Validation**: Ensures responses aren't compromised
- ✅ **Unicode Attack Prevention**: Homoglyphs, zero-width, RTL
- ✅ **Semantic Cloaking**: Detects professional manipulation
- ✅ **Legal Manipulation**: Blocks false authorization claims

### Quick Example

```rust
use llm_security::{LLMSecurityLayer, LLMSecurityConfig};

fn main() -> Result<(), String> {
    let security = LLMSecurityLayer::new(LLMSecurityConfig::default());
    
    // Sanitize user code before sending to LLM
    let user_code = "function example() { return true; }";
    let safe_code = security.sanitize_code_for_llm(user_code)?;
    
    // Send to LLM...
    let llm_response = "Analysis: No vulnerabilities found.";
    
    // Validate LLM output
    security.validate_llm_output(llm_response)?;
    
    println!("✓ Security checks passed");
    Ok(())
}
```

## Attack Coverage

- Direct instruction injection
- Jailbreak techniques
- Hidden unicode attacks
- Comment-based injection
- Semantic cloaking
- Legal/auth manipulation
- Execution manipulation

## Support

- **GitHub**: https://github.com/redasgard/llm-security
- **Email**: hello@redasgard.com
- **Security Issues**: security@redasgard.com

## License

MIT License - See [LICENSE](../LICENSE)

