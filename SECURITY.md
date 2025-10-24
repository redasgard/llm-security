# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security bugs seriously. We appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contributions.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**security@redasgard.com**

### What to Include

When reporting a security vulnerability, please include:

1. **Description**: A clear description of the vulnerability
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Impact**: Description of the potential impact
4. **Environment**: OS, Rust version, LLM model, and any other relevant details
5. **Proof of Concept**: If possible, include a minimal code example that demonstrates the issue

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Regular Updates**: We will keep you informed of our progress
- **Resolution**: We will work with you to resolve the issue and coordinate disclosure

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution**: Within 30 days (depending on complexity)

## Security Considerations

### LLM Security Specific Concerns

When reporting vulnerabilities, please consider:

1. **Prompt Injection**: Successful bypass of injection detection
2. **Jailbreak Attacks**: Successful jailbreak attempts
3. **Unicode Attacks**: Bypass through Unicode manipulation
4. **False Positives**: Legitimate inputs being blocked
5. **Performance**: DoS through resource exhaustion
6. **Memory Safety**: Unsafe memory operations or buffer overflows

### Attack Vectors

Common attack vectors to test:

- **Direct Injection**: "Ignore previous instructions"
- **Jailbreak Techniques**: DAN, STAN, developer mode
- **Unicode Homoglyphs**: Visually similar characters
- **Zero-Width Characters**: Hidden characters
- **RTL Override**: Right-to-left text manipulation
- **Encoding Attacks**: URL encoding, HTML entities
- **Social Engineering**: Professional-sounding manipulation
- **Semantic Cloaking**: Disguised attack patterns

## Security Best Practices

### For Users

1. **Always validate inputs** before sending to LLMs
2. **Use the library correctly** according to documentation
3. **Implement additional layers** of security
4. **Keep the library updated** to the latest version
5. **Monitor for security advisories**
6. **Test with your specific LLM models**

### For Developers

1. **Test with malicious inputs** regularly
2. **Implement defense in depth**
3. **Use the library correctly** according to documentation
4. **Consider additional validation** for critical applications
5. **Monitor security updates**
6. **Test with various LLM models**

## Security Features

### Built-in Protections

- **90+ Attack Patterns**: Comprehensive pattern matching
- **Multi-Layer Detection**: Input sanitization and output validation
- **Unicode Protection**: Homoglyph and zero-width character detection
- **Jailbreak Prevention**: DAN, STAN, and other jailbreak techniques
- **Memory Safety**: Rust's memory safety guarantees
- **Configurable Security**: Adjustable security levels

### Additional Recommendations

- **Input Sanitization**: Sanitize user input before validation
- **Output Validation**: Validate LLM responses
- **Rate Limiting**: Implement rate limiting for LLM calls
- **Logging**: Log security events for monitoring
- **Regular Updates**: Keep dependencies and the library updated
- **Model Testing**: Test with your specific LLM models

## Security Updates

### How We Handle Security Issues

1. **Assessment**: We assess the severity and impact
2. **Fix Development**: We develop a fix in private
3. **Testing**: We thoroughly test the fix
4. **Release**: We release the fix with a security advisory
5. **Disclosure**: We coordinate disclosure with reporters

### Security Advisories

Security advisories are published on:

- **GitHub Security Advisories**: https://github.com/redasgard/llm-security/security/advisories
- **Crates.io**: Security notices in release notes
- **Email**: Subscribers to security@redasgard.com

## Responsible Disclosure

We follow responsible disclosure practices:

1. **Private Reporting**: Report vulnerabilities privately first
2. **Coordinated Disclosure**: We coordinate disclosure timing
3. **Credit**: We give credit to security researchers
4. **No Legal Action**: We won't take legal action against good faith research

## Security Research

### Guidelines for Security Researchers

- **Test Responsibly**: Don't test on production systems
- **Respect Privacy**: Don't access or modify data
- **Report Promptly**: Report findings as soon as possible
- **Follow Guidelines**: Follow this security policy

### Scope

**In Scope:**
- Prompt injection bypasses
- Jailbreak technique bypasses
- Unicode manipulation attacks
- False positive issues
- Memory safety issues
- Performance DoS attacks

**Out of Scope:**
- Social engineering attacks
- Physical security issues
- Issues in dependencies (report to their maintainers)
- Issues in applications using this library
- Issues in LLM models themselves

## Contact

For security-related questions or to report vulnerabilities:

- **Email**: security@redasgard.com
- **PGP Key**: Available upon request
- **Response Time**: Within 48 hours

## Acknowledgments

We thank the security researchers who help keep our software secure. Security researchers who follow responsible disclosure practices will be acknowledged in our security advisories.

## Legal

By reporting a security vulnerability, you agree to:

1. **Not disclose** the vulnerability publicly until we've had a chance to address it
2. **Not access or modify** data that doesn't belong to you
3. **Not disrupt** our services or systems
4. **Act in good faith** to avoid privacy violations, destruction of data, and interruption or degradation of our services

Thank you for helping keep LLM Security and our users safe! 🤖🛡️
