use llm_security::{ValidationEngine, LLMSecurityConfig};

#[test]
fn test_validation_timestamp() {
    let config = LLMSecurityConfig::default();
    let engine = ValidationEngine::new(config);
    let result = engine.validate_output_comprehensive("There are two r's in 'strawberry'.");
    
    assert!(result.validation_timestamp > 0);
    // Check if timestamp is recent (within last hour) - simplified check
    let now = chrono::Utc::now().timestamp() as u64;
    assert!(result.validation_timestamp <= now);
    assert!(result.validation_timestamp > now - 3600);
}
