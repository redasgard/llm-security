# Integration Guide - LLM Security

## Overview

This guide covers integrating the LLM Security module with various systems, platforms, and tools. The module is designed to be flexible and work with existing security infrastructure.

## Integration Patterns

### 1. API Integration

#### REST API Server

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use warp::Filter;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct SecurityRequest {
    input: String,
    user_id: Option<String>,
    session_id: Option<String>,
}

#[derive(Serialize)]
struct SecurityResponse {
    is_secure: bool,
    threats: Vec<Threat>,
    confidence: f64,
    analysis_time: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true)
        .with_output_validation(true);

    let engine = SecurityEngine::with_config(config);

    // Create API routes
    let security_route = warp::path("api")
        .and(warp::path("security"))
        .and(warp::path("analyze"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: SecurityRequest| {
            let engine = engine.clone();
            async move {
                match engine.analyze_input(&request.input).await {
                    Ok(analysis) => {
                        let response = SecurityResponse {
                            is_secure: analysis.is_secure(),
                            threats: analysis.threats().to_vec(),
                            confidence: analysis.confidence(),
                            analysis_time: analysis.analysis_time().as_millis() as u64,
                        };
                        Ok(warp::reply::json(&response))
                    }
                    Err(e) => {
                        Err(warp::reject::custom(SecurityError::from(e)))
                    }
                }
            }
        });

    warp::serve(security_route).run(([0, 0, 0, 0], 8080)).await;
    Ok(())
}
```

#### GraphQL API

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use juniper::{EmptyMutation, EmptySubscription, RootNode, FieldResult};

type Schema = RootNode<'static, Query, EmptyMutation, EmptySubscription>;

struct Query;

#[juniper::object]
impl Query {
    async fn analyze_input(&self, input: String) -> FieldResult<SecurityAnalysis> {
        let config = SecurityConfig::new()
            .with_prompt_injection_detection(true)
            .with_jailbreak_detection(true)
            .with_unicode_attack_detection(true);

        let engine = SecurityEngine::with_config(config);
        let analysis = engine.analyze_input(&input).await?;
        Ok(analysis)
    }

    async fn validate_output(&self, output: String) -> FieldResult<ValidationResult> {
        let config = SecurityConfig::new()
            .with_output_validation(true);

        let engine = SecurityEngine::with_config(config);
        let validation = engine.validate_output(&output).await?;
        Ok(validation)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = Schema::new(Query, EmptyMutation, EmptySubscription);
    // Set up GraphQL server
    Ok(())
}
```

### 2. Webhook Integration

#### Outbound Webhooks

```rust
use llm_security::{SecurityEngine, SecurityConfig, WebhookConfig};
use reqwest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Configure webhook
    let webhook_config = WebhookConfig::new()
        .with_url("https://your-system.com/webhook".to_string())
        .with_secret("webhook-secret".to_string())
        .with_events(vec![
            "threat.detected".to_string(),
            "threat.mitigated".to_string(),
            "analysis.completed".to_string(),
        ]);

    engine.configure_webhook(webhook_config).await?;

    // Analyze input
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    if !analysis.is_secure() {
        // Webhook will be automatically triggered
        println!("Threats detected: {}", analysis.threats().len());
    }

    Ok(())
}
```

#### Inbound Webhooks

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use warp::Filter;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct WebhookRequest {
    event: String,
    data: serde_json::Value,
    timestamp: u64,
    signature: String,
}

#[derive(Serialize)]
struct WebhookResponse {
    status: String,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Create webhook endpoint
    let webhook_route = warp::path("webhook")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |request: WebhookRequest| {
            let engine = engine.clone();
            async move {
                // Verify webhook signature
                if !verify_webhook_signature(&request) {
                    return Ok(warp::reply::json(&WebhookResponse {
                        status: "error".to_string(),
                        message: "Invalid signature".to_string(),
                    }));
                }

                // Process webhook event
                match request.event.as_str() {
                    "threat.detected" => {
                        // Handle threat detection event
                        println!("Threat detected: {:?}", request.data);
                    }
                    "threat.mitigated" => {
                        // Handle threat mitigation event
                        println!("Threat mitigated: {:?}", request.data);
                    }
                    _ => {
                        println!("Unknown event: {}", request.event);
                    }
                }

                Ok(warp::reply::json(&WebhookResponse {
                    status: "success".to_string(),
                    message: "Webhook processed".to_string(),
                }))
            }
        });

    warp::serve(webhook_route).run(([0, 0, 0, 0], 8080)).await;
    Ok(())
}

fn verify_webhook_signature(request: &WebhookRequest) -> bool {
    // Implement webhook signature verification
    true
}
```

### 3. Database Integration

#### PostgreSQL Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use sqlx::PgPool;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SecurityEvent {
    id: String,
    event_type: String,
    input: String,
    threats: Vec<Threat>,
    confidence: f64,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Connect to PostgreSQL
    let pool = PgPool::connect("postgresql://user:pass@localhost/llm_security").await?;

    // Create security event table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS security_events (
            id UUID PRIMARY KEY,
            event_type VARCHAR NOT NULL,
            input TEXT NOT NULL,
            threats JSONB NOT NULL,
            confidence FLOAT NOT NULL,
            timestamp TIMESTAMP WITH TIME ZONE NOT NULL
        )
        "#
    )
    .execute(&pool)
    .await?;

    // Analyze input and store results
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    let security_event = SecurityEvent {
        id: uuid::Uuid::new_v4().to_string(),
        event_type: "threat_analysis".to_string(),
        input: input.to_string(),
        threats: analysis.threats().to_vec(),
        confidence: analysis.confidence(),
        timestamp: chrono::Utc::now(),
    };

    // Store in database
    sqlx::query(
        r#"
        INSERT INTO security_events (id, event_type, input, threats, confidence, timestamp)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#
    )
    .bind(&security_event.id)
    .bind(&security_event.event_type)
    .bind(&security_event.input)
    .bind(&serde_json::to_value(&security_event.threats)?)
    .bind(security_event.confidence)
    .bind(security_event.timestamp)
    .execute(&pool)
    .await?;

    println!("Security event stored: {}", security_event.id);
    Ok(())
}
```

#### MongoDB Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use mongodb::{Client, Collection};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SecurityEvent {
    #[serde(rename = "_id")]
    id: Option<mongodb::bson::oid::ObjectId>,
    event_type: String,
    input: String,
    threats: Vec<Threat>,
    confidence: f64,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Connect to MongoDB
    let client = Client::with_uri_str("mongodb://localhost:27017").await?;
    let db = client.database("llm_security");
    let collection: Collection<SecurityEvent> = db.collection("security_events");

    // Analyze input and store results
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    let security_event = SecurityEvent {
        id: None,
        event_type: "threat_analysis".to_string(),
        input: input.to_string(),
        threats: analysis.threats().to_vec(),
        confidence: analysis.confidence(),
        timestamp: chrono::Utc::now(),
    };

    // Store in database
    collection.insert_one(security_event, None).await?;

    println!("Security event stored in MongoDB");
    Ok(())
}
```

### 4. Message Queue Integration

#### Apache Kafka Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use kafka::producer::{Producer, Record};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SecurityMessage {
    event_type: String,
    input: String,
    threats: Vec<Threat>,
    confidence: f64,
    timestamp: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Create Kafka producer
    let producer = Producer::from_hosts(vec!["localhost:9092".to_string()])
        .create()
        .unwrap();

    // Analyze input and publish to Kafka
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    let security_message = SecurityMessage {
        event_type: "threat_analysis".to_string(),
        input: input.to_string(),
        threats: analysis.threats().to_vec(),
        confidence: analysis.confidence(),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    // Publish to Kafka
    let record = Record::from_value("security-events", &serde_json::to_string(&security_message)?);
    producer.send(&record)?;

    println!("Security message published to Kafka");
    Ok(())
}
```

#### RabbitMQ Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use lapin::{Connection, ConnectionProperties, Channel, ExchangeKind};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SecurityMessage {
    event_type: String,
    input: String,
    threats: Vec<Threat>,
    confidence: f64,
    timestamp: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Connect to RabbitMQ
    let connection = Connection::connect(
        "amqp://guest:guest@localhost:5672",
        ConnectionProperties::default(),
    ).await?;

    let channel = connection.create_channel().await?;

    // Declare exchange
    channel.exchange_declare(
        "security_events",
        ExchangeKind::Topic,
        lapin::options::ExchangeDeclareOptions::default(),
        lapin::types::FieldTable::default(),
    ).await?;

    // Analyze input and publish to RabbitMQ
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    let security_message = SecurityMessage {
        event_type: "threat_analysis".to_string(),
        input: input.to_string(),
        threats: analysis.threats().to_vec(),
        confidence: analysis.confidence(),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    // Publish to RabbitMQ
    channel.basic_publish(
        "security_events",
        "threat.analysis",
        lapin::options::BasicPublishOptions::default(),
        &serde_json::to_vec(&security_message)?,
        lapin::BasicProperties::default(),
    ).await?;

    println!("Security message published to RabbitMQ");
    Ok(())
}
```

## Cloud Platform Integration

### 1. AWS Integration

#### AWS Lambda Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use lambda_runtime::{handler_fn, Context, Error};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct LambdaRequest {
    input: String,
    user_id: Option<String>,
    session_id: Option<String>,
}

#[derive(Serialize)]
struct LambdaResponse {
    is_secure: bool,
    threats: Vec<Threat>,
    confidence: f64,
    analysis_time: u64,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    let handler = handler_fn(move |request: LambdaRequest, _: Context| {
        let engine = engine.clone();
        async move {
            match engine.analyze_input(&request.input).await {
                Ok(analysis) => {
                    let response = LambdaResponse {
                        is_secure: analysis.is_secure(),
                        threats: analysis.threats().to_vec(),
                        confidence: analysis.confidence(),
                        analysis_time: analysis.analysis_time().as_millis() as u64,
                    };
                    Ok(response)
                }
                Err(e) => {
                    Err(Error::from(e))
                }
            }
        }
    });

    lambda_runtime::run(handler).await?;
    Ok(())
}
```

#### AWS S3 Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use aws_sdk_s3::Client as S3Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SecurityReport {
    timestamp: chrono::DateTime<chrono::Utc>,
    total_requests: u64,
    secure_requests: u64,
    threat_requests: u64,
    threats_by_type: std::collections::HashMap<String, u64>,
    average_confidence: f64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Create S3 client
    let s3_config = aws_config::load_from_env().await;
    let s3_client = S3Client::new(&s3_config);

    // Generate security report
    let security_report = SecurityReport {
        timestamp: chrono::Utc::now(),
        total_requests: 1000,
        secure_requests: 950,
        threat_requests: 50,
        threats_by_type: {
            let mut map = std::collections::HashMap::new();
            map.insert("prompt_injection".to_string(), 30);
            map.insert("jailbreak".to_string(), 15);
            map.insert("unicode_attack".to_string(), 5);
            map
        },
        average_confidence: 0.85,
    };

    // Upload to S3
    let report_json = serde_json::to_string(&security_report)?;
    s3_client
        .put_object()
        .bucket("llm-security-reports")
        .key(format!("reports/{}.json", security_report.timestamp.format("%Y-%m-%d")))
        .body(report_json.into())
        .send()
        .await?;

    println!("Security report uploaded to S3");
    Ok(())
}
```

### 2. Azure Integration

#### Azure Functions Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use azure_functions::{FunctionApp, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct AzureRequest {
    input: String,
    user_id: Option<String>,
    session_id: Option<String>,
}

#[derive(Serialize)]
struct AzureResponse {
    is_secure: bool,
    threats: Vec<Threat>,
    confidence: f64,
    analysis_time: u64,
}

#[azure_functions::function]
async fn analyze_security(req: HttpRequest) -> HttpResponse {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    let request: AzureRequest = match req.json().await {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::bad_request()
                .json(serde_json::json!({"error": format!("Invalid request: {}", e)}));
        }
    };

    match engine.analyze_input(&request.input).await {
        Ok(analysis) => {
            let response = AzureResponse {
                is_secure: analysis.is_secure(),
                threats: analysis.threats().to_vec(),
                confidence: analysis.confidence(),
                analysis_time: analysis.analysis_time().as_millis() as u64,
            };
            HttpResponse::ok().json(response)
        }
        Err(e) => {
            HttpResponse::internal_server_error()
                .json(serde_json::json!({"error": format!("Analysis failed: {}", e)}))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = FunctionApp::new()
        .function(analyze_security);
    
    app.run().await?;
    Ok(())
}
```

### 3. Google Cloud Integration

#### Google Cloud Functions Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct CloudFunctionRequest {
    input: String,
    user_id: Option<String>,
    session_id: Option<String>,
}

#[derive(Serialize)]
struct CloudFunctionResponse {
    is_secure: bool,
    threats: Vec<Threat>,
    confidence: f64,
    analysis_time: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Handle Cloud Function request
    let request: CloudFunctionRequest = serde_json::from_str(&std::env::var("REQUEST_BODY")?)?;
    
    match engine.analyze_input(&request.input).await {
        Ok(analysis) => {
            let response = CloudFunctionResponse {
                is_secure: analysis.is_secure(),
                threats: analysis.threats().to_vec(),
                confidence: analysis.confidence(),
                analysis_time: analysis.analysis_time().as_millis() as u64,
            };
            println!("{}", serde_json::to_string(&response)?);
        }
        Err(e) => {
            eprintln!("Analysis failed: {}", e);
        }
    }

    Ok(())
}
```

## Security Tool Integration

### 1. SIEM Integration

#### Splunk Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct SplunkEvent {
    time: u64,
    source: String,
    sourcetype: String,
    index: String,
    event: serde_json::Value,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Create Splunk client
    let client = Client::new();
    let splunk_url = "https://splunk.company.com:8088/services/collector/event";
    let splunk_token = "your-splunk-token";

    // Analyze input and send to Splunk
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    if !analysis.is_secure() {
        let splunk_event = SplunkEvent {
            time: chrono::Utc::now().timestamp() as u64,
            source: "llm-security".to_string(),
            sourcetype: "llm_security".to_string(),
            index: "security".to_string(),
            event: serde_json::json!({
                "input": input,
                "threats": analysis.threats(),
                "confidence": analysis.confidence(),
                "analysis_time": analysis.analysis_time().as_millis(),
            }),
        };

        client
            .post(splunk_url)
            .header("Authorization", format!("Splunk {}", splunk_token))
            .json(&splunk_event)
            .send()
            .await?;

        println!("Security event sent to Splunk");
    }

    Ok(())
}
```

#### Elastic SIEM Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ElasticEvent {
    timestamp: chrono::DateTime<chrono::Utc>,
    input: String,
    threats: Vec<Threat>,
    confidence: f64,
    analysis_time: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Create Elastic client
    let client = Client::new();
    let elastic_url = "https://elastic.company.com:9200/llm-security/_doc";
    let elastic_username = "elastic";
    let elastic_password = "password";

    // Analyze input and send to Elastic
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    if !analysis.is_secure() {
        let elastic_event = ElasticEvent {
            timestamp: chrono::Utc::now(),
            input: input.to_string(),
            threats: analysis.threats().to_vec(),
            confidence: analysis.confidence(),
            analysis_time: analysis.analysis_time().as_millis() as u64,
        };

        client
            .post(elastic_url)
            .basic_auth(elastic_username, Some(elastic_password))
            .json(&elastic_event)
            .send()
            .await?;

        println!("Security event sent to Elastic");
    }

    Ok(())
}
```

### 2. SOAR Integration

#### Phantom Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct PhantomEvent {
    label: String,
    container: String,
    source_data_identifier: String,
    data: serde_json::Value,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Create Phantom client
    let client = Client::new();
    let phantom_url = "https://phantom.company.com/rest/container";
    let phantom_token = "your-phantom-token";

    // Analyze input and send to Phantom
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    if !analysis.is_secure() {
        let phantom_event = PhantomEvent {
            label: "LLM Security Threat".to_string(),
            container: "LLM Security".to_string(),
            source_data_identifier: uuid::Uuid::new_v4().to_string(),
            data: serde_json::json!({
                "input": input,
                "threats": analysis.threats(),
                "confidence": analysis.confidence(),
                "analysis_time": analysis.analysis_time().as_millis(),
            }),
        };

        client
            .post(phantom_url)
            .header("ph-auth-token", phantom_token)
            .json(&phantom_event)
            .send()
            .await?;

        println!("Security event sent to Phantom");
    }

    Ok(())
}
```

## Monitoring and Alerting

### 1. Prometheus Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use prometheus::{Counter, Histogram, Gauge, Registry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Create Prometheus metrics
    let registry = Registry::new();
    let requests_total = Counter::new("llm_security_requests_total", "Total number of requests").unwrap();
    let threats_detected = Counter::new("llm_security_threats_detected_total", "Total number of threats detected").unwrap();
    let analysis_duration = Histogram::new("llm_security_analysis_duration_seconds", "Analysis duration in seconds").unwrap();
    let confidence_gauge = Gauge::new("llm_security_confidence", "Average confidence score").unwrap();

    registry.register(Box::new(requests_total.clone()))?;
    registry.register(Box::new(threats_detected.clone()))?;
    registry.register(Box::new(analysis_duration.clone()))?;
    registry.register(Box::new(confidence_gauge.clone()))?;

    // Analyze input and update metrics
    let input = "User input here";
    let start_time = std::time::Instant::now();
    
    let analysis = engine.analyze_input(input).await?;
    
    let duration = start_time.elapsed();
    requests_total.inc();
    
    if !analysis.is_secure() {
        threats_detected.inc_by(analysis.threats().len() as f64);
    }
    
    analysis_duration.observe(duration.as_secs_f64());
    confidence_gauge.set(analysis.confidence());

    println!("Metrics updated");
    Ok(())
}
```

### 2. Grafana Integration

```rust
use llm_security::{SecurityEngine, SecurityConfig};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct GrafanaAnnotation {
    time: u64,
    title: String,
    text: String,
    tags: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::new()
        .with_prompt_injection_detection(true)
        .with_jailbreak_detection(true)
        .with_unicode_attack_detection(true);

    let engine = SecurityEngine::with_config(config);

    // Create Grafana client
    let client = Client::new();
    let grafana_url = "https://grafana.company.com/api/annotations";
    let grafana_token = "your-grafana-token";

    // Analyze input and send annotation to Grafana
    let input = "User input here";
    let analysis = engine.analyze_input(input).await?;

    if !analysis.is_secure() {
        let annotation = GrafanaAnnotation {
            time: chrono::Utc::now().timestamp() as u64,
            title: "LLM Security Threat Detected".to_string(),
            text: format!("Threats detected: {}", analysis.threats().len()),
            tags: vec!["llm-security".to_string(), "threat".to_string()],
        };

        client
            .post(grafana_url)
            .header("Authorization", format!("Bearer {}", grafana_token))
            .json(&annotation)
            .send()
            .await?;

        println!("Annotation sent to Grafana");
    }

    Ok(())
}
```

## Best Practices

### 1. Integration Best Practices

1. **Error Handling**: Implement robust error handling and retry logic
2. **Rate Limiting**: Respect API rate limits and implement backoff
3. **Monitoring**: Monitor integration health and performance
4. **Security**: Use secure authentication and encryption
5. **Testing**: Implement comprehensive integration tests
6. **Documentation**: Document integration patterns and configurations

### 2. Performance Optimization

1. **Batch Operations**: Use batch operations when possible
2. **Caching**: Implement caching for frequently accessed data
3. **Async Processing**: Use async processing for non-blocking operations
4. **Resource Management**: Monitor and manage resource usage
5. **Connection Pooling**: Use connection pooling for database connections

### 3. Security Considerations

1. **Authentication**: Use secure authentication methods
2. **Encryption**: Encrypt data in transit and at rest
3. **Access Control**: Implement proper access control
4. **Audit Logging**: Log all security events
5. **Compliance**: Ensure compliance with regulations
