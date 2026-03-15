# HadesAI: Unified Systems Integration Guide

## Overview

Three core systems have been enhanced and unified for HadesAI:

1. **Unified LLM Routing** - Intelligent routing across multiple AI providers
2. **Web Learning Integration** - Seamless knowledge extraction and enhancement  
3. **Enhanced Defense System** - Advanced threat detection and automated response

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     HadesAI Core                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐    ┌──────────────────┐             │
│  │  Web Learning    │    │  Unified LLM     │             │
│  │  Integration     │◄──►│  Router          │             │
│  └──────────────────┘    └──────────────────┘             │
│           │                       │                        │
│           │                       │ Routes requests        │
│           │              ┌────────┴────────┐              │
│           │              │                 │              │
│           │         ┌────▼─┐  ┌─────┐  ┌──▼──┐            │
│           │         │OpenAI│  │Azure│  │Ollama│          │
│           │         └──────┘  └─────┘  └──────┘            │
│           │                                                │
│  ┌────────▼──────────────────────────────┐                │
│  │   Enhanced Defense System              │                │
│  │   ├─ Threat Detection                  │                │
│  │   ├─ Anomaly Analysis                  │                │
│  │   └─ Automated Response                │                │
│  └────────────────────────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Unified LLM Router

**File:** `unified_llm_router.py`

### Features

- **Multi-Provider Support**: OpenAI, Mistral, Azure, Ollama, Fallback
- **Intelligent Routing**: Automatic selection based on availability, speed, reliability
- **Request Caching**: Reduces API calls and improves response time
- **Performance Metrics**: Tracks latency, success rate, token usage
- **Priority Queue**: Critical requests routed to fastest providers

### Quick Start

```python
from unified_llm_router import UnifiedLLMRouter, LLMRequest, RequestPriority

# Initialize router
router = UnifiedLLMRouter()

# Create request
request = LLMRequest(
    prompt="Analyze this vulnerability...",
    priority=RequestPriority.HIGH,
    system_prompt="You are HadesAI security expert"
)

# Route request (automatically selects best provider)
response = router.route_request(request)
print(response.content)  # AI-generated analysis

# View statistics
print(router.get_stats())
```

### Provider Configuration

Set environment variables:
```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Mistral (or edit .hades_config.json)
export MISTRAL_API_KEY="..."

# Azure
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://..."

# Ollama (local)
export OLLAMA_URL="http://localhost:11434"
```

### Core Classes

- **LLMProvider (Enum)**: Available providers (OPENAI, MISTRAL, etc.)
- **LLMRequest**: Encapsulates request with metadata
- **LLMResponse**: Response with metrics and cache status
- **UnifiedLLMRouter**: Main routing engine
- **RequestCache**: SQLite-based response caching

---

## 2. Enhanced Defense System

**File:** `enhanced_defense_system.py`

### Features

- **Signature-Based Detection**: Known malicious patterns and IPs
- **Anomaly Detection**: Statistical analysis of suspicious behavior
- **Automatic Response**: Executes defense actions on threat detection
- **Threat Intelligence**: Built-in threat indicators and rules
- **Incident Logging**: Complete audit trail of security events

### Quick Start

```python
from enhanced_defense_system import EnhancedDefenseSystem, ThreatLevel

# Initialize defense system
defense = EnhancedDefenseSystem()

# Scan content for threats
event = defense.scan_content(
    content="SELECT * FROM users WHERE id = ' OR '1'='1",
    context={"source_ip": "192.168.1.100"}
)

if event:
    print(f"Threat: {event.threat_type}")
    print(f"Severity: {event.threat_level.name}")
    print(f"Actions: {event.response_actions}")

# Get security status
status = defense.get_security_status()
print(status)
```

### Defense Actions

- **BLOCK_IP**: Block attacker IP
- **TERMINATE_PROCESS**: Kill malicious process
- **ISOLATE_SYSTEM**: Network isolation
- **ALERT_ADMIN**: Alert security team
- **LOG_INCIDENT**: Record security event
- **ENABLE_WAF**: Activate web application firewall
- **REVOKE_SESSION**: Invalidate active sessions

### Threat Detection Methods

1. **Signature Matching**: Pattern recognition against known exploits
2. **Anomaly Detection**: Entropy analysis, behavioral patterns
3. **Protocol Analysis**: HTTP header injection detection
4. **Payload Analysis**: Suspicious encoding/obfuscation

### Core Classes

- **ThreatLevel (Enum)**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **ThreatDetectionEngine**: Signature and anomaly detection
- **AnomalyDetector**: Statistical threat analysis
- **DefenseResponseEngine**: Automated response execution
- **EnhancedDefenseSystem**: Main orchestrator

---

## 3. Web Learning Integration

**File:** `web_learning_integration.py`

### Features

- **Integrated Learning**: Extract knowledge while scanning for threats
- **AI Enhancement**: LLM-based analysis of learned content
- **Security Verification**: Defense system validates learned information
- **Knowledge Storage**: Persistent database of all learning contexts
- **Automated Worker**: Background thread for continuous learning

### Quick Start

```python
from web_learning_integration import create_integrated_system

# Create integrated system
integrator = create_integrated_system()

# Learn from webpage with security scanning
context = integrator.learn_and_defend_webpage(
    url="https://example.com/vulnerability-report",
    content=webpage_content,
    metadata={"title": "CVE Analysis"}
)

# View results
print(f"Learned: {context.learned_knowledge['total_items_learned']} items")
print(f"Threats Detected: {context.defense_scan_results}")
print(f"AI Analysis:\n{context.ai_enhancements['analysis']}")

# Get statistics
stats = integrator.get_learning_statistics()
print(stats)
```

### Automated Continuous Learning

```python
from web_learning_integration import AutomatedLearningWorker

# Create worker
worker = AutomatedLearningWorker(integrator, batch_size=5)
worker.start()

# Add URLs to learn
worker.add_url_to_learn("https://security-blog.example.com/cve-analysis")
worker.add_url_to_learn("https://exploit-db.example.com/exploit-123")

# Worker processes in background
# Stop when done
worker.stop()
```

### Learning Pipeline

```
1. Extract Knowledge
   ├─ CVEs
   ├─ Exploits
   ├─ Techniques
   └─ Vulnerability Patterns

2. Security Scan
   ├─ Signature Matching
   ├─ Anomaly Detection
   └─ Threat Assessment

3. AI Enhancement
   ├─ Risk Assessment
   ├─ Exploitation Analysis
   ├─ Defense Recommendations
   └─ Knowledge Application

4. Storage
   ├─ Learning Context
   ├─ Security Findings
   └─ Integrated Knowledge
```

### Core Classes

- **LearningContext**: Holds complete learning results
- **EnhancedWebLearningIntegrator**: Main orchestrator
- **AutomatedLearningWorker**: Background processing thread

---

## Integration Examples

### Example 1: Complete Security Analysis

```python
from web_learning_integration import create_integrated_system
from unified_llm_router import LLMRequest, RequestPriority

integrator = create_integrated_system()

# Learn from security advisory
context = integrator.learn_and_defend_webpage(
    "https://security.example.com/advisory",
    advisory_content
)

# Request detailed LLM analysis using learned context
analysis_prompt = f"""
Analyze this learned vulnerability information:

CVEs: {', '.join(context.learned_knowledge['cves'])}
Exploits: {context.learned_knowledge['exploits']}
Threat Level: {context.defense_scan_results['threat_level'] if context.defense_scan_results else 'UNKNOWN'}

Provide:
1. Exploitation difficulty assessment
2. Detection evasion techniques
3. Defense mitigation strategies
"""

request = LLMRequest(
    prompt=analysis_prompt,
    priority=RequestPriority.HIGH
)

response = integrator.router.route_request(request)
print(response.content)
```

### Example 2: Threat Hunting with Integrated System

```python
# Hunt for threats in multiple sources
urls_to_scan = [
    "https://exploit-db.example.com",
    "https://github.com/malware-repo",
    "https://darkweb-mirror.example.com"
]

for url in urls_to_scan:
    context = integrator.learn_and_defend_webpage(url, content)
    
    if context.defense_scan_results:
        # Threat detected - get detailed analysis
        threat_data = context.defense_scan_results
        print(f"THREAT FOUND in {url}")
        print(f"Type: {threat_data['threat_type']}")
        print(f"Severity: {threat_data['threat_level']}")
        print(f"Actions: {threat_data['actions_taken']}")
```

### Example 3: Learning Callback System

```python
def on_learning_complete(context):
    """Called when learning completes"""
    if context.defense_scan_results:
        # Send alert for detected threats
        alert_message = f"""
        Security Threat Detected During Learning
        URL: {context.url}
        Threat: {context.defense_scan_results['threat_type']}
        Severity: {context.defense_scan_results['threat_level']}
        """
        send_alert(alert_message)

integrator.register_learning_callback(on_learning_complete)
```

---

## Database Schema

### learning_integration.db

**learning_contexts**
- context_id: Unique context identifier
- url: Source URL
- timestamp: Learning timestamp
- learned_items: Number of knowledge items extracted
- security_issues: Count of detected issues
- ai_enhancements: JSON analysis results

**web_security_findings**
- finding_id: Unique finding identifier
- url: Source URL
- threat_level: CRITICAL/HIGH/MEDIUM/LOW
- finding_type: Type of threat
- description: Detailed description
- remediation: Mitigation recommendations

**learned_and_secured_knowledge**
- knowledge_id: Unique knowledge identifier
- knowledge_type: CVE/EXPLOIT/TECHNIQUE/PATTERN
- content: Knowledge content
- source_url: Where learned from
- security_verified: Defense system verification
- defense_scanned: Scan completion flag
- ai_enhanced: LLM enhancement flag

### defense_system.db

**threat_indicators**
- indicator_id: Unique identifier
- indicator_type: ip/domain/pattern/signature
- value: Actual threat indicator
- severity: CRITICAL/HIGH/MEDIUM/LOW
- source: Threat source/database

**detection_events**
- event_id: Unique event identifier
- timestamp: Detection time
- threat_level: Severity level
- threat_type: Type of threat detected
- indicators_matched: Matched signature IDs
- response_actions: Actions executed

**defense_rules**
- rule_id: Rule identifier
- name: Rule name
- trigger_conditions: JSON conditions
- response_actions: Actions to execute
- enabled: Enable/disable flag

### llm_cache.db

**llm_cache**
- cache_id: Unique cache entry
- prompt_hash: MD5 hash of prompt
- request: Original request
- response: Cached response
- provider: Provider name
- hits: Cache hit counter

**request_history**
- id: Record ID
- request_id: Request identifier
- provider: LLM provider used
- tokens_used: API tokens consumed
- latency_ms: Response time
- success: Success flag
- error: Error message if failed

---

## Configuration

### .hades_config.json

```json
{
  "mistral_api_key": "your_mistral_key",
  "openai_api_key": "your_openai_key",
  "ai_provider": "mistral",
  "defense_enabled": true,
  "learning_enabled": true,
  "auto_learning": true,
  "learning_batch_size": 5,
  "threat_detection_level": "HIGH",
  "cache_responses": true
}
```

---

## Performance Metrics

### LLM Router Statistics

```python
stats = router.get_stats()
# Returns:
{
  "providers": {
    "mistral": {
      "requests": 42,
      "successes": 41,
      "failures": 1,
      "avg_latency": 1234.5
    },
    ...
  },
  "cache_stats": {
    "total_requests": 150
  }
}
```

### Defense System Status

```python
status = defense.get_security_status()
# Returns:
{
  "status": "ACTIVE",
  "recent_events_24h": 5,
  "threat_distribution": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 2
  },
  "active_blocks": 3,
  "response_history_count": 47
}
```

### Learning Statistics

```python
stats = integrator.get_learning_statistics()
# Returns:
{
  "total_contexts": 156,
  "total_security_findings": 23,
  "learned_cves": 45,
  "learned_exploits": 78,
  "learned_techniques": 234,
  "learned_patterns": 567,
  "web_sources_processed": 89,
  "llm_provider_stats": {...}
}
```

---

## Error Handling

All three systems include comprehensive error handling:

- **LLM Router**: Graceful fallback if provider unavailable
- **Defense System**: Continues operation with reduced functionality
- **Learning Integration**: Non-blocking processing with error logging

```python
try:
    response = router.route_request(request)
except Exception as e:
    logger.error(f"Routing error: {e}")
    # Falls back to fallback provider automatically
```

---

## Testing

### Unit Tests

```python
# Test LLM Router
from unified_llm_router import UnifiedLLMRouter, LLMRequest

router = UnifiedLLMRouter()
request = LLMRequest(prompt="test")
response = router.route_request(request)
assert response.content

# Test Defense System
from enhanced_defense_system import EnhancedDefenseSystem

defense = EnhancedDefenseSystem()
event = defense.scan_content("' OR '1'='1")
assert event is not None

# Test Web Learning
from web_learning_integration import create_integrated_system

integrator = create_integrated_system()
context = integrator.learn_and_defend_webpage(
    "https://test.com", 
    "CVE-2024-1234"
)
assert context.learned_knowledge['total_items_learned'] > 0
```

---

## Troubleshooting

### LLM Router Issues

**All providers unavailable**
- Check API keys in environment or .hades_config.json
- Ollama must be running for local provider
- Falls back to rule-based provider automatically

**Slow responses**
- Check network connectivity
- Review provider statistics with `router.get_stats()`
- Consider enabling request caching

### Defense System Issues

**False positives**
- Adjust anomaly detection threshold
- Add custom indicators to whitelist
- Modify trigger conditions in defense rules

**Missed detections**
- Update threat signatures
- Review detection events
- Enhance anomaly detection tuning

### Learning Integration Issues

**Learning timeout**
- Increase request timeout
- Reduce batch size for learning worker
- Check network connectivity

**Memory usage**
- Clear old learning contexts
- Archive historical databases
- Limit cache size

---

## Advanced Features

### Custom Threat Indicators

```python
defense.add_custom_indicator(
    indicator_type="pattern",
    value="admin' OR '1'='1",
    severity=ThreatLevel.CRITICAL
)
```

### Custom Defense Rules

```python
defense.add_defense_rule({
    "name": "Custom SQLi Detection",
    "trigger": {"threat_type": "SIGNATURE_MATCH"},
    "actions": [DefenseAction.ALERT_ADMIN, DefenseAction.LOG_INCIDENT]
})
```

### Learning Callbacks

```python
def handle_threat_detection(context):
    if context.defense_scan_results:
        # Custom handling
        pass

integrator.register_learning_callback(handle_threat_detection)
```

---

## Best Practices

1. **Always use RequestPriority** for proper load balancing
2. **Enable caching** for frequently asked questions
3. **Review detection events** regularly
4. **Update threat indicators** from threat intelligence
5. **Monitor LLM provider costs** via statistics
6. **Test defense rules** before production
7. **Archive old data** for database performance
8. **Use callbacks** for real-time alerts

---

## Support & Logging

All systems log to `HadesAI` logger:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("HadesAI")
```

Log levels:
- **DEBUG**: Detailed request/response tracing
- **INFO**: Normal operations and statistics
- **WARNING**: Provider unavailability, detection misses
- **ERROR**: Critical failures requiring attention

---

## Summary

The unified system provides:

✓ Intelligent multi-provider LLM routing  
✓ Advanced threat detection and response  
✓ Seamless web-based knowledge learning  
✓ Integrated security analysis  
✓ Automated continuous learning  
✓ Comprehensive audit trails  
✓ Performance monitoring  

Perfect for autonomous security operations!
