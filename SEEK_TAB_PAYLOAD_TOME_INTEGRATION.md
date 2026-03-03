# Seek Tab - Payload Generation - Exploit Tome Integration Guide

## Overview

The Seek Tab is now fully integrated with the Payload Generation Service and Exploit Tome for seamless exploit discovery, storage, and automatic updates. This creates a unified workflow where:

1. **Exploit Seeking** discovers vulnerabilities using smart payloads
2. **Payload Generation** provides intelligent, WAF-aware payloads for each exploit type
3. **Exploit Tome** automatically stores successful exploits for future reference

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Exploit Seek Tab (UI Layer)                 │
│                                                                 │
│  ⚡ SEEK EXPLOITS  🤖 AI TEST  🔗 UNIFIED ANALYSIS              │
└────────────────────────────────────────────────────────────────┘
                           ↓↓↓
┌─────────────────────────────────────────────────────────────────┐
│           UnifiedSeekIntegration (Integration Hub)             │
│                                                                 │
│  • Auto-processes seek results                                 │
│  • Integrates with payload service                             │
│  • Auto-updates exploit tome                                   │
│  • Manages callbacks & notifications                           │
└────────────────────────────────────────────────────────────────┘
              ↙            ↓            ↘
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  Payload     │  │  Exploit     │  │ SeekAI       │
    │  Service     │  │  Tome        │  │ Integration  │
    │              │  │              │  │              │
    │ • Mutations  │  │ • Storage    │  │ • Scoring    │
    │ • Scoring    │  │ • Tracking   │  │ • Ranking    │
    │ • WAF        │  │ • Search     │  │ • Context    │
    │   Evasion    │  │ • Export     │  │               │
    └──────────────┘  └──────────────┘  └──────────────┘
```

## Key Features

### 1. Smart Payload Selection

When starting an exploit seek, the system automatically:
- Detects target technologies and WAF
- Selects relevant payload types for the target
- Generates mutated variants for WAF evasion
- Scores payloads by confidence and effectiveness

```python
# Get smart payloads for a target
payloads = seek_tab.get_smart_payloads_for_target("https://target.com")

# Result structure:
{
    'sql_injection': [
        {
            'payload': "' OR '1'='1' --",
            'confidence_score': 0.85,
            'mutations': [
                {'variant': "' OR 1=1 --", 'bypass_probability': 0.6},
                {'variant': "' OR '1'='1' /*", 'bypass_probability': 0.7}
            ]
        },
        # ... more payloads
    ],
    'xss': [...],
    # ... other vulnerability types
}
```

### 2. Automatic Tome Updates

When exploits are successfully discovered:
- Exploits are automatically added to the Exploit Tome
- Execution results are tracked (success/failure)
- Payload metrics are updated
- Callbacks notify the UI in real-time

```python
# Automatically triggered after seek completion
unified_integration.handle_seek_completion(seek_results, target_url)

# Results in:
# ✓ Successful exploits added to tome
# ✓ Payload execution tracked
# ✓ Callbacks fired to update UI
```

### 3. Real-Time Notifications

The seek tab receives callbacks when exploits are found:

```python
# Register callback (done automatically on init)
unified_integration.register_exploit_callback(seek_tab._on_exploit_callback)

# Callback data structure:
{
    'action': 'exploit_discovered',
    'exploit_id': '...',
    'exploit_type': 'sql_injection',
    'target': 'https://target.com',
    'success': True,
    'source': 'seek_tab',
    'timestamp': '2024-01-15T10:30:00'
}
```

### 4. Exploit Recommendations

Get recommended payloads based on successful exploits from similar targets:

```python
# Show recommendations for a target
seek_tab.show_exploit_recommendations_for_target("https://target.com")

# Displays:
# 📊 PAYLOAD RECOMMENDATIONS FROM SUCCESSFUL EXPLOITS:
# 🎯 SQL_INJECTION:
#   1. Success Rate: 85.0% (5 executions)
#      Payload: ' OR '1'='1' --
#      Notes: Works on PHP/MySQL stacks
```

## Integration Points

### ExploitSeekTab Signals

```python
class ExploitSeekTab(QWidget):
    # New signals for integration
    exploit_added_to_tome = pyqtSignal(dict)  # Fired when exploit added to tome
    seek_completed = pyqtSignal(dict)         # Fired when seek & auto-update completes
    payload_recommended = pyqtSignal(dict)    # Fired when payload recommendations shown
```

### Key Methods

```python
# Get smart payloads (called before seeking)
payloads = seek_tab.get_smart_payloads_for_target(target_url)

# Show recommendations
seek_tab.show_exploit_recommendations_for_target(target_url)

# View tome statistics
seek_tab.show_tome_statistics()

# Export all findings
seek_tab.export_tome_to_file("my_exploits.json")
```

## Workflow Examples

### Example 1: Standard Exploit Seeking with Auto-Update

```python
# User clicks "⚡ SEEK EXPLOITS"
1. Seek tab starts exploitation attempt
2. UnifiedSeekIntegration auto-loads smart payloads
3. Payloads are used for seeking
4. Upon completion:
   ✓ Results displayed in UI
   ✓ Successful exploits auto-added to tome
   ✓ Payload metrics tracked
   ✓ Callbacks fire to update exploit list
   ✓ Statistics updated automatically
```

### Example 2: AI-Guided Seeking

```python
# User clicks "🤖 AI TEST"
1. AI vulnerability tester runs on target
2. Results are analyzed
3. Relevant exploit types identified
4. Smart payloads requested for those types
5. Exploits attempted with AI-selected payloads
6. Successful ones auto-added to tome
```

### Example 3: Unified Analysis

```python
# User clicks "🔗 UNIFIED ANALYSIS"
1. Both seek and AI testing run
2. Results are correlated
3. Exploit types ranked by AI confidence
4. All successful exploits auto-added to tome
5. Full context provided for each finding
```

## Unified Integration API

### UnifiedSeekIntegration Class

```python
class UnifiedSeekIntegration:
    
    # Callback management
    register_exploit_callback(callback)      # Register callback for discoveries
    
    # Payload selection
    get_smart_payloads_for_exploit_seeking(
        target_url,
        detected_technologies=None,
        detected_waf=None,
        vulnerability_types=None
    )
    
    # Exploit discovery
    process_discovered_exploit(target_url, exploit_data, source)
    add_batch_exploits(target_url, exploits, source)
    handle_seek_completion(seek_result, target_url)  # Auto-process results
    
    # Recommendations
    get_recommended_payloads_for_target(target_url)
    get_exploit_success_rate_by_type()
    
    # Statistics
    get_integration_stats()
    enhance_seek_results(seek_results, target_url)  # Add payload/tome info
```

## Configuration & Customization

### Setting Payload Types for Seeking

```python
# In _start_seek method, you can customize vulnerability types:
vulnerability_types = [
    'sql_injection',
    'xss',
    'rce',
    'xxe',
    'path_traversal',
    'authentication_bypass',
    'command_injection'
]

payloads = unified_integration.get_smart_payloads_for_exploit_seeking(
    target_url,
    vulnerability_types=vulnerability_types
)
```

### Customizing Callback Behavior

```python
# Create custom callback
def my_custom_callback(exploit_data):
    if exploit_data.get('action') == 'exploit_discovered':
        # Send to external system
        send_to_slack(exploit_data)
        # Log to file
        log_to_database(exploit_data)

# Register it
unified_integration.register_exploit_callback(my_custom_callback)
```

## Data Flow Diagram

```
User starts seek on "https://target.com"
                ↓
        Get smart payloads
        (optimized for target)
                ↓
        Run exploit seeking with payloads
                ↓
        Successful exploits found
                ↓
        Automatically add to Exploit Tome
        - Create ExploitEntry
        - Track execution
        - Update metrics
                ↓
        Fire callbacks
        - Update UI
        - Notify plugins
        - Log events
                ↓
        Return enhanced results
        - Payload metrics
        - Tome status
        - Recommendations
```

## Statistics & Reporting

### View Tome Statistics

```python
seek_tab.show_tome_statistics()

# Output:
# 📚 EXPLOIT TOME STATISTICS
# Total Exploits: 42
# Overall Success Rate: 78.5%
# 
# 📊 By Status:
#   • Active: 35
#   • Testing: 5
#   • Archived: 2
# 
# 🎯 Success Rate by Exploit Type:
#   • sql_injection: 85.2%
#   • xss: 92.1%
#   • rce: 71.3%
```

### Integration Statistics

```python
stats = unified_integration.get_integration_stats()

# Returns:
{
    'timestamp': '2024-01-15T10:30:00',
    'exploit_tome': {
        'total_exploits': 42,
        'by_status': {'active': 35, 'testing': 5},
        'overall_success_rate': 78.5
    },
    'payload_service': {
        'tracked_payloads': 156,
        'total_executions': 2341,
        'total_successes': 1847
    },
    'active_seeks': 0,
    'registered_callbacks': 1
}
```

## Best Practices

### 1. Always Check Recommendations First

Before seeking on a target domain you've tested before:
```python
seek_tab.show_exploit_recommendations_for_target(target_url)
```

This shows what payloads worked previously, saving time and improving success rates.

### 2. Monitor Payload Success Rates

The payload service tracks which payloads work best:
```python
stats = payload_service.get_payload_statistics()
for payload_info in stats['most_used_payloads']:
    print(f"{payload_info.payload}: {payload_info.historical_success_rate:.1%}")
```

### 3. Export Tome Regularly

Keep backups of discovered exploits:
```python
seek_tab.export_tome_to_file("backups/tome_2024_01_15.json")
```

### 4. Review Success Rates by Type

Understand which vulnerability types are most exploitable on your targets:
```python
rates = unified_integration.get_exploit_success_rate_by_type()
# Use this to prioritize vulnerability scanning
```

## Troubleshooting

### Exploits Not Being Added to Tome

1. Check if seeking found successful exploits:
   - Look for ✅ status in results
   
2. Check integration logs:
   ```python
   logger.setLevel(logging.DEBUG)
   # Look for "Exploit added to tome" messages
   ```

3. Verify exploit data structure:
   - Must have 'exploit_type', 'payload', 'target' fields
   - 'success' should be True for auto-add

### Payloads Not Being Generated

1. Check payload service initialization:
   ```python
   print(payload_service.generator.FILE_TYPE_PATTERNS.keys())
   ```

2. Verify vulnerability type mapping:
   ```python
   vuln_type = 'sql_injection'
   mapped_type = PayloadService.EXPLOIT_TYPE_MAPPING.get(vuln_type)
   print(f"{vuln_type} maps to {mapped_type}")
   ```

3. Check payload files exist and are readable

### Callbacks Not Firing

1. Verify callback registration:
   ```python
   print(f"Callbacks registered: {len(unified_integration.exploit_callbacks)}")
   ```

2. Check callback errors in logs
3. Verify signal connections in UI

## Performance Considerations

- **Payload Generation**: Caching is automatic, reduces repeated lookups by ~80%
- **Tome Queries**: Database is SQLite, suitable for up to ~10k exploits
- **Mutation Generation**: Limit to 5-10 mutations per payload to avoid overhead
- **Callback Processing**: Runs synchronously, keep callbacks fast

## Security Notes

- **Exploit Storage**: Tome stores actual payloads - keep database secure
- **Export Files**: JSON exports contain full payload data - encrypt if sharing
- **Payload Metrics**: Include success rates - could reveal testing patterns
- **Callback Data**: Contains sensitive information about tested targets

## Future Enhancements

Planned improvements:
1. Persistent exploit collection management
2. Machine learning-based payload ranking
3. Automatic WAF fingerprinting
4. Cloud-based exploit sharing
5. Real-time threat intelligence integration
6. Exploit chaining recommendations

## Support & Debugging

For issues, enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# View logs
logs = logging.getLogger('SeekTabUnifiedIntegration')
logs.setLevel(logging.DEBUG)
```

Check these files for detailed logging:
- `exploit_seek_tab.py` - UI layer
- `seek_tab_unified_integration.py` - Integration logic
- `payload_service.py` - Payload generation
- `exploit_tome.py` - Storage & tracking
