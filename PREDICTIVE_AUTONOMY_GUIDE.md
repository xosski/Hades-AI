# Predictive Autonomy & Adaptive Thresholds Guide

## Overview

Three new modules enable fully autonomous AI operation:

### 1. **Predictive Executor** (`modules/predictive_executor.py`)
Anticipates next optimal actions using learned patterns from memory.

- **Pattern Learning**: Tracks sequences of successful actions
- **Markov Chains**: Predicts next actions based on transitions
- **Memory Integration**: Uses cognitive memory for context-aware predictions
- **Auto-Execution**: Optionally executes high-confidence predictions automatically

### 2. **Adaptive Thresholds** (`modules/adaptive_thresholds.py`)
Dynamically adjusts security parameters based on real-time threat analysis.

- **Threat Metrics**: Continuously tracks threat indicators
- **Trend Analysis**: Detects increasing/decreasing threat patterns
- **Dynamic Adjustment**: Automatically raises/lowers detection/blocking thresholds
- **Anomaly Detection**: Identifies unusual patterns to trigger threshold changes
- **Volatility Tracking**: Measures stability of threat metrics

### 3. **Autonomous Intelligence** (`modules/autonomous_intelligence.py`)
Master orchestrator integrating predictive execution + adaptive thresholds.

- **Decision Making**: Synthesizes predictions + threat analysis
- **Autonomy Levels**: Manual → Assisted → Semi-Autonomous → Fully Autonomous
- **Feedback Loop**: Reinforces successful predictions, penalizes failures
- **Coordination**: Keeps predictive actions aligned with current threat level

---

## Quick Start

### Basic Integration

```python
from modules.predictive_executor import PredictiveExecutor
from modules.adaptive_thresholds import AdaptiveThresholdsEngine
from modules.autonomous_intelligence import AutonomousIntelligence, AutonomyLevel
from modules.cognitive_memory import CognitiveLayer

# Initialize
cognitive = CognitiveLayer()
autonomy = AutonomousIntelligence(
    cognitive_layer=cognitive,
    action_executor=my_action_executor_fn,
    autonomy_level=AutonomyLevel.SEMI_AUTONOMOUS
)

# Enable autonomous operation
autonomy.set_autonomy_level(AutonomyLevel.SEMI_AUTONOMOUS)
```

### Process Observations

```python
# When system observes something
observation = {
    'threat_count': 5,
    'anomaly_score': 0.7,
    'last_action': 'scan_port',
    'target_type': 'web_app'
}

# System automatically:
# 1. Analyzes threat level
# 2. Updates thresholds (if needed)
# 3. Predicts next action
# 4. Executes if confidence high enough
decision = autonomy.process_observation(
    observation, 
    DecisionContext.THREAT_DETECTED
)

if decision.success:
    print(f"✅ Autonomous action executed: {decision.predicted_action.action}")
```

### Learning from Actions

```python
# Record a sequence of successful actions
autonomy.predictor.learn_action_sequence(
    actions=['scan_port', 'probe_service', 'exploit_vulnerability'],
    context={'target_type': 'web_app', 'threat_level': 'high'},
    success=True,
    execution_time=120
)

# Next time similar context is detected, these actions will be predicted
```

---

## Autonomy Levels

### 1. **MANUAL** (Default)
- User must approve all actions
- System suggests predictions
- No autonomous execution

```python
system.set_autonomy_level(AutonomyLevel.MANUAL)
```

### 2. **ASSISTED**
- System provides suggestions with reasoning
- User can quick-accept suggestions
- No automatic execution
- Good for learning & validation

```python
system.set_autonomy_level(AutonomyLevel.ASSISTED)
```

### 3. **SEMI_AUTONOMOUS** (Recommended)
- Automatically executes low-risk, high-confidence actions
- Still logs & tracks everything
- Confidence threshold: 65%+
- Critical threats trigger lower thresholds

```python
system.set_autonomy_level(AutonomyLevel.SEMI_AUTONOMOUS)
```

### 4. **FULLY_AUTONOMOUS**
- Complete autonomous operation
- Minimal confidence threshold: 50%+
- Maximum response speed
- Use with caution

```python
system.set_autonomy_level(AutonomyLevel.FULLY_AUTONOMOUS)
```

---

## Predictive Execution Features

### Pattern Discovery
```python
# System learns from action sequences
executor = autonomy.predictor

# Get learned patterns
patterns = executor.get_common_sequences(min_frequency=2)
for pattern in patterns:
    print(f"Pattern: {pattern['sequence']}")
    print(f"Success rate: {pattern['success_rate']:.1%}")
```

### Predict Next Actions
```python
# Predict what comes next
predictions = executor.predict_next_actions(
    current_state={
        'last_action': 'scan_port',
        'target_type': 'web_app',
        'threat_level': 'high'
    },
    top_k=3  # Get 3 best predictions
)

for pred in predictions:
    print(f"{pred.action}: {pred.confidence:.1%} confidence")
    print(f"  Reasoning: {pred.reasoning}")
```

### Reinforcement Learning
```python
# Mark prediction as successful
executor.reinforce_prediction(
    prediction=pred,
    success=True,
    feedback={'outcome': 'target_exploited'}
)

# The prediction's confidence increases for future similar contexts
```

---

## Adaptive Thresholds Features

### Record Threats
```python
thresholds = autonomy.thresholds

# Record a threat metric
thresholds.record_threat(
    metric_name="failed_auth_attempts",
    value=0.8,  # Normalized 0-1
    threat_type="brute_force",
    context={'protocol': 'SSH', 'port': 22}
)

# Thresholds automatically adjust based on threat level
```

### Monitor Threshold Changes
```python
# View all adjustments made
history = thresholds.get_adjustment_history(limit=10)
for adj in history:
    print(f"{adj['threshold']}: {adj['old_value']} → {adj['new_value']}")
    print(f"  Reason: {adj['reason']}")

# Get current threshold values
current = thresholds.get_current_thresholds()
print(f"Detection sensitivity: {current['detection_sensitivity']}")
print(f"Block threshold: {current['block_threshold']}")
```

### Threat Trend Analysis
```python
# Get summary of threat activity
summary = thresholds.get_threat_summary()

print(f"Threat level: {summary['threat_level']}")
print(f"Composite score: {summary['composite_threat_level']:.2f}")
print(f"Adjustments made: {summary['threshold_adjustments']}")

# Get specific metric trend
trend = thresholds.analyzer.get_threat_trend("failed_auth_attempts")
print(f"Trend: {trend}")  # 'increasing', 'decreasing', or 'stable'
```

---

## Decision Making

### Decision Types

**Action Execution Decisions**
- Predicted action meets confidence threshold
- Threat level permits execution
- Prerequisites satisfied
- Autonomy level allows execution

**Threshold Adjustment Decisions**
- Threat metrics change significantly
- Trend reversal detected
- Anomalies identified
- Stability changes

### Get Decision Log
```python
# View recent autonomous decisions
decisions = autonomy.get_decision_log(limit=10)

for d in decisions:
    print(f"[{d['timestamp']}] {d['decision_type']}")
    print(f"  Action: {d['action']}")
    print(f"  Confidence: {d['confidence']:.1%}")
    print(f"  Success: {d['success']}")
    print(f"  Rationale: {d['rationale']}")
```

### Autonomy Status
```python
status = autonomy.get_autonomy_status()

print(f"Level: {status['autonomy_level']}")
print(f"Total decisions: {status['total_decisions']}")
print(f"Executed: {status['executed']}")
print(f"Success rate: {status['success_rate']:.1%}")
print(f"Avg decision time: {status['avg_decision_time_ms']:.1f}ms")
```

---

## Configuration Examples

### Conservative Configuration
```python
# For high-security environments
autonomy.set_autonomy_level(AutonomyLevel.ASSISTED)
autonomy.set_predictor_confidence_threshold(0.85)
autonomy.thresholds.set_aggressiveness(0.3)  # Conservative
```

### Aggressive Configuration
```python
# For fast-moving threats
autonomy.set_autonomy_level(AutonomyLevel.FULLY_AUTONOMOUS)
autonomy.set_predictor_confidence_threshold(0.55)
autonomy.thresholds.set_aggressiveness(0.9)  # Very aggressive
```

### Balanced Configuration (Recommended)
```python
# Good balance between safety and responsiveness
autonomy.set_autonomy_level(AutonomyLevel.SEMI_AUTONOMOUS)
autonomy.set_predictor_confidence_threshold(0.65)
autonomy.thresholds.set_aggressiveness(0.5)  # Moderate
```

---

## Integration with HadesAI

### In Main GUI
```python
class HadesAI(QMainWindow):
    def __init__(self):
        # ... existing code ...
        
        from modules.autonomous_intelligence import AutonomousIntelligence
        self.autonomy = AutonomousIntelligence(
            cognitive_layer=self.cognitive_layer,
            action_executor=self.execute_action,
            autonomy_level=AutonomyLevel.SEMI_AUTONOMOUS
        )
        
    def on_threat_detected(self, threat_data):
        # Let autonomous system handle it
        decision = self.autonomy.process_observation(
            threat_data,
            DecisionContext.THREAT_DETECTED
        )
        
        # Log result
        self.chat_display.append(f"[AUTO] {decision.rationale}")
```

### Memory Integration
```python
# Cognitive memory feeds into predictions
cognitive = CognitiveLayer()

# When learning actions, they're stored in memory
autonomy.predictor.learn_action_sequence(...)

# When predicting, relevant memories are recalled
# for additional context
predictions = autonomy.predictor.predict_next_actions(...)
```

---

## Performance Tuning

### Adjust Confidence Threshold
```python
# Higher = more conservative
autonomy.set_predictor_confidence_threshold(0.75)

# Lower = more aggressive
autonomy.set_predictor_confidence_threshold(0.50)
```

### Control Aggressiveness
```python
# 0.0 = conservative (raises thresholds during threats)
# 1.0 = aggressive (lowers thresholds rapidly)
autonomy.thresholds.set_aggressiveness(0.5)
```

### Enable/Disable Adaptation
```python
# Disable adaptive thresholds (use fixed values)
autonomy.thresholds.enable_adaptive(False)

# Re-enable
autonomy.thresholds.enable_adaptive(True)
```

---

## Monitoring & Debugging

### Comprehensive Status
```python
full_status = autonomy.get_comprehensive_status()

print(json.dumps(full_status, indent=2, default=str))
```

### Check Pattern Learning
```python
patterns = autonomy.predictor.get_common_sequences()
print(f"Patterns learned: {len(patterns)}")

for p in patterns[:5]:
    print(f"  {' → '.join(p['sequence'])}")
    print(f"    Success: {p['success_rate']:.1%}")
```

### Analyze Threshold Changes
```python
history = autonomy.thresholds.get_adjustment_history(limit=20)

# Find most common adjustments
adjustments = {}
for adj in history:
    threshold = adj['threshold']
    adjustments[threshold] = adjustments.get(threshold, 0) + 1

print("Most adjusted thresholds:")
for threshold, count in sorted(adjustments.items(), key=lambda x: x[1], reverse=True):
    print(f"  {threshold}: {count} changes")
```

---

## Troubleshooting

### No Predictions Generated
- Check if patterns have been learned: `len(executor.analyzer.patterns)`
- Verify predictor is configured: `autonomy.predictor is not None`
- Check confidence threshold: `executor.confidence_threshold`

### Thresholds Not Adjusting
- Verify adaptive is enabled: `autonomy.thresholds.adaptive_enabled`
- Check threat metrics are being recorded: `len(autonomy.thresholds.threat_history)`
- Review adjustment history: `autonomy.thresholds.get_adjustment_history()`

### Actions Not Executing
- Check autonomy level: `autonomy.autonomy_level`
- Verify executor function is configured: `autonomy.action_executor is not None`
- Check prediction confidence: Compare to threshold

---

## Next Steps

1. **Start with ASSISTED mode** - See suggestions before execution
2. **Monitor accuracy** - Check `get_autonomy_status()` regularly
3. **Adjust confidence threshold** - Based on accuracy metrics
4. **Progress to SEMI_AUTONOMOUS** - When accuracy > 75%
5. **Fine-tune parameters** - Based on your threat landscape

---

## References

- `modules/predictive_executor.py` - Full implementation
- `modules/adaptive_thresholds.py` - Threshold engine
- `modules/autonomous_intelligence.py` - Orchestrator
- `modules/cognitive_memory.py` - Memory system
