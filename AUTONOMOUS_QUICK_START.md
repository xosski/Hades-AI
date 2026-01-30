# Autonomous Operations - Quick Start (5 Minutes)

## What You Get

**Three autonomous systems:**
1. ✓ **Threat Response** - Auto-block IPs, auto-patch vulnerabilities
2. ✓ **Learning Engine** - Learns from every exploit attempt
3. ✓ **Decision Agent** - Intelligently decides what to exploit

## Integration (2 Steps)

### Step 1: Add Import to HadesAI.py

```python
from autonomous_ops_gui import AutonomousOpsTab
```

### Step 2: Add Tab in MainWindow.__init__

```python
self.autonomous_tab = AutonomousOpsTab(db_path="hades_knowledge.db")
self.tabs.addTab(self.autonomous_tab, "🤖 Autonomous Ops")
```

## Usage (In GUI)

After restarting HadesAI, you'll see **"🤖 Autonomous Ops"** tab:

### Threat Response (Most Useful)
1. Check: **"Enable Auto-Response to Threats"**
2. Check: **"Auto-Patch Vulnerabilities"**
3. Optionally check: **"Auto-Exploit"** (expert only)
4. Set threshold: **0.7** (default)
5. Status changes to green: ✓ Active

Now HadesAI will:
- Detect threats automatically
- Block malicious IPs
- Generate patches
- Alert on critical issues

### Learning Engine (Recommended)
1. Check: **"Enable Continuous Learning"**
2. Check: **"Auto-Update Exploit Rankings"**
3. Optionally check: **"Pattern Generation"**
4. Check: **"Enable Feedback Loop"**
5. Status changes to green: ✓ Active

Now HadesAI will:
- Learn from every exploit attempt
- Track success rates
- Auto-rank best exploits
- Generate new attack patterns

### Decision Agent (Advanced)
1. Check: **"Enable Decision Agent"**
2. Set **CVSS Threshold**: 7.0 (exploits CVSS 7+)
3. Check: **"Auto-Prioritize Targets"**
4. Check: **"Explain Reasoning"**
5. Status changes to green: ✓ Active

Now HadesAI will:
- Evaluate targets automatically
- Recommend exploitation strategy
- Show reasoning for decisions
- Prioritize high-value targets

## Programmatic Usage

```python
from modules.autonomous_operations import (
    ThreatResponseEngine, ContinuousLearningEngine,
    DecisionMakingAgent, ThreatEvent
)

# Initialize
threat = ThreatResponseEngine()
learning = ContinuousLearningEngine()
decisions = DecisionMakingAgent(learning, threat)

# Enable
threat.enable_auto_response(auto_patch=True)
learning.enable_continuous_learning()
decisions.enable_autonomous_decisions()

# Use
# 1. Process threats
threat_event = ThreatEvent(
    id="threat-1",
    threat_type="SQL Injection",
    severity=0.85,
    source_ip="192.168.1.100"
)
threat.process_threat(threat_event)  # Auto-responds

# 2. Record learning
learning.record_attempt("SQL Injection", "web_server", success=True)

# 3. Make decisions
targets = [
    {"name": "WebServer-01", "type": "web_server", "cvss_score": 8.5}
]
strategy = decisions.recommend_strategy(targets)
print(strategy["recommended_order"])  # ["WebServer-01"]
```

## Example Flow (What Happens)

```
1. Threat detected: SQL Injection (CVSS 8.5)
   → Threat Response Engine blocks source IP
   → Generates patch recommendation
   → Logs to response history

2. Manual exploit test: SQL Injection succeeds
   → Learning Engine records: "SQL Injection: success"
   → Updates success rate: 100%
   → Increases confidence score

3. Another SQL Injection opportunity appears
   → Decision Agent evaluates target
   → Finds SQL Injection at 100% success
   → Recommends: EXPLOIT
   → If auto_exploit=true: Executes autonomously

4. Pattern analysis
   → Learning sees: SQL Injection → RCE chain
   → Generates new pattern
   → Suggests to other instances
```

## Three Modes

### 🟢 Learning Only (Safest - Recommended)
```python
threat.enabled = False
learning.enabled = True
decisions.enabled = False
```
Result: Shows recommendations, user decides

### 🟡 Threat Response Only (Defensive)
```python
threat.enabled = True
learning.enabled = False
decisions.enabled = False
```
Result: Blocks threats, patches, no exploitation

### 🔴 Full Autonomy (Expert Only)
```python
threat.enabled = True
learning.enabled = True
decisions.enabled = True
```
Result: Fully autonomous, minimal human input

## Key Settings

| Setting | Recommended | Safe | Aggressive |
|---------|-------------|------|-----------|
| Auto-Patch | ✓ | ✓ | ✓ |
| Auto-Exploit | ✗ | ✗ | ✓ |
| CVSS Threshold | 7.0 | 8.5 | 6.0 |
| Pattern Generation | ✗ | ✗ | ✓ |
| Min Success Rate | 70% | 80% | 60% |

## Monitoring

### Check Status
```python
# Threat response
blocked_ips = threat.get_blocked_ips()
history = threat.get_response_history()

# Learning
stats = learning.get_learning_stats()
top_exploits = learning.get_top_exploits(5)

# Decisions
decisions_made = decisions.get_decision_history()
```

### View Logs
```
Check "Autonomous Operations Status" section in GUI
Shows:
  - Active systems
  - Number of blocked IPs
  - Exploits learned
  - Average success rate
```

## Common Use Cases

### Use Case 1: Learn & Observe
```
threat.enabled = False
learning.enabled = True
decisions.enabled = False
```
Ideal for: Testing environment, learning phase
Result: Gathers data, shows recommendations

### Use Case 2: Defend Network
```
threat.enabled = True
learning.enabled = True
decisions.enabled = False
```
Ideal for: Security monitoring, threat detection
Result: Blocks threats, learns, but doesn't exploit

### Use Case 3: Autonomous Lab
```
threat.enabled = True
learning.enabled = True
decisions.enabled = True
```
Ideal for: Isolated test lab, capture-the-flag
Result: Full autonomy, minimal supervision

## Safety First

✅ **DO:**
- Start with Learning Only
- Monitor all decisions
- Set high thresholds
- Run in isolated lab first
- Review decision history regularly

❌ **DON'T:**
- Enable auto_exploit immediately
- Set threshold below 6.0 CVSS
- Run in production without approval
- Ignore decision logs
- Leave unattended for days

## Next Steps

1. **Integrate:** Add the 2 lines to HadesAI.py
2. **Test:** Enable Learning Only, run some exploits
3. **Monitor:** Check success rates in Learning tab
4. **Learn:** See how confidence increases
5. **Upgrade:** Enable Threat Response when comfortable
6. **Expert:** Enable Decision Agent in isolated lab

## Support

- Full docs: [AUTONOMOUS_OPERATIONS.md](AUTONOMOUS_OPERATIONS.md)
- Examples: See "Example Decision" section in docs
- Troubleshooting: Check logs in Status section

---

**Autonomy ready. Safety first. Learn as you go.** 🤖
