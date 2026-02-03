# Advanced Autonomy Quick Start

## Install (2 minutes)

Add to `HadesAI.py` imports:
```python
from advanced_autonomy_gui import AdvancedAutonomyTab
```

Add to `MainWindow.__init__` where tabs are created:
```python
self.advanced_autonomy = AdvancedAutonomyTab(db_path=self.db_path)
self.tabs.addTab(self.advanced_autonomy, "🚀 Advanced Autonomy")
```

Restart: `python HadesAI.py`

---

## 4 New Systems

### 1️⃣ Self-Healing System (`🏥`)
**Auto-detects errors and fixes them**

```python
from modules.self_healing_system import SelfHealingSystem

healing = SelfHealingSystem()
healing.enable_self_healing()  # Auto-monitors & heals

# Report errors
healing.report_error("database", "connection_error", "DB offline", severity=0.8)

# Check health
status = healing.get_health_status()
```

**What happens:**
- Detects errors in real-time
- Chooses recovery strategy (retry, rollback, fallback, reset, isolate)
- Attempts recovery automatically
- Tracks healing history

---

### 2️⃣ Adaptive Strategy Engine (`⚙️`)
**Modifies attacks based on success rates**

```python
from modules.adaptive_strategy_engine import AdaptiveStrategyEngine, StrategyType

engine = AdaptiveStrategyEngine()
engine.enable_adaptive_strategies()

# Register strategies
engine.register_strategy("sql_injection", StrategyType.EXPLOIT_KNOWN, "web_app")

# Record attempts
engine.record_attempt("sql_injection", success=True, execution_time=2.5)

# Get best strategy
best = engine.get_best_strategy("web_app")
```

**What happens:**
- Tracks success rate of each strategy
- Auto-switches to better ones
- Creates & tests variants (A/B testing)
- Adapts parameters based on feedback
- Disables underperforming strategies

---

### 3️⃣ Autonomous Scheduler (`⏰`)
**Runs operations on schedule**

```python
from modules.autonomous_scheduler import AutonomousScheduler, TaskPriority

scheduler = AutonomousScheduler()
scheduler.enable_scheduling()

# Schedule task
def scan_targets():
    return {"scanned": 100}

scheduler.schedule_task(
    "scan_hourly",
    "Hourly Scan",
    scan_targets,
    "@hourly",  # or @daily, @weekly, */5
    priority=TaskPriority.HIGH
)

# Manually trigger
scheduler.trigger_task("scan_hourly")
```

**What happens:**
- Runs tasks on cron schedule
- Handles dependencies
- Auto-retries with backoff
- Executes based on conditions
- Tracks execution history

**Schedules:**
- `@hourly`, `@daily`, `@weekly`
- `*/5` (every 5 minutes)
- `HH:MM` (specific time daily)

---

### 4️⃣ Multi-Agent System (`👥`)
**Agents collaborate on complex tasks**

```python
from modules.multi_agent_system import MultiAgentSystem, AgentRole

system = MultiAgentSystem()
system.enable_multi_agent_system()

# Register agents
system.register_agent("scout_1", "Scout", AgentRole.SCOUT, ["scan", "recon"])
system.register_agent("breach_1", "Breacher", AgentRole.BREACHER, ["exploit"])

# Create collaborative task
task_id = system.create_collaborative_task(
    "Network Assessment",
    "Full assessment and exploitation",
    [AgentRole.SCOUT, AgentRole.BREACHER],
    priority=4
)

# Send inter-agent messages
system.send_message("scout_1", "breach_1", "vulnerability_found", 
                   {"target": "192.168.1.1", "cvss": 9.2})

# Report results
system.report_agent_result("scout_1", task_id, {"targets": 50})
```

**Agent Roles:**
- `SCOUT` - Reconnaissance
- `BREACHER` - Exploitation
- `LATERAL` - Lateral movement
- `ESCALATOR` - Privilege escalation
- `EXFILTRATOR` - Data extraction
- `PERSISTENCE` - Maintaining access
- `CLEANER` - Covering tracks
- `COORDINATOR` - Orchestrating others

**What happens:**
- Automatically assigns best agents to tasks
- Handles agent-to-agent communication
- Reassigns tasks if agents go offline
- Resolves conflicts
- Aggregates results

---

## GUI Controls

Open HadesAI → "🚀 Advanced Autonomy" tab → Choose sub-tab

### 🏥 Self-Healing Tab
- Enable/start monitoring
- Configure retry, rollback, healing options
- View health metrics
- See error history

### ⚙️ Adaptive Strategies Tab
- Enable adaptive strategies
- Configure A/B testing, auto-switch, threshold
- View active strategies & success rates
- See performance summary

### ⏰ Scheduler Tab
- Enable/start scheduler
- Configure task execution
- View scheduled tasks
- See execution history

### 👥 Multi-Agent Tab
- Enable multi-agent system
- Start coordination
- View active agents
- See collaborative tasks

---

## Testing

```bash
# Test all systems
python test_advanced_autonomy.py
```

Expected output:
```
✅ PASS: Self-Healing
✅ PASS: Adaptive Strategies
✅ PASS: Autonomous Scheduler
✅ PASS: Multi-Agent System
```

---

## Integration Examples

### Self-Healing + Adaptive Strategies

```python
healing.enable_self_healing()
engine.enable_adaptive_strategies()

# Error occurs → healing detects → chooses strategy
# Strategy fails → healing retries with different strategy
```

### Scheduler + Multi-Agent

```python
scheduler.enable_scheduling()
system.enable_multi_agent_system()

# Task scheduled → agents assigned
# Agents execute → report results → task completes
```

### All Together

```python
# Enable all systems
healing.enable_self_healing()
engine.enable_adaptive_strategies()
scheduler.enable_scheduling()
system.enable_multi_agent_system()

# Register agents
system.register_agent("worker_1", "Worker", AgentRole.SCOUT)

# Schedule task
def work():
    # Work code
    return result

scheduler.schedule_task("work_hourly", "Work", work, "@hourly")

# Create collaborative task
task = system.create_collaborative_task(
    "Complex Operation",
    "Multi-agent complex operation",
    [AgentRole.SCOUT, AgentRole.BREACHER]
)

# System now:
# - Runs work hourly (scheduler)
# - Assigns agents to task (multi-agent)
# - Adapts strategies (adaptive engine)
# - Heals errors (self-healing)
```

---

## Best Practices

### Start Simple
1. Enable Self-Healing first
2. Monitor for 1 hour
3. Enable Adaptive Strategies
4. Record 20+ attempts
5. Enable Scheduler with 1 task
6. Test multi-agent with 2 agents

### Monitor Regularly
- Check health status every hour
- Review error history daily
- Watch strategy success rates
- Monitor execution history
- Check agent health

### Gradual Escalation
- Low complexity tasks → High complexity
- Few agents → Many agents
- Simple strategies → Complex strategies
- Lenient thresholds → Strict thresholds

---

## Performance Metrics

### Self-Healing
- Health check interval: 30s
- Recovery methods: 5 types
- Max retries: 3
- Healing rate target: >95%

### Adaptive Strategies
- Min attempts before adapting: 10
- Success rate update: Real-time
- Variant testing: A/B enabled
- Performance threshold: 0.3

### Autonomous Scheduler
- Task execution: On schedule
- Retry policy: Exponential backoff
- Max retries: 3
- Timeout: 300s default

### Multi-Agent System
- Agent health check: 60s intervals
- Task assignment: Automatic
- Conflict resolution: Enabled
- Load balancing: Enabled

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Systems won't enable | Check database exists, verify imports |
| No status updates | Click refresh, verify monitoring running |
| Scheduler doesn't run | Check schedule format, verify timeout |
| Agents not assigned | Verify roles match, check agent health |
| Strategies not adapting | Need 10+ attempts, check threshold |

---

## Files Added

- `modules/self_healing_system.py` - Self-healing engine
- `modules/adaptive_strategy_engine.py` - Strategy adaptation
- `modules/autonomous_scheduler.py` - Task scheduling
- `modules/multi_agent_system.py` - Agent coordination
- `advanced_autonomy_gui.py` - GUI interface
- `test_advanced_autonomy.py` - Test suite
- `ADVANCED_AUTONOMY_INTEGRATION.md` - Full guide
- `ADVANCED_AUTONOMY_QUICK_START.md` - This file

---

## Next Steps

1. Add to HadesAI.py ✓
2. Restart HadesAI ✓
3. Run test_advanced_autonomy.py ✓
4. Open GUI → Enable Self-Healing ✓
5. Monitor for errors ✓
6. Enable Adaptive Strategies ✓
7. Record attempts ✓
8. Enable Scheduler ✓
9. Create tasks ✓
10. Enable Multi-Agent ✓
11. Create collaborative tasks ✓

---

**Advanced autonomy ready. Go faster. Break less. 🚀**
