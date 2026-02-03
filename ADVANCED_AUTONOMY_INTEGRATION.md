# Advanced Autonomy Integration Guide

## Overview

Four powerful autonomous systems added to Hades-AI:

1. **🏥 Self-Healing System** - Auto-detects and fixes errors
2. **⚙️ Adaptive Strategy Engine** - Modifies attacks based on success rates
3. **⏰ Autonomous Scheduler** - Runs operations on schedule
4. **👥 Multi-Agent System** - Agents collaborate on complex tasks

---

## Quick Start (5 Minutes)

### Step 1: Integrate into HadesAI.py

Find the imports section and add:

```python
from advanced_autonomy_gui import AdvancedAutonomyTab
```

### Step 2: Add Tab in MainWindow.__init__

Find where other tabs are created, add:

```python
# Advanced Autonomy Tab
try:
    self.advanced_autonomy = AdvancedAutonomyTab(db_path=self.db_path)
    self.tabs.addTab(self.advanced_autonomy, "🚀 Advanced Autonomy")
except Exception as e:
    logger.warning(f"Failed to load Advanced Autonomy tab: {e}")
```

### Step 3: Restart HadesAI

```bash
python HadesAI.py
```

You'll see the new **"🚀 Advanced Autonomy"** tab with 4 sub-tabs!

---

## System Details

### 1. Self-Healing System

**What it does:**
- Detects errors in real-time
- Automatically determines healing strategy
- Attempts recovery (retry, rollback, fallback, reset, isolate)
- Monitors system health continuously

**Key Features:**
- Real-time error detection
- Automatic recovery mechanisms
- System state validation
- Database integrity checks
- Process health monitoring
- Automatic rollback on failure

**Configuration:**

```python
from modules.self_healing_system import SelfHealingSystem

healing = SelfHealingSystem()

# Enable with options
healing.enable_self_healing(
    auto_retry=True,
    auto_rollback=True,
    auto_heal=True,
    monitoring=True
)

# Register recovery handler
def custom_recovery(error):
    print(f"Custom recovery for {error.component}")
    return True

healing.register_recovery_handler("database:retry", custom_recovery)
```

**Monitoring:**

```python
# Get health status
status = healing.get_health_status()
print(f"Overall: {status['status']}")
print(f"Healthy: {status['healthy_metrics']}/{status['total_metrics']}")

# Get error history
errors = healing.get_error_history()

# Get healing history
healed = healing.get_healing_history()
```

---

### 2. Adaptive Strategy Engine

**What it does:**
- Tracks performance of all attack strategies
- Auto-switches between strategies based on success rates
- Creates and tests strategy variants (A/B testing)
- Adapts strategy parameters based on feedback

**Key Features:**
- Dynamic exploit selection
- Strategy optimization
- Performance-based ranking
- Environmental adaptation
- A/B strategy testing
- Automatic strategy switching

**Configuration:**

```python
from modules.adaptive_strategy_engine import (
    AdaptiveStrategyEngine, StrategyType
)

engine = AdaptiveStrategyEngine()

# Enable
engine.enable_adaptive_strategies(
    ab_testing=True,
    auto_switch=True,
    performance_threshold=0.3
)

# Register strategies
engine.register_strategy(
    "exploit_1",
    StrategyType.EXPLOIT_KNOWN,
    "windows_server"
)

# Record attempts
engine.record_attempt(
    "exploit_1",
    success=True,
    execution_time=2.5,
    environmental_factors={"target_os": "Windows 2016"}
)

# Create variants
variant_id = engine.create_variant(
    "exploit_1",
    {"timeout": 30, "retries": 5}
)

# Evaluate variants
engine.evaluate_variant(variant_id, success=True)

# Get best strategy
best = engine.get_best_strategy("windows_server")
```

**Metrics:**

```python
# Get all strategies
strategies = engine.get_all_strategies("windows_server")

# Get performance summary
summary = engine.get_performance_summary()
print(f"Best success rate: {summary['best_success_rate']:.1%}")

# Get adaptation history
history = engine.get_adaptation_history()
```

---

### 3. Autonomous Scheduler

**What it does:**
- Schedules tasks to run automatically
- Supports cron-like scheduling
- Handles dependencies between tasks
- Auto-retries with exponential backoff
- Conditional execution

**Key Features:**
- Task scheduling (cron-like)
- Conditional execution
- Operation orchestration
- Resource-aware scheduling
- Automatic retries
- Priority-based execution

**Configuration:**

```python
from modules.autonomous_scheduler import (
    AutonomousScheduler, TaskPriority, ExecutionCondition
)

scheduler = AutonomousScheduler()

# Enable
scheduler.enable_scheduling(auto_start=True)

# Define task
def scan_targets():
    print("Scanning targets...")
    return {"scanned": 100}

# Schedule task
scheduler.schedule_task(
    task_id="scan_hourly",
    name="Hourly Target Scan",
    operation=scan_targets,
    schedule_time="@hourly",
    priority=TaskPriority.NORMAL,
    parameters={},
    max_retries=3,
    timeout=300
)

# Manual trigger
scheduler.trigger_task("scan_hourly")

# Enable/disable
scheduler.disable_task("scan_hourly")
scheduler.enable_task("scan_hourly")
```

**Available Schedules:**
- `@hourly` - Every hour
- `@daily` - Every day
- `@weekly` - Every week
- `*/5` - Every 5 minutes
- `HH:MM` - Specific time daily

**Monitoring:**

```python
# Get status
status = scheduler.get_scheduler_status()
print(f"Running: {status['running']}")
print(f"Active tasks: {status['active_tasks']}")

# Get task status
task = scheduler.get_task_status("scan_hourly")

# Get execution history
history = scheduler.get_execution_history(
    task_id="scan_hourly",
    limit=20
)
```

---

### 4. Multi-Agent System

**What it does:**
- Coordinates multiple autonomous agents
- Assigns agents to collaborative tasks
- Handles inter-agent communication
- Auto-reassigns tasks from offline agents
- Resolves conflicts between agents

**Key Features:**
- Agent coordination and communication
- Task delegation and distribution
- Result aggregation
- Conflict resolution
- Load balancing
- Emergent behavior and cooperation

**Configuration:**

```python
from modules.multi_agent_system import (
    MultiAgentSystem, AgentRole
)

system = MultiAgentSystem()

# Enable
system.enable_multi_agent_system(auto_start=True)

# Register agents
system.register_agent(
    agent_id="scout_1",
    name="Scout Agent",
    role=AgentRole.SCOUT,
    capabilities=["network_scan", "port_scan", "service_detection"]
)

system.register_agent(
    agent_id="breacher_1",
    name="Breach Agent",
    role=AgentRole.BREACHER,
    capabilities=["exploit", "brute_force", "vulnerability_check"]
)

# Create collaborative task
task_id = system.create_collaborative_task(
    task_name="Full System Compromise",
    task_description="Scout -> Breach -> Escalate -> Exfiltrate",
    required_roles=[
        AgentRole.SCOUT,
        AgentRole.BREACHER,
        AgentRole.ESCALATOR
    ],
    priority=5
)

# Send inter-agent messages
system.send_message(
    sender_id="scout_1",
    recipient_id="breacher_1",
    message_type="vulnerability_found",
    content={"target": "192.168.1.1", "cvss": 9.2}
)

# Report results
system.report_agent_result(
    agent_id="scout_1",
    task_id=task_id,
    result={"targets_found": 50, "open_ports": 127}
)
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

**Monitoring:**

```python
# Get agent status
agent = system.get_agent_status("scout_1")
print(f"Status: {agent['status']}")
print(f"Performance: {agent['performance_score']}")

# Get system status
status = system.get_system_status()
print(f"Active agents: {status['active_agents']}")
print(f"Running tasks: {status['active_tasks']}")
```

---

## Integration Example

Complete example using all four systems:

```python
from modules.self_healing_system import SelfHealingSystem
from modules.adaptive_strategy_engine import AdaptiveStrategyEngine, StrategyType
from modules.autonomous_scheduler import AutonomousScheduler, TaskPriority
from modules.multi_agent_system import MultiAgentSystem, AgentRole

# Initialize all systems
healing = SelfHealingSystem()
strategy = AdaptiveStrategyEngine()
scheduler = AutonomousScheduler()
agents = MultiAgentSystem()

# Enable all systems
healing.enable_self_healing(auto_retry=True)
strategy.enable_adaptive_strategies(auto_switch=True)
scheduler.enable_scheduling(auto_start=True)
agents.enable_multi_agent_system(auto_start=True)

# Register attack strategies
strategy.register_strategy("sql_injection", StrategyType.EXPLOIT_KNOWN, "web_app")
strategy.register_strategy("bruteforce", StrategyType.BRUTE_FORCE, "ssh")

# Register agents
agents.register_agent("recon", "Reconnaissance", AgentRole.SCOUT)
agents.register_agent("exploit", "Exploitation", AgentRole.BREACHER)

# Schedule reconnaissance every hour
def run_recon():
    print("Running reconnaissance...")
    return {"targets": 100}

scheduler.schedule_task(
    "recon_hourly",
    "Hourly Reconnaissance",
    run_recon,
    "@hourly"
)

# Create collaborative task
task = agents.create_collaborative_task(
    "Network Assessment",
    "Full network assessment and exploitation",
    [AgentRole.SCOUT, AgentRole.BREACHER],
    priority=4
)

print("All systems ready!")
print(f"Task assigned: {task}")
```

---

## Best Practices

### Self-Healing
- ✓ Start with monitoring-only mode
- ✓ Review healed errors regularly
- ✓ Register custom handlers for specific errors
- ✓ Set up log monitoring

### Adaptive Strategies
- ✓ Start with A/B testing disabled
- ✓ Gather ~20+ attempts before trusting adaptation
- ✓ Monitor performance summary regularly
- ✓ Disable underperforming strategies manually

### Autonomous Scheduler
- ✓ Start with long intervals (@hourly)
- ✓ Verify task execution in logs
- ✓ Set appropriate timeouts
- ✓ Use dependencies for sequential tasks

### Multi-Agent System
- ✓ Register all agents before creating tasks
- ✓ Test with small collaborative tasks first
- ✓ Monitor agent health regularly
- ✓ Start with high-reliability agents

---

## Testing

### Verify Installation

```bash
python test_advanced_autonomy.py
```

Should output:
```
[OK] Self-healing system initialized
[OK] Adaptive strategy engine initialized
[OK] Autonomous scheduler initialized
[OK] Multi-agent system initialized
[OK] All systems ready
```

### Test in GUI

1. Open "🚀 Advanced Autonomy" tab
2. Click "Refresh Status" on each sub-tab
3. Enable each system one by one
4. Monitor the status indicators
5. Check history tables

---

## Troubleshooting

### Systems won't enable
- Check database exists: `hades_knowledge.db`
- Verify all modules import successfully
- Check console for specific error messages

### No status updates
- Click "Refresh Status" button
- Check if monitoring is running
- Verify database connectivity

### Scheduler doesn't execute
- Check task parameters are valid
- Verify schedule_time format
- Check timeout isn't too short
- Look at execution history for errors

### Agents not assigned to tasks
- Verify agents registered with correct roles
- Check required roles match available agents
- Monitor agent health status

---

## Files Added

| File | Purpose | Lines |
|------|---------|-------|
| `modules/self_healing_system.py` | Self-healing engine | 600 |
| `modules/adaptive_strategy_engine.py` | Strategy adaptation | 650 |
| `modules/autonomous_scheduler.py` | Task scheduling | 700 |
| `modules/multi_agent_system.py` | Agent coordination | 850 |
| `advanced_autonomy_gui.py` | GUI controls | 800 |
| `ADVANCED_AUTONOMY_INTEGRATION.md` | This guide | 500 |

---

## Next Steps

1. ✓ Add import to HadesAI.py
2. ✓ Add tab in MainWindow.__init__
3. ✓ Restart HadesAI
4. ✓ Enable Self-Healing first
5. ✓ Run system manually and monitor healing
6. ✓ Enable Adaptive Strategies
7. ✓ Record some attack attempts
8. ✓ Watch strategy adaptation
9. ✓ Enable Autonomous Scheduler
10. ✓ Create simple scheduled tasks
11. ✓ Enable Multi-Agent System
12. ✓ Create collaborative tasks

---

## Status

✅ **Complete & Ready to Use**
✅ **All modules functional**
✅ **GUI fully integrated**
✅ **Production-ready code**

---

**Advanced autonomy is now part of Hades-AI. Integrate carefully. Monitor continuously.** 🚀
