# Advanced Autonomy - Integration Checklist

## Pre-Integration

- [ ] Backup current HadesAI.py
- [ ] Backup hades_knowledge.db
- [ ] Verify Python 3.8+ installed
- [ ] Check all dependencies available

## Files Verification

### New Modules (in `modules/`)
- [ ] `self_healing_system.py` exists (600+ lines)
- [ ] `adaptive_strategy_engine.py` exists (650+ lines)
- [ ] `autonomous_scheduler.py` exists (700+ lines)
- [ ] `multi_agent_system.py` exists (850+ lines)

### New GUI
- [ ] `advanced_autonomy_gui.py` exists (800+ lines)

### New Tests
- [ ] `test_advanced_autonomy.py` exists (350+ lines)

### New Documentation
- [ ] `ADVANCED_AUTONOMY_QUICK_START.md` exists
- [ ] `ADVANCED_AUTONOMY_INTEGRATION.md` exists
- [ ] `ADVANCED_AUTONOMY_SUMMARY.md` exists
- [ ] `ADVANCED_AUTONOMY_CHECKLIST.md` exists (this file)

## HadesAI.py Integration

### Step 1: Add Import
- [ ] Open HadesAI.py
- [ ] Find imports section (line ~40-50)
- [ ] Add: `from advanced_autonomy_gui import AdvancedAutonomyTab`
- [ ] Verify no import errors

### Step 2: Add Tab
- [ ] Find MainWindow.__init__ method
- [ ] Find where other tabs are created (search for `self.tabs.addTab`)
- [ ] Add this code block:
```python
# Advanced Autonomy Tab
try:
    self.advanced_autonomy = AdvancedAutonomyTab(db_path=self.db_path)
    self.tabs.addTab(self.advanced_autonomy, "🚀 Advanced Autonomy")
except Exception as e:
    logger.warning(f"Failed to load Advanced Autonomy tab: {e}")
```
- [ ] Verify indentation matches surrounding code
- [ ] Save file

### Step 3: Test Import
- [ ] Run: `python -c "from advanced_autonomy_gui import AdvancedAutonomyTab; print('OK')"`
- [ ] Should print "OK" with no errors
- [ ] If error, check Python path and module location

## Testing

### Unit Tests
- [ ] Run: `python test_advanced_autonomy.py`
- [ ] Should see: `✅ PASS: Self-Healing System Test`
- [ ] Should see: `✅ PASS: Adaptive Strategy Engine Test`
- [ ] Should see: `✅ PASS: Autonomous Scheduler Test`
- [ ] Should see: `✅ PASS: Multi-Agent System Test`
- [ ] Should see: `✅ ALL TESTS PASSED`

### GUI Test
- [ ] Start HadesAI: `python HadesAI.py`
- [ ] Look for "🚀 Advanced Autonomy" tab
- [ ] Click on it - should display 4 sub-tabs:
  - [ ] 🏥 Self-Healing
  - [ ] ⚙️ Adaptive Strategies
  - [ ] ⏰ Autonomous Scheduler
  - [ ] 👥 Multi-Agent System
- [ ] Each tab should be fully functional

### Functional Tests

#### Self-Healing Tab
- [ ] Click "Enable Self-Healing" button
- [ ] Status should change to "Status: Enabled" (green)
- [ ] Click "Start Monitoring" button
- [ ] No errors in console
- [ ] Click "Refresh Status" button
- [ ] Health table should populate
- [ ] Health status should display

#### Adaptive Strategies Tab
- [ ] Click "Enable Adaptive Strategies" button
- [ ] Status should change to "Status: Enabled" (green)
- [ ] Click "Refresh" button
- [ ] Performance summary should display
- [ ] Strategies table should be visible

#### Scheduler Tab
- [ ] Click "Enable Scheduler" button
- [ ] Status should change to "Status: Enabled" (orange)
- [ ] Click "Start Scheduler" button
- [ ] Status should change to "Status: Running" (green)
- [ ] Tasks table should be visible
- [ ] Click "Refresh Status" button
- [ ] No errors in console

#### Multi-Agent Tab
- [ ] Click "Enable Multi-Agent System" button
- [ ] Status should change to "Status: Enabled" (green)
- [ ] Click "Start Coordination" button
- [ ] Status should change to "Status: Running" (green)
- [ ] Agents table should be visible
- [ ] Click "Refresh Status" button
- [ ] No errors in console

## Database Verification

- [ ] Check `hades_knowledge.db` exists
- [ ] File size increased (new tables added)
- [ ] Can open in SQLite browser
- [ ] New tables present:
  - [ ] `healing_events`
  - [ ] `health_metrics`
  - [ ] `strategy_metrics`
  - [ ] `strategy_variants`
  - [ ] `adaptation_events`
  - [ ] `scheduled_tasks`
  - [ ] `execution_history`
  - [ ] `agents`
  - [ ] `collaborative_tasks`
  - [ ] `agent_messages`

## Documentation Review

- [ ] Read ADVANCED_AUTONOMY_QUICK_START.md
- [ ] Read ADVANCED_AUTONOMY_INTEGRATION.md
- [ ] Review ADVANCED_AUTONOMY_SUMMARY.md
- [ ] Understand all 4 systems
- [ ] Know how to enable each
- [ ] Know how to monitor each

## Production Checklist

### Before Going Live
- [ ] All tests passing
- [ ] GUI fully functional
- [ ] Database working properly
- [ ] Logging enabled
- [ ] Documentation reviewed
- [ ] Team trained

### Initial Deployment
- [ ] Deploy to test environment first
- [ ] Enable Self-Healing only
- [ ] Monitor for 24 hours
- [ ] Review error logs
- [ ] Enable Adaptive Strategies
- [ ] Monitor for 24 hours

### Gradual Rollout
- [ ] Week 1: Self-Healing enabled
- [ ] Week 2: Add Adaptive Strategies
- [ ] Week 3: Add Scheduler
- [ ] Week 4: Add Multi-Agent System
- [ ] Ongoing: Monitor and optimize

## Troubleshooting Checklist

### Import Errors
- [ ] Check `advanced_autonomy_gui.py` in root directory
- [ ] Check all module files exist in `modules/`
- [ ] Verify Python path includes project root
- [ ] Check for circular imports
- [ ] Review error message carefully

### GUI Won't Load
- [ ] Verify PyQt6 installed: `pip install PyQt6`
- [ ] Check HadesAI.py has proper try-except
- [ ] Verify db_path is correct
- [ ] Check console for error messages
- [ ] Review HadesAI.py syntax

### Systems Won't Enable
- [ ] Check database exists and is writable
- [ ] Verify all modules imported successfully
- [ ] Check SQLite is working
- [ ] Review enable() method calls
- [ ] Check logs for specific errors

### No Status Updates
- [ ] Click "Refresh Status" button
- [ ] Check if monitoring is running
- [ ] Verify database connectivity
- [ ] Check that systems are enabled
- [ ] Review error logs

### Tasks Not Executing
- [ ] Check schedule format is correct
- [ ] Verify scheduler is running
- [ ] Check timeout isn't too short
- [ ] Review execution history
- [ ] Check for task dependencies

## Performance Monitoring

### Metrics to Track
- [ ] Self-healing success rate (target: >95%)
- [ ] Strategy adaptation events (track in history)
- [ ] Task execution success rate (target: >90%)
- [ ] Agent availability (target: 100%)
- [ ] Database size (monitor for growth)

### Optimization
- [ ] Archive old execution records
- [ ] Clean up old healing events
- [ ] Review adaptation history
- [ ] Disable unused strategies
- [ ] Adjust thresholds as needed

## Documentation Updates

After integration, update project docs:
- [ ] Add Advanced Autonomy to main README
- [ ] Update feature list
- [ ] Add Quick Start link
- [ ] Update deployment guide
- [ ] Update troubleshooting guide

## Backup & Recovery

### Before Integration
- [ ] Backup HadesAI.py
- [ ] Backup hades_knowledge.db
- [ ] Backup modules/ directory
- [ ] Document original state

### After Integration
- [ ] Regular database backups (daily)
- [ ] Version control commits
- [ ] Monitor disk space usage
- [ ] Keep recovery procedure documented

## Sign-Off

- [ ] All tests passing: ________ (Date)
- [ ] GUI fully functional: ________ (Date)
- [ ] Documentation complete: ________ (Date)
- [ ] Approved for production: ________ (Date)
- [ ] Deployed to production: ________ (Date)

---

## Integration Summary

**Estimated Time:** 10-15 minutes

**Complexity:** Low (2 import lines + 1 code block)

**Risk Level:** Minimal (backwards compatible)

**Rollback Plan:** Remove 2 import lines + 1 code block

---

## Quick Reference

### Enable All Systems Programmatically

```python
from modules.self_healing_system import SelfHealingSystem
from modules.adaptive_strategy_engine import AdaptiveStrategyEngine
from modules.autonomous_scheduler import AutonomousScheduler
from modules.multi_agent_system import MultiAgentSystem

healing = SelfHealingSystem()
strategy = AdaptiveStrategyEngine()
scheduler = AutonomousScheduler()
agents = MultiAgentSystem()

healing.enable_self_healing()
strategy.enable_adaptive_strategies()
scheduler.enable_scheduling()
agents.enable_multi_agent_system()

print("All systems ready!")
```

### Quick Test

```bash
python test_advanced_autonomy.py
```

### Reset/Clean

```python
import os
os.remove("hades_knowledge.db")
# Restart application to recreate
```

---

**Integration Checklist Complete - Ready for Advanced Autonomy!** ✅
