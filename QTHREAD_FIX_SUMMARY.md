# QThread Cleanup Fix - Deploy Test Error

## Issue
When running a deploy test, the application was throwing:
```
QThread: Destroyed while thread '' is still running
```

## Root Cause
This is a classic Qt threading issue where:
1. `TestRunner` and `DeploymentStager` QThread objects were started but never properly stopped
2. When the application exited or threads completed, Qt tried to destroy a still-running thread
3. No cleanup mechanism existed to gracefully stop threads before application shutdown

## Solution

### 1. **deployment_automation_gui.py**

#### Added cleanup checks before starting new threads:
- In `_run_single_test()`: Stop and wait for previous test runner
- In `_stage_deployment()`: Stop and wait for previous deployment stager

#### Added thread cleanup in completion callbacks:
- `_test_completed()`: Properly quit/wait the test runner thread after completion
- `_deployment_completed()`: Properly quit/wait the deployment stager thread after completion

#### Added cleanup method:
```python
def cleanup(self):
    """Cleanup threads on application close"""
    # Stop and wait for test runner
    if hasattr(self, 'test_runner') and self.test_runner.isRunning():
        self.test_runner.quit()
        self.test_runner.wait(5000)  # 5 second timeout
    
    # Stop and wait for deployment stager
    if hasattr(self, 'deployment_stager') and self.deployment_stager.isRunning():
        self.deployment_stager.quit()
        self.deployment_stager.wait(5000)  # 5 second timeout
```

### 2. **HadesAI.py**

#### Added closeEvent handler to HadesGUI class:
```python
def closeEvent(self, event):
    """Handle application close - cleanup all threads"""
    try:
        # Cleanup deployment automation threads
        if hasattr(self, 'deployment_automation_tab') and self.deployment_automation_tab:
            if hasattr(self.deployment_automation_tab, 'cleanup'):
                self.deployment_automation_tab.cleanup()
        
        # Cleanup autonomous agent
        if hasattr(self, '_agent') and self._agent and self._agent.isRunning():
            self._agent.stop()
            self._agent.wait(2000)
        
        # Cleanup other threads gracefully
        if hasattr(self, 'scanner') and self.scanner and self.scanner.isRunning():
            self.scanner.quit()
            self.scanner.wait(1000)
        
        if hasattr(self, 'network_monitor') and self.network_monitor and self.network_monitor.isRunning():
            self.network_monitor.quit()
            self.network_monitor.wait(1000)
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
    finally:
        event.accept()
```

## Key Points

1. **Thread.quit()** - Stops the event loop in the thread
2. **Thread.wait()** - Blocks until the thread terminates (with timeout)
3. **Layered cleanup** - Removes threads at multiple levels (completion + application close)
4. **Error handling** - Gracefully handles cleanup errors to ensure event.accept() is always called
5. **Timeout protection** - Prevents hanging with explicit wait timeouts

## Testing

Run the deploy test again. The "QThread: Destroyed while thread is still running" error should no longer appear.

```bash
# Run tests
python -m pytest test_deployment_automation_gui.py

# Or through the GUI
# 1. Open HadesAI
# 2. Go to "🚀 Deploy & Test" tab
# 3. Select tests (syntax, imports, unit, integration)
# 4. Click "Run Tests"
# 5. Verify no QThread errors on application close
```

## Files Modified
- `deployment_automation_gui.py` - Added thread cleanup checks and cleanup method
- `HadesAI.py` - Added closeEvent handler to HadesGUI class
