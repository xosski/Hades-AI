# Null Check Fix - AttributeError Resolution

## The Issue
```
AttributeError: 'NoneType' object has no attribute 'isRunning'
```

When trying to check `self.test_runner.isRunning()` or `self.deployment_stager.isRunning()`, the object was `None`.

## Root Cause
The code was checking `hasattr(self, 'test_runner')` but not checking if the value was `None` before calling methods on it.

**Before (WRONG):**
```python
if hasattr(self, 'test_runner') and self.test_runner.isRunning():
    # This fails if self.test_runner is None
```

**After (CORRECT):**
```python
if hasattr(self, 'test_runner') and self.test_runner is not None and self.test_runner.isRunning():
    # Safe - checks for None before calling isRunning()
```

## Changes Made

### deployment_automation_gui.py - 5 locations fixed:

1. **Line 601: `_run_single_test()`**
   - Added `self.test_runner is not None` check

2. **Line 629: `_test_completed()`**
   - Added `hasattr` + `is not None` checks

3. **Line 658: `_stage_deployment()`**
   - Added `self.deployment_stager is not None` check

4. **Line 689: `_deployment_completed()`**
   - Added `hasattr` + `is not None` checks

5. **Line 793-801: `cleanup()`**
   - Added `is not None` checks in both thread cleanup blocks

## Pattern Used
```python
# Safe pattern for optional thread objects
if hasattr(self, 'thread_name') and self.thread_name is not None and self.thread_name.isRunning():
    self.thread_name.quit()
    self.thread_name.wait()
```

## Testing
Run deploy tests again:
```bash
# GUI: HadesAI -> Deploy & Test -> Select tests -> Run Tests
python HadesAI.py
```

Should now work without `AttributeError`.
