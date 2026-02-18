# Exact Code Changes Made

## File 1: deployment_automation_gui.py

### Change 1: _run_single_test() - Lines 598-605
**Added:**
```python
# Stop previous runner if still running
if hasattr(self, 'test_runner') and self.test_runner.isRunning():
    self.test_runner.quit()
    self.test_runner.wait()
```

**Before:**
```python
def _run_single_test(self, test_type: str):
    """Run a single test"""
    self.test_runner = TestRunner(test_type, {})
```

**After:**
```python
def _run_single_test(self, test_type: str):
    """Run a single test"""
    # Stop previous runner if still running
    if hasattr(self, 'test_runner') and self.test_runner.isRunning():
        self.test_runner.quit()
        self.test_runner.wait()
    
    self.test_runner = TestRunner(test_type, {})
```

---

### Change 2: _test_completed() - Lines 625-629
**Added:**
```python
# Properly cleanup thread
if self.test_runner.isRunning():
    self.test_runner.quit()
    self.test_runner.wait()
```

**Before:**
```python
def _test_completed(self, results: dict):
    """Test completed"""
    self.test_output.append(f"\n[{results.get('status', 'UNKNOWN')}] {results.get('type', 'Unknown')}")
    
    row = self.test_results_table.rowCount()
    self.test_results_table.insertRow(row)
    
    test_type = results.get("type", "Unknown")
    status = results.get("status", "UNKNOWN")
    
    self.test_results_table.setItem(row, 0, QTableWidgetItem(test_type))
    self.test_results_table.setItem(row, 1, QTableWidgetItem(status))
    self.test_results_table.setItem(row, 2, QTableWidgetItem(json.dumps(results, default=str)[:100]))
```

**After:**
```python
def _test_completed(self, results: dict):
    """Test completed"""
    self.test_output.append(f"\n[{results.get('status', 'UNKNOWN')}] {results.get('type', 'Unknown')}")
    
    row = self.test_results_table.rowCount()
    self.test_results_table.insertRow(row)
    
    test_type = results.get("type", "Unknown")
    status = results.get("status", "UNKNOWN")
    
    self.test_results_table.setItem(row, 0, QTableWidgetItem(test_type))
    self.test_results_table.setItem(row, 1, QTableWidgetItem(status))
    self.test_results_table.setItem(row, 2, QTableWidgetItem(json.dumps(results, default=str)[:100]))
    
    # Properly cleanup thread
    if self.test_runner.isRunning():
        self.test_runner.quit()
        self.test_runner.wait()
```

---

### Change 3: _stage_deployment() - Lines 648-655
**Added:**
```python
# Stop previous stager if still running
if hasattr(self, 'deployment_stager') and self.deployment_stager.isRunning():
    self.deployment_stager.quit()
    self.deployment_stager.wait()
```

**Before:**
```python
def _stage_deployment(self):
    """Stage deployment"""
    files = []
    for i in range(self.deployment_files_list.count()):
        files.append(self.deployment_files_list.item(i).text())
    
    if not files:
        QMessageBox.warning(self, "No Files", "Please add files to deploy")
        return
    
    self.deploy_progress.setVisible(True)
```

**After:**
```python
def _stage_deployment(self):
    """Stage deployment"""
    files = []
    for i in range(self.deployment_files_list.count()):
        files.append(self.deployment_files_list.item(i).text())
    
    if not files:
        QMessageBox.warning(self, "No Files", "Please add files to deploy")
        return
    
    # Stop previous stager if still running
    if hasattr(self, 'deployment_stager') and self.deployment_stager.isRunning():
        self.deployment_stager.quit()
        self.deployment_stager.wait()
    
    self.deploy_progress.setVisible(True)
```

---

### Change 4: _deployment_completed() - Lines 683-691
**Added:**
```python
# Properly cleanup thread
if self.deployment_stager.isRunning():
    self.deployment_stager.quit()
    self.deployment_stager.wait()
```

**Before:**
```python
def _deployment_completed(self, results: dict):
    """Deployment completed"""
    status = results.get("status", "UNKNOWN")
    self.deploy_output.append(f"\n[{status}] Deployment Complete")
    
    if status == "SUCCESS":
        QMessageBox.information(self, "Success", f"Deployment staged successfully!\nBackup: {results.get('backup_dir', 'N/A')}")
    else:
        QMessageBox.critical(self, "Error", f"Deployment failed: {results.get('error', 'Unknown')}")
```

**After:**
```python
def _deployment_completed(self, results: dict):
    """Deployment completed"""
    status = results.get("status", "UNKNOWN")
    self.deploy_output.append(f"\n[{status}] Deployment Complete")
    
    # Properly cleanup thread
    if self.deployment_stager.isRunning():
        self.deployment_stager.quit()
        self.deployment_stager.wait()
    
    if status == "SUCCESS":
        QMessageBox.information(self, "Success", f"Deployment staged successfully!\nBackup: {results.get('backup_dir', 'N/A')}")
    else:
        QMessageBox.critical(self, "Error", f"Deployment failed: {results.get('error', 'Unknown')}")
```

---

### Change 5: NEW METHOD cleanup() - Lines 780-791
**Added:**
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

**Location:** Just before `def main():`

---

## File 2: HadesAI.py

### Change: NEW METHOD closeEvent() - Lines 8500-8527
**Added entire new method:**
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

**Location:** Added to HadesGUI class, after `_on_agent_finished()` method, before AutoReconScanner class definition

---

## Summary

| File | Changes | Type |
|------|---------|------|
| deployment_automation_gui.py | 5 changes | 4 methods + 1 new method |
| HadesAI.py | 1 change | 1 new method |
| **Total** | **6 changes** | **5 modified + 1 new** |

## Lines of Code Changed
- deployment_automation_gui.py: ~25 lines added
- HadesAI.py: ~28 lines added
- **Total: ~53 lines of code**

## Verification Command
```bash
python -m py_compile deployment_automation_gui.py HadesAI.py
```

Expected output: No errors (clean compilation)
