# Deployment Automation GUI Integration

## Quick Integration (2 minutes)

### Step 1: Add Import (Top of HadesAI.py)

Find the imports section (around line 79-100) and add:

```python
# Deployment Automation
try:
    from deployment_automation_gui import DeploymentAutomationTab
    HAS_DEPLOYMENT_AUTOMATION = True
except ImportError:
    DeploymentAutomationTab = None
    HAS_DEPLOYMENT_AUTOMATION = False
```

### Step 2: Add Tab to GUI (Around line 1000+)

Find where other tabs are added:

```python
if HAS_DEPLOYMENT_AUTOMATION:
    try:
        self.deployment_automation_tab = DeploymentAutomationTab(db_path=self.db_path)
        self.tabs.addTab(self.deployment_automation_tab, "🚀 Deploy & Test")
    except Exception as e:
        logger.warning(f"Deployment Automation tab failed: {e}")
```

### Step 3: Test

```bash
python HadesAI.py
```

You should see a new "🚀 Deploy & Test" tab.

---

## Features Overview

### 🧪 Test Automation
- **Syntax Validation** - Check all Python files for syntax errors
- **Module Imports** - Verify all dependencies are installed
- **Unit Tests** - Run test_*.py files automatically
- **Integration Tests** - Test database, GUI, modules, and network

### 📦 Deployment Staging
- **File Selection** - Choose files to deploy
- **Automatic Backups** - Creates timestamped backups before deploy
- **File Integrity** - SHA256 hash verification
- **Smart Rollback** - Auto-rollback if deployment fails

### ⚙️ Batch Operations
- **Scheduled Operations** - Queue multiple tasks
- **Configurable Delays** - Set delays between operations
- **Parallel Execution** - Run sequential or parallel
- **Retry Logic** - Auto-retry failed operations
- **Batch Logging** - Complete operation history

### 💾 Backup & Restore
- **Multiple Backup Types**:
  - Full backup (database + config)
  - Database only
  - Configuration only
  - Custom selection
- **Compression** - Optional backup compression
- **Backup History** - Track all backups
- **One-Click Restore** - Restore from any backup

---

## Usage Examples

### Example 1: Quick Syntax Check

1. Open HadesAI.py
2. Go to "🚀 Deploy & Test" tab
3. Check "Syntax Validation"
4. Click "▶ Run Selected Tests"
5. Review results in test output

### Example 2: Safe Deployment

1. Click "+ Add Files" 
2. Select files to deploy
3. Ensure "Create Backup Before Deploy" is checked
4. Click "📦 Stage Deployment"
5. Review deployment log
6. Files are staged in `deployments/staging/`
7. Backup created in `deployments/backups/`

### Example 3: Batch Testing & Deploy

1. Go to "⚙️ Batch Operations" tab
2. Set delay to 5 seconds
3. Click "+ Add Operation" 3 times
4. Configure operations
5. Select "Sequential" mode
6. Click "▶ Run Batch Operations"
7. Monitor in batch log

### Example 4: Daily Backup

1. Go to "💾 Backup & Restore" tab
2. Select "Full" backup type
3. Check "Compress Backup"
4. Click "💾 Create Backup Now"
5. Backup appears in history table
6. Backups stored in `backups/` directory

---

## Background Workers

The automation runs tests and deployments in background threads to keep the GUI responsive:

- **TestRunner** - Runs tests asynchronously
- **DeploymentStager** - Stages deployments in background
- Both emit progress signals and completion results

---

## Configuration

### Test Settings
```python
# In _run_tests() method
- Syntax: Checks all *.py files
- Imports: Tests critical modules
- Unit: Runs test_*.py files
- Integration: Validates key systems
```

### Deployment Settings
```python
# In _stage_deployment() method
backup: bool              # Create backup before deploy
verify: bool              # Verify file integrity
auto_rollback: bool       # Rollback on error
```

### Batch Settings
```python
batch_delay: int          # Seconds between operations (0-300)
retry_count: int          # Retries on failure (1-10)
parallel_operations: str  # Sequential, 2 Parallel, or 4 Parallel
```

---

## Directory Structure

After use, you'll have:

```
deployments/
├── backups/
│   ├── 20260217_143022/
│   │   ├── file1.py
│   │   └── file2.py
│   └── 20260217_144015/
│       └── ...
└── staging/
    ├── 20260217_143022/
    │   └── updated_files.py
    └── ...

backups/
├── 20260217_130000/
│   ├── hades_knowledge.db
│   └── network_config.json
└── 20260217_140000/
    └── ...
```

---

## Troubleshooting

### Tab doesn't appear
- Check HAS_DEPLOYMENT_AUTOMATION is True
- Verify import statement added correctly
- Check for syntax errors: `python -m py_compile HadesAI.py`

### Tests fail to run
- Ensure test files exist (test_*.py)
- Check Python version is 3.8+
- Verify database file is accessible

### Deployment staging fails
- Check file paths are valid
- Ensure write permissions to deployments/ directory
- Verify disk space available

### Backup/Restore issues
- Check backups/ directory exists and has write permissions
- Verify database file isn't locked
- Ensure sufficient disk space

---

## Advanced Usage

### Custom Test Scripts

Add custom test files with pattern `test_*.py`:

```python
# test_custom.py
def test_my_feature():
    assert True
    print("✓ Custom test passed")

if __name__ == "__main__":
    test_my_feature()
```

### Automated Scheduled Backups

Use with system scheduler:

```bash
# Linux crontab (daily at 2 AM)
0 2 * * * cd ~/hades-ai && python -c "from deployment_automation_gui import *; create_backup()"

# Windows Task Scheduler
# Run: python C:\path\to\deployment_backup.py
```

### CI/CD Integration

```bash
# In your CI/CD pipeline
python -c "from deployment_automation_gui import TestRunner; TestRunner('syntax', {}).run()"
```

---

## Success Indicators

✅ Tab loads without errors  
✅ Tests run and display results  
✅ Deployments create backups  
✅ File integrity verified  
✅ Restore from backups works  
✅ Batch operations complete  

---

**Version:** 1.0  
**Added:** February 17, 2026  
**Status:** Ready for Production
