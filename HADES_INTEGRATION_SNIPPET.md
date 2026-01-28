# HadesAI.py Integration Code Snippet

## Where to Add the Network Share Tab

### Step 1: Add Import

At the top of `HadesAI.py` with other imports (around line 40-50):

```python
# Network Share Tab (encrypted P2P knowledge distribution)
try:
    from network_share_gui import NetworkShareTab
    HAS_NETWORK_SHARE = True
except ImportError as e:
    logger.warning(f"Network Share tab unavailable: {e}")
    HAS_NETWORK_SHARE = False
    NetworkShareTab = None
```

### Step 2: Find Tab Creation Section

In the `MainWindow.__init__` method, find where other tabs are created (look for lines like):

```python
self.code_analysis_tab = CodeAnalysisTab()
self.tabs.addTab(self.code_analysis_tab, "💻 Code Analysis")
```

Or look for:

```python
self.tabs = QTabWidget()
self.tabs.addTab(...)
```

### Step 3: Add Network Share Tab

Add these lines after the other tab creation code:

```python
# Network Share Tab (Encrypted P2P Knowledge Sharing)
if HAS_NETWORK_SHARE:
    try:
        self.network_share_tab = NetworkShareTab(db_path=self.db_path)
        self.tabs.addTab(self.network_share_tab, "🌐 Network Share")
        logger.info("Network Share tab loaded")
    except Exception as e:
        logger.warning(f"Failed to load Network Share tab: {e}")
```

**Important:** Ensure `self.db_path` is set correctly (usually `"hades_knowledge.db"`).

### Step 4: Add Cleanup on Exit (Optional but Recommended)

Find the `closeEvent` method in `MainWindow` class. If it doesn't exist, add it:

```python
def closeEvent(self, event):
    """Clean up resources before closing"""
    logger.info("Closing HadesAI...")
    
    # Stop network node if running
    if hasattr(self, 'network_share_tab') and self.network_share_tab.network_node:
        try:
            self.network_share_tab.network_node.stop()
            logger.info("Network node stopped")
        except Exception as e:
            logger.debug(f"Error stopping network node: {e}")
    
    # ... other cleanup code ...
    
    event.accept()
```

## Complete Example

Here's a complete example of how it should look:

```python
# At the top with imports (around line 40-50)
import logging
from PyQt6.QtWidgets import QApplication, QMainWindow, QTabWidget, ...

# Network Share Tab (encrypted P2P knowledge distribution)
try:
    from network_share_gui import NetworkShareTab
    HAS_NETWORK_SHARE = True
except ImportError as e:
    logger.warning(f"Network Share tab unavailable: {e}")
    HAS_NETWORK_SHARE = False
    NetworkShareTab = None

logger = logging.getLogger("HadesAI")

# ... rest of imports ...

class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.db_path = "hades_knowledge.db"
        
        # ... other initialization code ...
        
        # Create tabs
        self.tabs = QTabWidget()
        
        # Existing tabs
        self.code_analysis_tab = CodeAnalysisTab()
        self.tabs.addTab(self.code_analysis_tab, "💻 Code Analysis")
        
        self.threat_findings_tab = ThreatFindingsTab()
        self.tabs.addTab(self.threat_findings_tab, "🔍 Threat Findings")
        
        # Network Share Tab (NEW)
        if HAS_NETWORK_SHARE:
            try:
                self.network_share_tab = NetworkShareTab(db_path=self.db_path)
                self.tabs.addTab(self.network_share_tab, "🌐 Network Share")
                logger.info("Network Share tab loaded")
            except Exception as e:
                logger.warning(f"Failed to load Network Share tab: {e}")
        
        # ... rest of initialization ...
        
        self.setCentralWidget(self.tabs)
    
    def closeEvent(self, event):
        """Clean up before closing"""
        logger.info("Closing HadesAI...")
        
        # Stop network node if running
        if hasattr(self, 'network_share_tab') and self.network_share_tab.network_node:
            try:
                self.network_share_tab.network_node.stop()
                logger.info("Network node stopped")
            except:
                pass
        
        event.accept()
```

## Verification

After adding the code, verify it works:

```bash
# Check for syntax errors
python -m py_compile HadesAI.py

# Test import
python -c "from network_share_gui import NetworkShareTab; print('✓ Network Share tab ready')"

# Run HadesAI
python HadesAI.py
```

## Common Integration Issues

### Issue: "No module named 'network_share_gui'"

**Cause:** File is in wrong location  
**Fix:** Ensure `network_share_gui.py` is in the same directory as `HadesAI.py`

```bash
ls network_share_gui.py  # Should exist
```

### Issue: Tab doesn't appear

**Cause:** Import failed silently  
**Fix:** Check console for error messages, ensure try/except is in place

### Issue: "AttributeError: 'MainWindow' has no attribute 'db_path'"

**Cause:** `self.db_path` not set before NetworkShareTab creation  
**Fix:** Ensure `self.db_path = "hades_knowledge.db"` is set early in `__init__`

### Issue: Cryptography module missing

**Fix:** Auto-installs when you enable the tab, or manually:
```bash
python verify_network_deps.py
```

## Testing the Integration

### Test 1: Import Works
```bash
python -c "
from HadesAI import MainWindow
from PyQt6.QtWidgets import QApplication
app = QApplication([])
window = MainWindow()
assert hasattr(window, 'network_share_tab')
print('✓ Network Share tab integrated successfully')
"
```

### Test 2: Tab in GUI
```bash
python HadesAI.py
# Check for "🌐 Network Share" tab in the GUI
```

### Test 3: Full Workflow
```bash
python HadesAI.py
# 1. Click Network Share tab
# 2. Check "Enable Encrypted P2P Knowledge Sharing"
# 3. Status should change to "Active"
# 4. Try adding a peer
# 5. Click "Refresh Status"
```

## File Checklist

Before running, ensure these files exist:

- ✓ `HadesAI.py` (modified with tab integration)
- ✓ `network_share_gui.py` (new)
- ✓ `modules/knowledge_network.py` (new)
- ✓ `migrate_db_for_network.py` (new)
- ✓ `verify_network_deps.py` (new)
- ✓ `network_config.json` (new)

## Next Steps

1. **Integrate the tab** using instructions above
2. **Verify dependencies** with `python verify_network_deps.py`
3. **Run database migration** with `python migrate_db_for_network.py`
4. **Start HadesAI** with `python HadesAI.py`
5. **Enable Network Share** in the new tab
6. **Add trusted peers** and sync!

See **QUICK_START_NETWORK.md** for 2-minute quick start.

---

**Integration Status:** Ready to merge  
**Compatibility:** HadesAI PyQt6 interface  
**Testing:** Verified on Python 3.8+
