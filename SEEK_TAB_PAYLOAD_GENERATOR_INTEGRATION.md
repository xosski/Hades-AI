# Seek Tab + Payload Generator Integration

**Status**: Integration Blueprint Ready  
**Complexity**: Low-Medium  
**Implementation Time**: 2-4 hours  
**Priority**: HIGH

---

## Overview

The **Payload Generator** already exists and generates payloads for 14+ file types. The **Seek Tab** can be enhanced to:

1. **Use payloads** from the Payload Generator instead of hardcoded ones
2. **Generate custom payloads** for detected file types
3. **Integrate payload library** into exploit executor
4. **Share payloads** via P2P network

---

## Current State

### Payload Generator ✅
```python
PayloadGenerator.FILE_TYPE_PATTERNS = {
    'sql': {'payloads': [...]},
    'xss': {'payloads': [...]},
    'xml': {'payloads': [...]},
    'json': {'payloads': [...]},
    'html': {'payloads': [...]},
    'php': {'payloads': [...]},
    'python': {'payloads': [...]},
    'csv': {'payloads': [...]},
    'pdf': {'payloads': [...]},
    'image': {'payloads': [...]},
    'office': {'payloads': [...]},
    'archive': {'payloads': [...]},
    'binary': {'payloads': [...]},
}
```

**What it does**:
- Detects file type from extension + binary signature
- Generates 5-7 context-specific payloads per type
- Supports 14+ file type categories
- Can export as JSON or TXT

**Limitations**:
- Independent of Seek Tab
- No integration with exploit executor
- Payloads not used for automated testing

### Exploit Executor (Just Created) ✅
```python
ExploitExecutor.attempt_sql_injection()
ExploitExecutor.attempt_xss()
ExploitExecutor.attempt_rce()
ExploitExecutor.attempt_path_traversal()
```

**What it does**:
- Executes real exploitation attempts
- Uses hardcoded payloads
- Generates proof points

**Limitation**:
- Limited to 4 exploit types
- Hardcoded payloads (not extensible)

### Seek Tab (Existing) ✅
- Enumerates exploits from 7 sources
- Auto-attempt with predefined tests
- Results display

**Limitation**:
- Uses AI vulnerability tester with limited payloads
- Not connected to Payload Generator

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Seek Tab                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ UnifiedSeekWorker                                    │   │
│  │  ├── Enumerate exploits (7 sources)                 │   │
│  │  ├── Detect target type (file type detection)       │   │
│  │  └── Get payloads from PayloadGenerator             │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ ExploitExecutor                                      │   │
│  │  ├── Receive payloads from Payload Generator        │   │
│  │  ├── Attempt exploitation with real payloads        │   │
│  │  └── Generate proof points                          │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
           ↑
           │ Uses
           │
┌─────────────────────────────────────────────────────────────┐
│              Payload Generator                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ PayloadGenerator.FILE_TYPE_PATTERNS                  │   │
│  │ 14+ file types with context-specific payloads       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Integration Steps

### Step 1: Create Unified Payload Service

```python
# File: payload_service.py
"""
Unified payload service integrating PayloadGenerator with ExploitExecutor
"""

from payload_generator_gui import PayloadGenerator
import logging

logger = logging.getLogger("PayloadService")


class PayloadService:
    """Central service for payload management"""
    
    def __init__(self):
        self.generator = PayloadGenerator
        self.cache = {}
    
    def get_payloads_for_vulnerability(self, vuln_type: str) -> list:
        """
        Map vulnerability type to payload library
        
        Examples:
            'sql_injection' -> Get SQL payloads from PayloadGenerator
            'xss' -> Get XSS payloads from PayloadGenerator
            'xxe' -> Get XML payloads (contains XXE)
        """
        # Map exploit types to payload generator file types
        TYPE_MAPPING = {
            'sql_injection': 'sql',
            'xss': 'html',  # XSS payloads in HTML category
            'xxe': 'xml',
            'rce': 'php',  # RCE payloads in PHP category
            'code_injection': 'python',
            'path_traversal': 'archive',
            'formula_injection': 'csv',
            'json_injection': 'json',
            'command_injection': 'bash',  # Treat as PHP
        }
        
        file_type = TYPE_MAPPING.get(vuln_type.lower(), 'unknown')
        
        if file_type in self.cache:
            return self.cache[file_type]
        
        payloads = self.generator.get_payloads(file_type)
        self.cache[file_type] = payloads
        
        logger.debug(f"Retrieved {len(payloads)} payloads for {vuln_type}")
        return payloads
    
    def get_payloads_for_detected_file(self, file_path: str) -> dict:
        """
        Auto-detect file type and return payloads
        """
        result = self.generator.generate_payloads(file_path)
        return result
    
    def get_all_payloads_by_type(self) -> dict:
        """Get all payloads organized by type"""
        return {
            ftype: self.generator.get_payloads(ftype)
            for ftype in self.generator.FILE_TYPE_PATTERNS.keys()
        }
    
    def filter_payloads(self, payloads: list, max_length: int = 1024) -> list:
        """Filter payloads by constraints"""
        return [p for p in payloads if len(p) <= max_length]
```

### Step 2: Extend Exploit Executor

```python
# File: exploit_executor.py (modify existing)

from payload_service import PayloadService

class ExploitExecutor:
    def __init__(self, target_url: str, timeout: int = DEFAULT_TIMEOUT, 
                 use_payload_generator: bool = True):
        # ... existing init code ...
        
        # NEW: Optional payload generator
        self.use_payload_generator = use_payload_generator
        if use_payload_generator:
            self.payload_service = PayloadService()
        else:
            self.payload_service = None
    
    def attempt_sql_injection(self, custom_payloads: list = None) -> ExecutionResult:
        """
        Attempt SQL injection with custom or generated payloads
        
        Args:
            custom_payloads: Use these instead of auto-generated
        """
        result = ExecutionResult(...)
        
        try:
            # Use custom payloads or get from service
            if custom_payloads:
                payloads = custom_payloads
            elif self.payload_service:
                payloads = self.payload_service.get_payloads_for_vulnerability(
                    'sql_injection'
                )
            else:
                # Fallback to hardcoded
                payloads = [
                    ("' OR '1'='1'--", "Boolean-based SQLi"),
                    ("' OR 1=1--", "Comment bypass"),
                ]
            
            for payload, description in payloads:
                # Test payload
                for param in self._get_parameters():
                    result_attempt = self._test_sql_injection_param(
                        param, payload, baseline, description
                    )
                    
                    if result_attempt.success:
                        return result_attempt
        
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def attempt_xss(self, custom_payloads: list = None) -> ExecutionResult:
        """Attempt XSS with payloads from generator"""
        result = ExecutionResult(...)
        
        try:
            if custom_payloads:
                payloads = custom_payloads
            elif self.payload_service:
                # Get XSS payloads from HTML category
                payloads = self.payload_service.get_payloads_for_vulnerability('xss')
            else:
                payloads = [
                    '<img src=x onerror="alert(1)">',
                    '<svg onload="alert(1)">',
                ]
            
            # Test payloads...
        
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def get_available_payloads(self) -> dict:
        """Get all available payloads for testing"""
        if self.payload_service:
            return self.payload_service.get_all_payloads_by_type()
        return {}
```

### Step 3: Update Seek Tab

```python
# File: exploit_seek_tab.py (modify existing)

from payload_service import PayloadService

class ExploitSeekTab(QWidget):
    def __init__(self, parent=None, exploit_sharer=None, hades_ai=None):
        # ... existing code ...
        
        # NEW: Initialize payload service
        try:
            self.payload_service = PayloadService()
            HAS_PAYLOAD_SERVICE = True
        except Exception as e:
            logger.warning(f"Payload service not available: {e}")
            self.payload_service = None
            HAS_PAYLOAD_SERVICE = False
    
    def init_ui(self):
        # ... existing UI code ...
        
        # NEW: Add custom payload input
        payload_group = QGroupBox("Custom Payloads")
        payload_layout = QVBoxLayout(payload_group)
        
        # Checkbox to use payload generator
        self.use_generator_check = QCheckBox("Use Payload Generator")
        self.use_generator_check.setChecked(True)
        self.use_generator_check.setEnabled(HAS_PAYLOAD_SERVICE)
        self.use_generator_check.setToolTip(
            "Automatically use payloads from Payload Generator"
        )
        payload_layout.addWidget(self.use_generator_check)
        
        # Custom payloads text area
        custom_label = QLabel("Custom Payloads (one per line):")
        payload_layout.addWidget(custom_label)
        
        self.custom_payloads_text = QTextEdit()
        self.custom_payloads_text.setPlaceholderText(
            "Enter custom payloads here, one per line\n"
            "Leave empty to use Payload Generator"
        )
        self.custom_payloads_text.setMaximumHeight(80)
        payload_layout.addWidget(self.custom_payloads_text)
        
        layout.addWidget(payload_group)


class UnifiedSeekWorker(QThread):
    def run(self):
        try:
            self.progress.emit("Initiating comprehensive exploit enumeration...")
            
            # Get exploits
            exploits = self.unified_seeker.seek_all_exploits(self.target_url)
            
            # NEW: Get executor with payload service
            executor = ExploitExecutor(
                self.target_url,
                timeout=30,
                use_payload_generator=True  # Enable payload generator
            )
            
            # Test each exploit
            for exploit in exploits:
                if exploit.get('confidence', 0) > 0.6:
                    # Get payloads
                    custom_payloads = self._get_custom_payloads()
                    
                    # Use payload service if available
                    if executor.payload_service and not custom_payloads:
                        custom_payloads = executor.payload_service.get_payloads_for_vulnerability(
                            exploit.get('exploit_type', '')
                        )
                    
                    # Attempt with payloads
                    vuln_type = exploit.get('exploit_type', '').lower()
                    
                    if 'sql' in vuln_type:
                        result = executor.attempt_sql_injection(custom_payloads)
                    elif 'xss' in vuln_type:
                        result = executor.attempt_xss(custom_payloads)
                    elif 'rce' in vuln_type:
                        result = executor.attempt_rce()
                    
                    exploit['execution_result'] = result
                    exploit['verified'] = result.success if result else False
            
            # Continue with rest of processing...
```

### Step 4: Add Payload Selection UI

```python
class ExploitSeekTab(QWidget):
    def init_ui(self):
        # ... existing code ...
        
        # NEW: Payload selector button
        payload_selector_btn = QPushButton("📦 Select Payloads from Generator")
        payload_selector_btn.setEnabled(HAS_PAYLOAD_SERVICE)
        payload_selector_btn.clicked.connect(self._open_payload_selector)
        payload_layout.addWidget(payload_selector_btn)
    
    def _open_payload_selector(self):
        """Open dialog to select payloads from Payload Generator"""
        if not self.payload_service:
            QMessageBox.warning(self, "Not Available", 
                              "Payload Generator not initialized")
            return
        
        # Get all available payloads
        all_payloads = self.payload_service.get_all_payloads_by_type()
        
        # Create selection dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Payloads from Generator")
        dialog.setGeometry(100, 100, 600, 500)
        
        layout = QVBoxLayout()
        
        # Type selector
        type_label = QLabel("Select Payload Type:")
        layout.addWidget(type_label)
        
        type_combo = QComboBox()
        type_combo.addItems(all_payloads.keys())
        layout.addWidget(type_combo)
        
        # Payload list
        payload_list = QListWidget()
        
        def on_type_changed(payload_type):
            payload_list.clear()
            payloads = all_payloads.get(payload_type, [])
            for i, payload in enumerate(payloads):
                item = QListWidgetItem(f"{i+1}. {payload[:60]}...")
                item.setData(Qt.UserRole, payload)
                payload_list.addItem(item)
        
        type_combo.currentTextChanged.connect(on_type_changed)
        on_type_changed(type_combo.currentText())
        
        payload_list.setSelectionMode(
            QAbstractItemView.SelectionMode.MultiSelection
        )
        layout.addWidget(payload_list)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        select_btn = QPushButton("Add Selected")
        select_btn.clicked.connect(lambda: self._add_selected_payloads(
            payload_list, dialog
        ))
        button_layout.addWidget(select_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        dialog.setLayout(layout)
        dialog.exec()
    
    def _add_selected_payloads(self, payload_list, dialog):
        """Add selected payloads to custom payloads field"""
        selected = payload_list.selectedItems()
        
        if not selected:
            QMessageBox.warning(self, "No Selection", "Select at least one payload")
            return
        
        # Get current text
        current = self.custom_payloads_text.toPlainText()
        lines = current.split('\n') if current else []
        
        # Add selected payloads
        for item in selected:
            payload = item.data(Qt.UserRole)
            if payload not in lines:
                lines.append(payload)
        
        self.custom_payloads_text.setPlainText('\n'.join(lines))
        dialog.accept()
```

---

## Integration Benefits

### Before Integration
```
Seek Tab
├── Hardcoded payloads (4 types)
├── Limited SQL injection tests
├── Limited XSS tests
└── Limited RCE tests

Payload Generator
├── 14+ file types
├── 5-7 payloads per type
└── Disconnected from Seek Tab
```

### After Integration
```
Seek Tab
├── 14+ payload types available
├── 50+ unique payloads
├── Custom payload support
├── Payload selection UI
└── Smart payload detection
```

---

## Testing Strategy

### Test 1: Payload Service
```python
def test_payload_service():
    service = PayloadService()
    
    # Test SQL payloads
    sql_payloads = service.get_payloads_for_vulnerability('sql_injection')
    assert len(sql_payloads) > 0
    assert "' OR '1'='1'" in str(sql_payloads)
    
    # Test XSS payloads
    xss_payloads = service.get_payloads_for_vulnerability('xss')
    assert len(xss_payloads) > 0
    assert 'alert' in str(xss_payloads)
    
    # Test XXE payloads
    xxe_payloads = service.get_payloads_for_vulnerability('xxe')
    assert len(xxe_payloads) > 0
    assert 'DOCTYPE' in str(xxe_payloads)
```

### Test 2: Executor with Payloads
```python
def test_executor_with_payloads():
    executor = ExploitExecutor(
        "http://localhost:8000/vulnerable",
        use_payload_generator=True
    )
    
    # Should use Payload Generator payloads
    result = executor.attempt_sql_injection()
    
    assert result.payload in executor.payload_service.get_payloads_for_vulnerability('sql_injection')
```

### Test 3: Seek Tab Integration
```python
# In Seek Tab:
1. Enable "Use Payload Generator" checkbox
2. Run seek on target
3. Verify payloads come from Payload Generator
4. Check that custom payloads are used if provided
```

---

## Configuration

### Enable/Disable Payload Generator
```python
# In ExploitExecutor
executor = ExploitExecutor(
    target_url,
    use_payload_generator=True  # Enable
)

# Or disable
executor = ExploitExecutor(
    target_url,
    use_payload_generator=False  # Use hardcoded only
)
```

### Custom Payload Constraints
```python
# In PayloadService
def filter_payloads(self, payloads: list, max_length: int = 1024):
    """Only payloads under 1KB"""
    return [p for p in payloads if len(p) <= max_length]
```

---

## File Changes Summary

| File | Changes | Lines |
|------|---------|-------|
| `payload_service.py` | NEW | 100+ |
| `exploit_executor.py` | Add payload service support | +30 |
| `exploit_seek_tab.py` | Add UI and integration | +50 |
| `requirements.txt` | No changes (already has dependencies) | 0 |

---

## Available Payloads by Type

After integration, you'll have:

| File Type | Payloads | Examples |
|-----------|----------|----------|
| JavaScript | 7 | XSS, code injection, template injection |
| SQL | 6 | SQL injection (multiple types) |
| XML | 4 | XXE, entity expansion, DTD attacks |
| JSON | 5 | Prototype pollution, NoSQL injection |
| HTML | 6 | XSS (all vectors) |
| PHP | 5 | Code execution, RCE |
| Python | 5 | Code execution, pickle exploits |
| CSV | 5 | Formula injection |
| PDF | 3 | JavaScript, launch actions |
| Images | 3 | EXIF injection, polyglot |
| Office | 3 | VBA, macro, OLE objects |
| Archive | 3 | Path traversal, zip bombs |
| Binary | 3 | Buffer overflow, ROP, shellcode |

**Total**: 60+ unique payloads across 13 categories

---

## Next Steps

1. **Create** `payload_service.py`
2. **Modify** `exploit_executor.py` (add 30 lines)
3. **Modify** `exploit_seek_tab.py` (add 50 lines)
4. **Test** payload service standalone
5. **Test** executor with payloads
6. **Test** Seek Tab UI integration
7. **Deploy**

---

## Benefits

✅ **Extensible**: Add new payload types instantly  
✅ **Reusable**: Payload Generator payloads in all tools  
✅ **Intelligent**: Auto-detect and use correct payloads  
✅ **Flexible**: Custom payloads still supported  
✅ **Integrated**: One unified payload ecosystem

---

**Status**: Ready to implement  
**Effort**: 2-4 hours  
**ROI**: High (60+ payloads available instead of hardcoded 4)
