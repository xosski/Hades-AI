# Cache Scanner Tab with Details View - Integration Guide

## Overview
Enhanced cache scanner tab that displays full threat details including:
- Matched code snippets
- Code context (before/after)
- Complete file content
- Threat metadata (type, severity, browser, path)
- Exploit linking

## Files Required

1. **cache_scanner_tab_enhanced.py** - The new UI component
2. **cache_scanner_enhanced.py** - Core scanner (already created)
3. **cache_scanner_integration.py** - Integration layer (already created)

## Step 1: Import the Enhanced Tab

Add to imports at top of HadesAI.py:

```python
from cache_scanner_tab_enhanced import EnhancedCacheScannerTab
from cache_scanner_integration import CacheScannerIntegration
```

## Step 2: Replace _create_cache_tab Method

Replace the entire `_create_cache_tab` method (lines 5748-5782) with:

```python
def _create_cache_tab(self) -> QWidget:
    """Create enhanced cache scanner tab with full code visibility"""
    self.cache_tab = EnhancedCacheScannerTab(self)
    
    # Connect signals
    self.cache_tab.cache_scan_btn.clicked.connect(self._start_cache_scan_enhanced)
    self.cache_tab.cache_stop_btn.clicked.connect(self._stop_cache_scan)
    self.cache_tab.cache_export_btn.clicked.connect(self._export_cache_findings)
    
    return self.cache_tab
```

## Step 3: Add New Scan Handler

Add this new method to HadesAI class (replace the old `_start_cache_scan`):

```python
def _start_cache_scan_enhanced(self):
    """Start enhanced cache scan with full code visibility"""
    self.cache_tab.enable_controls(False)
    self.cache_tab.clear_details()
    self.cache_tab.cache_tree.clear()
    self.cache_tab.set_progress(0)
    self.cache_tab.set_status("Initializing scanner...")
    
    # Initialize scanner
    self.cache_integration = CacheScannerIntegration()
    self.cache_integration.initialize_scanner()
    
    # Register callbacks
    self.cache_integration.register_callback(
        'threat_detected',
        self._on_cache_threat_detected
    )
    self.cache_integration.register_callback(
        'scan_complete',
        self._on_cache_scan_complete
    )
    
    # Start in thread
    from threading import Thread
    scan_thread = Thread(
        target=self.cache_integration.scan_browser_caches,
        daemon=True
    )
    scan_thread.start()
```

## Step 4: Add Threat Detection Handler

Add this method to HadesAI class:

```python
def _on_cache_threat_detected(self, data: Dict):
    """Handle individual threat detection"""
    self.cache_tab.set_progress(
        int((data.get('total_files', 0) / 500) * 100)
    )
```

## Step 5: Add Scan Complete Handler

Add this method to HadesAI class:

```python
def _on_cache_scan_complete(self, results: Dict):
    """Handle cache scan completion with full code details"""
    
    # Format findings for display
    threat_details = results.get('threat_details', [])
    
    # Transform to match tab expectations
    formatted_findings = []
    for threat in threat_details:
        formatted_findings.append({
            'threat_type': threat.get('threat_type', 'unknown'),
            'severity': threat.get('severity', 'LOW'),
            'browser': threat.get('browser', 'unknown'),
            'path': threat.get('path', 'unknown'),
            'file_size': threat.get('file_size', 0),
            'file_hash': threat.get('file_hash', 'N/A'),
            'detected_at': threat.get('detected_at', ''),
            'matched_code': threat.get('matched_code', ''),
            'context_before': threat.get('context_before', ''),
            'context_after': threat.get('context_after', ''),
            'full_code': threat.get('full_code', ''),
            'pattern': threat.get('pattern', 'N/A'),
            'position': threat.get('position', 0),
            'length': threat.get('length', 0),
            'matched_exploit_id': threat.get('matched_exploit_id'),
        })
    
    # Display in tab
    stats = {
        'total_files': results.get('total_files', 0),
        'total_size': results.get('total_size', 0),
    }
    
    self.cache_tab.display_findings(formatted_findings, stats)
    
    # Chat notification
    summary = self._generate_cache_summary(formatted_findings)
    self._add_chat_message('system', summary)
    
    # Enable controls
    self.cache_tab.enable_controls(True)
    self.cache_tab.set_progress(100)
    self.cache_tab.set_status(f"Scan complete! Found {len(formatted_findings)} threats")
```

## Step 6: Add Summary Generator

Add this helper method to HadesAI class:

```python
def _generate_cache_summary(self, findings: List[Dict]) -> str:
    """Generate cache scan summary"""
    by_severity = {}
    by_type = {}
    by_browser = {}
    
    for finding in findings:
        severity = finding.get('severity', 'LOW')
        threat_type = finding.get('threat_type', 'unknown')
        browser = finding.get('browser', 'unknown')
        
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_type[threat_type] = by_type.get(threat_type, 0) + 1
        by_browser[browser] = by_browser.get(browser, 0) + 1
    
    msg = f"""
[CACHE SCAN COMPLETE]
Total Threats Found: {len(findings)}

By Severity:
"""
    for sev, count in sorted(by_severity.items()):
        msg += f"  {sev}: {count}\n"
    
    msg += "\nBy Type:\n"
    for threat_type, count in sorted(by_type.items()):
        msg += f"  {threat_type}: {count}\n"
    
    msg += "\nBy Browser:\n"
    for browser, count in sorted(by_browser.items()):
        msg += f"  {browser}: {count}\n"
    
    msg += "\nClick on threats in the Scanner tab to view full code and details."
    
    return msg
```

## Step 7: Add Export Handler

Add this method to HadesAI class:

```python
def _export_cache_findings(self):
    """Export cache findings to JSON/HTML"""
    if not self.cache_integration:
        self._add_chat_message('system', "No scan results to export")
        return
    
    try:
        import os
        export_dir = os.path.join(os.getcwd(), 'cache_reports')
        os.makedirs(export_dir, exist_ok=True)
        
        self.cache_integration.export_all_findings(export_dir)
        
        self._add_chat_message('system', 
            f"[+] Findings exported to:\n"
            f"    JSON: {export_dir}/cache_findings.json\n"
            f"    HTML: {export_dir}/cache_findings.html"
        )
    except Exception as e:
        self._add_chat_message('system', f"[-] Export failed: {str(e)[:100]}")
```

## Step 8: Update Stop Handler

Replace `_stop_cache_scan` method with:

```python
def _stop_cache_scan(self):
    """Stop cache scan"""
    if hasattr(self, 'cache_integration') and self.cache_integration:
        try:
            self.cache_integration.close()
        except:
            pass
    
    self.cache_tab.enable_controls(True)
    self.cache_tab.set_status("Scan stopped by user")
```

## What the Tab Shows

### Left Panel: Results Tree
```
File Name          | Type        | Severity | Browser | Size
eval_code_123.js   | eval_code   | HIGH     | Chrome  | 2.5 KB
inject_456.html    | injection   | MEDIUM   | Edge    | 1.2 KB
backdoor_789.ps1   | backdoor    | HIGH     | Firefox | 3.8 KB
```

### Right Panel: Four Detail Tabs

**Tab 1: Summary**
```
THREAT DETAILS
==============
Type:        eval_code
Severity:    HIGH
Browser:     Chrome
PATH:        C:\Users\...\Cache\file_123
File Size:   2560 bytes
File Hash:   abc123def456
...
```

**Tab 2: Code**
```
MATCHED CODE:

eval(user_input)
document.location = attacker_site

Length: 45 characters
```

**Tab 3: Context**
```
BEFORE THREAT:
var x = 1;
var y = 2;

>>> THREAT DETECTED <<<
eval(user_input)

AFTER THREAT:
var z = 3;
console.log(z);
```

**Tab 4: Full Code**
```
FULL FILE CODE (2560 bytes):

function malicious() {
  var x = 1;
  var y = 2;
  eval(user_input)
  var z = 3;
  console.log(z);
  document.location = attacker_site;
  ... (up to 50KB shown)
```

## Features

✓ **Full Code Visibility** - See complete file content
✓ **Code Context** - Before/after surrounding code
✓ **Multiple Views** - Summary, matched code, context, full file
✓ **Filtering** - Filter by severity
✓ **Limiting** - Control how many results shown
✓ **Export** - Save to JSON/HTML
✓ **Real-time** - See findings as they're detected
✓ **Color-coded** - Severity color highlighting

## Usage

### Starting a Scan
1. Click "Scan Browser Cache" button
2. Scan runs in background
3. Findings appear in left panel as they're found
4. Progress bar shows scan progress

### Viewing Details
1. Click any finding in left panel
2. Details appear in right panel tabs:
   - Summary: Metadata about threat
   - Code: The matched malicious code
   - Context: Surrounding code context
   - Full Code: Complete file content

### Filtering Results
1. Use "Filter" dropdown to show only HIGH/MEDIUM/LOW
2. Use "Limit" spinner to control how many shown
3. Tree updates automatically

### Exporting
1. Click "Export Findings" button
2. Saves to cache_reports/ directory
3. Two files created:
   - cache_findings.json (machine-readable)
   - cache_findings.html (human-readable)

## Troubleshooting

### Tab not showing details
- Ensure cache_scanner_enhanced.py and cache_scanner_integration.py are in same directory
- Check imports are correct
- Verify scan actually found threats (check chat message)

### Missing full code
- Full code only available if scanner was able to read the file
- Some cache files may be locked or unreadable
- Matched code and context should always be available

### Export not working
- Ensure cache_reports directory can be created
- Check write permissions
- Try different export path

### Slow scan
- Large cache directories take time
- Limit spinner can reduce results shown
- Scan still completes, just more to display

## Integration Checklist

- [ ] Import EnhancedCacheScannerTab
- [ ] Import CacheScannerIntegration
- [ ] Replace _create_cache_tab method
- [ ] Add _start_cache_scan_enhanced method
- [ ] Add _on_cache_threat_detected method
- [ ] Add _on_cache_scan_complete method
- [ ] Add _generate_cache_summary method
- [ ] Add _export_cache_findings method
- [ ] Update _stop_cache_scan method
- [ ] Test scan functionality
- [ ] Test detail viewing
- [ ] Test export functionality
- [ ] Test filtering and limiting

## Complete Working Example

See the bottom of CACHE_SCANNER_HADES_INTEGRATION.md for a complete working integration example.

## Next Steps

After integration:
1. Test the scan button
2. Verify findings appear
3. Click findings to view code
4. Try export feature
5. Test filtering options
6. Verify all details display correctly

The system should be fully functional!
