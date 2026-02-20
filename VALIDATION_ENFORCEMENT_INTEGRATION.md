# Validation Enforcement Integration Guide

## Overview
Integrates 5 credibility fixes into Hades reporting system:

1. **Confidence/Status Alignment** - No more "Confirmed" at 0.2 confidence
2. **Proof Requirements** - Actual errors, stack traces, behavioral evidence required
3. **Scope Filtering** - Block non-target domains (HackerOne, BugCrowd, etc.)
4. **CVE Detection** - Framework detection + payload execution proof required
5. **Status Accuracy** - Proper Suspected/Likely/Confirmed mapping

---

## Changes to exploit_seek_tab.py

### Location 1: Report Generation (Line ~767)

**Before:**
```python
def _generate_hackerone_report(self) -> dict:
    # ... existing code ...
    finding = {
        "status": "Confirmed" if attempt.get('success') else "Potential",
        "confidence": conf,
        # ...
    }
```

**After:**
```python
from validation_enforcement import ComplianceReport, ScopeValidator

def __init__(self):
    # ... existing code ...
    self.compliance_report = ComplianceReport()
    self.compliance_report.scope_validator.add_allowed_target(self.target_domain)

def _generate_hackerone_report(self) -> dict:
    report = { ... }
    
    # Pre-validate all findings
    validated_findings = []
    for finding in raw_findings:
        validated = self.compliance_report.validate_finding(finding)
        
        # Skip out-of-scope findings
        if validated.get('validation_result') == 'EXCLUDED_OUT_OF_SCOPE':
            logger.warning(f"Skipping out-of-scope: {validated['scope_reason']}")
            continue
        
        # Downgrade unproven findings
        if validated.get('validated_status'):
            finding['status'] = validated['validated_status']
            finding['confidence'] = validated['validated_confidence']
        
        validated_findings.append(finding)
    
    report['findings'] = validated_findings
    report['validation_metadata'] = {
        'total_submitted': len(raw_findings),
        'total_validated': len(validated_findings),
        'validation_framework': 'ComplianceReport',
        'scope_enforced': True,
    }
    return report
```

### Location 2: Finding Collection (Line ~789-824)

**Before:**
```python
# Add exploit seek findings
for attempt in self.current_search_results.get('attempts', []):
    if attempt.get('success') or attempt.get('severity') in ['Critical', 'High']:
        finding = {
            "id": attempt.get('exploit_id', f"exploit_{len(all_findings) + 1}"),
            "type": attempt.get('exploit_type', 'Unknown'),
            "severity": attempt.get('severity', 'Medium'),
            "status": "Confirmed" if attempt.get('success') else "Potential",
            # ...
        }
```

**After:**
```python
# Add exploit seek findings (with scope checking)
for attempt in self.current_search_results.get('attempts', []):
    url = attempt.get('url', '')
    
    # Scope check
    in_scope, scope_reason = self.compliance_report.scope_validator.is_in_scope(url)
    if not in_scope:
        logger.warning(f"Skipping {attempt.get('exploit_type')}: {scope_reason}")
        continue
    
    if attempt.get('success') or attempt.get('severity') in ['Critical', 'High']:
        # Validate proof
        proof_count = 0
        if attempt.get('error_message'):
            proof_count += 1  # Actual error message
        if attempt.get('payload_echoed'):
            proof_count += 1  # Payload echo
        if attempt.get('behavioral_change'):
            proof_count += 1  # Response difference
        
        # Map confidence to status
        confidence = attempt.get('confidence', 0.5)
        if confidence < 0.4:
            status = "Suspected"
        elif confidence < 0.7:
            status = "Likely"
        else:
            status = "Confirmed" if proof_count > 0 else "Likely"
        
        finding = {
            "id": attempt.get('exploit_id', f"exploit_{len(all_findings) + 1}"),
            "type": attempt.get('exploit_type', 'Unknown'),
            "severity": attempt.get('severity', 'Medium'),
            "status": status,
            "confidence": confidence,
            "proof_count": proof_count,
            "in_scope": in_scope,
            # ...
        }
```

### Location 3: AI Results Integration (Line ~827-863)

**Before:**
```python
for test in self.current_ai_results.get('results', []):
    if test.get('vulnerable'):
        finding = {
            "status": "Confirmed",  # ← WRONG: Always Confirmed!
            "confidence": conf,
            # ...
        }
```

**After:**
```python
for test in self.current_ai_results.get('results', []):
    if test.get('vulnerable'):
        conf = test.get('confidence', 0)
        
        # Status mapping based on confidence
        if conf < 0.4:
            status = "Suspected"
        elif conf < 0.7:
            status = "Likely"
        else:
            # High confidence - check for proof
            has_error = 'error' in test.get('evidence', '').lower()
            has_stack = 'traceback' in test.get('evidence', '').lower()
            has_behavior = test.get('baseline_comparison', {}).get('hash_differs')
            
            status = "Confirmed" if (has_error or has_stack or has_behavior) else "Likely"
        
        finding = {
            "status": status,
            "confidence": conf,
            "proof_type": "error_message" if has_error else (
                "stack_trace" if has_stack else "behavioral_change"
            ),
            # ...
        }
```

### Location 4: Export Filtering

**Before:**
```python
def _export_security_report(self):
    """Export all findings (including weak/out-of-scope)"""
    if not self.current_search_results and not self.current_ai_results:
        # ... export everything ...
```

**After:**
```python
def _export_security_report(self):
    """Export only validated, in-scope findings"""
    
    if not self.current_search_results and not self.current_ai_results:
        QMessageBox.warning(self, "No Results", "No valid vulnerabilities to report")
        return
    
    # Pre-filter out-of-scope
    target_url = self.url_input.text()
    parsed = urlparse(target_url)
    target_domain = parsed.netloc.lower()
    
    self.compliance_report.scope_validator.add_allowed_target(target_domain)
    
    # Generate and validate report
    raw_report = self._generate_hackerone_report()
    
    # Filter findings
    validated_findings = []
    for finding in raw_report.get('findings', []):
        validated = self.compliance_report.validate_finding(finding)
        
        # Only include in-scope, validated findings
        if validated.get('validation_result') != 'EXCLUDED_OUT_OF_SCOPE':
            validated_findings.append(finding)
    
    # Report statistics
    skipped = len(raw_report.get('findings', [])) - len(validated_findings)
    logger.info(f"Exported {len(validated_findings)} findings (skipped {skipped} out-of-scope)")
```

---

## Configuration

### Add to __init__ method:

```python
def __init__(self, parent=None):
    # ... existing initialization ...
    
    # Initialize compliance enforcement
    from validation_enforcement import ComplianceReport
    self.compliance_report = ComplianceReport()
    
    # Allow user to configure scope
    self.scope_targets = set()
    self.scope_blocklist = ComplianceReport().scope_validator.BLOCKED_DOMAINS.copy()
```

### Add UI controls (optional):

```python
# Add buttons to Exploit Seek tab
scope_frame = QFrame()
scope_layout = QHBoxLayout()

add_scope_btn = QPushButton("Add Target Domain")
add_scope_btn.clicked.connect(self._add_scope_domain)
scope_layout.addWidget(add_scope_btn)

view_scope_btn = QPushButton("View Scope")
view_scope_btn.clicked.connect(self._show_scope_info)
scope_layout.addWidget(view_scope_btn)

scope_frame.setLayout(scope_layout)
# Add to tab layout
```

---

## Validation Rules

### Status Mapping (Fixed!)
```
Confidence 0.0-0.4   → "Suspected"    (guessing)
Confidence 0.4-0.7   → "Likely"       (probable)
Confidence 0.7-1.0   → "Confirmed"    (proven)
```

### Proof Requirements by Type

| Vulnerability | Minimum Confidence | Required Proof |
|--------------|-------------------|----------------|
| SQL Injection | 0.7+ | Database error OR payload echo in SQL context OR significant response delta |
| XSS | 0.7+ | Payload reflected unescaped in HTML context |
| Path Traversal | 0.75+ | File content (passwd entries, win.ini sections, SSH keys) |
| Auth Bypass | 0.8+ | Access to protected content unique to authenticated users |
| RCE | 0.85+ | Command output (`uid=`, `gid=`) OR shell environment detection |
| CVE (Log4j/Struts2/Spring4) | 0.9+ | Framework version detection + payload execution proof |

### Scope Rules (Auto-enforced)

**Blocked domains (auto-rejected):**
- HackerOne, BugCrowd, Intigriti, Yeswehack, Synack, etc.
- GitHub, Google, Microsoft, Amazon, etc.

**Required for scope acceptance:**
- Target domain must be explicitly whitelisted OR
- Target domain not in blocked list

---

## Testing

### Test Case 1: Confidence/Status Mismatch
```python
# Before fix: Status=Confirmed, Confidence=0.2
# After fix: Status=Suspected, Confidence=0.2
```

### Test Case 2: Out-of-Scope Detection
```python
validator = ScopeValidator()
in_scope, reason = validator.is_in_scope('https://hackerone.com/opportunities/all')
# Returns: (False, 'Domain hackerone.com is a bug bounty platform (blocked)')
```

### Test Case 3: Weak Proof Rejection
```python
finding = {
    'type': 'sql_injection',
    'confidence': 0.6,
    'status': 'Confirmed',
    'response': 'HTTP 200 OK',  # Only HTTP 200
    'proof_details': []
}
validated = compliance_report.validate_finding(finding)
# Returns: status='Likely', validation_result='ACCEPTED' (but downgraded)
```

### Test Case 4: CVE False Positive Prevention
```python
# Before: Any 200 + "log4j" keyword = RCE Confirmed
# After: Requires Log4j detection + JNDI payload echo in logs
```

---

## Migration Checklist

- [ ] Add `validation_enforcement.py` to modules
- [ ] Import `ComplianceReport, ScopeValidator` in exploit_seek_tab.py
- [ ] Update `__init__` to initialize compliance_report
- [ ] Fix `_generate_hackerone_report()` to validate findings
- [ ] Update finding collection to check scope
- [ ] Add proof counting for each finding type
- [ ] Fix status mapping (Suspected/Likely/Confirmed)
- [ ] Test with HackerOne URL (should be rejected)
- [ ] Test with low-confidence findings (should be downgraded)
- [ ] Test with 404 findings (should reject SQLi as "Confirmed")
- [ ] Verify reports no longer have 0.2 confidence + "Confirmed" pairs

---

## Verification Steps

After integration, run:

```bash
# 1. Test scope validation
python -c "from validation_enforcement import ScopeValidator; v = ScopeValidator(); print(v.is_in_scope('https://hackerone.com'))"

# 2. Test proof validation
python -c "from validation_enforcement import ProofValidator; print(ProofValidator.validate_sql_injection('HTTP 200', payload, 200, baseline))"

# 3. Test confidence enforcement
python -c "from validation_enforcement import ConfidenceEnforcer; print(ConfidenceEnforcer.validate_confidence_status_alignment('sql_injection', 0.2, 'Confirmed', 0))"

# 4. Generate a test report and verify:
#    - No "Confirmed" findings with <0.7 confidence
#    - No HackerOne/BugCrowd findings
#    - All findings have proof_details
#    - Status accurately reflects confidence
```

---

## Impact Summary

| Issue | Before | After |
|-------|--------|-------|
| "Confirmed" @ 0.2 confidence | 10+ findings | 0 findings |
| HackerOne page scanned | Reported as "Critical" | Auto-rejected |
| 404 response marked "Confirmed" | Yes | No - downgraded to "Likely" |
| CVE claims without framework detection | "Confirmed" | "Suspected" |
| Missing proof | Ignored | Tracked & reported |
| Out-of-scope findings | Included | Excluded |

**Result:** Reports become credible, actionable, and policy-compliant.
