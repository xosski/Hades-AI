# Compliance Integration Guide

## Overview

This guide integrates compliance-ready vulnerability testing into HadesAI. The new system enforces:

1. **Response Capture** - Exact endpoint, payload, and response excerpts
2. **Baseline Comparison** - Benign vs. attack payload comparison  
3. **Authorization Verification** - Explicit consent before testing
4. **Deterministic Tests** - Database error signatures, XSS reflection, file content detection

---

## Files Added

| File | Purpose |
|------|---------|
| `enhanced_vulnerability_tester.py` | Compliance-ready testing with evidence capture |
| `authorization_verifier.py` | Authorization & audit logging system |
| `COMPLIANCE_INTEGRATION_GUIDE.md` | This file |

---

## Quick Start (5 minutes)

### 1. Basic Setup

```python
from enhanced_vulnerability_tester import EnhancedVulnerabilityTester
from authorization_verifier import AuthorizationDatabase, ComplianceEnforcer

# Initialize
auth_db = AuthorizationDatabase("authorizations.db")
tester = EnhancedVulnerabilityTester()
enforcer = ComplianceEnforcer(auth_db)
```

### 2. Add Authorization

```python
from authorization_verifier import AuthorizationRecord
from datetime import datetime

record = AuthorizationRecord(
    target_url="http://testapp.local:8000",
    target_domain="testapp.local",
    authorized_by="security_team@company.com",
    authorization_date=datetime.now().isoformat(),
    authorization_method="written_permission",
    scope="security_assessment",
    expiration_date=None,
    notes="Authorized for internal testing",
    approved=True
)

auth_db.add_authorization(record)
```

### 3. Run Test with Compliance Check

```python
target = "http://testapp.local:8000/search"

# Pre-test compliance check
is_allowed, reason = enforcer.pre_test_check(
    target,
    "sql_injection"
)

if not is_allowed:
    print(f"Testing blocked: {reason}")
    exit()

# Run test
result = tester.test_sql_injection(target, param_name='q')

# Log result
if result.vulnerable:
    print(f"✅ VULNERABLE: {result.test_name}")
    print(f"   Evidence: {result.evidence_excerpt}")
else:
    print(f"❌ NOT VULNERABLE: {result.test_name}")

# Audit log
enforcer.log_test_result(
    target_url=target,
    test_id=result.test_id,
    endpoint=result.endpoint_tested,
    test_type=result.test_type,
    payload=result.payload_used,
    result="vulnerable" if result.vulnerable else "not_vulnerable",
    confidence=result.confidence,
    performed_by="security_agent"
)
```

### 4. Export Reports

```python
# JSON report (for automated processing)
json_file = tester.export_results_json("compliance_report.json")

# Markdown report (for human review)
md_file = tester.export_results_markdown("compliance_report.md")

print(f"Reports saved: {json_file}, {md_file}")
```

---

## What Changed

### Before (Old System)

```
❌ Keyword matching only
   Example: "error" or "syntax" found in response = vulnerable?

❌ No endpoint tracking
   Report: "SQL Injection found" - but WHERE?

❌ No baseline
   No proof that payload caused the response

❌ No authorization
   Tools test any URL without consent
```

### After (New System)

```
✅ Deterministic detection
   Example: SQLSTATE or ORA- error = definitely vulnerable

✅ Exact endpoint capture
   Report: /search?id=123 - exact path + parameters

✅ Baseline comparison
   Benign payload vs. attack payload - proves causation

✅ Authorization enforcement
   Can't test without explicit consent record
```

---

## Test Types Supported

### SQL Injection (`test_sql_injection`)

**Detection Methods:**
1. **Database Error Signatures** (highest confidence)
   - PostgreSQL: `SQLSTATE` errors
   - Oracle: `ORA-` errors
   - MySQL: `MySQL Error` messages
   - SQL Server: `MSSQL Error`
   - SQLite: `near '` syntax errors

2. **Baseline Comparison** (fallback)
   - Compares benign vs. attack response
   - Triggers if >5% content change or status code change

**Evidence Captured:**
- Exact endpoint path + parameters
- Payload sent
- Status code (benign vs. attack)
- Response hash (SHA256)
- Response excerpt (first 500 chars)
- Full baseline comparison metrics

**Example Output:**
```json
{
  "test_id": "sqli_a1b2c3d4",
  "vulnerable": true,
  "confidence": 0.95,
  "evidence_type": "sql_error",
  "evidence_excerpt": "Database error detected: PostgreSQL SQLSTATE error",
  "endpoint_tested": "/search?id=%27%20OR%20%271%27=%271%27--",
  "payload_used": "' OR '1'='1'--",
  "baseline_comparison": {
    "benign_response_hash": "abc123...",
    "attack_response_hash": "xyz789...",
    "status_differs": true,
    "length_differs": true,
    "delta_bytes": 245
  }
}
```

### XSS (Cross-Site Scripting) (`test_xss`)

**Detection Method:**
- Verifies payload is reflected unescaped in HTML
- Checks for HTML-encoding (escaped = not vulnerable)
- Detects dangerous contexts (href, src, event handlers)

**Evidence:**
- Exact reflection location in response
- Context where reflection occurs
- HTML encoding status

### Path Traversal (`test_path_traversal`)

**Detection Methods:**
1. **File Content Signatures**
   - `/etc/passwd`: `root:`, `bin:`, `daemon:` entries
   - `win.ini`: `[fonts]`, `[extensions]` sections

2. **Baseline Delta** (fallback)
   - Response length change indicates different file served

---

## Integration with HadesAI

### Step 1: Add to imports (HadesAI.py)

```python
# After existing imports
from enhanced_vulnerability_tester import EnhancedVulnerabilityTester, DeterministicValidators
from authorization_verifier import AuthorizationDatabase, ComplianceEnforcer
```

### Step 2: Initialize in HadesAI class

```python
class HadesAI(QMainWindow):
    def __init__(self):
        # ... existing init code ...
        
        # Compliance system
        self.auth_db = AuthorizationDatabase("hades_authorizations.db")
        self.enforcer = ComplianceEnforcer(self.auth_db)
        self.compliance_tester = EnhancedVulnerabilityTester()
```

### Step 3: Use in vulnerability testing tab

```python
def run_compliance_test(self):
    target_url = self.target_url_input.text()
    
    # Check authorization
    is_allowed, reason = self.enforcer.pre_test_check(target_url, "sql_injection")
    
    if not is_allowed:
        QMessageBox.critical(self, "Compliance", f"Testing blocked:\n{reason}")
        return
    
    # Run test
    result = self.compliance_tester.test_sql_injection(target_url)
    
    # Display result
    if result.vulnerable:
        self.display_vulnerability(result)
        
        # Log
        self.enforcer.log_test_result(
            target_url=target_url,
            test_id=result.test_id,
            endpoint=result.endpoint_tested,
            test_type=result.test_type,
            payload=result.payload_used,
            result="vulnerable",
            confidence=result.confidence,
            performed_by=self.current_user
        )
    else:
        self.status_update.emit("No vulnerability detected")
```

---

## Authorization Workflow

### Adding Authorization (Code)

```python
# One-time: Add authorization for a target
from authorization_verifier import AuthorizationRecord
from datetime import datetime, timedelta

record = AuthorizationRecord(
    target_url="http://client-app.test",
    target_domain="client-app.test",
    authorized_by="InfoSec@company.com",
    authorization_date=datetime.now().isoformat(),
    authorization_method="written_permission",  # or 'email', 'contract'
    scope="all_vulnerability_classes",
    expiration_date=(datetime.now() + timedelta(days=365)).isoformat(),
    notes="Authorized per engagement contract #2024-001",
    approved=True
)

auth_db.add_authorization(record)
```

### Checking Authorization

```python
# Check if target is authorized before testing
is_authorized, record = auth_db.is_authorized("http://client-app.test")

if is_authorized:
    print(f"✅ Authorized by: {record.authorized_by}")
    print(f"   Scope: {record.scope}")
else:
    print("❌ Target not authorized")
```

### Revoking Authorization

```python
# Revoke testing permission
auth_db.revoke_authorization("http://client-app.test")
```

---

## Audit Logging

### Automatic Logging

Every test is automatically logged:

```python
# When you call enforcer.log_test_result(), it creates:
# - Timestamp
# - Test type
# - Target URL & endpoint
# - Payload (first 100 chars)
# - Result (vulnerable/not)
# - Confidence score
# - User who ran test
# - Authorization reference
```

### Retrieving Audit Logs

```python
# All tests
all_logs = auth_db.get_test_history(limit=100)

# Tests on specific target
target_logs = auth_db.get_test_history("http://testapp.local", limit=50)

for log in target_logs:
    print(f"{log['timestamp']} - {log['test_type']} on {log['endpoint_tested']}")
```

---

## Report Format

### JSON Report

```json
{
  "report_type": "Compliance-Ready Vulnerability Assessment",
  "generated": "2026-02-19T14:23:45.123456",
  "total_tests": 5,
  "vulnerabilities_proven": 2,
  "results": [
    {
      "test_id": "sqli_a1b2c3d4",
      "test_name": "SQL Injection",
      "vulnerable": true,
      "confidence": 0.95,
      "severity": "Critical",
      "evidence_type": "sql_error",
      "evidence_excerpt": "Database error: PostgreSQL SQLSTATE...",
      "endpoint_tested": "/search?id=123",
      "payload_used": "' OR '1'='1'--",
      "capture_benign": {
        "endpoint_path": "/search?id=1",
        "status_code": 200,
        "response_length": 1250,
        "response_hash": "abc123..."
      },
      "capture_attack": {
        "endpoint_path": "/search?id=%27%20OR%20%271%27=%271%27--",
        "status_code": 500,
        "response_length": 2100,
        "response_hash": "xyz789..."
      },
      "baseline_comparison": {
        "status_differs": true,
        "length_differs": true,
        "delta_bytes": 850
      }
    }
  ]
}
```

### Markdown Report

Each vulnerability gets detailed markdown section:
- Test name & ID
- Status (VULNERABLE / NOT VULNERABLE)
- Confidence %
- Severity
- Evidence type
- Full evidence description
- Endpoint path + full URL
- Exact payload used
- Baseline comparison table
- Response excerpts (benign & attack)

---

## Compliance Checklist

Before submitting any bug bounty report, verify:

- [ ] **Endpoint Specific**: Report shows exact path + parameters
- [ ] **Evidence Captured**: Response excerpt shows payload reflection or DB error
- [ ] **Baseline Included**: Benign response differs from attack response
- [ ] **Proof of Execution**: Vulnerability is proven, not assumed
- [ ] **Authorization Logged**: Authorization record exists for target
- [ ] **Audit Trail**: Test logged in audit system with timestamp + user
- [ ] **Export Valid**: JSON or Markdown report generated successfully

---

## Troubleshooting

### "NOT AUTHORIZED: Target not in authorization database"

```python
# Solution: Add authorization first
from authorization_verifier import AuthorizationRecord
from datetime import datetime

record = AuthorizationRecord(
    target_url="http://target-to-test.com",
    target_domain="target-to-test.com",
    authorized_by="your_email@company.com",
    authorization_date=datetime.now().isoformat(),
    authorization_method="manual",
    scope="security_assessment",
    expiration_date=None,
    notes="Added for testing",
    approved=True
)

auth_db.add_authorization(record)
```

### "Vulnerability: True, Confidence: 0.0"

This means:
- No deterministic evidence found
- Fallback baseline comparison also failed
- Result is unreliable

**Solution**: Review the response excerpt in the report to determine if false positive.

### "Rate Limited: Target tested 5s ago"

```python
# Prevent rapid-fire requests on same target
# Default: 30 second cooldown between tests
# Adjust in ComplianceEnforcer._check_rate_limit() if needed
```

---

## Best Practices

1. **Always check authorization first**
   ```python
   is_allowed, reason = enforcer.pre_test_check(target, test_type)
   if not is_allowed:
       log_and_exit(reason)
   ```

2. **Log every test**
   ```python
   enforcer.log_test_result(
       target_url=...,
       test_id=...,
       result="vulnerable" if result.vulnerable else "not_vulnerable",
       confidence=result.confidence,
       performed_by=current_user
   )
   ```

3. **Review response excerpts**
   - Don't trust confidence scores alone
   - Look at actual evidence in reports
   - For SQL injection: verify DB error signature
   - For XSS: verify payload unescaped in HTML

4. **Export and backup reports**
   ```python
   json_file = tester.export_results_json()
   md_file = tester.export_results_markdown()
   # Store for audit trail
   ```

5. **Rotate authorizations**
   - Set expiration dates on authorizations
   - Revoke when engagement ends
   - Keep audit logs indefinitely

---

## Next Steps

1. Review `enhanced_vulnerability_tester.py` - understand the test validators
2. Review `authorization_verifier.py` - understand the authorization model
3. Run example tests against your own lab applications
4. Integrate with HadesAI using Step 1-3 above
5. Generate compliance reports and verify format

---

## Legal Disclaimer

This system enforces **authorization verification** but does not replace:
- Written engagement contracts
- Responsible disclosure policies
- Legal review of testing scope
- Professional liability insurance

Always ensure testing is legally authorized before proceeding.

---

## Questions?

All code includes detailed docstrings and inline comments. Refer to:
- `enhanced_vulnerability_tester.py` - Test implementation details
- `authorization_verifier.py` - Authorization & audit details
- This file - Integration & usage examples
