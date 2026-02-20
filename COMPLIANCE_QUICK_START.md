# Compliance Quick Start (10 minutes)

## What You Got

Four production-ready files that fix all compliance gaps:

1. **`enhanced_vulnerability_tester.py`** (755 lines)
   - Response capture with exact endpoints
   - Baseline comparison (benign vs. attack)
   - Deterministic validators (no keyword matching)
   - Database-specific error detection

2. **`authorization_verifier.py`** (520 lines)
   - Authorization database
   - Compliance enforcement gate
   - Audit logging system
   - Authorization records + expiration

3. **`test_compliance_system.py`** (410 lines)
   - Full test suite (all passing ✅)
   - Demonstrates all features
   - Safe to run, uses in-memory DB

4. **`COMPLIANCE_INTEGRATION_GUIDE.md`** (600 lines)
   - Step-by-step integration
   - Code examples
   - Troubleshooting

---

## Verify It Works (2 min)

```bash
python test_compliance_system.py
```

**Expected output:** `ALL TESTS PASSED ✅`

---

## One-Time Setup (3 min)

### Step 1: Create Authorization

```python
from authorization_verifier import AuthorizationDatabase, AuthorizationRecord
from datetime import datetime, timedelta

# Create database (once)
auth_db = AuthorizationDatabase("hades_authorizations.db")

# Add authorization for your test target
record = AuthorizationRecord(
    target_url="http://your-testapp.local:8000",
    target_domain="your-testapp.local",
    authorized_by="your_email@company.com",
    authorization_date=datetime.now().isoformat(),
    authorization_method="written_permission",  # or "email", "contract"
    scope="security_assessment",                 # or "all_vulnerability_classes"
    expiration_date=(datetime.now() + timedelta(days=365)).isoformat(),
    notes="Authorized for testing",
    approved=True
)

auth_db.add_authorization(record)
print("✓ Authorization added")
```

---

## Run a Test (2 min)

```python
from enhanced_vulnerability_tester import EnhancedVulnerabilityTester
from authorization_verifier import ComplianceEnforcer

# Initialize
auth_db = AuthorizationDatabase("hades_authorizations.db")
enforcer = ComplianceEnforcer(auth_db)
tester = EnhancedVulnerabilityTester()

target = "http://your-testapp.local:8000/search"

# Check authorization
is_allowed, reason = enforcer.pre_test_check(target, "sql_injection")
if not is_allowed:
    print(f"❌ {reason}")
    exit()

# Run test
print("✓ Testing SQL injection...")
result = tester.test_sql_injection(target, param_name='q')

# Show result
if result.vulnerable:
    print(f"✅ VULNERABLE: {result.test_name}")
    print(f"   Endpoint: {result.endpoint_tested}")
    print(f"   Confidence: {result.confidence:.0%}")
    print(f"   Evidence: {result.evidence_excerpt[:100]}...")
else:
    print(f"❌ NOT VULNERABLE: {result.test_name}")

# Log for audit trail
enforcer.log_test_result(
    target_url=target,
    test_id=result.test_id,
    endpoint=result.endpoint_tested,
    test_type=result.test_type,
    payload=result.payload_used,
    result="vulnerable" if result.vulnerable else "not_vulnerable",
    confidence=result.confidence,
    performed_by="my_username"
)

print("✓ Test logged to audit trail")
```

---

## Export Report (1 min)

```python
# JSON (for automated tools)
json_file = tester.export_results_json("report.json")

# Markdown (for human review)
md_file = tester.export_results_markdown("report.md")

print(f"✓ Reports saved: {json_file}, {md_file}")
```

---

## Check Audit Trail (1 min)

```python
# View all tests
history = auth_db.get_test_history(limit=20)
for log in history:
    print(f"{log['timestamp']} - {log['test_type']} on {log['endpoint_tested']}")

# View authorizations
auths = auth_db.get_authorizations()
for auth in auths:
    print(f"{auth['target_url']} - {auth['authorized_by']}")
```

---

## Key Features

### ✅ Response Capture
Every test records:
- Exact endpoint path + parameters
- Payload sent
- HTTP status code
- Response length
- Response excerpt (first 500 chars)
- Response hash (SHA256)

### ✅ Baseline Comparison
Every test includes:
- Benign response (e.g., `id=1`)
- Attack response (e.g., `id=' OR '1'='1'--`)
- Status code difference
- Response length delta
- Response hash difference
- Proof of causation

### ✅ Deterministic Detection
Database-specific error signatures:
- PostgreSQL: SQLSTATE
- Oracle: ORA-
- MySQL: MySQL Error
- SQL Server: MSSQL Error
- SQLite: near '

No more keyword matching!

### ✅ Authorization Enforcement
Before testing:
- Check if target is authorized
- Verify not expired
- Block if unauthorized
- Log all activity

### ✅ Audit Logging
Every test creates:
- Timestamp
- Test type
- Target URL
- Payload
- Result
- Confidence
- User who ran it
- Authorization reference

---

## Report Quality Before/After

### ❌ OLD REPORT (Would be rejected)
```
Vulnerability: SQL Injection
Status: Vulnerable
Confidence: 45%
Evidence: "Indicators: error, syntax, sql"
```

### ✅ NEW REPORT (Will be accepted)
```
Vulnerability: SQL Injection
Status: PROVEN VULNERABLE
Confidence: 95%
Endpoint: /search?id=%27%20OR%20%271%27=%271%27--
Payload: ' OR '1'='1'--
Evidence: PostgreSQL SQLSTATE error detected
Baseline: Status 200→500, Length 1250→2100
Authorization: Approved by security@company.com
Audit Trail: Test ID sqli_a1b2c3d4, Feb 19 14:23:45
```

---

## Common Tasks

### Add another target
```python
record = AuthorizationRecord(
    target_url="http://another-app.test",
    # ... rest of fields
)
auth_db.add_authorization(record)
```

### Run XSS test
```python
result = tester.test_xss("http://testapp.local/search", param_name='q')
```

### Run path traversal test
```python
result = tester.test_path_traversal("http://testapp.local/view", param_name='file')
```

### View logs for specific target
```python
logs = auth_db.get_test_history("http://testapp.local", limit=100)
```

### Revoke authorization
```python
auth_db.revoke_authorization("http://testapp.local")
```

---

## Integration with HadesAI

See `COMPLIANCE_INTEGRATION_GUIDE.md` sections "Integration with HadesAI" for:
- Adding imports
- Initializing in HadesAI class
- Using in vulnerability testing tab
- Displaying results to user

---

## Report Files

After running tests, you'll have:

### `compliance_test_report_YYYYMMDD_HHMMSS.json`
Machine-readable format:
- All test details
- Baseline comparisons
- Authorization info
- Audit trail

### `compliance_test_report_YYYYMMDD_HHMMSS.md`
Human-readable markdown:
- Formatted nicely
- Evidence highlighted
- Tables for comparisons
- Easy to review/submit

---

## Checklist Before Submitting to Bug Bounty

- [ ] Authorization record exists for target
- [ ] Test has endpoint information (`/path?param=value`)
- [ ] Confidence > 70% (based on actual evidence)
- [ ] Evidence excerpt shows actual proof (error or reflection)
- [ ] Baseline comparison included (benign vs. attack)
- [ ] Payload clearly documented
- [ ] Report exported (JSON or Markdown)
- [ ] Audit log shows test was performed

If all checked, you're ready to submit! ✅

---

## Troubleshooting

**"NOT AUTHORIZED: Target not in database"**
→ Add authorization first (see "One-Time Setup" above)

**"Confidence: 0.0"**
→ No deterministic evidence found; review response excerpt in report

**"Test not logged"**
→ Call `enforcer.log_test_result()` after test completes

**"Rate limited"**
→ 30 second cooldown between tests on same target (safety feature)

---

## Next Steps

1. ✅ Run `python test_compliance_system.py` (verify it works)
2. ✅ Create authorization for your test target
3. ✅ Run your first compliance test
4. ✅ Export report (JSON or Markdown)
5. ✅ Review report for completeness
6. ✅ Submit to bug bounty with confidence!

---

## File Reference

| File | What It Does |
|------|-------------|
| `enhanced_vulnerability_tester.py` | Core testing engine with evidence capture |
| `authorization_verifier.py` | Authorization + audit system |
| `test_compliance_system.py` | Test suite (run this to verify) |
| `COMPLIANCE_INTEGRATION_GUIDE.md` | Full integration guide |
| `COMPLIANCE_IMPROVEMENTS_SUMMARY.md` | What was fixed |
| `BEFORE_AFTER_COMPLIANCE.md` | Examples of improvements |
| `COMPLIANCE_QUICK_START.md` | This file |

---

**Ready?** Run the tests and start testing! 🚀
