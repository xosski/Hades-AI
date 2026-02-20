# Authorized Testing Quick Start

## Before You Start

✅ **Verify Authorization:**
- Do you have written permission from the target owner?
- Is there an active bug bounty program?
- Has the target explicitly authorized security testing?

⚠️ **STOP if:**
- You don't have explicit written authorization
- The target prohibits security testing
- You're testing a third-party hosted service

---

## Fixed Scanner Usage

### 1. Quick Test (CLI)

```bash
# Run the test script
python test_fixed_scanner.py

# This will:
# - Test https://syfe.com (authorized)
# - Display findings with HTTP evidence
# - Export JSON report
# - Show before/after comparison
```

### 2. Programmatic Usage

```python
from ai_vulnerability_tester_fixed import AIVulnerabilityTester

# Initialize
tester = AIVulnerabilityTester()

# Run assessment
results = tester.test_website(
    'https://target.com',
    test_categories=['headers', 'cookie_security', 'configuration'],
    callback=lambda msg: print(f"[+] {msg}")
)

# Check findings
print(f"Found {results['total_vulnerabilities']} vulnerabilities")

# Export report
filename = tester.export_results()
print(f"Report saved to {filename}")
```

### 3. In HadesAI GUI

The Seek Tab now uses the fixed scanner:
1. Open HadesAI
2. Go to "🔍 Exploit Seek" tab
3. Enter authorized target URL
4. Click "🤖 AI TEST"
5. Results include full HTTP evidence

---

## What Gets Tested (Fixed Version)

### ✅ Security Headers (Objective)
- HSTS header presence
- CSP header presence
- X-Frame-Options header
- CORS configuration

### ✅ Cookie Security (Objective)
- HttpOnly flag check
- Secure flag check
- SameSite attribute

### ✅ Configuration (Evidence-Based)
- Admin panel accessibility (checks for actual form)
- Backup file exposure
- Git directory exposure

### ✅ Access Control (HTTP Evidence)
- Unauthenticated admin access
- Shows actual endpoint + response

### ✅ Injection (Error-Based)
- SQL injection (only on 500/502 or SQL errors)
- XSS (only on actual injection evidence)

### ❌ Removed (Not Web-applicable)
- Buffer overflow detection
- Memory safety tests
- Uninitialized pointers
- System calls

---

## Understanding Results

### Real Vulnerability
```json
{
  "title": "Missing HSTS Header",
  "severity": "High",
  "vulnerable": true,
  "confidence": "90%",
  "proof_points": [
    "HSTS header missing - site not forcing HTTPS",
    "HTTP/HTTPS downgrade possible"
  ],
  "http_evidence": {
    "status_code": 200,
    "headers": {
      "Content-Type": "text/html",
      "Server": "nginx/1.19.0"
      // Note: No Strict-Transport-Security
    }
  }
}
```
✅ **Professional quality** - Can be reported

### False Positive (Now Caught)
```json
{
  "title": "SQL Injection",
  "severity": "Critical",
  "vulnerable": false,
  "reason": "HTTP 403 - Request blocked by WAF",
  "proof_points": [
    "Injection payload was blocked with 403 response",
    "WAF/CDN protection working correctly"
  ],
  "http_evidence": {
    "status_code": 403,
    "response_time": "0.02s"
  }
}
```
✅ **Correctly identified as protected** - Not reported

---

## Reporting Findings

### For Bug Bounty

Include in your report:
1. ✅ Vulnerability title
2. ✅ Severity assessment
3. ✅ Proof points (what you found)
4. ✅ HTTP evidence (headers, status code, URL)
5. ✅ Impact statement
6. ✅ Reproduction steps

**Example:**
```
Title: Missing HSTS Header

Severity: High

Description:
The target website does not implement HTTP Strict Transport Security (HSTS).

Proof:
- Tested GET https://target.com/
- Response HTTP 200
- Response headers: [list actual headers]
- Missing: Strict-Transport-Security

Impact:
- HTTP→HTTPS downgrade attacks possible
- Man-in-the-middle interception risk

Reproduction:
curl -i https://target.com/
(Note missing Strict-Transport-Security header)

Remediation:
Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### For Responsible Disclosure

1. Run scanner with authorization
2. Document all findings with proof
3. Export JSON report (includes HTTP evidence)
4. Send to security@target.com
5. Include: scope, dates, methodology

---

## Command Examples

### Test Single Category
```bash
python -c "
from ai_vulnerability_tester_fixed import AIVulnerabilityTester
tester = AIVulnerabilityTester()
results = tester.test_website('https://target.com', test_categories=['headers'])
print(f'Found {results[\"total_vulnerabilities\"]} header issues')
"
```

### Test Multiple URLs
```bash
for url in target1.com target2.com target3.com; do
    python -c "
from ai_vulnerability_tester_fixed import AIVulnerabilityTester
tester = AIVulnerabilityTester()
results = tester.test_website('https://$url')
tester.export_results()
"
done
```

### Export Custom Report
```python
from ai_vulnerability_tester_fixed import AIVulnerabilityTester
import json

tester = AIVulnerabilityTester()
results = tester.test_website('https://target.com')

# Custom report with only critical findings
critical = [f for f in results['findings'] if f['severity'] == 'Critical']
with open('critical_findings.json', 'w') as f:
    json.dump(critical, f, indent=2)
```

---

## Troubleshooting

### Scanner times out
```python
# Increase timeout
tester = AIVulnerabilityTester()
tester.timeout = 30  # 30 seconds
results = tester.test_website('https://target.com')
```

### SSL certificate errors
```python
# The scanner ignores cert errors by default (for authorized testing)
# If you need to verify certs:
tester.session.verify = True
```

### Need to test specific endpoints
```python
# Modify test payloads
from ai_vulnerability_tester_fixed import VulnerabilityTest
test = VulnerabilityTest(
    'custom_001', 'Custom Test',
    'config', 'Medium',
    '/api/admin',  # Custom path
    [], False
)
# Then run manually
tester._run_test(test)
```

---

## Ethics Checklist

Before reporting findings:

- [x] Do I have written authorization?
- [x] Did I test within scope?
- [x] Are findings accurate (not false positives)?
- [x] Did I include reproducible evidence?
- [x] Will I report responsibly?
- [x] Did I avoid causing harm?

---

## What You Can Now Do

✅ **Accurate scanning** - No more keyword matching
✅ **Professional reports** - All HTTP evidence included
✅ **Responsible disclosure** - Reproducible findings
✅ **Bug bounty submissions** - Credible evidence
✅ **Security audits** - Industry-standard format
✅ **Compliance testing** - Objective assessment

---

## Next Steps

1. ✅ Run `test_fixed_scanner.py` on authorized target
2. ✅ Review findings with HTTP evidence
3. ✅ Understand proof points for each issue
4. ✅ Export JSON report
5. ✅ Submit credible findings through proper channels

---

## Support

- **Questions?** Review `SCANNER_FIX_SUMMARY.md`
- **Integration?** See `FIXED_SCANNER_INTEGRATION.md`
- **Before/After?** Check `SCANNER_BEFORE_AFTER.md`
- **Issues?** Check logs in results export

---

## Key Files

| File | Purpose |
|------|---------|
| `ai_vulnerability_tester_fixed.py` | Fixed scanner implementation |
| `test_fixed_scanner.py` | Validation & testing |
| `SCANNER_FIX_SUMMARY.md` | Detailed changes |
| `SCANNER_BEFORE_AFTER.md` | Side-by-side comparison |
| `FIXED_SCANNER_INTEGRATION.md` | Integration guide |
| `AUTHORIZED_TESTING_QUICKSTART.md` | This file |

---

**Remember: Authorization > Everything**

Only test systems you own or have explicit written permission to test.
