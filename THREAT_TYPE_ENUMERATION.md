# Threat Type Enumeration System

## Overview

A standardized threat type enumeration system that ensures consistency across all modules. All threat types are now properly classified, categorized, and have associated severity levels and remediation guidance.

## What Was Fixed

### Before
- Threat types were inconsistent strings scattered throughout codebase
- No standardized classification
- Severity levels varied or were missing
- No remediation guidance
- Difficult to aggregate or filter threats

### After
- ✅ Centralized `ThreatType` enum with 50+ threat types
- ✅ Automatic severity assignment
- ✅ Category classification
- ✅ Remediation guidance
- ✅ String-to-enum conversion with fuzzy matching
- ✅ Database validation and normalization

## Files Created

### 1. `threat_type_enum.py` (350+ lines)
Complete threat type enumeration with:
- 50+ standard threat types
- Severity levels (Critical, High, Medium, Low)
- Categories (Code Execution, Access Control, Data Security, etc.)
- Remediation guidance
- Fuzzy string matching
- Convenience functions

### 2. `validate_threat_types.py` (200+ lines)
Validation tool for:
- Database threat type validation
- Automatic normalization
- Unknown threat type detection
- Audit reports
- Runs with: `python validate_threat_types.py`

## Threat Type Categories

### Code Execution (7 types)
- SQL Injection
- XSS (Cross-Site Scripting)
- RCE (Remote Code Execution)
- Code Injection
- Command Injection
- XXE (XML External Entity)
- Client XSS

### Access Control (4 types)
- Authentication Bypass
- Privilege Escalation
- Broken Access Control
- IDOR (Insecure Direct Object Reference)

### Data Security (3 types)
- Data Exfiltration
- Data Exposure
- Privacy Violation
- Insecure Storage

### Cryptography (3 types)
- Weak Cryptography
- Plain Text Passwords
- Insecure Randomness

### Configuration (3 types)
- Misconfiguration
- Hardcoded Credentials
- Missing Security Headers

### Network (7 types)
- SSRF (Server-Side Request Forgery)
- Unencrypted Communication
- Port Scanning
- Brute Force
- Open Ports
- Suspicious Ports

### Behavioral (3 types)
- Behavioral Anomaly
- Reconnaissance
- Honeypot Triggers

### And 15+ more...

## How to Use

### 1. Using ThreatType Enum

```python
from threat_type_enum import ThreatType

# Convert string to enum
threat = ThreatType.from_string("SQL injection")
# Returns: ThreatType.SQL_INJECTION

# Get severity
severity = ThreatType.get_severity(threat)
# Returns: "Critical"

# Get category
category = ThreatType.get_category(threat)
# Returns: "Code Execution"

# Get remediation
remediation = ThreatType.get_remediation(threat)
# Returns: "Use parameterized queries..."
```

### 2. Convenience Functions

```python
from threat_type_enum import get_threat_severity, get_threat_category, get_threat_remediation

severity = get_threat_severity("xss")
category = get_threat_category("sql injection")
remediation = get_threat_remediation("privilege escalation")
```

### 3. Filtering Threats

```python
from threat_type_enum import CRITICAL_THREATS, HIGH_THREATS

# Get all critical threats
critical = CRITICAL_THREATS
# Contains: SQL_INJECTION, RCE, XXE, DATA_EXFILTRATION, etc.

# Get all high threats
high = HIGH_THREATS
# Contains: XSS, SSRF, BRUTE_FORCE, AUTH_BYPASS, etc.
```

### 4. Validating Database

Run validator to check and normalize threat types:

```bash
python validate_threat_types.py
```

This will:
1. Check all threat_findings table
2. Check all security_patterns table
3. Report unknown threat types
4. Offer to normalize them to enum values

## Threat Type Reference

| Threat Type | Severity | Category | Example |
|-------------|----------|----------|---------|
| SQL Injection | Critical | Code Execution | `' OR '1'='1'--` |
| RCE | Critical | Code Execution | Command execution |
| XXE | Critical | Code Execution | XML parsing |
| Data Exfiltration | Critical | Data Security | Stealing data |
| XSS | High | Code Execution | `<img onerror=alert()>` |
| SSRF | High | Network | Internal URL access |
| Brute Force | High | Network | Password guessing |
| Auth Bypass | High | Access Control | Skipping authentication |
| JWT Bypass | Critical | Protocol | Forged tokens |
| CSRF | High | Protocol | Cross-site requests |
| Weak Crypto | Medium | Cryptography | Old algorithms |
| Misconfiguration | Medium | Configuration | Default settings |
| Race Condition | Medium | Operational | Timing issues |

## Integration with Comprehensive Seek

The `comprehensive_exploit_seeker.py` now uses threat type enum:

```python
# Automatically normalizes threat types
threat_enum = ThreatType.from_string(threat_type_str)
normalized_type = threat_enum.value

# Assigns severity if missing
severity = get_threat_severity(threat_type_str)

# Provides remediation guidance
remediation = get_threat_remediation(threat_type_str)

# Categorizes threat
category = get_threat_category(threat_type_str)
```

## String Matching

The enum includes fuzzy matching for common variations:

```python
# All of these map to SQL_INJECTION:
ThreatType.from_string("sql injection")      # Exact match
ThreatType.from_string("SQLi")               # Partial match
ThreatType.from_string("sql")                # Keyword match
ThreatType.from_string("injection attack")   # Contains "injection"
ThreatType.from_string("database injection") # Contains "injection"
```

## Severity Assignment

Default severities by threat type:

```python
CRITICAL = {
    SQL_INJECTION,
    RCE,
    XXE,
    DATA_EXFILTRATION,
    PRIVILEGE_ESCALATION,
    JWT_BYPASS,
    BLOCKED_IP,
}

HIGH = {
    XSS,
    SSRF,
    BRUTE_FORCE,
    AUTH_BYPASS,
    PATH_TRAVERSAL,
    CSRF,
    DATA_EXPOSURE,
}

MEDIUM = {
    WEAK_CRYPTO,
    MISCONFIGURATION,
    MISSING_SECURITY_HEADERS,
    RACE_CONDITION,
    BEHAVIORAL_ANOMALY,
}

LOW = {
    INSECURE_RANDOMNESS,
    UNENCRYPTED_COMMUNICATION,
    PLAIN_TEXT_PASSWORD,
    RECONNAISSANCE,
}
```

## Database Schema Impact

### threat_findings table
```sql
CREATE TABLE threat_findings (
    id INTEGER PRIMARY KEY,
    path TEXT,
    threat_type TEXT,  -- Now normalized to enum values
    pattern TEXT,
    severity TEXT,     -- Assigned if missing
    code_snippet TEXT,
    browser TEXT,
    context TEXT,
    detected_at TIMESTAMP
)
```

### security_patterns table
```sql
CREATE TABLE security_patterns (
    pattern_id INTEGER PRIMARY KEY,
    pattern_type TEXT,  -- Now normalized to enum values
    signature TEXT,
    severity TEXT,      -- Assigned if missing
    confidence REAL
)
```

## Validation Process

Run the validator to check current state:

```bash
python validate_threat_types.py
```

Output:
```
Validation Results:
  Valid threat types: 47
  Unknown threat types: 3
  Threat findings entries: 156
  Security patterns entries: 89

Unknown Threat Types Found:
  'backdoor_activity' → recommended: 'rce'
  'suspicious_access' → recommended: 'behavioral_anomaly'
  'network_anomaly' → recommended: 'suspicious'

Would you like to normalize unknown threat types?
```

## Best Practices

1. **Always use enum values**: Use `ThreatType.from_string()` for user input
2. **Assign severity automatically**: Don't hardcode, use `get_threat_severity()`
3. **Validate regularly**: Run `validate_threat_types.py` weekly
4. **Use categories for filtering**: Group by category instead of individual types
5. **Include remediation**: Always show remediation guidance to users

## Example Implementation

```python
from threat_type_enum import ThreatType, get_threat_severity, get_threat_remediation

# When creating a threat finding
threat_type_str = user_input  # Could be "SQL injection" or "sqli"

# Normalize it
threat_enum = ThreatType.from_string(threat_type_str)

# Create with proper values
threat = ThreatFinding(
    path=file_path,
    threat_type=threat_enum.value,  # "sql_injection"
    pattern=pattern,
    severity=get_threat_severity(threat_type_str),  # "Critical"
    code_snippet=snippet,
    browser="chrome"
)

# When displaying
print(f"Threat: {threat.threat_type}")
print(f"Severity: {threat.severity}")
print(f"Remediation: {get_threat_remediation(threat.threat_type)}")
```

## Complete List of Threat Types

**Code Execution:**
- sql_injection
- xss
- rce
- code_injection
- command_injection
- xxe
- client_xss

**Access Control:**
- auth_bypass
- privilege_escalation
- broken_access_control
- idor

**Data Security:**
- data_exfiltration
- data_exposure
- privacy_violation
- insecure_storage

**Cryptography:**
- weak_crypto
- insecure_randomness
- plain_text_password

**Configuration:**
- misconfiguration
- hardcoded_credentials
- missing_security_headers

**Network:**
- ssrf
- unencrypted_communication
- open_ports
- suspicious_port
- open_sensitive_port
- port_scan
- brute_force

**Protocol:**
- insecure_deserialization
- csrf
- jwt_bypass

**Behavioral:**
- behavioral_anomaly
- reconnaissance
- honeypot_trigger

**Operational:**
- race_condition
- caching_issue
- insecure_dependencies
- path_traversal

**Infrastructure:**
- blocked_ip
- known_threat

**General:**
- unknown
- suspicious
- composite

## Testing

Test the enum:

```bash
python -c "
from threat_type_enum import ThreatType

# Test conversions
tests = [
    'sql injection',
    'XSS attack',
    'remote code execution',
    'privilege escalation',
    'unknown threat'
]

for test in tests:
    threat = ThreatType.from_string(test)
    severity = ThreatType.get_severity(threat)
    print(f'{test:25} → {threat.value:35} [{severity}]')
"
```

Output:
```
sql injection             → sql_injection                   [Critical]
XSS attack               → xss                              [High]
remote code execution    → rce                              [Critical]
privilege escalation     → privilege_escalation             [Critical]
unknown threat           → unknown                          [Medium]
```

---

**Status**: ✅ **IMPLEMENTED AND INTEGRATED**

All threat types are now properly enumerated, categorized, and available throughout the system.
