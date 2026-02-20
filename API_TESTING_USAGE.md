# API Testing & Data Harvesting - Usage Guide

## Overview

This module provides **non-exploitative API security assessment** focused on:
- Security infrastructure detection (WAF, authentication, edge/CDN)
- Data exposure identification (what data is accessible)
- Security posture reporting (not vulnerability exploitation)

## Quick Start

### Basic Usage

```python
from api_testing_harvester import APITester, APITestReport

# Create tester instance
tester = APITester('http://target-api.example.com')

# Test single endpoint
endpoint = tester.test_endpoint('/api/users')
print(f"Status: {endpoint.response_code}")
print(f"Auth Required: {endpoint.auth_required}")
print(f"WAF Detected: {endpoint.waf_detected}")
print(f"Data Harvested: {len(endpoint.data_harvested)} points")

# Generate report
if endpoint.data_harvested:
    for point in endpoint.data_harvested:
        print(f"  {point.field_name} ({point.sensitivity}): {point.data_type}")
```

### Full API Traversal

```python
from api_testing_harvester import APITester, APITestReport

tester = APITester('http://api.example.com')

# Discover and test endpoints
session = tester.traverse_api(max_depth=2)

# Generate security posture report
report = APITestReport.generate_summary(session)
print(report)

# Export data for analysis
exported_data = APITestReport.export_harvested_data(session)
for item in exported_data:
    print(f"{item['endpoint']}: {item['field_name']} = {item['sensitivity']}")

# Save JSON report
import json
with open('api_assessment.json', 'w') as f:
    json.dump(session.to_dict(), f, indent=2)
```

## Security Infrastructure Detection

### WAF Detection

The module detects common WAF solutions:

```python
endpoint = tester.test_endpoint('/api/admin')

if endpoint.waf_detected:
    print(f"WAF Detected: {endpoint.waf_name}")
    if endpoint.blocked_by_waf:
        print("  → Request was blocked (403 Forbidden)")
```

**Supported WAFs:**
- Cloudflare
- Akamai
- ModSecurity
- Imperva/Incapsula
- Barracuda
- F5
- AWS WAF
- Fortinet
- Sucuri
- Wordfence

### Authentication Detection

```python
if endpoint.auth_required:
    print("Endpoint requires authentication (401 Unauthorized)")
```

### Edge/CDN Detection

```python
if endpoint.edge_detected:
    print("Response came through edge/CDN provider")
```

## Data Harvesting & Classification

### Data Types Identified

- **PII** (Personally Identifiable Information)
  - Email addresses
  - Phone numbers
  - SSN/Tax IDs
  - Addresses

- **Sensitive Data**
  - API Keys
  - Passwords
  - Credit card numbers
  - Secrets

- **Internal Data**
  - Hash values
  - Auth tokens
  - Session identifiers

- **Public Data**
  - IP addresses
  - Generic text

### Example: Extract Sensitive Data

```python
from api_testing_harvester import APITester

tester = APITester('http://api.example.com')
endpoint = tester.test_endpoint('/api/config')

# Filter by sensitivity
sensitive_data = [p for p in endpoint.data_harvested 
                  if p.sensitivity == 'sensitive']

print(f"Found {len(sensitive_data)} sensitive data points:")
for point in sensitive_data:
    print(f"  {point.field_name}: {point.data_type}")
    print(f"    Value: {point.field_value}")
    print(f"    Source: {point.source_endpoint}")
```

## Parameter Fuzzing

Test common parameters for accessibility:

```python
# Fuzz common parameter names
results = tester.parameter_fuzzing('/api/search')

# Show interesting responses
for result in results:
    if result.get('interesting'):
        print(f"{result['parameter']}={result['value']} → HTTP {result['status']}")
```

## Injection Testing (Safe)

Test for injection vulnerabilities **without exploitation**:

```python
# Returns injection test attempts and responses
results = tester.test_injection_vulnerabilities('/api/search')

for result in results:
    print(f"[{result['type']}] Payload: {result['payload']}")
    print(f"  Status: {result['status']}")
    print(f"  Error indicators: {result['error_indicators']}")
```

## Cookie Security

Extract and inspect cookie headers:

```python
from api_testing_harvester import WAFDetector

# Cookies are automatically extracted with redacted values
cookies = endpoint.set_cookies
for cookie in cookies:
    print(cookie)
    # Output: session_id=[REDACTED]; Path=/; HttpOnly; Secure
```

## Server Information

Identify server/framework disclosure:

```python
if endpoint.server_info:
    print(f"Server: {endpoint.server_info}")
else:
    print("Server header not exposed")

# Check for information disclosure
common_headers = ['x-powered-by', 'x-aspnet-version', 'x-runtime-version']
for header in common_headers:
    if header in endpoint.headers:
        print(f"Found: {header} = {endpoint.headers[header]}")
```

## Generating Reports

### Summary Report (Human-Readable)

```python
report = APITestReport.generate_summary(session)
print(report)

# Example output:
# ================================================================================
# API SECURITY POSTURE ASSESSMENT REPORT
# ================================================================================
# 
# Base URL: http://api.example.com
# Endpoints Assessed: 25
# 
# --- SECURITY INFRASTRUCTURE ---
#   ✓ Endpoints with WAF detected: 15/25
#   ✓ Endpoints requiring authentication: 20/25
#   ✓ Endpoints through edge/CDN: 12/25
# ...
```

### JSON Report

```python
import json

json_report = APITestReport.generate_json(session)
data = json.loads(json_report)

print(f"Assessment Date: {data['timestamp']}")
print(f"Total Data Points: {data['total_data_points']}")
print(f"Sensitivity Breakdown: {data['sensitivity_breakdown']}")
```

### Export Harvested Data

```python
exported = APITestReport.export_harvested_data(session)

# CSV export
import csv
with open('harvested_data.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=exported[0].keys())
    writer.writeheader()
    writer.writerows(exported)
```

## What This Tool Does NOT Do

- ❌ Does not exploit vulnerabilities
- ❌ Does not modify server state
- ❌ Does not brute-force credentials
- ❌ Does not perform malicious actions
- ❌ Does not report false positives as vulnerabilities

## What This Tool DOES Do

- ✅ Identifies security infrastructure (WAF, CDN, auth)
- ✅ Discovers accessible data and its sensitivity level
- ✅ Detects authentication requirements
- ✅ Identifies information disclosure (server headers)
- ✅ Reports security posture objectively
- ✅ Provides actionable assessment data

## Configuration

### Custom Timeout

```python
tester = APITester('http://api.example.com', timeout=20)
```

### Custom Headers

```python
headers = {
    'Authorization': 'Bearer token',
    'User-Agent': 'Custom-Agent'
}
endpoint = tester.test_endpoint('/api/admin', headers=headers)
```

### Custom Parameters for Fuzzing

```python
custom_params = ['id', 'admin_id', 'parent_id', 'internal_flag']
results = tester.parameter_fuzzing('/api/users', param_names=custom_params)
```

## API Reference

### APITester

```python
class APITester:
    def __init__(self, base_url: str, timeout: int = 10)
    def test_endpoint(self, endpoint: str, method: str = 'GET', 
                      data: Dict = None, headers: Dict = None) -> APIEndpoint
    def traverse_api(self, max_depth: int = 3, test_payloads: bool = True) -> APITestSession
    def parameter_fuzzing(self, endpoint: str, param_names: List[str] = None) -> List[Dict]
    def test_injection_vulnerabilities(self, endpoint: str) -> List[Dict]
```

### WAFDetector

```python
class WAFDetector:
    @staticmethod
    def detect_waf(response_headers: Dict, response_status: int) -> Tuple[bool, Optional[str], bool]
    @staticmethod
    def detect_edge(response_headers: Dict) -> bool
    @staticmethod
    def extract_cookies(response_headers: Dict) -> List[str]
    @staticmethod
    def get_server_info(response_headers: Dict) -> Optional[str]
```

### DataHarvester

```python
class DataHarvester:
    def harvest_from_json(self, data: Dict, source_path: str) -> List[DataPoint]
    def harvest_from_text(self, text: str, source_path: str) -> List[DataPoint]
```

## Testing

Run the comprehensive test suite:

```bash
python test_api_harvesting.py
```

Expected output:
```
Ran 26 tests in 0.03s
OK
```

All tests pass, covering:
- Data extraction and classification
- WAF detection
- Authentication detection
- Header analysis
- Error handling
- Edge cases

## Example Output

### Security Posture Report

```
================================================================================
API SECURITY POSTURE ASSESSMENT REPORT
================================================================================

Base URL: http://api.example.com
Assessment Timestamp: 2026-02-19T23:30:00.000000

Endpoints Assessed: 15

--- SECURITY INFRASTRUCTURE ---
  ✓ Endpoints with WAF detected: 12/15
  ✓ Endpoints requiring authentication: 14/15
  ✓ Endpoints through edge/CDN: 10/15

--- SERVER INFORMATION ---
  nginx/1.24.0
  (Server info not exposed on other endpoints)

--- COOKIE SECURITY ---
  session_id=[REDACTED]; Path=/; HttpOnly; Secure
  csrf_token=[REDACTED]; SameSite=Strict
  No cookies set on other endpoints

--- DATA EXPOSURE ASSESSMENT ---
  Total data points found: 156

  Sensitivity Breakdown:
    SENSITIVE: 34 data points
    PII: 28 data points
    INTERNAL: 45 data points
    PUBLIC: 49 data points

  Data Types Identified:
    api_key: 12
    token: 18
    email: 11
    ip_address: 28
    ...
```

## Disclaimer

This tool is designed for authorized security assessments only. Ensure you have explicit permission before testing any API.
