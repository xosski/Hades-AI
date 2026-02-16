# Attack Vectors & Threat Simulations Integration

Unified system that ties attack vectors to threat scenarios for comprehensive pentesting training.

## Overview

This system connects:
- **Attack Vectors**: Individual exploitation techniques mapped to CWE/CVSS
- **Threat Scenarios**: Complex multi-step attack chains using multiple vectors
- **Simulations**: Interactive training environment combining both

```
┌─────────────────────────────────────────────────────────┐
│  Attack Vectors & Threat Scenarios Integration         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Attack Vectors (7 core vectors)                       │
│  ├─ SQL Injection (CWE-89)                             │
│  ├─ Reflected XSS (CWE-79)                             │
│  ├─ Broken Authentication (CWE-287)                    │
│  ├─ SSRF (CWE-918)                                     │
│  ├─ File Upload RCE (CWE-434)                          │
│  ├─ Privilege Escalation (CWE-269)                     │
│  └─ Lateral Movement (Multi-vector)                    │
│                                                          │
│  ↓ Combined Into ↓                                      │
│                                                          │
│  Threat Scenarios (3 complex scenarios)                │
│  ├─ E-Commerce Breach (3 vectors, 60 min)             │
│  ├─ Network Takeover (3 vectors, 90 min)              │
│  └─ Cloud Metadata Theft (2 vectors, 30 min)          │
│                                                          │
│  ↓ Trained With ↓                                      │
│                                                          │
│  Realistic Simulations (Live + Scenario Modes)         │
│  ├─ Scenario Training: Guided exploitation             │
│  ├─ Live Target: Real web reconnaissance               │
│  └─ Attack Chains: Multi-step exploitation             │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Architecture

### 1. Attack Vectors Engine (`attack_vectors_engine.py`)

Comprehensive database of attack vectors with metadata:

```python
AttackVector:
  ├─ name: str
  ├─ vector_id: str
  ├─ description: str
  ├─ vulnerability_type: CWE
  ├─ attack_phase: MITRE ATT&CK phase
  ├─ tools: list of recommended tools
  ├─ payloads: sample exploitation payloads
  ├─ cve_refs: real CVE references
  ├─ difficulty: Easy | Medium | Hard | Expert
  ├─ detection_signals: how to identify
  ├─ mitigation: defensive measures
  └─ references: educational resources
```

### 2. Threat Scenarios

Multi-vector attack chains with sequential execution:

```python
ThreatScenario:
  ├─ name: str
  ├─ scenario_id: str
  ├─ description: str
  ├─ target_type: Web App | Network | Cloud | Endpoint
  ├─ severity: Low | Medium | High | Critical
  ├─ attack_vectors: [vector_ids] - vectors used
  ├─ attack_chain: [(phase, vector_id), ...] - sequential order
  ├─ difficulty: Easy | Medium | Hard | Expert
  ├─ estimated_time: int (minutes)
  ├─ learning_objectives: [goals]
  ├─ success_criteria: [measurable outcomes]
  └─ references: MITRE/research links
```

## Attack Vectors Catalog

### SQL Injection (CWE-89)
- **Phase**: Exploitation
- **Difficulty**: Easy
- **Tools**: sqlmap, burp_suite, curl
- **Payloads**: `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`
- **Used In**: E-Commerce Breach
- **Detection**: SQL errors, time delays, boolean differences
- **Mitigation**: Prepared statements, input validation, WAF

### Reflected XSS (CWE-79)
- **Phase**: Exploitation
- **Difficulty**: Easy
- **Tools**: burp_suite, browser dev tools
- **Payloads**: `<script>alert(1)</script>`, onerror handlers
- **Used In**: E-Commerce Breach, Multi-vulnerability scenarios
- **Detection**: Input reflection, lack of encoding
- **Mitigation**: Output encoding, CSP, HTTPOnly cookies

### Broken Authentication (CWE-287)
- **Phase**: Exploitation
- **Difficulty**: Medium
- **Tools**: jwt_tool, hashcat, burp_suite
- **Payloads**: Default credentials, JWT bypass, session fixation
- **Used In**: Cloud Metadata Breach, Network Takeover
- **Detection**: Weak passwords, predictable tokens
- **Mitigation**: MFA, strong password policy, JWT validation

### SSRF (CWE-918)
- **Phase**: Exploitation
- **Difficulty**: Medium
- **Tools**: curl, burp_suite
- **Payloads**: `http://localhost:8080`, AWS metadata endpoint
- **Used In**: Cloud Metadata Breach
- **Detection**: Internal IP requests, unusual protocols
- **Mitigation**: URL validation, internal IP deny-list, network segmentation

### File Upload RCE (CWE-434)
- **Phase**: Exploitation
- **Difficulty**: Medium
- **Tools**: burp_suite, curl
- **Payloads**: PHP shell, executable files, double extensions
- **Used In**: E-Commerce Breach
- **Detection**: Executable uploads, accessible files
- **Mitigation**: File type validation, magic bytes, upload isolation

### Privilege Escalation (CWE-269)
- **Phase**: Exploitation
- **Difficulty**: Hard
- **Tools**: LinPEAS, GTFObins, kernel exploits
- **Payloads**: SUID exploitation, sudo bypass, capabilities
- **Used In**: Network Takeover, Complex scenarios
- **Detection**: SUID binaries, weak sudo config
- **Mitigation**: Minimal SUID, sudo restrictions, kernel updates

### Lateral Movement
- **Phase**: Command & Control / Actions on Objectives
- **Difficulty**: Hard
- **Tools**: nmap, mimikatz, psexec, wmic
- **Payloads**: Pass-the-hash, kerberoasting, golden ticket
- **Used In**: Network Takeover, all advanced scenarios
- **Detection**: Lateral connections, credential reuse
- **Mitigation**: Network segmentation, MFA, monitoring

## Threat Scenarios

### Scenario 1: E-Commerce Breach
**Severity**: Critical | **Time**: 60 minutes | **Difficulty**: Hard

Attack chain:
1. [Reconnaissance] SQL Injection
2. [Exploitation] SQL Injection → Extract database
3. [Exploitation] XSS → Steal admin session
4. [Exploitation] File Upload → RCE
5. [Actions] Exfiltrate customer data

Learning objectives:
- Master SQL injection exploitation
- Chain multiple vulnerabilities
- Achieve remote code execution
- Exfiltrate sensitive data

Success criteria:
- Extract customer database
- Achieve RCE on web server
- Access payment processing files

### Scenario 2: Internal Network Takeover
**Severity**: Critical | **Time**: 90 minutes | **Difficulty**: Expert

Attack chain:
1. [Exploitation] Broken Authentication
2. [Exploitation] Privilege Escalation
3. [Command & Control] Lateral Movement
4. [Actions] Compromise domain controller

Learning objectives:
- Compromise initial account
- Escalate to system/SYSTEM
- Pivot through network
- Achieve domain admin

Success criteria:
- Extract domain admin creds
- Create golden ticket
- Compromise DC
- Maintain persistence

### Scenario 3: Cloud Metadata & Credentials Theft
**Severity**: Critical | **Time**: 30 minutes | **Difficulty**: Medium

Attack chain:
1. [Reconnaissance] SSRF
2. [Exploitation] SSRF → Extract credentials
3. [Actions] Use stolen AWS credentials

Learning objectives:
- Identify SSRF vulnerabilities
- Access metadata endpoints
- Extract cloud credentials
- Lateral movement to cloud resources

Success criteria:
- Access metadata endpoint
- Extract AWS credentials
- List S3 buckets
- Access sensitive cloud data

## Integration with Simulations

### Mode 1: Scenario Training
Users follow a guided attack chain through a threat scenario:

```
1. System presents scenario: "E-Commerce Breach"
2. User sees attack chain: SQL Injection → XSS → RCE
3. User tries commands: "sqlmap", "union select", etc.
4. System provides realistic responses based on vector
5. AI coaching guides next steps
6. Success: All objectives completed
```

### Mode 2: Live Target Analysis
Users apply attack vectors against real websites:

```
1. User enters target: http://target.com
2. System extracts live data: forms, endpoints, headers
3. User maps vectors: "This has SQL injection potential"
4. User attempts: curl, nmap, form enumeration
5. System shows real data extracted from target
6. Learning: Understand real-world vulnerability patterns
```

### Mode 3: Vector Reference
Users study attack vectors and scenarios:

```
Tabs:
├─ Threat Scenarios: View complex attack chains
├─ Attack Vectors: Study individual techniques
│   ├─ Filter by: Vulnerability type, attack phase
│   ├─ View: Tools, payloads, detection, mitigation
│   └─ Related: See which scenarios use this vector
└─ Learning Paths: Progressive difficulty progression
```

## Usage Flow

### For Beginners (Easy)
1. Start with SQL Injection vector tutorial
2. Run SQL Injection scenario (30 min)
3. Practice on example.com (no real impact)
4. Move to XSS scenario

### For Intermediate (Medium)
1. Study SSRF vector
2. Run Cloud Metadata scenario
3. Practice on test environment
4. Combine 2-3 vectors in one attack

### For Advanced (Hard+)
1. Multi-vector scenario: E-Commerce Breach
2. Attack chain: 5 sequential steps
3. Live target analysis with multiple vectors
4. Create custom attack chains

## Key Features

### Comprehensive Metadata
Each vector includes:
- Real CVE references
- CWE mappings
- MITRE ATT&CK phase
- Actual tools used
- Real exploitation payloads
- Detection mechanisms
- Defensive mitigations

### Attack Chain Visualization
See exactly how vectors combine:
```
E-Commerce Breach:
  Step 1: SQL Injection (Reconnaissance)
  Step 2: SQL Injection (Exploitation) → Database access
  Step 3: XSS (Exploitation) → Cookie stealing
  Step 4: File Upload (Exploitation) → RCE
  Step 5: Post-Exploitation (Data exfiltration)
```

### Learning Paths
Progressive difficulty:
- **Easy Path**: Single vectors, 20-30 minutes
- **Medium Path**: 2-3 vectors, 30-60 minutes
- **Hard Path**: 4+ vectors, 60+ minutes
- **Expert Path**: Complex chains with persistence

### Real-World Mapping
Every vector tied to:
- Real CVEs and exploits
- Actual tools (sqlmap, metasploit, etc.)
- Common payloads
- Detection patterns from real incidents
- Proven mitigations

## Database Schema

### Vectors Table (7 core vectors)
```
sql_injection          → CWE-89, Exploitation
xss_reflected          → CWE-79, Exploitation
broken_authentication  → CWE-287, Exploitation
ssrf                   → CWE-918, Exploitation
rce_file_upload        → CWE-434, Exploitation
privilege_escalation   → CWE-269, Exploitation
lateral_movement       → CWE-285, Command & Control
```

### Scenarios Table (3 scenarios)
```
ecommerce_breach       → Critical, 3 vectors, 60 min
internal_network_takeover → Critical, 3 vectors, 90 min
cloud_metadata_breach  → Critical, 2 vectors, 30 min
```

### Mappings
```
Scenario → [Vector IDs]
Vector → [Scenario IDs]
Phase → [Vector IDs]
Vuln Type → [Vector IDs]
```

## API Reference

```python
from attack_vectors_engine import AttackVectorEngine, AttackPhase, VulnerabilityType

engine = AttackVectorEngine()

# Get single vector
vector = engine.get_vector('sql_injection')
print(vector.payloads)  # See exploitation payloads

# Get scenario
scenario = engine.get_scenario('ecommerce_breach')
print(scenario.attack_chain)  # See sequential steps

# Get all vectors for a scenario
vectors = engine.get_scenario_vectors('ecommerce_breach')
for v in vectors:
    print(f"{v.name}: {v.vuln_type}")

# Get attack chain with details
chain = engine.get_scenario_chain('ecommerce_breach')
for step in chain:
    print(f"{step['phase']}: {step['vector']['name']}")

# Filter vectors
injection_vectors = engine.find_vectors_by_vuln_type(VulnerabilityType.INJECTION)
exploitation_vectors = engine.find_vectors_by_phase(AttackPhase.EXPLOITATION)

# Find related scenarios
scenarios = engine.get_related_scenarios('sql_injection')

# Export for sharing
catalog = engine.export_catalog()
print(json.dumps(catalog, indent=2))

# Log execution for training
engine.log_execution(
    scenario_id='ecommerce_breach',
    vector_id='sql_injection',
    success=True,
    payload="' OR '1'='1",
    result="Database accessed successfully"
)
```

## Integration Points

### With Realistic Simulations
- Simulations now show which vector is being tested
- Coaching feedback references vector details
- Learning objectives tied to vector mastery

### With Autonomy System
- Agents can use attack vectors database
- Decision making informed by vector difficulty
- Learning recorded against vectors

### With Network Monitor
- Detected threats mapped to vectors
- Attack attribution to specific vectors
- Defensive recommendations from vector mitigation

## Future Enhancements

1. **More Vectors**: Add 20+ vectors (buffer overflow, XXE, etc.)
2. **More Scenarios**: Advanced scenarios (APT simulations, zero-days)
3. **Custom Chains**: Users create custom attack chains
4. **Scoring**: Points for detecting/defeating vectors
5. **Team Competitions**: Leaderboards for scenario completion
6. **Integration**: Import from MITRE ATT&CK database
7. **Visualization**: Attack tree diagrams
8. **Video Tutorials**: Linked to each vector

## References

- **MITRE ATT&CK**: https://attack.mitre.org/
- **CWE Top 25**: https://cwe.mitre.org/top25/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CVE Database**: https://cve.mitre.org/
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
