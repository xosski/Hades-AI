# Attack Vectors & Threat Simulations - Quick Start

## What's New

Attack vectors are now **tightly integrated** with threat simulations. Each scenario shows:
- ✓ Which attack vectors are used
- ✓ Sequential execution order (attack chain)
- ✓ Tools, payloads, and detection methods
- ✓ Learning objectives and success criteria

## Three Ways to Learn

### 1️⃣ **Follow a Threat Scenario** (Recommended for beginners)
Learn attack chains by following a real-world scenario.

**Example**: E-Commerce Breach
```
Step 1: SQL Injection in login form
Step 2: Extract customer database
Step 3: Use XSS to steal admin session
Step 4: Upload file to get RCE
Step 5: Exfiltrate payment data
```

**How to**:
1. Open Simulations tab → Select scenario
2. System shows attack chain with vector details
3. Try commands: `sqlmap`, `curl`, etc.
4. Follow AI coaching for next steps
5. Complete success criteria = scenario mastered

### 2️⃣ **Study Individual Attack Vectors** (Reference material)
Deep-dive into specific techniques.

**Example**: SQL Injection
```
Description: Inject malicious SQL into form fields
Tools: sqlmap, burp, curl
Payloads: ' OR '1'='1, UNION SELECT, DROP TABLE
Detection: SQL errors, time delays, error messages
Mitigation: Prepared statements, input validation
Used In: E-Commerce Breach (Step 1), Cloud Breach
```

**How to**:
1. Open Attack Vectors tab
2. Browse or filter by difficulty/phase
3. Click vector to see full details
4. See which scenarios use this vector
5. Click scenario to practice

### 3️⃣ **Scan Live Targets** (Advanced)
Apply vectors against real websites.

**Example**: Analyze example.com
```
Command: curl http://example.com
Result: Fetch page, extract forms, scripts, endpoints
Vector Used: Reconnaissance / Target Analysis
```

**How to**:
1. Enable "Use Live Target Data"
2. Enter URL: `http://target.com`
3. Execute: `curl`, `form`, `endpoint`, `nmap`
4. See real data from target
5. Map vulnerabilities to vectors

## Quick Reference

### By Difficulty

**Easy** (Start here):
- SQL Injection - Basic injection
- Reflected XSS - JavaScript injection
- Broken Auth - Default credentials

**Medium** (Next):
- SSRF - Internal requests
- File Upload RCE - Shell upload
- Authentication Bypass

**Hard** (Advanced):
- Privilege Escalation - SUID/sudo
- Lateral Movement - Network pivot

### By Vulnerability Type

**Injection** (CWE-89):
- SQL Injection
- Command Injection
- XSS

**Authentication** (CWE-287):
- Weak passwords
- JWT bypass
- Session fixation

**Access Control** (CWE-284):
- Privilege escalation
- Broken authorization

**Server Misconfig** (CWE-918):
- SSRF
- File upload issues

### By Attack Phase

**Reconnaissance**: Target analysis, information gathering
**Exploitation**: Vulnerability abuse
**Installation**: Backdoor/shell installation
**Command & Control**: Attacker communication
**Actions on Objectives**: Data theft, lateral movement

## Sample Workflows

### Workflow 1: Learn SQL Injection (20 minutes)
```
1. Go to Attack Vectors tab
2. Search: "SQL Injection"
3. Review:
   - Description
   - Sample payloads
   - Detection methods
   - Mitigation
4. Click "E-Commerce Breach" scenario
5. Practice steps 1-2 in simulation
```

### Workflow 2: Complete E-Commerce Breach (60 minutes)
```
1. Go to Simulations tab
2. Select: "E-Commerce Login Bypass"
3. Read attack chain description
4. Execute sequence:
   a. SQL Injection → Extract database
   b. XSS → Steal cookies
   c. File Upload → Get shell
5. Complete all success criteria
6. Review what you learned
```

### Workflow 3: Analyze Live Target (30 minutes)
```
1. Go to Simulations tab
2. Check "Use Live Target Data"
3. Enter: http://example.com
4. Execute:
   - curl http://example.com (fetch page)
   - form example.com (find forms)
   - endpoint example.com (find APIs)
5. Map findings to vectors
6. Identify potential attacks
```

## UI Layout

```
┌─ Simulations Tab ────────────────────────────┐
│                                               │
│  [Attack Vectors] [Threat Scenarios] [...]   │
│                                               │
│  ┌─────────────────────────────────────────┐ │
│  │ 🎭 Threat Scenarios                     │ │
│  │ [Critical] E-Commerce Breach            │ │
│  │ [Critical] Network Takeover             │ │
│  │ [Critical] Cloud Metadata Breach        │ │
│  └─────────────────────────────────────────┘ │
│  Scenario Details:                           │
│  ┌─────────────────────────────────────────┐ │
│  │ Description, vectors used, attack chain │ │
│  │ Learning objectives, success criteria   │ │
│  └─────────────────────────────────────────┘ │
│                                               │
└───────────────────────────────────────────────┘

┌─ Attack Vectors Tab ─────────────────────────┐
│ Filter: [Vulnerability ▼] [Phase ▼]          │
│                                               │
│  ┌─────────────────────────────────────────┐ │
│  │ [Easy] SQL Injection                    │ │
│  │ [Easy] Reflected XSS                    │ │
│  │ [Medium] SSRF                           │ │
│  │ [Hard] Privilege Escalation             │ │
│  └─────────────────────────────────────────┘ │
│  Vector Details:                             │
│  ┌─────────────────────────────────────────┐ │
│  │ Tools, payloads, detection, mitigation  │ │
│  │ Used in scenarios, references           │ │
│  └─────────────────────────────────────────┘ │
│                                               │
└───────────────────────────────────────────────┘
```

## Common Questions

**Q: Which one should I start with?**
A: Start with scenarios. They guide you through attack chains. Then study vectors for deep knowledge.

**Q: How are vectors and scenarios connected?**
A: Scenarios = attack chains combining multiple vectors. Each scenario step shows which vector is used.

**Q: Can I use live targets?**
A: Yes, but ONLY targets you own or have permission to test. example.com is safe to practice.

**Q: What if I get stuck?**
A: Read the vector details (tools, payloads, tips). AI coaching will guide next steps in scenarios.

**Q: How do I progress?**
A: Easy → Medium → Hard → Expert. Each level uses more vectors in complex chains.

## Learning Path Examples

### Beginner Path (4-6 hours)
```
1. SQL Injection vector (30 min)
2. Reflected XSS vector (30 min)
3. E-Commerce Breach scenario (60 min)
4. Cloud Metadata scenario (30 min)
```

### Intermediate Path (8-10 hours)
```
1. Privilege Escalation vector (60 min)
2. Lateral Movement vector (60 min)
3. Network Takeover scenario (90 min)
4. Custom attack chain practice (60 min)
```

### Advanced Path (12+ hours)
```
1. All Hard vectors (180 min)
2. All scenarios (180 min)
3. Live target analysis (120 min)
4. Multi-vector exploitation (120 min)
5. Create custom scenario (60 min)
```

## Key Metrics

### Vectors Covered
- 7 core attack vectors
- 4 difficulty levels
- 7 attack phases
- 10+ CWE/CVE mappings

### Scenarios Included
- 3 real-world scenarios
- 5-7 attack steps each
- Multiple vector combinations
- Complete attack chains

### Learning Outcomes
- Understand attack methodology
- Master exploitation techniques
- Learn defensive countermeasures
- Build security mindset

## Integration Features

✓ **Scenario shows vector details** - Click vector name in scenario
✓ **Vector shows related scenarios** - See "Used in scenarios" section
✓ **Attack chains are sequential** - Learn proper attack order
✓ **Payloads are real** - Use actual exploitation code
✓ **Detection methods** - Learn to find these attacks
✓ **Mitigations included** - Understand defense

## Next Steps

1. **Open Simulations tab**
2. **Select scenario** (start with "Easy")
3. **Read attack chain** (understand vector sequence)
4. **Execute commands** (follow vector order)
5. **Study vectors** (deep-dive on techniques)
6. **Complete scenario** (achieve all success criteria)
7. **Try next difficulty** (progress to Medium)

---

**Remember**: This is for educational purposes only. Always get written permission before testing on any system you don't own.
