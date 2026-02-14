# Simulations Tab - Feature Guide

## Overview
The new **🎮 Simulations** tab has been added to HadesAI to provide a safe, sandboxed environment for practicing pentesting skills and learning common attack vectors.

## Features

### Available Scenarios (8 Total)

#### Easy Difficulty
1. **🔓 SQL Injection** - Practice basic SQL injection techniques to bypass login forms and extract database information
2. **🕸️ XSS Attack** - Learn about Cross-Site Scripting vulnerabilities and steal session cookies

#### Medium Difficulty
3. **🔐 Authentication Bypass** - Bypass weak authentication mechanisms and exploit logical flaws
4. **💉 Command Injection** - Execute arbitrary system commands and achieve RCE
5. **🎭 SSRF Attack** - Server-Side Request Forgery for accessing internal resources
6. **🌐 Network Enumeration** - Discover hosts, ports, and services on a network

#### Hard Difficulty
7. **🏗️ Web App Pentesting** - Full end-to-end web application penetration test
8. **🔑 Privilege Escalation** - Escalate privileges from user to root/admin

## Tab Layout

### Left Panel - Scenario Selection
- List of all available scenarios
- Start/Reset buttons to manage simulation lifecycle
- Quick access to all practice scenarios

### Right Panel - Scenario Details
- **Difficulty Badge** - Shows scenario difficulty level (Easy/Medium/Hard)
- **Description** - Overview of what the scenario teaches
- **Objectives** - Specific goals to complete the scenario
- **Hints** - Clickable hints that reveal tips as you progress

### Bottom Section - Simulation Environment
- **Target URL** - Shows the vulnerable target endpoint for the current scenario
- **Test Payload Input** - Enter your exploits, commands, or payloads here
- **Execute Button** - Run your payload against the simulation
- **Results Output** - See the simulated target response and debug information
- **Score Tracking** - 0-100 score that increases as you successfully exploit vulnerabilities

## How to Use

### 1. Select a Scenario
- Click on any scenario from the list on the left
- Scenario details will populate on the right
- Review the objectives and hints

### 2. Start the Simulation
- Click **▶️ Start Scenario** to begin
- A welcome message will appear in the Results section
- Your score will reset to 0/100
- Status will show "In Progress"

### 3. Test Your Payloads
- Read the objectives carefully
- Click on hints to get guidance (hints appear in the chat)
- Type your payload/command in the Test Payload field
- Click **🚀 Execute Payload** to test it

### 4. Monitor Your Progress
- Successful payloads earn 20 points
- Partially successful attempts earn 10-15 points
- Each attempt adds 1 point minimum
- Status updates based on score:
  - 0-49: "In Progress" 🟦
  - 50-79: "Making Progress..." 🟦
  - 80+: "Completed!" 🟩

### 5. Reset and Try Again
- Click **🔄 Reset** to start over
- Clear your payload history and score
- Try a different approach

## Example Payloads

### SQL Injection
```
admin'--
' OR '1'='1
' OR 1=1--
UNION SELECT * FROM users
```

### XSS
```
<script>alert('xss')</script>
<img src=x onerror=alert('xss')>
javascript:alert('xss')
```

### Command Injection
```
id
; cat /etc/passwd
| whoami
$(id)
```

### SSRF
```
http://localhost:8080
http://169.254.169.254
http://internal.service
file:///etc/passwd
```

## Learning Benefits

✅ **Safe Practice** - All scenarios are sandboxed with no real system impact
✅ **Immediate Feedback** - See success/failure instantly
✅ **Guided Learning** - Built-in hints and objectives
✅ **Progress Tracking** - Score system motivates completion
✅ **Diverse Topics** - 8 scenarios covering different vulnerability types
✅ **Real-World Skills** - Techniques mirror actual pentesting

## Future Enhancements

Potential improvements to consider:
- Add custom scenario creation
- Save/load progress between sessions
- More complex multi-step scenarios
- Integration with OWASP Top 10
- Difficulty progression path
- Achievement/badge system
- Time-based challenges

## Tips for Success

1. **Read the objectives** - They tell you exactly what to accomplish
2. **Start with Easy scenarios** - Build foundation before harder ones
3. **Use the hints** - They appear in the chat when clicked
4. **Try variations** - If one payload doesn't work, modify and retry
5. **Understand why** - Think about why vulnerabilities exist
6. **Document findings** - Use the chat to note your discoveries

## Integration with HadesAI

The Simulations tab integrates with the main AI chat:
- Messages appear in the 💬 AI Chat tab
- Hints and feedback come from the AI
- You can ask for help in the main chat while practicing

---

**Version**: 1.0
**Added**: February 2026
**Status**: Ready to use
