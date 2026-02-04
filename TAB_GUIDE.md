# HadesAI Tab Navigation Guide

## Launch
```bash
python run_hades.py
```

## 8 Main Tabs (Clean & Organized)

### 1. 💬 Chat & Knowledge
**Sub-tabs**:
- `💬 Chat` - Interactive chat with HadesAI
- `🌐 Web Knowledge` - Learn from website URLs
- `🧠 Learned` - Review previously learned exploits

### 2. 🛡️ Active Defense ⭐ NEW
**Dedicated Defense Tab** - Works independently!

Controls:
- `⚔️ Active Defense` - Toggle auto-blocking
- `🧠 Learning Mode` - Toggle learning
- `🤖 Autonomous Defense` - AI-driven defense
- `Level` - Select (Passive/Reactive/Proactive/Aggressive)
- `Block IP` / `Unblock IP` - Manual IP management

**Key Feature**: NO network monitor needed!

### 3. 📡 Network Monitor
**Monitoring Only** - Defense controls moved to Defense tab

Controls:
- `▶ Start Monitor` - Begin monitoring
- `⏹ Stop Monitor` - Stop monitoring

Views:
- `🌐 Live Connections` - Active connections
- `⚠️ Threat Detections` - Threats detected
- `📊 Real-Time Statistics` - Connection stats

### 4. ⚔️ Exploitation
**Sub-tabs**:
- `⚔️ Exploit` - Active exploit testing
- `💉 Injection` - Request injection attacks
- `🔓 Auth Bypass` - Authentication bypass techniques

### 5. 🛠️ Tools
**Sub-tabs**:
- `🛠️ Tools & Targets` - Target configuration
- `🌐 Proxy` - Proxy settings
- `🧩 Modules` - Module management and loading

### 6. 📊 Analysis
**Sub-tabs**:
- `💻 Code` - Code analysis and review
- `💻 Helper` - Code modification assistance
- `📂 Cache` - Browser cache analysis
- `🔍 Threats` - Threat findings report

### 7. 🎯 Automation
**Sub-tabs**:
- `🎯 AutoRecon` - Automated reconnaissance
- `🔧 Self-Improve` - Self-improvement settings
- `🤖 Agent` - Autonomous coding agent

### 8. 📦 Payloads
- Generate payloads for different file types
- File type detection
- Payload export (JSON/CSV/TXT)

---

## Quick Workflows

### Workflow 1: Defense Only
```
1. Launch: python run_hades.py
2. Go to: 🛡️ Active Defense tab
3. Click: ⚔️ Active Defense (toggle)
4. Select: Level (Reactive recommended)
5. Done! Defense is active and independent
```

### Workflow 2: Defense + Monitoring
```
1. Go to: 🛡️ Active Defense tab → Enable defense
2. Go to: 📡 Network Monitor tab → Start Monitor
3. Monitor network while defense is active
4. Both work independently
```

### Workflow 3: Web Penetration Testing
```
1. Go to: ⚔️ Exploitation tab
2. Choose: Sub-tab (Exploit/Injection/Auth Bypass)
3. Configure and execute tests
4. View results in same tab
```

### Workflow 4: Analysis & Learning
```
1. Go to: 📊 Analysis tab
2. Choose: Sub-tab (Code/Helper/Cache/Threats)
3. Upload or configure targets
4. View analysis results
```

### Workflow 5: Full Automation
```
1. Go to: 🎯 Automation tab
2. Configure: AutoRecon target
3. Run: Automated scan
4. Review: Findings in results
```

---

## Key Differences from Old Version

### Old (Fragmented)
- ❌ 18+ separate tabs
- ❌ Defense mixed with Network Monitor
- ❌ Hard to find things
- ❌ Defense dependent on monitor

### New (Consolidated)
- ✅ 8 main tabs
- ✅ Defense in own tab
- ✅ Easy to navigate
- ✅ Defense independent

---

## Pro Tips

### Tip 1: Use Sub-tabs
All main tabs have sub-tabs for organization. Click tabs within tabs to switch between functions.

### Tip 2: Defense Independence
Defense tab works completely alone:
- No network monitor needed
- No other dependencies
- Can enable/disable anytime

### Tip 3: Multi-Tab Workflow
Use multiple features simultaneously:
- Defense in one tab
- Network Monitor in another
- Exploitation tests in third tab
- All work independently

### Tip 4: Defense Levels
- `Passive` = Monitor only (no blocking)
- `Reactive` = Block confirmed threats (recommended)
- `Proactive` = Actively hunt attackers
- `Aggressive` = Maximum defense

### Tip 5: Sub-tab Organization
- **Chat & Knowledge**: 3 sub-tabs for different knowledge sources
- **Exploitation**: 3 sub-tabs for different attack types
- **Tools**: 3 sub-tabs for different tools
- **Analysis**: 4 sub-tabs for comprehensive analysis
- **Automation**: 3 sub-tabs for different automation options

---

## Status Indicators

### Defense Tab
- 🔴 Red = Inactive
- 🟢 Green = Active
- 🟡 Yellow = Warning

### Network Monitor
- ⏸️ Stopped (not monitoring)
- ▶️ Running (actively monitoring)
- ⚠️ Threats detected

---

## Documentation

- **This file**: Tab navigation guide
- **CONSOLIDATION_DONE.md**: What changed
- **LAUNCH_INSTRUCTIONS.md**: Full user guide
- **FINAL_CHANGES.md**: Bug fixes

---

## Need Help?

### Defense not working?
→ Check: Active Defense toggle is ON
→ Check: Defense Level not set to PASSIVE
→ Check: Console for error messages

### Can't find a feature?
→ Check: Sub-tabs (click tabs within tabs)
→ Check: Correct main tab
→ See: CONSOLIDATION_DONE.md for tab mapping

### Network Monitor not working?
→ Check: Defense tab first (enable defense if needed)
→ Check: Start Monitor button clicked
→ Check: Network permissions

---

## Summary

🎯 **8 Clean Main Tabs**
🛡️ **Independent Active Defense**
📊 **Organized Sub-tabs**
⚡ **All Features Accessible**
✅ **No Dependencies**

→ Launch: `python run_hades.py`

Enjoy the streamlined interface!
