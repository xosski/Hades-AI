# HadesAI Consolidated Launch Guide

## Quick Start

### Option 1: Using Launcher (Recommended)
```bash
python run_hades.py
```

### Option 2: Direct Execution
```bash
python HadesAI_consolidated.py
```

## What Changed

### ✅ All Tabs Now in ONE Program
- No more multiple separate GUI windows
- Single unified interface
- 9 condensed tabs with all features

### ✅ Active Defense is NOW INDEPENDENT
- Previously required Network Monitor running
- **Now works standalone** without any dependencies
- Can enable/disable independently
- Full configuration controls in Defense tab

### ✅ Tab Layout (Condensed)

```
┌─────────────────────────────────────────────────────────┐
│  HadesAI - Unified Pentesting Platform                  │
├─────────────────────────────────────────────────────────┤
│ [💬Chat] [🔍Analysis] [🌐Web] [🛡️Defense] [⚡Ops]     │
│ [🧠Autonomy] [💣Payloads] [📡Network] [📚Knowledge]    │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Active Tab Content Here                                 │
│                                                           │
├─────────────────────────────────────────────────────────┤
│ Status: Ready                                            │
└─────────────────────────────────────────────────────────┘
```

## Tab Reference

### 💬 Chat Tab
- Main chat interface
- Send commands and messages
- Basic interaction

### 🔍 Analysis Tab
- Code analysis
- Paste code to analyze
- View results

### 🌐 Web Tab
- Web penetration testing
- Target URL input
- Multiple test options (port scan, vuln scan, headers)

### 🛡️ Defense Tab (NEW - INDEPENDENT!)
- **Enable/Disable Defense** - Toggle independently
- **Defense Level** - Low/Medium/High/Extreme
- **Auto-Response** - Automatic threat handling
- **Block Threshold** - Sensitivity control
- **Threat Log** - View recent threats
- **Blocked IPs** - Manage IP blocks
- **Manual Block** - Block specific IPs on demand

**Key Feature**: No network monitor needed!

### ⚡ Ops Tab (Autonomous Operations)
- **Threat Response** - Auto-respond to attacks
- **Continuous Learning** - Learn from events
- **Decision Agent** - Autonomous decisions
- **Top Exploits** - Success statistics
- **Status Monitor** - Real-time monitoring

All three components toggle independently.

### 🧠 Autonomy Tab (Advanced Systems)
- **Self-Healing** - Auto-recovery from errors
- **Adaptive Strategies** - Dynamic adjustments
- **Scheduler** - Task automation
- **Multi-Agent** - Agent coordination

All in sub-tabs within Autonomy.

### 💣 Payloads Tab
- Select file for analysis
- Auto-detect file type
- Generate targeted payloads
- Copy/export payloads

### 📡 Network Tab (Combined)
- **Monitor** - Network traffic monitoring
- **P2P** - Encrypted peer-to-peer knowledge sharing
- Two independent sub-tabs

### 📚 Knowledge Tab
- Search knowledge base
- Query learned exploits
- View documented patterns

## Configuration

### Starting Minimal
All components start **disabled** by default. Enable only what you need:

1. **Just Defense?**
   - Go to 🛡️ Defense tab
   - Click "Enable Defense"
   - No other dependencies

2. **Defense + Learning?**
   - Go to 🛡️ Defense tab → Enable
   - Go to ⚡ Ops tab → Enable "Continuous Learning"
   - Independent of network

3. **Full Autonomy?**
   - Enable all tabs as needed
   - Each system runs independently
   - No cascading dependencies

## Key Improvements

| Issue | Before | After |
|-------|--------|-------|
| Defense dependency | Needed network monitor | Standalone |
| Multiple windows | Fragmented interface | Single window |
| Tab count | 4-8 scattered files | 9 condensed tabs |
| Startup overhead | Multiple processes | Single process |
| Navigation | Jump between windows | Tab buttons |
| Configuration | Spread across files | Localized per tab |

## Architecture

```
HadesAI_consolidated.py (Main Application)
├── ChatTab
├── AnalysisTab
├── WebTestingTab
├── ActiveDefenseTab (INDEPENDENT)
│   ├── Defense Engine
│   ├── Configuration Controls
│   ├── Threat Log
│   └── IP Management
├── OperationsTab
│   ├── Threat Response
│   ├── Learning Engine
│   └── Decision Agent
├── AdvancedAutonomyTab
│   ├── Self-Healing
│   ├── Adaptive Strategies
│   ├── Scheduler
│   └── Multi-Agent
├── PayloadTab
├── NetworkTab
│   ├── Monitor Sub-Tab
│   └── P2P Sub-Tab
└── KnowledgeBaseTab
```

All tabs can run independently. No shared state requirements.

## Defense Tab Details

### Enable Defense
1. Click "Enable Defense" button
2. Select defense level (default: MEDIUM)
3. Optionally adjust block threshold
4. Monitor threat log in real-time

### Manual IP Blocking
1. Enter IP in input field
2. Click "Block IP"
3. View in blocked IPs list

### Defense Levels
- **LOW**: Monitor only, no auto-block
- **MEDIUM**: Auto-block on confirmed threats
- **HIGH**: Aggressive blocking, low threshold
- **EXTREME**: Block on suspicious patterns

### Threshold Adjustment
- Range: 0.0 - 1.0
- Lower = more aggressive blocking
- Default: 0.7 (70% confidence required)

## Performance Notes

- Single Qt application instance (lower memory overhead)
- Each tab loads components on demand
- Optional modules gracefully disabled if unavailable
- Threaded operations prevent UI freezing

## Troubleshooting

### Defense Not Responding
```
✓ Check: Defense tab "Enable" button is clicked
✓ Check: Defense Level is set (not LOW)
✓ Check: Console for error messages
```

### Tab Not Showing
```
✓ Module may not be installed
✓ Check: CONSOLIDATION_NOTES.md for dependencies
✓ Try: Running with verbose logging
```

### High CPU Usage
```
✓ Disable unused tabs
✓ Reduce monitoring intervals
✓ Check: Threat log size (clear if huge)
```

## File Locations

- **Main Program**: `HadesAI_consolidated.py`
- **Launcher**: `run_hades.py`
- **Documentation**: `CONSOLIDATION_NOTES.md`
- **Legacy**: `HadesAI.py` (kept for advanced features)

## Next: Run the Application

```bash
# Start HadesAI Consolidated Edition
python run_hades.py
```

All features are now in one window. Enjoy streamlined pentesting!
