# Quick Start - Exploit Seek Tab

## 1-Minute Setup

### Start HadesAI
```bash
python HadesAI.py
```

### Find the Tab
Look for **🔍 Exploit Seek** in the tab bar (between Simulations and Deploy)

### Use It
1. Paste target URL
2. Click **⚡ SEEK EXPLOITS** (red button)
3. Wait for results
4. View exploits from all sources

## What It Does

Searches **6 knowledge sources** automatically:
- P2P Network exploits (from peers)
- Learned exploits (from your sessions)
- Threat findings (from your scans)
- Security patterns (detected patterns)
- Cognitive memory (AI memories)
- Attack vectors (standard vectors)

## Results

Shows exploits with:
- **Severity**: Critical/High/Medium/Low
- **Type**: sql_injection, xss, rce, ssrf, etc.
- **Source**: Which knowledge source it came from
- **Confidence**: How sure we are it will work
- **Payload**: The actual exploit code/payload

## Options

| Option | Effect |
|--------|--------|
| Severity Filter | Only show Critical/High/etc. |
| Max Attempts | How many to try (auto-attempt) |
| Timeout | Seconds per attempt |
| Auto-Attempt | Try exploits automatically |

## Tabs

### Search Results
Table of discovered exploits with details

### Network Shared Exploits
Exploits other team members found (P2P)

### Detailed Analysis
Full exploit info including payloads and descriptions

## Examples

### Example 1: Search Target
```
Target: https://vulnerable-app.test
Click: SEEK EXPLOITS

Results (2 seconds later):
Found 15 exploits from 6 sources
- 5 from P2P Network
- 8 from Learned Database
- 2 from Threat Findings

Top result: SQL Injection (Critical, 95% confidence)
```

### Example 2: Auto-Attempt
```
Target: https://test.example.com
Enable: Auto-Attempt checkbox
Click: SEEK EXPLOITS

System:
- Finds 23 exploits
- Tries them in order (Critical first)
- Stops on first success
- Shows: ✅ SUCCESS! (after 3 attempts)
```

### Example 3: Share Successful Exploit
```
After successful exploitation:
Click: Share to Network

System:
- Broadcasts exploit to all peers
- All team members now have it
- Shows: "1 exploits shared to network"
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+Click | Multi-select exploits |
| Enter | Click SEEK button |
| Shift+Tab | Switch between tabs |

## Common Commands

```
Target: https://website.com/login
Type: sql_injection
Payload: admin'--
Result: ✅ Bypassed login
```

## Troubleshooting

### Nothing found
- **Check**: Target is actually vulnerable
- **Check**: Other instances using same target
- **Fix**: Try known vulnerable app first

### "Cannot create children" error
- **Fix**: Delete __pycache__ folder
- **Fix**: Restart Python

### Tab doesn't appear
- **Fix**: Check HadesAI.py imports
- **Fix**: Restart HadesAI

### Slow search
- Normal: Searching 6 sources takes time
- Expected: 500-2000ms is typical
- Faster: Second search uses cache

## Tips

1. **Run simulations first** to populate knowledge base
2. **Enable network sharing** to get team's exploits
3. **Use auto-attempt** for fast exploitation
4. **Check severity filter** to focus on critical
5. **Share successful exploits** to help team

## What Gets Searched

| Source | What | Count |
|--------|------|-------|
| P2P Network | Peer discoveries | Real-time |
| Learned DB | Your past wins | Hundreds |
| Threat Findings | Your scans | Hundreds |
| Security Patterns | Detected patterns | Variable |
| Cognitive Memory | AI memories | Variable |
| Attack Vectors | Standard vectors | ~50 |

## Information Shown

```
Target: https://vulnerable.test

Type: sql_injection
Severity: CRITICAL
Confidence: 0.95
Source: P2P Network (from peer_001)

Payload: ' OR '1'='1'--
Description: SQL injection in login form
Impact: Full database access
Remediation: Use parameterized queries
```

## Advanced Usage

### Export Results
Click **📤 Export Results** to save exploits to JSON

### Import Exploits
Import previously exported exploit databases

### Share to Network
Click **🔗 Share to Network** to broadcast successful exploits

### Severity Filtering
- Only try Critical/High exploits
- Set Max Attempts to limit
- Set Timeout appropriately

## Stats Shown

After search completes:
- Total exploits found
- Count by source
- Count by severity
- Count by type
- Unique exploits (after dedup)

## Performance

- **Search**: 500-2000ms
- **Display**: <100ms
- **Memory**: ~10MB per search
- **CPU**: Minimal (most is I/O)

## Support

1. Check console for error messages
2. Review STATUS_FINAL.md for details
3. Check COMPREHENSIVE_EXPLOIT_SEEK_SUMMARY.md for architecture
4. Run test_seek_tab.py to verify setup

---

**Pro Tip**: Run simulations regularly to keep knowledge base fresh!
