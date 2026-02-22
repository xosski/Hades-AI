# Seeker + AI Integration - Quick Start

## TL;DR

New unified analysis combines **AI vulnerability detection** + **exploit discovery** into a single integrated pipeline.

**One button:** `🔗 UNIFIED ANALYSIS`
**One output:** Ranked exploits with AI confidence scores and correlations

---

## Launch & Use

### From HadesAI GUI

1. Launch **HadesAI.py**
2. Go to **"Exploit Seek & Share"** tab
3. Enter target URL
4. Click **`🔗 UNIFIED ANALYSIS`** (new teal button)
5. Wait 40-90 seconds for results
6. View ranked exploits with AI scoring

### From Command Line

```python
from SeekAIIntegration import SeekAIIntegration
from ai_vulnerability_tester_fixed import AIVulnerabilityTester
from p2p_exploit_sharing import ExploitSeeker, P2PExploitSharer

# Setup
sharer = P2PExploitSharer()
ai_tester = AIVulnerabilityTester(hades_ai=None)  # or pass hades_ai
seeker = ExploitSeeker(sharer)

# Create integration
integration = SeekAIIntegration(
    ai_tester=ai_tester,
    exploit_seeker=seeker
)

# Run analysis
result = integration.analyze_and_score("https://target.com")

# View results
for exploit in result.seek_findings[:5]:
    print(f"#{exploit.execution_priority}: {exploit.exploit_type}")
    print(f"   Score: {exploit.combined_score:.2f}")
    print(f"   Reasoning: {exploit.ai_reasoning}\n")
```

---

## What It Does

### Step 1: AI Analysis (30-60s)
- Detects technologies, frameworks
- Finds weak points, security issues
- Lists likely vulnerabilities
- Identifies defense mechanisms

### Step 2: Exploit Seeking (Parallel, 10-30s)
- Searches databases for applicable exploits
- Extracts payload, impact, remediation
- Builds comprehensive exploit list

### Step 3: Intelligent Scoring
- Scores each exploit against AI findings
- Calculates success probability
- Ranks by likelihood to succeed

### Step 4: Correlation
- Links exploits to specific AI vulnerabilities
- Shows which findings match
- Calculates correlation strength

---

## Result Table

| # | Type | Severity | AI Score | Combined | Reason | Status |
|---|------|----------|----------|----------|--------|--------|
| 1 | SQL Injection | Critical | 92% | 0.94 | Matches detected injection | ✓ Correlated |
| 2 | Auth Bypass | High | 85% | 0.88 | Targets weak CSRF | ✓ Correlated |
| 3 | XSS Stored | Medium | 72% | 0.76 | Found weak input validation | ✓ Correlated |

**Green = Correlated with AI findings** (more likely to work)
**Red = Not correlated** (verify before attempting)

---

## Key Metrics

- **Execution Priority** (1-N): Order to attempt exploits
- **AI Score** (0-100%): AI assessment of relevance
- **Combined Score** (0-1): Final ranking metric
- **Correlation**: Number of AI findings matched

---

## Getting Exploit Details

### Get top exploit
```python
top = integration.get_exploit_by_priority(1)
print(f"Attempt: {top.exploit_type}")
print(f"Payload: {top.payload}")
print(f"Success: {top.ai_success_probability:.2%}")
print(f"Reasoning: {top.ai_reasoning}")
```

### Get all ranked exploits
```python
for exp in integration.get_ranked_exploits()[:10]:
    print(f"#{exp.execution_priority}: {exp.exploit_type} ({exp.combined_score:.2f})")
```

### Get exploits for specific vulnerability
```python
sqli = integration.get_findings_for_vulnerability('SQL Injection')
for exp in sqli:
    print(f"{exp.exploit_type}: {exp.payload[:50]}...")
```

---

## Export Reports

### JSON Report
```python
json_report = integration.export_results('json')
with open('report.json', 'w') as f:
    f.write(json_report)
```

Contains:
- All exploit details + scoring
- AI findings
- Correlations
- Target context
- Timestamps

### Text Report
```python
text_report = integration.export_results('text')
print(text_report)
```

Contains:
- Executive summary
- Target intelligence
- Ranked exploits (top 10)
- Correlation analysis
- Recommendations

---

## Understanding Scores

### AI Success Probability
- **90-100%**: Very likely to succeed on this target
- **70-89%**: Likely to succeed, may need tuning
- **50-69%**: Possible, but uncertain
- **<50%**: Unlikely, low priority

### Combined Score
- **0.90-1.0**: Critical - attempt first
- **0.80-0.89**: High - likely to work
- **0.70-0.79**: Medium - worth trying
- **0.60-0.69**: Low - lower priority
- **<0.60**: Very low - last resort

### Execution Priority
- **#1-3**: Most likely to succeed
- **#4-10**: Good candidates
- **#11+**: Lower probability

---

## Progress Messages

You'll see real-time updates:

```
📊 Running AI vulnerability analysis...
📊 AI found 12 vulnerabilities
🔍 Using unified exploit knowledge...
🔍 Unified seeker found 45 exploits
⚡ Scoring exploits against target context...
  • Checked exploit_1 vs SQL Injection (95% match)
  • Checked exploit_2 vs Auth Bypass (88% match)
  • ...
🔗 Correlating findings across systems...
  • Linked 8 exploit-vulnerability pairs
  • Found 12 strong correlations
✅ Analysis complete: 45 exploits + 12 AI findings + 8 correlations
```

---

## Troubleshooting

### "No results found"
- Target may not have vulnerabilities
- Try a known vulnerable target first (DVWA, WebGoat)
- Check network connectivity

### "AI Tester not initialized"
- Ensure AIVulnerabilityTester installed
- Check dependencies: `pip install openai mistralai`
- May need API key for external AI

### "No correlated findings"
- AI findings and exploits don't match this target
- Run separate analyses to see what's detected
- Different targets will have different correlations

### "Analysis is slow"
- First run may be slower (loading models)
- Subsequent runs are faster
- Large targets take longer (more checks)
- Can run individually if time-critical

---

## Example Workflow

```python
# 1. Run analysis
result = integration.analyze_and_score("https://dvwa.local")

# 2. Check summary
print(result.summary)

# 3. Get top 5 exploits
top_exploits = [e for e in result.seek_findings if e.execution_priority <= 5]

# 4. Print details
for exp in top_exploits:
    print(f"Priority {exp.execution_priority}: {exp.exploit_type}")
    print(f"  Payload: {exp.payload[:80]}...")
    print(f"  Why it applies: {exp.ai_reasoning}")
    print(f"  Confidence: {exp.ai_success_probability:.2%}")
    print()

# 5. Get exploits for first AI vulnerability
first_vuln = result.ai_findings[0]['id']
related = integration.get_findings_for_vulnerability(first_vuln)
print(f"\nExploits for {first_vuln}:")
for exp in related:
    print(f"  - {exp.exploit_type}")

# 6. Export for sharing
with open('report.json', 'w') as f:
    f.write(integration.export_results('json'))
```

---

## Files

- **SeekAIIntegration.py** - Core integration engine
- **exploit_seek_tab.py** - Enhanced UI with unified button
- **SEEKAI_INTEGRATION_GUIDE.md** - Full documentation
- **SEEKAI_QUICKSTART.md** - This file

---

## What's New vs Old

| Feature | Before | After |
|---------|--------|-------|
| Exploit seeking | Yes, but no AI scoring | Ranked by AI relevance |
| AI testing | Yes, but no exploit correlation | Linked to exploits |
| Prioritization | Manual | Automatic (AI-based) |
| Reporting | Separate reports | Unified report |
| Time | 2+ button clicks | 1 click |

---

## Tips

1. **Start with known targets** - Test on DVWA/WebGoat first
2. **Check correlations** - Green highlights show AI-confirmed findings
3. **Read AI reasoning** - Explains why exploit applies
4. **Verify success rates** - AI scoring not 100% accurate
5. **Export reports** - Share findings with team
6. **Review weak points** - AI identifies target's specific issues

---

## Next: Execution

Once you have ranked exploits, you can:
1. Manually attempt them in priority order
2. Use exploit framework (Metasploit, etc.)
3. Generate custom payloads
4. Integrate with automated runners

---

Ready to use? **Click the `🔗 UNIFIED ANALYSIS` button and wait for results.**
