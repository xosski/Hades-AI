# HadesAI Unified Systems - START HERE

**Status:** All systems operational and tested ✓  
**Date:** March 15, 2026

---

## What's New?

Three powerful systems have been added to HadesAI:

### 1. Unified LLM Router
Intelligently routes requests across multiple AI providers (OpenAI, Mistral, Azure, Ollama)
- Automatic provider selection
- Caching for speed
- Fallback to rule-based engine (always works)

### 2. Enhanced Defense System  
Real-time threat detection and automated response
- Detects SQL injection, XSS, RCE, and more
- Automatically blocks threats
- Complete audit trail

### 3. Web Learning Integration
Learn from web content while securing it
- Extract CVEs, exploits, techniques
- Scan for threats during learning
- AI-enhanced analysis
- Background worker support

---

## 2-Minute Start

### Step 1: Verify Everything Works
```bash
python test_unified_systems.py
```
**Expected:** Shows "ALL SYSTEMS OPERATIONAL"

### Step 2: Try It Out
```python
# Use the LLM router
from unified_llm_router import UnifiedLLMRouter, LLMRequest
router = UnifiedLLMRouter()
response = router.route_request(LLMRequest(prompt="What is XSS?"))
print(response.content)

# Use the defense system
from enhanced_defense_system import EnhancedDefenseSystem
defense = EnhancedDefenseSystem()
event = defense.scan_content("' OR '1'='1")
if event: print(f"Threat detected: {event.threat_type}")

# Use web learning
from web_learning_integration import create_integrated_system
integrator = create_integrated_system()
context = integrator.learn_and_defend_webpage("https://example.com", content)
print(f"Learned {context.learned_knowledge['total_items_learned']} items")
```

### Step 3: Read the Docs
- **Quick Start:** `QUICK_START_UNIFIED_SYSTEMS.md`
- **Complete Guide:** `UNIFIED_SYSTEMS_INTEGRATION.md`
- **Summary:** `ENHANCEMENT_SUMMARY.txt`

---

## Files Overview

### Core Systems (Ready to Use)
| File | Purpose | Lines |
|------|---------|-------|
| `unified_llm_router.py` | LLM routing engine | 630 |
| `enhanced_defense_system.py` | Threat detection | 720 |
| `web_learning_integration.py` | Web learning | 510 |

### Testing & Docs
| File | Purpose |
|------|---------|
| `test_unified_systems.py` | Verify everything works |
| `QUICK_START_UNIFIED_SYSTEMS.md` | Quick start guide |
| `UNIFIED_SYSTEMS_INTEGRATION.md` | Complete reference |
| `SYSTEM_ENHANCEMENTS_COMPLETE.md` | Technical details |
| `ENHANCEMENT_SUMMARY.txt` | Summary of changes |

---

## Test Results

```
✓ LLM Router:         PASS (routing works, caching works)
✓ Defense System:     PASS (SQL injection detected, XSS detected)
✓ Web Learning:       PASS (learned 9 items, threat detected)
✓ Integration:        PASS (complete workflow tested)
```

All systems are operational and ready to use.

---

## Common Tasks

### Task 1: Analyze a Vulnerability
```python
from unified_llm_router import UnifiedLLMRouter, LLMRequest

router = UnifiedLLMRouter()
request = LLMRequest(prompt=cve_text)
response = router.route_request(request)
print(response.content)
```

### Task 2: Detect Threats
```python
from enhanced_defense_system import EnhancedDefenseSystem

defense = EnhancedDefenseSystem()
event = defense.scan_content(user_input)
if event:
    print(f"Threat: {event.threat_type}")
    print(f"Severity: {event.threat_level.name}")
```

### Task 3: Learn from Web
```python
from web_learning_integration import create_integrated_system

integrator = create_integrated_system()
context = integrator.learn_and_defend_webpage(url, content)
print(f"Learned: {context.learned_knowledge['total_items_learned']}")
if context.defense_scan_results:
    print(f"Threats: {context.defense_scan_results['threat_type']}")
```

---

## Configuration (Optional)

### Set API Keys for Better Performance
```bash
# Linux/Mac
export MISTRAL_API_KEY=your_key_here
export OPENAI_API_KEY=your_key_here

# Windows
set MISTRAL_API_KEY=your_key_here
set OPENAI_API_KEY=your_key_here
```

Or edit `.hades_config.json`:
```json
{
  "mistral_api_key": "your_key",
  "openai_api_key": "your_key",
  "ai_provider": "mistral"
}
```

**Note:** Works without keys using fallback provider.

---

## Documentation Roadmap

1. **First Time?** 
   - Read this file (2 min)
   - Run `test_unified_systems.py` (2 min)
   - Read `QUICK_START_UNIFIED_SYSTEMS.md` (10 min)

2. **Want to Use?**
   - Check examples in `QUICK_START_UNIFIED_SYSTEMS.md`
   - Review API in main Python files
   - Run tests and study output

3. **Need Details?**
   - Read `UNIFIED_SYSTEMS_INTEGRATION.md` (complete reference)
   - Review database schemas
   - Check error handling patterns

4. **Deploying?**
   - Follow deployment checklist in `ENHANCEMENT_SUMMARY.txt`
   - Configure environment variables
   - Set up monitoring

---

## Key Features

### Unified LLM Router
- ✓ Multi-provider support
- ✓ Intelligent routing
- ✓ Request caching
- ✓ Performance tracking
- ✓ Always-available fallback

### Enhanced Defense System
- ✓ Threat detection (SQL, XSS, RCE, etc.)
- ✓ Anomaly detection
- ✓ Automated response
- ✓ Complete audit trail
- ✓ Configurable rules

### Web Learning Integration
- ✓ Knowledge extraction
- ✓ Security scanning
- ✓ AI enhancement
- ✓ Background processing
- ✓ Persistent storage

---

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| LLM routing | 0-2000ms | 0ms if cached |
| Threat detection | <100ms | Fast signature matching |
| Web learning | 2-5sec | Per URL |
| Defense response | <10ms | Automated execution |

---

## Troubleshooting

**Q: Providers showing as unavailable**  
A: System uses fallback provider (always works). Set API keys to enable premium providers.

**Q: Getting too many threat alerts**  
A: Adjust defense rule thresholds in `enhanced_defense_system.py`

**Q: Learning is slow**  
A: Check network connectivity, or use local Ollama for faster LLM

**Q: Out of memory**  
A: Clear old databases: `rm *.db` (safe to delete)

More help: See `UNIFIED_SYSTEMS_INTEGRATION.md` troubleshooting section.

---

## Next Steps

1. ✓ Run `test_unified_systems.py`
2. ✓ Read `QUICK_START_UNIFIED_SYSTEMS.md`
3. ✓ Try the examples
4. ✓ Integrate into your workflows
5. ✓ Configure preferences

---

## Integration Points

Can be used with:
- ✓ Exploit generator
- ✓ Network monitor
- ✓ Web scanner
- ✓ Penetration testing suite
- ✓ Autonomous agents
- ✓ GUI tabs

---

## Database Files

Automatically created:
- `llm_cache.db` - Cached LLM responses
- `defense_system.db` - Threat detection database
- `learning_integration.db` - Learning results
- `hades_knowledge.db` - Web knowledge (existing)

Safe to delete anytime to reset.

---

## Support

**Questions?**
1. Check `QUICK_START_UNIFIED_SYSTEMS.md`
2. Review `UNIFIED_SYSTEMS_INTEGRATION.md`
3. Read docstrings in Python files
4. Check test file for examples

**Issues?**
1. Run `test_unified_systems.py` to diagnose
2. Check database files for logs
3. Verify configuration in `.hades_config.json`
4. Check environment variables

---

## Summary

HadesAI now has:

✅ **Intelligent LLM Routing** - Best AI provider for the job  
✅ **Advanced Defense System** - Real-time threat detection  
✅ **Web Learning Integration** - Learn while you secure  

All tested, documented, and ready to use!

---

## What Now?

1. **Run the test:** `python test_unified_systems.py`
2. **Read the guide:** `QUICK_START_UNIFIED_SYSTEMS.md`
3. **Try it out:** Copy examples and experiment
4. **Integrate:** Add to your workflows
5. **Deploy:** Follow deployment checklist

---

**Status: READY FOR USE** ✓

All systems are operational and tested. You're good to go!

For detailed information, see the other documentation files:
- `QUICK_START_UNIFIED_SYSTEMS.md` - Usage examples
- `UNIFIED_SYSTEMS_INTEGRATION.md` - Complete reference
- `ENHANCEMENT_SUMMARY.txt` - Technical summary

Good luck with HadesAI!
