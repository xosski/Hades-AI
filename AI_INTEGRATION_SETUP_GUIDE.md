# Full AI Integration Setup Guide

## Overview
This guide covers the complete AI integration for Payload Generator and Exploit Seeker in Hades-AI.

## Installation

### 1. Core Dependencies
```bash
pip install openai anthropic mistralai groq requests
```

### 2. Optional Dependencies (for specific providers)
```bash
# For Ollama support
pip install requests

# For advanced features
pip install numpy pandas
```

## Configuration

### Method 1: Environment Variables
```bash
# OpenAI
export OPENAI_API_KEY="sk-your-api-key-here"

# Anthropic
export ANTHROPIC_API_KEY="claude-..."

# Mistral
export MISTRAL_API_KEY="your-key-here"

# Groq
export GROQ_API_KEY="your-key-here"

# Optional: Ollama
export OLLAMA_BASE_URL="http://localhost:11434"
```

### Method 2: .hades_config.json
```json
{
  "ai": {
    "preferred_provider": "openai",
    "fallback_provider": "fallback",
    "max_payloads_per_request": 10,
    "temperature": 0.7,
    "request_timeout": 30,
    "retry_attempts": 3
  },
  "exploit_seeker": {
    "use_ai_analysis": true,
    "ai_analysis_threshold": 0.5,
    "enable_payload_recommendations": true
  }
}
```

## Available Providers

### 1. OpenAI GPT-3.5-turbo
**Best for:** Production use, high quality
- Speed: 2-5 seconds
- Cost: ~$0.002 per 1K tokens
- Requires: API key
```bash
export OPENAI_API_KEY="sk-..."
```

### 2. Anthropic Claude
**Best for:** Complex analysis, nuanced responses
- Speed: 2-5 seconds
- Cost: $0.008 per 1M input tokens
- Requires: API key
```bash
export ANTHROPIC_API_KEY="claude-..."
```

### 3. Mistral AI
**Best for:** Cost-effective, good quality
- Speed: 1-3 seconds
- Cost: Free for first 1M tokens
- Requires: API key
```bash
export MISTRAL_API_KEY="..."
```

### 4. Groq (Mixtral-8x7b)
**Best for:** Real-time analysis, speed
- Speed: 200-500ms (very fast)
- Cost: Free
- Requires: API key
```bash
export GROQ_API_KEY="..."
```

### 5. Ollama (Local)
**Best for:** Privacy, offline use
- Speed: Variable (depends on hardware)
- Cost: Free
- Setup:
```bash
# Install Ollama from https://ollama.ai
ollama pull mistral  # or another model
ollama serve  # Runs on http://localhost:11434
```

### 6. Fallback (No API)
**Best for:** Testing, no API keys
- Speed: Instant
- Cost: Free
- Quality: Rule-based (lower)
- Auto-enabled if no other providers available

## Usage

### Payload Generator with AI

#### Basic Usage
```python
from payload_generator_gui import PayloadGeneratorTab

# In GUI
payload_tab = PayloadGeneratorTab()
# Select file → Click "🤖 AI Enhanced" button
```

#### Programmatic Usage
```python
from payload_exploit_ai_integration import PayloadExploitAIBridge, PayloadRequest, LLMProvider

# Initialize bridge
ai_bridge = PayloadExploitAIBridge()

# Create payload request
request = PayloadRequest(
    file_type="php",
    vulnerability_type="SQL Injection",
    target_info={
        'file': '/var/www/html/app.php',
        'database': 'MySQL'
    },
    count=5
)

# Generate payloads
payloads = ai_bridge.payload_generator.generate_payloads(request)

# Payloads include:
# - payload: The actual injection code
# - description: What it does
# - risk_level: Critical/High/Medium/Low
# - ai_reasoning: Why this works
# - execution_method: How to execute
# - detection_evasion: Techniques to evade detection
```

### Exploit Seeker with AI

#### Enable AI Analysis
```python
from exploit_seek_tab import ExploitSeekTab

# In GUI, AI is automatically enabled if available
seek_tab = ExploitSeekTab()

# AI features:
# 1. Analyzes discovered exploits
# 2. Scores effectiveness
# 3. Recommends payloads
# 4. Assesses detection risk
```

#### Programmatic Usage
```python
from exploit_seek_tab import AIExploitAnalysisWorker

# Analyze discovered exploits
worker = AIExploitAnalysisWorker(
    exploits=discovered_exploits,
    target_url="https://example.com",
    ai_bridge=ai_bridge
)
worker.finished.connect(handle_analysis)
worker.start()
```

### Check Active Provider
```python
ai_bridge = PayloadExploitAIBridge()

# Get active provider
active = ai_bridge.get_active_provider()
print(f"Using: {active}")

# List available providers
available = ai_bridge.get_available_providers()
print(f"Available: {available}")
```

## Features

### Payload Generation
✅ Multi-LLM support
✅ Context-aware payloads
✅ Risk assessment
✅ Detection evasion suggestions
✅ Fallback rule-based generation

### Exploit Analysis
✅ Effectiveness scoring (0-1)
✅ Detection probability (0-1)
✅ Exploitation difficulty assessment
✅ Impact scoring
✅ Prerequisites extraction
✅ Payload recommendations

### Integration
✅ Unified AI bridge
✅ Automatic provider detection
✅ Graceful fallback
✅ Concurrent processing
✅ Real-time progress updates

## Example Workflows

### Workflow 1: Generate and Score Payloads
```python
from payload_exploit_ai_integration import PayloadExploitAIBridge

ai = PayloadExploitAIBridge()

# Generate payloads for SQL injection
payloads = ai.generate_targeted_payloads(
    exploit_type="SQL Injection",
    file_type="php",
    target_info={'database': 'MySQL'},
    count=5
)

# Score and rank them
scored = ai.score_and_rank_payloads(
    payloads,
    target_context={'app': 'vulnerable_app.php'}
)

for payload in scored:
    print(f"{payload['effectiveness']:.1%} effective: {payload['payload'][:50]}")
```

### Workflow 2: Analyze Discovered Exploits
```python
from exploit_seek_tab import AIExploitAnalysisWorker

exploits = [
    {'id': 1, 'type': 'SQL Injection', 'payload': "' OR '1'='1'},
    {'id': 2, 'type': 'XSS', 'payload': "<script>alert(1)</script>"}
]

worker = AIExploitAnalysisWorker(
    exploits=exploits,
    target_url="https://example.com",
    ai_bridge=ai_bridge
)

# Results include effectiveness scores, difficulty, impact, etc.
```

### Workflow 3: Complete Security Assessment
```python
ai = PayloadExploitAIBridge()

# 1. Discover exploits
exploits = exploit_seeker.seek_all_exploits(target)

# 2. Analyze with AI
analyzed = ai.exploit_analyzer.analyze_exploit(exploit)

# 3. Generate tailored payloads
payloads = ai.generate_targeted_payloads(
    exploit['type'],
    exploit['file_type'],
    target_info
)

# 4. Score and rank
ranked = ai.score_and_rank_payloads(payloads, target_context)

# 5. Generate report
report = {
    'target': target,
    'exploits': analyzed,
    'recommended_payloads': ranked[:3],
    'risk_assessment': scored
}
```

## Performance Notes

### Payload Generation Speed
- OpenAI: 2-5 seconds
- Anthropic: 2-5 seconds
- Mistral: 1-3 seconds
- Groq: 200-500ms
- Ollama: Variable (0.5-5s)
- Fallback: <100ms

### Exploit Analysis Speed
- Per exploit: 1-3 seconds
- 10 exploits: 10-30 seconds
- Parallelizable for speed improvement

### Cost Estimation (per 1000 payloads)
- OpenAI: ~$2-5
- Anthropic: ~$0.01
- Mistral: Free (first 1M tokens)
- Groq: Free
- Ollama: Free
- Fallback: Free

## Troubleshooting

### Issue: "AI integration not available"
**Solution:** Install dependencies
```bash
pip install openai anthropic mistralai groq requests
```

### Issue: "API key not found"
**Solution:** Set environment variables
```bash
export OPENAI_API_KEY="sk-..."
```

### Issue: "Connection timeout"
**Solution:** Check provider availability
```python
ai_bridge = PayloadExploitAIBridge()
print(ai_bridge.get_available_providers())
```

### Issue: "Fallback mode only"
**Solution:** No API keys configured, but system still works!
```python
# Fallback generates payloads based on rules
# Good for testing, limited quality
```

## Testing

### Run Test Suite
```bash
python test_payload_exploit_ai_integration.py
```

### Test Individual Components
```python
from payload_exploit_ai_integration import AIPayloadGenerator, LLMProvider

# Test payload generation
gen = AIPayloadGenerator(LLMProvider.OPENAI)
payloads = gen.generate_payloads(request)
assert len(payloads) > 0

# Test analyzer
analyzer = AIExploitAnalyzer()
analysis = analyzer.analyze_exploit(exploit_data)
assert 0 <= analysis.effectiveness_score <= 1
```

## Security Considerations

1. **API Keys**: Never commit API keys to git
2. **Privacy**: Ollama local mode for sensitive data
3. **Rate Limiting**: Groq free tier has rate limits
4. **Timeout**: Set appropriate timeouts for production
5. **Fallback**: Always have fallback enabled

## Integration with Hades-AI

The AI integration is automatically loaded when:
1. Payload Generator tab initializes
2. Exploit Seeker tab initializes
3. API keys are available

Current status:
✅ Payload Generator - Full integration
✅ Exploit Seeker - Full integration
✅ AI Bridge - Complete
✅ Multi-provider support - Complete

## Next Steps

1. Configure preferred LLM provider
2. Set API keys in environment
3. Enable AI features in HadesAI UI
4. Test with sample targets
5. Monitor performance and costs

## Support

For issues or questions:
1. Check logs: `~/.hades/logs/`
2. Run diagnostics: `python -m hades.diagnostics`
3. Test provider availability: `ai_bridge.get_available_providers()`

---

**Version**: 1.0
**Last Updated**: 2024
**Status**: Production Ready
