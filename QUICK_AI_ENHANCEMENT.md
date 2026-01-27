# Quick AI Enhancement - 15-Minute Setup

If you want better AI responses **right now** without modifying code, follow these steps:

---

## Step 1: Configure an AI Provider (5 minutes)

### For OpenAI (Recommended):
1. Open **HadesAI** → **Self-Improvement Tab**
2. Select **"OpenAI (GPT)"** from Provider dropdown
3. Enter your **OpenAI API Key** in the "API Key" field
   - Get from: https://platform.openai.com/api-keys
4. Click **"Test"** to verify connection
5. Click **"Save"** to persist

### For Free Local AI (Ollama):
1. Download Ollama: https://ollama.ai
2. In HadesAI → **Self-Improvement Tab**
3. Select **"Ollama (Local - FREE)"**
4. Choose model: **llama3.2** (fast, good quality)
5. Click **"🔄 Refresh"** to load models
6. No API key needed!

### For Mistral AI:
1. Get free API key: https://console.mistral.ai
2. In HadesAI → **Self-Improvement Tab**
3. Select **"Mistral AI"**
4. Enter API key
5. Click **"Test"** and **"Save"**

---

## Step 2: Test AI in Chat (3 minutes)

1. Go to **Chat Tab**
2. Try these commands:

### Test 1: Complex Question
```
Explain how SQL injection works and what are the main defenses?
```
**Expected**: AI provides detailed, sophisticated response (not just pre-programmed text)

### Test 2: Security Analysis
```
What are the top 5 OWASP vulnerabilities I should know about?
```
**Expected**: AI lists and explains each one

### Test 3: Code Security
```
Is this code vulnerable to injection attacks? [paste code]
```
**Expected**: AI analyzes code for security issues

### Test 4: Vulnerability Query
```
CVE-2024-1086
```
**Expected**: AI provides details about the CVE

---

## Step 3: Boost Response Quality (7 minutes)

### Option A: Use More Detailed Queries
Instead of:
```
scan 192.168.1.1
```

Try:
```
I need a comprehensive security assessment of 192.168.1.1. Please explain what ports are open, what services are running, and what vulnerabilities they might have.
```
**Result**: AI response is more sophisticated and detailed (>8 word queries trigger AI)

### Option B: Ask Follow-ups
AI remembers context, so ask follow-ups:
```
1. "What's SQL injection?"
2. "Can you give me an example attack?"
3. "How do I prevent it?"
```
**Result**: Each response builds on previous context

### Option C: Enable for Specific Tasks
Current system auto-enables AI for:
- Complex questions (>8 words)
- CVE lookups
- IP reputation checks
- Vulnerability analysis

Just ask naturally and AI will engage when needed.

---

## Current AI Features (Already Enabled!)

✅ **Automatic Activation**
- AI activates for complex questions automatically
- Just type >8 word messages for AI responses

✅ **Context Awareness**
- AI knows about scans, learning, threats
- References your mood and personality

✅ **Multi-Provider**
- Switch providers anytime in Self-Improvement tab
- Local (Ollama), Cloud (OpenAI/Mistral), or Enterprise (Azure)

✅ **Knowledge Integration**
- AI references learned exploits from your database
- Understands security patterns you've discovered

✅ **Personality System**
- AI responds with HADES personality
- Emotional context affects tone

---

## Advanced: Custom System Prompts

If you want AI to respond a specific way, here's the current system prompt (in `_get_gpt_response()` at line 6643):

```python
You are HADES, an AI pentesting assistant. Your personality is {personality}.
Current mood: {mood}
Be concise, technical when needed, and maintain your dark, calculated persona.
You can help with: port scanning, vulnerability assessment, exploit research, and security analysis.
```

The system is designed to use this, but you can enhance it by:
1. Making queries more specific (e.g., "As a security architect, explain...")
2. Asking for specific formats (e.g., "List 5 ways to...")
3. Setting context (e.g., "For a web application test, explain...")

---

## Troubleshooting

### AI Not Responding?

**Check 1: Is provider configured?**
- Go to Self-Improvement tab
- Provider should show checkmark: ✅
- If ❌: Configure API key or install Ollama

**Check 2: Is the question complex enough?**
- AI activates for >8 word messages
- Try: "Explain SQL injection attacks and their impact" (10+ words)
- Short questions use built-in personality responses

**Check 3: Did you test the API key?**
- Click "Test" button in Self-Improvement tab
- You should see green "✅ Connected" message
- If red ❌: Check API key validity

### Responses Too Short?

- **Reason**: Default is max 500 tokens for chat
- **Fix**: Ask follow-up: "Can you elaborate?" or "Give more details"
- AI will expand response in next message

### Getting Same Response Repeatedly?

- **Reason**: Could be hitting API limits or cache
- **Fix**: 
  1. Wait 30 seconds
  2. Try a slightly different phrasing
  3. Restart HadesAI

### Want Faster Responses?

- **Use Ollama** (Local, instant)
  - Download: https://ollama.ai
  - No API key needed
  - Runs on your computer

---

## What Happens Under the Hood

When you send a message in Chat:

```
┌─ Message received
├─ Extract targets (IPs, URLs, domains)
├─ Check for commands (scan, learn, etc.)
├─ Query knowledge base for patterns
├─ Count words: >8 words? Call AI Provider
│  └─ Selected provider (OpenAI, Mistral, Ollama, Azure)
│  └─ Gets system prompt with personality + mood
│  └─ Gets conversation history (last 10 messages)
│  └─ Generates sophisticated response
├─ Allow modules to enhance response
├─ Update personality system
└─ Display response
```

---

## Example Queries for Good Results

### "Help, I need security analysis"
Too vague - uses personality response. Try:

### "I need to assess the security posture of our web application. What should I test for and what tools would you recommend?"
✅ Good - 20 words, specific, triggers AI

---

### "SQL injection"
Too short - uses built-in knowledge. Try:

### "I found potential SQL injection vulnerability in a login form. How can I confirm it and what's the best way to fix it?"
✅ Good - 20 words, specific scenario, triggers AI

---

### "CVE-2024-1086"
Works! AI looks up CVE details

---

### "scan 192.168.1.1"
Short command, executes scan with AI-enhanced summary

---

## One-Click Setup Recommendation

For best experience out of the box:

1. **Download Ollama**: https://ollama.ai (2 min install)
2. **Open HadesAI**, go to Self-Improvement
3. Select "Ollama (Local - FREE)"
4. Choose "llama3.2"
5. Click "Test" - should show ✅
6. Go to Chat and ask any question >8 words
7. Enjoy AI responses!

**No API key, no costs, runs locally, instant responses**

---

## Upgrading to Better Responses

Current behavior:
- Chat tab: Good responses, some AI when needed

To get **better** responses:
- Install our enhancement pack (ENHANCE_CHAT_AI_RESPONSES.md)
- Adds: conversation history, specialized prompts, refined responses
- Time: ~2 hours to implement
- Benefit: Context-aware, specialized analysis per query type

---

## Summary

✅ **AI is already configured and working**
✅ **You need to set an API key (or use Ollama)**
✅ **Longer questions trigger AI automatically**
✅ **Multiple providers supported**
✅ **Can be enhanced further with code changes**

**Current Setup**: Good for general security queries
**With Enhancements**: Excellent for detailed analysis and follow-up discussions

---

## Next Steps

1. **Immediate**: Set up provider in Self-Improvement tab (5 min)
2. **Test**: Try queries in Chat tab (3 min)  
3. **Optimize**: Use more detailed questions (ongoing)
4. **Enhance**: Implement ENHANCE_CHAT_AI_RESPONSES.md if needed (2 hours)

---

**You now have everything needed for sophisticated AI responses in HadesAI!**
