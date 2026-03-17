# LLM Integration Quick Start

## ✓ Integration Status: COMPLETE

The LLM system is **fully integrated** and ready to use in HadesAI.

---

## Quick Setup (2 minutes)

### 1. Install Dependencies
```bash
pip install openai mistralai ollama python-dotenv
```

### 2. Add API Keys (Optional)
Create a `.env` file in HadesAI directory:
```env
OPENAI_API_KEY=sk-your-key
MISTRAL_API_KEY=your-mistral-key
AZURE_OPENAI_API_KEY=your-azure-key
```

### 3. Run HadesAI
```bash
python HadesAI.py
```

### 4. Use LLM in Chat Tab
- Go to "💬 AI Chat" tab
- Select LLM provider from dropdown
- Type your message
- Get response from selected LLM

---

## Available Providers

| Provider | Status | Setup | Cost |
|----------|--------|-------|------|
| **OpenAI** | Ready | API key | Paid |
| **Mistral** | Ready | API key | Paid |
| **Ollama** | Ready | Local install | Free |
| **Azure OpenAI** | Ready | Credentials | Paid |
| **Fallback** | Always Ready | None | Free |

---

## Testing Integration

Run the test suite:
```bash
python test_llm_integration.py
```

Expected output:
```
✓ PASS: LLM Core Import
✓ PASS: ConversationManager
✓ PASS: HadesAI Integration
✓ PASS: LLM Chat
✓ PASS: Conversation Persistence

Total: 5/5 tests passed
✓ All tests passed! LLM integration is working correctly.
```

---

## Usage Examples

### Basic Chat
```python
from HadesAI import HadesAI

ai = HadesAI()

# Chat using selected provider
response = ai.llm_chat("Explain SQL injection")
print(response)
```

### With Custom Provider
```python
response = ai.llm_chat(
    "What is XSS?",
    provider="openai",
    model="gpt-4"
)
```

### With Custom System Prompt
```python
response = ai.llm_chat(
    "Analyze this code: SELECT * FROM users WHERE id = ' + input",
    provider="mistral",
    system_prompt="You are a pentesting expert. Analyze the code for vulnerabilities."
)
```

### With Streaming (Advanced)
```python
for chunk in ai.llm_chat(
    "Explain authentication",
    use_streaming=True
):
    print(chunk, end='', flush=True)
```

### Get Available Providers
```python
providers = ai.get_available_llm_providers()
print(f"Available: {providers}")
# Output: Available: ['openai', 'ollama', 'fallback']
```

---

## In the GUI

### Chat Tab Features
1. **LLM Provider Dropdown** - Select which LLM to use
2. **Provider Info** - Shows available providers
3. **Chat Input** - Type your message
4. **Smart Fallback** - Automatically uses personality system if LLM fails

### Provider Selection
```
🤖 LLM Provider: [Dropdown ▼]
Available: openai, ollama, fallback
```

---

## Troubleshooting

### Provider Not Available?
Check what's installed:
```python
from HadesAI import HadesAI
ai = HadesAI()
print(ai.get_available_llm_providers())
```

### API Key Errors?
1. Verify `.env` file exists
2. Check API key is valid
3. Test manually:
```bash
echo $OPENAI_API_KEY  # Linux/Mac
echo %OPENAI_API_KEY%  # Windows
```

### Slow Responses?
- Use local Ollama instead of cloud providers
- Cloud providers take 1-5 seconds
- Ollama is faster (1-3 seconds)

### No LLM Available?
- Fallback provider always works
- Uses rule-based responses
- Automatic fallback if primary provider fails

---

## What Changed

### HadesAI.py Modifications
1. ✅ Added LLM import (line 57-65)
2. ✅ Initialize LLM manager (line 2910-2920)
3. ✅ Added `llm_chat()` method (line 3233-3284)
4. ✅ Enhanced chat GUI (line 4313-4365)
5. ✅ Updated chat logic (line 7428-7467)

### New Files
- `test_llm_integration.py` - Test suite
- `LLM_INTEGRATION_VERIFICATION.md` - Full docs

### Existing Files (Unchanged)
- `llm_conversation_core.py` - Core system
- `LLM_INTEGRATION_GUIDE.md` - Detailed guide

---

## Key Features

✅ **Multi-Provider** - OpenAI, Mistral, Ollama, Azure, Fallback
✅ **Automatic Fallback** - Never crashes, always has response
✅ **Conversation Persistence** - All chats saved to database
✅ **Provider Switching** - Change LLM without restarting
✅ **Streaming Support** - Real-time token-by-token responses
✅ **Custom Prompts** - System prompt configuration
✅ **Full Integration** - Works seamlessly with existing features

---

## Next: Advanced Usage

See `LLM_INTEGRATION_GUIDE.md` for:
- Detailed architecture
- All available methods
- Advanced streaming
- Conversation management
- Performance tuning

---

## Support

**Issue?** Run the test suite first:
```bash
python test_llm_integration.py
```

**Questions?** Check these docs:
- `LLM_INTEGRATION_GUIDE.md` - Comprehensive guide
- `llm_conversation_core.py` - Source code docs
- `test_llm_integration.py` - Working examples

---

## Status Summary

```
✓ LLM Core imported correctly
✓ ConversationManager initialized in HadesAI
✓ Multiple providers configured and available
✓ GUI integration complete with provider selector
✓ Chat logic updated to use LLM
✓ Fallback system working
✓ Database persistence active
✓ All tests passing
✓ Ready for production use
```

**You can now use advanced LLMs in HadesAI!** 🚀

