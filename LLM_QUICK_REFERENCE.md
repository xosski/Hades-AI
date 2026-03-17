# Hades AI LLM - Quick Reference Card

## 🚀 Get Started in 60 Seconds

```bash
# 1. Install dependencies
pip install -r requirements_llm.txt

# 2. Run setup (creates .env, tests everything)
python llm_quickstart.py

# 3. Start chatting
python llm_cli.py              # CLI (recommended to start)
python llm_web_ui.py           # Or web (localhost:5000)
```

## 📱 Three Ways to Use

### 1. Web UI (Browser)
```bash
python llm_web_ui.py
# Visit http://localhost:5000
```
**Best for:** Daily use, comfortable interface

### 2. CLI (Terminal)
```bash
python llm_cli.py
```
**Best for:** Quick testing, automation

### 3. Python API
```python
from llm_conversation_core import ConversationManager
manager = ConversationManager()
conv = manager.create_conversation("Chat")
response = manager.send_message("Hello", conv_id=conv.id)
```
**Best for:** Integration, custom code

## 🎮 CLI Commands (Type these)

| Command | What it does |
|---------|-------------|
| `new [title]` | Create conversation |
| `list` | Show all conversations |
| `load <id>` | Open conversation |
| `clear` | Delete all messages |
| `history` | Show messages |
| `save` | Save as text |
| `export` | Save as JSON |
| `provider <name>` | Switch LLM |
| `temp <0-1>` | Set creativity |
| `tokens <num>` | Response length |
| `help` | Show all commands |
| `quit` | Exit |
| Or just type message | Send to LLM |

## 🤖 Available LLM Providers

| Provider | Cost | Speed | Setup |
|----------|------|-------|-------|
| **Ollama** | Free | ⚡ | Install & run |
| **OpenAI** | $$ | ⚡⚡ | Add API key |
| **Mistral** | $$ | ⚡⚡ | Add API key |
| **Azure** | $$$ | ⚡⚡⚡ | Enterprise setup |
| **Fallback** | Free | Instant | Built-in |

## 🔑 Setup API Keys

### For Free (Recommended)
```bash
# Install Ollama from https://ollama.ai
ollama pull llama2
ollama serve
# In another terminal: python llm_cli.py
```

### For Cloud APIs
Create `.env` file:
```env
OPENAI_API_KEY=sk-...
MISTRAL_API_KEY=...
```

## 🔄 Switch Providers (in CLI)
```
> provider openai          # Switch to OpenAI
> provider mistral         # Switch to Mistral
> provider ollama          # Switch to Ollama (local)
> provider fallback        # Switch to fallback
> provider azure           # Switch to Azure
```

## 📁 Files You Need

| File | Purpose |
|------|---------|
| `llm_conversation_core.py` | Engine (required) |
| `llm_cli.py` | CLI (optional) |
| `llm_web_ui.py` | Web UI (optional) |
| `llm_quickstart.py` | Setup (one-time) |
| `conversations.db` | Database (auto-created) |
| `.env` | API keys (create manually or auto) |

## 📚 Documentation

| File | What it covers |
|------|---|
| `LLM_README.md` | Quick overview |
| `LLM_INTEGRATION_GUIDE.md` | Full technical details |
| `llm_examples.py` | 10 working examples |
| `LLM_INDEX.md` | Complete map |

## 🐍 Python API Quick Examples

```python
from llm_conversation_core import ConversationManager

# Initialize
manager = ConversationManager()

# Create conversation
conv = manager.create_conversation(
    title="My Chat",
    provider="openai",
    model="gpt-3.5-turbo"
)

# Send message (get full response)
response = manager.send_message("Hello!", conv_id=conv.id)
print(response)

# Send message (stream chunks)
for chunk in manager.send_message(
    "Write a poem",
    conv_id=conv.id,
    use_streaming=True
):
    print(chunk, end="", flush=True)

# Load conversation
conv = manager.load_conversation(conv_id)

# List conversations
for conv in manager.list_conversations(limit=10):
    print(conv['title'])

# Switch provider
manager.switch_provider(conv_id, "mistral", "mistral-tiny")

# Delete conversation
manager.delete_conversation(conv_id)
```

## ⚙️ Conversation Settings

```python
# Create with custom settings
conv = manager.create_conversation(
    title="My Chat",
    provider="openai",
    model="gpt-3.5-turbo",
    temperature=0.7,              # 0=focused, 1=creative
    max_tokens=2000,              # Max response length
    system_prompt="You are...",   # Instructions
)
```

## 🧠 System Prompts (Examples)

### Security Expert
```python
system_prompt="""You are an expert security researcher.
For vulnerabilities: analyze, explain impact, suggest fixes."""
```

### Code Reviewer
```python
system_prompt="""You are an expert code reviewer.
Analyze: performance, security, best practices."""
```

### Teacher
```python
system_prompt="""Explain concepts simply with examples.
Use analogies for clarity."""
```

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| "No provider available" | Run `ollama serve` or add API keys |
| "API key invalid" | Check .env file, get new key |
| "Database locked" | Close other CLI/Web instances |
| "Slow responses" | Use local Ollama instead of cloud |
| "Connection refused" | Check Ollama is running or internet connection |

## 📊 Default Settings

| Setting | Default | Range |
|---------|---------|-------|
| Provider | openai | (5 options) |
| Model | gpt-3.5-turbo | Provider-specific |
| Temperature | 0.7 | 0.0 - 1.0 |
| Max tokens | 2000 | 1 - 128000 |
| System prompt | (none) | Any text |

## 🌐 Web UI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+Enter` | Send message |
| `Enter` (new line) | Add newline |
| Auto-expand | Textarea grows with content |

## 🔐 Security Quick Notes

- API keys in `.env` (never commit)
- Database is local SQLite
- No data sent externally with Ollama
- All operations are thread-safe

## 💻 Integration with Hades AI

```python
# In your Hades module:
from llm_conversation_core import ConversationManager

class HadesModule:
    def __init__(self):
        self.llm = ConversationManager()
        self.conv = self.llm.create_conversation("Analysis")
    
    def analyze(self, data):
        return self.llm.send_message(
            f"Analyze: {data}",
            conv_id=self.conv.id
        )
```

## 🎯 Common Tasks

### Chat with local AI (Free)
```bash
# Terminal 1
ollama serve

# Terminal 2
python llm_cli.py
> new "Chat"
> provider ollama
> What is AI?
```

### Use OpenAI GPT
```python
manager.create_conversation(
    title="GPT Chat",
    provider="openai"
)
```

### Batch analyze items
```python
for item in items:
    response = manager.send_message(
        f"Analyze: {item}",
        conv_id=conv.id
    )
    print(response)
```

### Stream long responses
```python
for chunk in manager.send_message(prompt, conv_id=conv.id, use_streaming=True):
    print(chunk, end="", flush=True)
```

## 📱 Port Numbers

| Service | Port | Command |
|---------|------|---------|
| Web UI | 5000 | `python llm_web_ui.py` |
| Ollama | 11434 | `ollama serve` |
| OpenAI | (cloud) | (needs API key) |

## 🎓 Learning Path

1. Read: `LLM_README.md` (5 min)
2. Run: `python llm_quickstart.py` (2 min)
3. Try: `python llm_cli.py` (5 min)
4. Study: `llm_examples.py` (10 min)
5. Integrate: Add to your modules (varies)

## ✅ Checklist to Get Started

- [ ] Run `pip install -r requirements_llm.txt`
- [ ] Run `python llm_quickstart.py`
- [ ] Choose interface (CLI or Web)
- [ ] Create first conversation
- [ ] Send a message
- [ ] Try different providers
- [ ] Read LLM_INTEGRATION_GUIDE.md
- [ ] Integrate with your code

## 💬 Sample Prompts to Try

- "What is cryptography?"
- "Explain JWT tokens"
- "Find vulnerabilities in: [code]"
- "Write a Python script for: [task]"
- "Compare these approaches: [code1] vs [code2]"
- "Explain this error: [error message]"
- "Best practices for: [topic]"

## 🔗 Useful Links

- **Ollama:** https://ollama.ai
- **OpenAI:** https://platform.openai.com
- **Mistral:** https://www.mistral.ai
- **Azure:** https://azure.microsoft.com/openai
- **Docs:** See LLM_INTEGRATION_GUIDE.md

## 📞 Quick Support

**Problem: Can't get it working?**

1. Run `python llm_quickstart.py` (auto-setup)
2. Check `LLM_README.md` troubleshooting
3. Look at `llm_examples.py`
4. Read `LLM_INTEGRATION_GUIDE.md`

**Problem: Need more details?**

- See `LLM_INTEGRATION_GUIDE.md` (400+ lines of docs)
- Check `llm_examples.py` (10 examples)
- See `LLM_INDEX.md` (complete map)

---

## 🎬 TL;DR Start Now

```bash
pip install -r requirements_llm.txt && python llm_cli.py
```

Type: `new "My Chat"` → `What is AI?` → Enjoy!

**That's it. You're ready to use Hades AI LLM system.**
