# Hades AI - LLM Conversation System

Complete multi-LLM conversation layer with Web UI, CLI, and Python API.

## Quick Start

```bash
# Install
pip install flask flask-cors openai mistralai ollama python-dotenv

# Setup
python llm_quickstart.py

# Use
python llm_cli.py              # CLI
python llm_web_ui.py           # Web (visit http://localhost:5000)
python llm_examples.py          # Examples
```

## Features

✅ **Multi-Provider Support**
- OpenAI GPT (cloud)
- Mistral AI (cloud)
- Ollama (free, local, no API key)
- Azure OpenAI (enterprise)
- Fallback (always available)

✅ **Real-time Streaming**
- Stream responses token-by-token
- Web, CLI, and Python API support
- Responsive UX

✅ **Conversation Management**
- SQLite persistence
- Export/import JSON
- Full message history
- Metadata support

✅ **Multiple Interfaces**
- 🌐 Web UI (Flask) - responsive chat interface
- 💻 CLI - terminal with color output
- 🔌 Python API - programmatic access
- ⚙️ PyQt GUI integration with Hades

✅ **Flexibility**
- Switch providers anytime
- Control temperature, tokens, system prompts
- Automatic fallback chain
- Thread-safe operations

## Architecture

```
User Interface Layer
├── Web UI (Flask)
├── CLI (Terminal)
└── Python API

Conversation Manager
├── Create/Load/Save conversations
├── Provider routing
├── Fallback handling
└── Persistence (SQLite)

LLM Providers
├── OpenAI
├── Mistral
├── Ollama
├── Azure
└── Fallback

External APIs
├── api.openai.com
├── api.mistral.ai
├── localhost:11434 (Ollama)
└── Azure OpenAI
```

## Files

| File | Purpose |
|------|---------|
| `llm_conversation_core.py` | Core conversation engine |
| `llm_web_ui.py` | Flask web interface |
| `llm_cli.py` | Terminal CLI |
| `llm_quickstart.py` | Setup wizard |
| `llm_examples.py` | Usage examples |
| `LLM_INTEGRATION_GUIDE.md` | Detailed documentation |

## Usage Examples

### Web Interface

```bash
python llm_web_ui.py
# Visit http://localhost:5000
```

Features:
- Real-time chat with streaming
- Conversation history
- Provider/model selection
- Export conversations

### Command-Line Interface

```bash
python llm_cli.py

# Interactive commands:
> new "My Chat"           # Create conversation
> list                    # List all conversations
> help                    # Show commands
> provider openai         # Switch provider
> clear                   # Clear messages
> save chat.txt          # Save to file
> export chat.json       # Export as JSON
> quit                   # Exit
```

### Python API

```python
from llm_conversation_core import ConversationManager

# Initialize
manager = ConversationManager()

# Create conversation
conv = manager.create_conversation(
    title="My Chat",
    provider="openai",
    model="gpt-3.5-turbo",
    system_prompt="You are a helpful assistant"
)

# Send message (blocking)
response = manager.send_message("Hello!", conv_id=conv.id)
print(response)

# Send message (streaming)
for chunk in manager.send_message("Tell me a joke", conv_id=conv.id, use_streaming=True):
    print(chunk, end='', flush=True)

# List conversations
conversations = manager.list_conversations(limit=10)
for conv in conversations:
    print(f"{conv['title']} ({conv['provider']})")

# Load conversation
conv = manager.load_conversation(conv_id)
print(f"Messages: {len(conv.messages)}")

# Switch provider
manager.switch_provider(conv_id, "mistral", "mistral-tiny")

# Delete conversation
manager.delete_conversation(conv_id)
```

## Configuration

### Environment Variables

Create `.env` file:

```env
# OpenAI
OPENAI_API_KEY=sk-...

# Mistral
MISTRAL_API_KEY=...

# Azure
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://...

# Ollama
OLLAMA_BASE_URL=http://localhost:11434
```

### Conversation Settings

```python
ConversationManager().create_conversation(
    title="My Chat",
    provider="openai",           # "openai", "mistral", "ollama", "azure", "fallback"
    model="gpt-3.5-turbo",      # Model ID
    temperature=0.7,            # 0.0 (focused) - 1.0 (creative)
    max_tokens=2000,            # Max response length
    system_prompt="You are...", # System instructions
)
```

## Getting Started

### Option 1: Free Local LLM (Recommended)

```bash
# Install Ollama
# From: https://ollama.ai

# Download model
ollama pull llama2

# Run Ollama server
ollama serve

# In another terminal
python llm_cli.py
> new "Local Chat"
> provider ollama
> What is Python?
```

### Option 2: Cloud LLMs

1. Get API key:
   - OpenAI: https://platform.openai.com/api-keys
   - Mistral: https://console.mistral.ai/api-keys
   - Azure: https://portal.azure.com/

2. Add to `.env`:
   ```
   OPENAI_API_KEY=sk-...
   ```

3. Use:
   ```bash
   python llm_web_ui.py
   # Visit http://localhost:5000
   ```

### Option 3: Combination

Use free Ollama for testing, cloud APIs for production:

```python
manager = ConversationManager()

# Test locally
test_conv = manager.create_conversation(
    title="Test",
    provider="ollama"
)

# Production
prod_conv = manager.create_conversation(
    title="Analysis",
    provider="openai"
)
```

## Integration with Hades AI

Add to your Hades modules:

```python
from llm_conversation_core import ConversationManager

class HadesAIModule:
    def __init__(self):
        self.llm_manager = ConversationManager()
        self.analysis_conv = self.llm_manager.create_conversation(
            title="Hades Analysis",
            system_prompt="You are an expert security analyst..."
        )
    
    def analyze_code(self, code):
        """Use LLM for code analysis"""
        prompt = f"Analyze this code:\n{code}"
        return self.llm_manager.send_message(
            prompt,
            conv_id=self.analysis_conv.id
        )
    
    def stream_analysis(self, code):
        """Stream analysis results"""
        prompt = f"Detailed analysis:\n{code}"
        for chunk in self.llm_manager.send_message(
            prompt,
            conv_id=self.analysis_conv.id,
            use_streaming=True
        ):
            yield chunk
```

## Performance

| Provider | Speed | Cost | Setup |
|----------|-------|------|-------|
| Ollama | ⚡ Fast | 🆓 Free | 📦 Install |
| OpenAI | ⚡⚡ Fast | 💰 API charges | 🔑 API key |
| Mistral | ⚡⚡ Fast | 💰 API charges | 🔑 API key |
| Azure | ⚡⚡⚡ Fast | 💰 Azure charges | 📋 Enterprise |
| Fallback | ⚡⚡⚡ Instant | 🆓 Free | ✨ Built-in |

## Troubleshooting

### "No provider available"
- Install Ollama (free, local)
- Add API keys to `.env`
- Check `.env` file syntax

### "Streaming not working"
- Check network connection
- Some providers have rate limits
- Try non-streaming mode

### "Database locked"
- Close other instances
- Delete `.db-shm` and `.db-wal` files
- Use only one instance at a time

### "Slow responses"
- Use Ollama (local) instead of cloud
- Reduce `max_tokens`
- Check network latency

## Advanced Usage

### Custom System Prompts

```python
conv = manager.create_conversation(
    title="Security Analyst",
    system_prompt="""You are an expert security researcher.
    For each query:
    1. Analyze the security implications
    2. List potential attack vectors
    3. Recommend mitigations
    4. Reference CVE/CWE standards
    """
)
```

### Batch Processing

```python
items = [
    "SELECT * FROM users WHERE id = " + input,
    "eval(user_code)",
    "<img src=x onerror='alert(1)'>",
]

for item in items:
    result = manager.send_message(
        f"Analyze: {item}",
        conv_id=conv.id
    )
    print(result)
```

### Provider Comparison

```python
providers = ["openai", "mistral", "ollama"]
prompt = "Explain machine learning"

for provider in providers:
    conv = manager.create_conversation(
        title=f"{provider} test",
        provider=provider
    )
    response = manager.send_message(prompt, conv_id=conv.id)
    print(f"{provider}: {response[:100]}...")
```

## Limits & Quotas

| Provider | Rate Limit | Max Tokens | Concurrent |
|----------|-----------|-----------|-----------|
| OpenAI | 3 req/min (free) | 4,096 | 1 |
| Mistral | ~100 req/min | 32,000 | 10 |
| Ollama | Unlimited | Set by model | 1 |
| Azure | Configurable | 4,096 | Configurable |
| Fallback | Unlimited | 500 | Unlimited |

## Security

- 🔐 API keys stored in `.env` (never commit)
- 🔒 SQLite database (local only)
- 🚫 No data sent to external services (for Ollama)
- ✅ Automatic fallback (never fails)
- 🛡️ Thread-safe operations

## Support

### Documentation
- [LLM_INTEGRATION_GUIDE.md](LLM_INTEGRATION_GUIDE.md) - Full documentation
- [llm_examples.py](llm_examples.py) - 10 usage examples
- [llm_quickstart.py](llm_quickstart.py) - Setup wizard

### Debugging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
# All operations now logged to console
```

### Contact
- GitHub Issues (if applicable)
- Email support
- Community forum

## License

Part of Hades AI Framework - See LICENSE.md

## Changelog

### v1.0.0 (Current)
- ✨ Core LLM conversation system
- 🌐 Web UI with streaming
- 💻 CLI interface
- 🔌 Python API
- 📚 Multi-provider support
- 🗄️ SQLite persistence
- 📤 Export/import
- ⚡ Real-time streaming

## Roadmap

- [ ] OpenAPI/Swagger documentation
- [ ] WebSocket support for live streaming
- [ ] User authentication
- [ ] Rate limiting middleware
- [ ] Analytics dashboard
- [ ] Fine-tuning support
- [ ] Embeddings support
- [ ] Vector database integration

## Credits

Built as part of Hades AI Framework
Contributors: Security research and pentesting community

---

**Ready to chat? Start with:** `python llm_quickstart.py`
