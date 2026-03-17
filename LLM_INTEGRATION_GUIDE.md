# Hades AI - Complete LLM Integration Guide

## Overview

The LLM integration layer provides a unified conversation interface across multiple LLM providers:

- **OpenAI GPT** (requires API key)
- **Mistral AI** (requires API key)
- **Ollama** (free, local, no API key)
- **Azure OpenAI** (Microsoft hosted, requires credentials)
- **Fallback** (rule-based, always available)

## Architecture

```
┌─────────────────────────────────────────────┐
│     User Interface Layer                    │
│  ┌──────────────┬────────────┬───────────┐ │
│  │ Web UI       │ CLI        │ PyQt GUI  │ │
│  │ (Flask)      │ (Terminal) │ (Hades)   │ │
│  └──────────────┴────────────┴───────────┘ │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│   Conversation Manager                      │
│  ┌──────────────────────────────────────┐  │
│  │ Conversation Lifecycle Management    │  │
│  │ Message Storage & History            │  │
│  │ Provider Routing & Fallback         │  │
│  └──────────────────────────────────────┘  │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│     LLM Provider Abstraction Layer           │
│  ┌─────────┬──────────┬────────┬──────────┐ │
│  │ OpenAI  │ Mistral  │ Ollama │ Azure    │ │
│  └─────────┴──────────┴────────┴──────────┘ │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│  External LLM APIs & Local Models           │
│  ├─ api.openai.com                         │
│  ├─ api.mistral.ai                         │
│  ├─ localhost:11434 (Ollama)                │
│  └─ Azure OpenAI endpoints                  │
└─────────────────────────────────────────────┘
```

## Components

### 1. Core: `llm_conversation_core.py`

**Conversation Manager** - Central orchestrator
- Creates and manages conversations
- Routes messages to appropriate LLM provider
- Handles conversation history and persistence
- Provides automatic fallback mechanisms

**LLM Providers** - Unified API for each LLM
- `OpenAIProvider` - GPT-3.5, GPT-4
- `MistralProvider` - Mistral models
- `OllamaProvider` - Local models (Llama2, Mistral, etc.)
- `AzureOpenAIProvider` - Azure-hosted OpenAI
- `FallbackProvider` - Rule-based responses

**Data Models**
- `Message` - Single message with metadata
- `Conversation` - Conversation session with history
- `ConversationManager` - State and persistence management

### 2. Web UI: `llm_web_ui.py`

Flask-based web interface with:
- Real-time streaming responses
- Conversation management UI
- Provider switching
- Export/import functionality
- Responsive design (mobile-friendly)

**Endpoints:**
```
GET  /api/health              - Health check
GET  /api/providers           - List providers
GET  /api/conversations       - List conversations
POST /api/conversations       - Create conversation
GET  /api/conversations/<id>  - Get conversation
DEL  /api/conversations/<id>  - Delete conversation
POST /api/conversations/<id>/messages - Send message
PUT  /api/conversations/<id>/provider - Switch provider
GET  /api/conversations/<id>/export - Export conversation
```

### 3. CLI: `llm_cli.py`

Terminal-based interface with:
- Interactive command prompt
- Message streaming with color output
- Conversation management
- Save/export options
- Fast, lightweight

**Commands:**
```
new [title]           - Create new conversation
list                  - List conversations
load <id>            - Load conversation
clear                - Clear messages
status               - Show status
provider <name>      - Switch provider
model <name>         - Switch model
save [filename]      - Save as text
export [filename]    - Export as JSON
history              - Show messages
delete <id>          - Delete conversation
help                 - Show help
quit                 - Exit
```

## Installation

### Requirements

```bash
pip install flask flask-cors openai mistralai ollama python-dotenv
```

### Environment Setup

Create `.env` file in Hades AI directory:

```env
# OpenAI
OPENAI_API_KEY=sk-...

# Mistral
MISTRAL_API_KEY=...

# Azure OpenAI
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://...

# Ollama (optional, if not on localhost:11434)
OLLAMA_BASE_URL=http://localhost:11434
```

### Database Setup

Conversations are stored in SQLite. Database is created automatically on first run:
- File: `conversations.db`
- Tables: `conversations`, `messages`

## Usage

### 1. Web Interface

Start the server:
```bash
python llm_web_ui.py
```

Visit: `http://localhost:5000`

**Features:**
- Responsive chat interface
- Real-time streaming
- Provider switching
- Conversation history

### 2. CLI Interface

```bash
python llm_cli.py
```

**Examples:**
```bash
# Interactive mode
python llm_cli.py

# Create new conversation
python llm_cli.py --new "Security Analysis"

# Load specific conversation
python llm_cli.py --load abc123...

# List all conversations
python llm_cli.py --list
```

### 3. Python API

```python
from llm_conversation_core import ConversationManager

# Initialize
manager = ConversationManager()

# Create conversation
conv = manager.create_conversation(
    title="Security Analysis",
    provider="openai",
    model="gpt-3.5-turbo",
    system_prompt="You are a security expert..."
)

# Send message (non-streaming)
response = manager.send_message(
    "Analyze this code for vulnerabilities",
    conv_id=conv.id,
    use_streaming=False
)

# Send message (streaming)
for chunk in manager.send_message(
    "Explain SSL/TLS handshake",
    conv_id=conv.id,
    use_streaming=True
):
    print(chunk, end='', flush=True)

# List conversations
conversations = manager.list_conversations(limit=20)

# Load conversation
conv = manager.load_conversation(conv_id)

# Switch provider
manager.switch_provider(conv_id, "mistral", "mistral-tiny")

# Delete conversation
manager.delete_conversation(conv_id)
```

## Configuration

### Conversation Settings

Each conversation has configurable parameters:

```python
Conversation(
    title="My Chat",
    provider="openai",           # LLM provider to use
    model="gpt-3.5-turbo",       # Specific model
    temperature=0.7,              # 0.0-1.0 (creativity)
    max_tokens=2000,              # Max response length
    system_prompt="You are...",   # System instructions
)
```

### Provider Configuration

**OpenAI:**
- Models: `gpt-3.5-turbo`, `gpt-4`
- Temperature: 0.0-1.0
- Max tokens: up to 4096

**Mistral:**
- Models: `mistral-tiny`, `mistral-small`, `mistral-medium`
- Temperature: 0.0-1.0
- Max tokens: up to 32000

**Ollama (Local):**
- Models: `llama2`, `mistral`, `neural-chat`, etc.
- Run: `ollama run llama2`
- Free, no API key required

**Azure OpenAI:**
- Same as OpenAI but hosted on Azure
- Requires deployment name
- Enterprise support

## Streaming

Real-time response streaming is supported across all providers:

```python
# Web API
POST /api/conversations/<conv_id>/messages
{
  "content": "Your message",
  "stream": true
}

# Response is streamed as NDJSON
{"type": "chunk", "content": "token"}
{"type": "chunk", "content": " more"}
{"type": "done"}

# CLI - automatic streaming with color output
# Python API - use iterator
for chunk in manager.send_message(..., use_streaming=True):
    print(chunk, end='')
```

## Persistence

### Database Schema

**Conversations Table:**
```sql
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    title TEXT,
    created_at TEXT,
    updated_at TEXT,
    provider TEXT,
    model TEXT,
    temperature REAL,
    max_tokens INTEGER,
    system_prompt TEXT,
    metadata TEXT
)
```

**Messages Table:**
```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    conversation_id TEXT,
    role TEXT,              -- "user", "assistant", "system"
    content TEXT,
    timestamp TEXT,
    metadata TEXT
)
```

### Backups

Export conversations:
```bash
# CLI
export <filename>          # Exports as JSON

# Web API
GET /api/conversations/<id>/export
```

## Error Handling

Automatic fallback chain:
```
Requested Provider
    ↓
  Available? → Yes → Use Provider
    ↓ No
  Next Provider
    ↓
  No providers available → Fallback Provider
```

## Security Considerations

1. **API Keys:** Store in `.env`, never commit to git
2. **CORS:** Web UI has CORS enabled (for development)
3. **Rate Limiting:** Implement in production
4. **Logging:** All requests logged
5. **Database:** Local SQLite, encrypt if needed

## Performance

- **Response Time:** Depends on provider
  - OpenAI/Mistral: 1-10 seconds
  - Ollama (local): 1-5 seconds
- **Streaming:** Real-time chunks as they arrive
- **Memory:** Efficient conversation storage
- **Scalability:** SQLite OK for single user, use PostgreSQL for multi-user

## Troubleshooting

### No Provider Available

**Problem:** All providers unavailable

**Solution:**
1. Check `.env` file and API keys
2. For Ollama: `ollama pull llama2 && ollama serve`
3. Use fallback provider (always available)

### Streaming Not Working

**Problem:** Responses not streaming

**Solution:**
1. Check network connection
2. Some providers may have rate limits
3. Fall back to non-streaming mode

### Slow Responses

**Problem:** Responses very slow

**Solution:**
1. Check API provider status
2. Reduce `max_tokens`
3. Use local Ollama instead
4. Check network latency

### Database Locked

**Problem:** SQLite database locked

**Solution:**
1. Close other instances
2. Delete `.db-shm` and `.db-wal` files
3. Use thread-safe access (included)

## Integration with Hades AI

The LLM layer integrates with existing Hades AI:

```python
# From HadesAI.py
from llm_conversation_core import ConversationManager

# Use in exploit generator, analysis tools, etc.
conv_manager = ConversationManager()

# Create conversation for analysis
conv = conv_manager.create_conversation(
    title="Vulnerability Analysis",
    provider="openai",
    system_prompt="You are a pentesting expert..."
)

# Use in tools
response = conv_manager.send_message(
    f"Analyze vulnerability in: {vulnerable_code}"
)
```

## Development

### Adding New LLM Provider

```python
class NewLLMProvider(LLMProviderBase):
    def __init__(self):
        super().__init__("newllm")
        self.api_key = os.getenv("NEWLLM_API_KEY", "")
        # Initialize client
        self.available = True
    
    def generate(self, prompt: str, **kwargs) -> str:
        # Implement generation
        pass
    
    def generate_stream(self, prompt: str, **kwargs) -> Iterator[str]:
        # Implement streaming
        pass
```

Register in `ConversationManager._init_providers()`:
```python
self.providers["newllm"] = NewLLMProvider()
```

## Examples

### Security Analysis Bot

```python
conv_manager = ConversationManager()

conv = conv_manager.create_conversation(
    title="Security Analyzer",
    system_prompt="""You are an expert security analyst.
    Analyze code for:
    - SQL injection vulnerabilities
    - XSS vulnerabilities
    - Authentication issues
    - Authorization issues
    - Information disclosure
    - Provide remediation steps"""
)

code = "SELECT * FROM users WHERE id = " + request.args.get('id')
response = conv_manager.send_message(
    f"Analyze this code: {code}",
    conv_id=conv.id
)
```

### Multi-Provider Comparison

```python
managers = {
    "openai": ConversationManager(),
    "ollama": ConversationManager()
}

conv_openai = managers["openai"].create_conversation(
    provider="openai",
    title="OpenAI Test"
)

conv_ollama = managers["ollama"].create_conversation(
    provider="ollama",
    title="Ollama Test"
)

# Compare responses
for mgr_name, mgr in managers.items():
    conv = conv_openai if mgr_name == "openai" else conv_ollama
    response = mgr.send_message("Explain JWT tokens", conv_id=conv.id)
    print(f"{mgr_name}: {response}\n")
```

## API Documentation

Full OpenAPI/Swagger available at: `/api/docs` (when implemented)

## License

Part of Hades AI Framework - See LICENSE.md

## Support

For issues and questions:
1. Check this guide
2. Review error logs
3. Test with fallback provider
4. Check provider status pages
