"""
LLM Conversation Core - Unified conversation layer for multi-LLM support
Handles OpenAI, Mistral, Ollama, Azure, and Fallback LLMs
"""

import os
import json
import sqlite3
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Iterator, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import hashlib
from abc import ABC, abstractmethod
from contextlib import closing

logger = logging.getLogger("LLMConversation")

# ============================================================================
# DATA MODELS
# ============================================================================

class LLMProvider(Enum):
    """Available LLM providers"""
    OPENAI = "openai"
    MISTRAL = "mistral"
    AZURE_OPENAI = "azure"
    OLLAMA = "ollama"
    FALLBACK = "fallback"


@dataclass
class Message:
    """Single conversation message"""
    role: str  # "user", "assistant", "system"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


@dataclass
class Conversation:
    """Manages a conversation session"""
    id: str
    title: str
    messages: List[Message] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    provider: str = "openai"
    model: str = "gpt-3.5-turbo"
    temperature: float = 0.7
    max_tokens: int = 2000
    system_prompt: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_message(self, role: str, content: str, metadata: Dict = None):
        """Add message to conversation"""
        msg = Message(role=role, content=content, metadata=metadata or {})
        self.messages.append(msg)
        self.updated_at = datetime.now()
        return msg
    
    def get_messages_for_api(self) -> List[Dict]:
        """Format messages for LLM API"""
        result = []
        if self.system_prompt:
            result.append({"role": "system", "content": self.system_prompt})
        for msg in self.messages:
            result.append({"role": msg.role, "content": msg.content})
        return result
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "provider": self.provider,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "system_prompt": self.system_prompt,
            "message_count": len(self.messages),
            "metadata": self.metadata
        }


# ============================================================================
# LLM PROVIDER ABSTRACTION
# ============================================================================

class LLMProviderBase(ABC):
    """Abstract base for LLM providers"""
    
    def __init__(self, provider_name: str):
        self.name = provider_name
        self.available = False
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate response"""
        pass
    
    @abstractmethod
    def generate_stream(self, prompt: str, **kwargs) -> Iterator[str]:
        """Generate response with streaming"""
        pass
    
    def test_connection(self) -> bool:
        """Test if provider is available"""
        try:
            response = self.generate("test", max_tokens=10)
            return bool(response)
        except:
            return False


class OpenAIProvider(LLMProviderBase):
    """OpenAI GPT provider"""
    
    def __init__(self):
        super().__init__("openai")
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.client = None
        self.available = False
        
        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
                self.available = True
                logger.info("OpenAI provider initialized")
            except ImportError:
                logger.warning("OpenAI package not installed")
    
    def generate(self, prompt: str, **kwargs) -> str:
        if not self.available:
            return None
        
        try:
            messages = kwargs.get("messages") or [{"role": "user", "content": prompt}]
            response = self.client.chat.completions.create(
                model=kwargs.get("model", "gpt-3.5-turbo"),
                messages=messages,
                max_tokens=kwargs.get("max_tokens", 2000),
                temperature=kwargs.get("temperature", 0.7),
                timeout=kwargs.get("timeout", 30)
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI generation error: {str(e)}")
            return None
    
    def generate_stream(self, prompt: str, **kwargs) -> Iterator[str]:
        if not self.available:
            return
        
        try:
            messages = kwargs.get("messages") or [{"role": "user", "content": prompt}]
            stream = self.client.chat.completions.create(
                model=kwargs.get("model", "gpt-3.5-turbo"),
                messages=messages,
                max_tokens=kwargs.get("max_tokens", 2000),
                temperature=kwargs.get("temperature", 0.7),
                stream=True,
                timeout=kwargs.get("timeout", 30)
            )
            
            for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error(f"OpenAI stream error: {str(e)}")


class MistralProvider(LLMProviderBase):
    """Mistral AI provider"""
    
    def __init__(self):
        super().__init__("mistral")
        self.api_key = os.getenv("MISTRAL_API_KEY", "")
        self.client = None
        self.available = False
        
        if self.api_key:
            try:
                from mistralai import Mistral
                self.client = Mistral(api_key=self.api_key)
                self.available = True
                logger.info("Mistral provider initialized")
            except ImportError:
                logger.warning("Mistral package not installed")
    
    def generate(self, prompt: str, **kwargs) -> str:
        if not self.available:
            return None
        
        try:
            messages = kwargs.get("messages") or [{"role": "user", "content": prompt}]
            response = self.client.chat.complete(
                model=kwargs.get("model", "mistral-tiny"),
                messages=messages,
                max_tokens=kwargs.get("max_tokens", 2000),
                temperature=kwargs.get("temperature", 0.7)
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Mistral generation error: {str(e)}")
            return None
    
    def generate_stream(self, prompt: str, **kwargs) -> Iterator[str]:
        if not self.available:
            return
        
        try:
            messages = kwargs.get("messages") or [{"role": "user", "content": prompt}]
            stream = self.client.chat.stream(
                model=kwargs.get("model", "mistral-tiny"),
                messages=messages,
                max_tokens=kwargs.get("max_tokens", 2000),
                temperature=kwargs.get("temperature", 0.7)
            )
            
            for chunk in stream:
                if chunk.data.choices[0].delta.content:
                    yield chunk.data.choices[0].delta.content
        except Exception as e:
            logger.error(f"Mistral stream error: {str(e)}")


class OllamaProvider(LLMProviderBase):
    """Ollama local LLM provider (free, no API key)"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        super().__init__("ollama")
        self.base_url = base_url
        self.available = False
        
        try:
            import ollama
            self.client = ollama
            self.available = self._test_ollama()
            if self.available:
                logger.info(f"Ollama provider initialized at {base_url}")
        except ImportError:
            logger.warning("Ollama package not installed")
    
    def _test_ollama(self) -> bool:
        try:
            import requests
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except:
            return False
    
    def generate(self, prompt: str, **kwargs) -> str:
        if not self.available:
            return None
        
        try:
            model = kwargs.get("model", "llama3.2")
            messages = kwargs.get("messages")

            if messages:
                response = self.client.chat(
                    model=model,
                    messages=messages,
                    stream=False,
                    options={
                        "temperature": kwargs.get("temperature", 0.7),
                        "num_predict": kwargs.get("max_tokens", 2000)
                    }
                )
                return (response.get("message") or {}).get("content", "")

            response = self.client.generate(
                model=model,
                prompt=prompt,
                stream=False,
                options={
                    "temperature": kwargs.get("temperature", 0.7),
                    "num_predict": kwargs.get("max_tokens", 2000)
                }
            )
            return response.get("response", "")
        except Exception as e:
            logger.error(f"Ollama generation error: {str(e)}")
            return None
    
    def generate_stream(self, prompt: str, **kwargs) -> Iterator[str]:
        if not self.available:
            return
        
        try:
            model = kwargs.get("model", "llama3.2")
            messages = kwargs.get("messages")

            if messages:
                stream = self.client.chat(
                    model=model,
                    messages=messages,
                    stream=True,
                    options={
                        "temperature": kwargs.get("temperature", 0.7),
                        "num_predict": kwargs.get("max_tokens", 2000)
                    }
                )

                for chunk in stream:
                    content = ((chunk.get("message") or {}).get("content"))
                    if content:
                        yield content
                return

            stream = self.client.generate(
                model=model,
                prompt=prompt,
                stream=True,
                options={
                    "temperature": kwargs.get("temperature", 0.7),
                    "num_predict": kwargs.get("max_tokens", 2000)
                }
            )
            
            for chunk in stream:
                if chunk.get("response"):
                    yield chunk["response"]
        except Exception as e:
            logger.error(f"Ollama stream error: {str(e)}")


class AzureOpenAIProvider(LLMProviderBase):
    """Azure OpenAI provider"""
    
    def __init__(self):
        super().__init__("azure")
        self.api_key = os.getenv("AZURE_OPENAI_API_KEY", "")
        self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.client = None
        self.available = False
        
        if self.api_key and self.endpoint:
            try:
                from openai import AzureOpenAI
                self.client = AzureOpenAI(
                    api_key=self.api_key,
                    api_version="2024-02-15-preview",
                    azure_endpoint=self.endpoint
                )
                self.available = True
                logger.info("Azure OpenAI provider initialized")
            except ImportError:
                logger.warning("Azure OpenAI package not installed")
    
    def generate(self, prompt: str, **kwargs) -> str:
        if not self.available:
            return None
        
        try:
            messages = kwargs.get("messages") or [{"role": "user", "content": prompt}]
            response = self.client.chat.completions.create(
                deployment_name=kwargs.get("deployment", "gpt-35-turbo"),
                messages=messages,
                max_tokens=kwargs.get("max_tokens", 2000),
                temperature=kwargs.get("temperature", 0.7)
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Azure OpenAI generation error: {str(e)}")
            return None
    
    def generate_stream(self, prompt: str, **kwargs) -> Iterator[str]:
        if not self.available:
            return
        
        try:
            messages = kwargs.get("messages") or [{"role": "user", "content": prompt}]
            stream = self.client.chat.completions.create(
                deployment_name=kwargs.get("deployment", "gpt-35-turbo"),
                messages=messages,
                max_tokens=kwargs.get("max_tokens", 2000),
                temperature=kwargs.get("temperature", 0.7),
                stream=True
            )
            
            for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error(f"Azure stream error: {str(e)}")


class FallbackProvider(LLMProviderBase):
    """Fallback rule-based response generator"""
    
    def __init__(self):
        super().__init__("fallback")
        self.available = True
        self.responses = {}
        self._load_responses()
    
    def _load_responses(self):
        self.responses = {
            "hello": "Hello! I'm Hades AI Assistant. How can I help you today?",
            "help": "I can assist with various topics. Try asking about security, coding, or analysis.",
            "how are you": "I'm functioning optimally. Ready to assist with your queries.",
        }
    
    @staticmethod
    def _looks_like_code(text: str) -> bool:
        markers = (
            "function(", "function ", "=>", "var ", "let ", "const ",
            "class ", "def ", "import ", "#include", "<?php", "</",
            "try{", "try {", "catch(", "catch (",
        )
        marker_count = sum(marker in text for marker in markers)
        punctuation_count = sum(text.count(char) for char in "{};()")
        has_source_shape = "\n" in text or len(text) >= 300
        return has_source_shape and (marker_count >= 2 or (marker_count >= 1 and punctuation_count >= 8))

    @classmethod
    def _recent_code(cls, messages: List[Dict[str, Any]]) -> Optional[str]:
        for message in reversed(messages[:-1]):
            content = message.get("content", "")
            if message.get("role") == "user" and cls._looks_like_code(content):
                return content
        return None

    @staticmethod
    def _high_risk_code_markers(code: str) -> List[str]:
        code_lower = code.lower()
        markers = {
            "shellcode": "embedded shellcode",
            "arb_write": "arbitrary memory write primitive",
            "rwx_page": "RWX memory execution",
            "writeprocessmemory": "cross-process memory write",
            "virtualallocex": "remote executable-memory allocation",
            "setthreadcontext": "thread-context redirection",
            "resumethread": "suspended-process execution",
            "create_suspended": "suspended process creation",
        }
        return [description for marker, description in markers.items() if marker in code_lower]

    @classmethod
    def _respond_to_code_request(cls, request: str, code: str) -> str:
        request_lower = request.lower()
        transform_requested = any(
            phrase in request_lower
            for phrase in (
                "combine", "convert", "port", "rewrite", "make this work",
                "make it work", "working python", "working script",
            )
        )
        risk_markers = cls._high_risk_code_markers(code)
        if transform_requested and len(risk_markers) >= 2:
            return """I can't combine or port this into an operational payload loader. The supplied material chains JavaScript-engine memory corruption and shellcode execution with Windows process injection (`VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, and `ResumeThread`).

I can still help concretely. This safe Python triage tool analyzes the supplied source without executing it. Save the mixed source as `sample.txt`, save this as `analyze_sample.py`, then run `python analyze_sample.py sample.txt`:

```python
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

INDICATORS = [
    "shellcode", "arb_read", "arb_write", "rwx_page",
    "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext",
    "ResumeThread", "CREATE_SUSPENDED", "PAGE_EXECUTE_READWRITE",
]


def extract_array(source: str, name: str) -> list[int]:
    pattern = rf"(?s)\\b{re.escape(name)}\\s*=\\s*(?:new\\s+Uint8Array\\s*\\()?\\[([^]]*)\\]"
    match = re.search(pattern, source)
    if not match:
        return []
    return [int(value) for value in re.findall(r"\\b\\d+\\b", match.group(1))]


def digest_values(values: list[int], width: int) -> str:
    if not values:
        return ""
    if width == 1:
        data = bytes(value & 0xFF for value in values)
    else:
        data = b"".join(struct.pack("<I", value & 0xFFFFFFFF) for value in values)
    return hashlib.sha256(data).hexdigest()


def main(path: str) -> None:
    source = Path(path).read_text(encoding="utf-8", errors="replace")
    shellcode = extract_array(source, "shellcode")
    wasm = extract_array(source, "wasm_code")
    report = {
        "file": str(Path(path).resolve()),
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "indicators": {
            indicator: len(re.findall(re.escape(indicator), source, re.IGNORECASE))
            for indicator in INDICATORS
            if re.search(re.escape(indicator), source, re.IGNORECASE)
        },
        "shellcode": {
            "uint32_count": len(shellcode),
            "byte_length": len(shellcode) * 4,
            "sha256_little_endian": digest_values(shellcode, 4),
        },
        "webassembly": {
            "byte_count": len(wasm),
            "valid_magic": wasm[:4] == [0, 97, 115, 109],
            "sha256": digest_values(wasm, 1),
        },
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python analyze_sample.py <source-file>")
    main(sys.argv[1])
```

This gives you reproducible evidence and IOCs without invoking WebAssembly, allocating executable memory, downloading a payload, or touching another process."""
        return cls._analyze_code(code)

    @staticmethod
    def _analyze_code(code: str) -> str:
        code_lower = code.lower()
        is_javascript = any(marker in code for marker in ("function(", "function ", "var ", "const ", "=>"))

        if is_javascript and "___jsl" in code and "apis.google.com" in code:
            return (
                "This is minified/generated JavaScript from Google's API loader and telemetry runtime, "
                "not application source written for readability.\n\n"
                "**What it does:**\n"
                "- Initializes the global `gapi` loader and builds validated `apis.google.com` module URLs.\n"
                "- Injects scripts with nonce and Trusted Types support.\n"
                "- Includes 64-bit integer/protobuf serialization helpers.\n"
                "- Reads Google authentication cookies and creates SAPISID/APISID request hashes.\n"
                "- Batches compressed telemetry and sends it to `play.google.com/log` using beacon, fetch, images, or XHR.\n"
                "- Contains retry, timeout, browser capability, and user-agent metadata handling.\n\n"
                "Nothing in the excerpt alone demonstrates an exploit; it resembles a legitimate Google bundle. "
                "Because it handles auth-derived hashes and dynamically loads scripts, only run the complete script "
                "when it came from a trusted Google page."
            )

        language = "JavaScript" if is_javascript else "source code"
        traits = []
        if code.count("\n") > 80 or (len(code) > 2000 and len(code.split()) < len(code) / 8):
            traits.append("appears minified or generated")
        if any(token in code_lower for token in ("fetch(", "xmlhttprequest", "requests.", "http://", "https://")):
            traits.append("performs network operations")
        if any(token in code_lower for token in ("cookie", "authorization", "api_key", "token")):
            traits.append("handles authentication or session-related data")
        if any(token in code_lower for token in ("eval(", "exec(", "document.write(")):
            traits.append("contains dynamic code or document execution that deserves source verification")

        summary = "; ".join(traits) if traits else "contains no immediately identifiable high-risk behavior from a structural scan"
        return (
            f"This looks like {language}. It {summary}. "
            "For a precise function-by-function explanation, provide the unminified source or the section you want traced."
        )

    def generate(self, prompt: str, **kwargs) -> str:
        prompt_lower = prompt.lower()
        messages = kwargs.get("messages") or []

        if self._looks_like_code(prompt):
            return self._respond_to_code_request(prompt, prompt)

        refers_to_code = "code" in prompt_lower and any(
            phrase in prompt_lower
            for phrase in ("just sent", "sent you", "above", "previous", "tell me about", "explain", "analyze")
        )
        transforms_recent_code = any(
            phrase in prompt_lower
            for phrase in ("combine", "convert", "port", "rewrite", "make it work", "working script")
        )
        if refers_to_code or transforms_recent_code:
            recent_code = self._recent_code(messages)
            if recent_code:
                return self._respond_to_code_request(prompt, recent_code)
        
        for key, value in self.responses.items():
            if key in prompt_lower:
                return value
        
        if any(token in prompt_lower for token in ["workdir", "working directory", "workspace"]):
            return (
                "I can help with workspace tasks, but in fallback mode I need an explicit path or command. "
                "Try: set the workdir in the Self-Improvement tab, then use /files or /open <file>."
            )

        if any(token in prompt_lower for token in ["file", "open", "edit", "save", "code"]):
            return (
                "I can help. Share the target file path and what you want changed, and I'll give a concrete edit plan."
            )

        # Default response
        return "I'm ready to help. Tell me your goal and the file or directory you want to work on."
    
    def generate_stream(self, prompt: str, **kwargs) -> Iterator[str]:
        response = self.generate(prompt, **kwargs)
        for word in response.split():
            yield word + " "


# ============================================================================
# CONVERSATION MANAGER
# ============================================================================

class ConversationManager:
    """Manages conversations with multiple LLM providers"""
    
    def __init__(self, db_path: str = "conversations.db"):
        self.db_path = db_path
        self.current_conversation: Optional[Conversation] = None
        self.conversations: Dict[str, Conversation] = {}
        self.providers: Dict[str, LLMProviderBase] = {}
        self.lock = threading.RLock()
        
        self._init_db()
        self._init_providers()

    def _connect(self) -> sqlite3.Connection:
        """Open a configured connection that tolerates short concurrent writes."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn
    
    def _init_providers(self):
        """Initialize all available LLM providers"""
        self.providers = {
            "openai": OpenAIProvider(),
            "mistral": MistralProvider(),
            "ollama": OllamaProvider(),
            "azure": AzureOpenAIProvider(),
            "fallback": FallbackProvider(),
        }
        
        available = [name for name, prov in self.providers.items() if prov.available]
        logger.info(f"Available LLM providers: {available}")

    def _default_model_for(self, provider: str) -> str:
        model_map = {
            "openai": "gpt-3.5-turbo",
            "mistral": "mistral-small-latest",
            "ollama": "llama3.2",
            "azure": "gpt-35-turbo",
            "fallback": "fallback",
        }
        return model_map.get(provider, "fallback")

    def _select_default_provider(self) -> str:
        """Prefer free local LLM when cloud API keys are absent."""
        if self.providers.get("ollama") and self.providers["ollama"].available:
            return "ollama"
        if self.providers.get("fallback") and self.providers["fallback"].available:
            return "fallback"
        for name, prov in self.providers.items():
            if prov.available:
                return name
        return "fallback"
    
    def _init_db(self):
        """Initialize SQLite database for conversation storage"""
        with closing(self._connect()) as conn, conn:
            # WAL lets the UI read conversation history while a worker saves a reply.
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
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
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT,
                    role TEXT,
                    content TEXT,
                    timestamp TEXT,
                    metadata TEXT,
                    FOREIGN KEY(conversation_id) REFERENCES conversations(id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_conversations_updated_at
                ON conversations(updated_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_conversation_id_id
                ON messages(conversation_id, id)
            """)
    
    def create_conversation(
        self,
        title: str,
        provider: str = "openai",
        model: str = "gpt-3.5-turbo",
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> Conversation:
        """Create new conversation"""
        conv_id = hashlib.md5(
            f"{title}{datetime.now().isoformat()}".encode()
        ).hexdigest()
        
        if provider not in self.providers or not self.providers[provider].available:
            provider = self._select_default_provider()
            model = self._default_model_for(provider)

        conv = Conversation(
            id=conv_id,
            title=title,
            provider=provider,
            model=model,
            system_prompt=system_prompt,
            **kwargs
        )
        
        with self.lock:
            self.conversations[conv_id] = conv
            self.current_conversation = conv
            self._save_conversation(conv)
        
        return conv
    
    def load_conversation(self, conv_id: str) -> Optional[Conversation]:
        """Load conversation from database"""
        try:
            with closing(self._connect()) as conn:
                cursor = conn.execute(
                    "SELECT * FROM conversations WHERE id = ?", (conv_id,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                conv = Conversation(
                    id=row[0],
                    title=row[1],
                    created_at=datetime.fromisoformat(row[2]),
                    updated_at=datetime.fromisoformat(row[3]),
                    provider=row[4],
                    model=row[5],
                    temperature=row[6],
                    max_tokens=row[7],
                    system_prompt=row[8],
                    metadata=json.loads(row[9]) if row[9] else {}
                )
                
                # Load messages
                messages = conn.execute(
                    "SELECT role, content, timestamp, metadata FROM messages WHERE conversation_id = ? ORDER BY id",
                    (conv_id,)
                ).fetchall()
                
                for role, content, timestamp, meta in messages:
                    conv.messages.append(
                        Message(
                            role=role,
                            content=content,
                            timestamp=datetime.fromisoformat(timestamp),
                            metadata=json.loads(meta) if meta else {}
                        )
                    )
                
                with self.lock:
                    self.conversations[conv_id] = conv
                
                return conv
        except Exception as e:
            logger.error(f"Error loading conversation: {str(e)}")
            return None
    
    def _save_conversation(self, conv: Conversation):
        """Save conversation metadata and its complete ordered message history."""
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute(
                    """INSERT INTO conversations
                    (id, title, created_at, updated_at, provider, model, temperature, max_tokens, system_prompt, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        title = excluded.title,
                        created_at = excluded.created_at,
                        updated_at = excluded.updated_at,
                        provider = excluded.provider,
                        model = excluded.model,
                        temperature = excluded.temperature,
                        max_tokens = excluded.max_tokens,
                        system_prompt = excluded.system_prompt,
                        metadata = excluded.metadata""",
                    (
                        conv.id, conv.title,
                        conv.created_at.isoformat(), conv.updated_at.isoformat(),
                        conv.provider, conv.model, conv.temperature, conv.max_tokens,
                        conv.system_prompt,
                        json.dumps(conv.metadata)
                    )
                )
                conn.execute("DELETE FROM messages WHERE conversation_id = ?", (conv.id,))
                conn.executemany(
                    """INSERT INTO messages
                    (conversation_id, role, content, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?)""",
                    [
                        (
                            conv.id, message.role, message.content,
                            message.timestamp.isoformat(), json.dumps(message.metadata)
                        )
                        for message in conv.messages
                    ]
                )
        except Exception as e:
            logger.error(f"Error saving conversation: {str(e)}")

    def _append_message(self, conv: Conversation, message: Message):
        """Persist one new message without rewriting the conversation history."""
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute(
                    """UPDATE conversations
                    SET updated_at = ?, provider = ?, model = ?, temperature = ?,
                        max_tokens = ?, system_prompt = ?, metadata = ?
                    WHERE id = ?""",
                    (
                        conv.updated_at.isoformat(), conv.provider, conv.model,
                        conv.temperature, conv.max_tokens, conv.system_prompt,
                        json.dumps(conv.metadata), conv.id
                    )
                )
                conn.execute(
                    """INSERT INTO messages
                    (conversation_id, role, content, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?)""",
                    (
                        conv.id, message.role, message.content,
                        message.timestamp.isoformat(), json.dumps(message.metadata)
                    )
                )
        except Exception as e:
            logger.error(f"Error appending conversation message: {str(e)}")
    
    def send_message(
        self,
        content: str,
        conv_id: Optional[str] = None,
        use_streaming: bool = False
    ) -> Union[str, Iterator[str]]:
        """Send message and get response"""
        if conv_id:
            conv = self.conversations.get(conv_id)
            if not conv:
                conv = self.load_conversation(conv_id)
        else:
            conv = self.current_conversation
        
        if not conv:
            raise ValueError("No active conversation")
        
        # Add user message
        with self.lock:
            user_message = conv.add_message("user", content)
            self._append_message(conv, user_message)
        
        # Get provider
        provider = self.providers.get(conv.provider)
        if not provider or not provider.available:
            provider = self.providers["fallback"]
            logger.warning(f"Provider {conv.provider} unavailable, using fallback")
        
        # Prepare prompt
        api_messages = conv.get_messages_for_api()
        
        # Generate response
        if use_streaming:
            response_stream = provider.generate_stream(
                content,
                messages=api_messages,
                model=conv.model,
                temperature=conv.temperature,
                max_tokens=conv.max_tokens
            )
            
            def _stream_and_persist():
                full_response = ""
                for chunk in response_stream:
                    full_response += chunk
                    yield chunk

                with self.lock:
                    assistant_message = conv.add_message("assistant", full_response)
                    self._append_message(conv, assistant_message)

            return _stream_and_persist()
        else:
            response = provider.generate(
                content,
                messages=api_messages,
                model=conv.model,
                temperature=conv.temperature,
                max_tokens=conv.max_tokens
            )
            
            if response:
                with self.lock:
                    assistant_message = conv.add_message("assistant", response)
                    self._append_message(conv, assistant_message)
            
            return response
    
    def list_conversations(self, limit: int = 50) -> List[Dict]:
        """List all conversations"""
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    "SELECT id, title, created_at, updated_at, provider FROM conversations ORDER BY updated_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            
            return [
                {
                    "id": row[0],
                    "title": row[1],
                    "created_at": row[2],
                    "updated_at": row[3],
                    "provider": row[4]
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"Error listing conversations: {str(e)}")
            return []
    
    def delete_conversation(self, conv_id: str) -> bool:
        """Delete conversation"""
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute("DELETE FROM messages WHERE conversation_id = ?", (conv_id,))
                conn.execute("DELETE FROM conversations WHERE id = ?", (conv_id,))

            with self.lock:
                self.conversations.pop(conv_id, None)
                if self.current_conversation and self.current_conversation.id == conv_id:
                    self.current_conversation = None
            return True
        except Exception as e:
            logger.error(f"Error deleting conversation: {str(e)}")
            return False
    
    def get_available_providers(self) -> List[str]:
        """Get list of available providers"""
        return [name for name, prov in self.providers.items() if prov.available]
    
    def switch_provider(self, conv_id: str, provider: str, model: str) -> bool:
        """Switch provider for conversation"""
        conv = self.conversations.get(conv_id)
        if not conv:
            conv = self.load_conversation(conv_id)
        
        if not conv or provider not in self.providers:
            return False
        
        if not self.providers[provider].available:
            return False

        conv.provider = provider
        conv.model = model or self._default_model_for(provider)
        self._save_conversation(conv)
        return True
