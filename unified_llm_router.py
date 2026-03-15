"""
Unified LLM Routing System for HadesAI
Intelligent routing across multiple LLM providers with fallback support
Integrates with Web Learning and Enhanced Defense Systems
"""

import os
import json
import logging
import threading
import time
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from datetime import datetime
import sqlite3
from dataclasses import dataclass
from abc import ABC, abstractmethod

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("UnifiedLLMRouter")


# ============================================================================
# ENUMS & DATA STRUCTURES
# ============================================================================

class LLMProvider(Enum):
    """Available LLM providers"""
    OPENAI = "openai"
    MISTRAL = "mistral"
    AZURE_OPENAI = "azure"
    OLLAMA = "ollama"
    FALLBACK = "fallback"
    CLAUDE = "claude"


class RequestPriority(Enum):
    """Request priority levels"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


@dataclass
class LLMRequest:
    """LLM request structure"""
    prompt: str
    priority: RequestPriority = RequestPriority.NORMAL
    max_tokens: int = 2000
    temperature: float = 0.7
    system_prompt: str = ""
    context: Dict[str, Any] = None
    request_id: str = ""
    timestamp: datetime = None
    
    def __post_init__(self):
        if not self.request_id:
            import uuid
            self.request_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now()


@dataclass
class LLMResponse:
    """LLM response structure"""
    request_id: str
    provider: LLMProvider
    content: str
    tokens_used: int = 0
    latency_ms: float = 0
    success: bool = True
    error: Optional[str] = None
    timestamp: datetime = None
    cached: bool = False
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now()


# ============================================================================
# ABSTRACT LLM PROVIDER
# ============================================================================

class AbstractLLMProvider(ABC):
    """Base class for LLM providers"""
    
    def __init__(self, name: str):
        self.name = name
        self.available = False
        self.priority = RequestPriority.NORMAL
        self.config = {}
    
    @abstractmethod
    def generate(self, request: LLMRequest) -> Optional[str]:
        """Generate response from LLM"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available"""
        pass
    
    def validate_request(self, request: LLMRequest) -> bool:
        """Validate request before sending"""
        return bool(request.prompt)


# ============================================================================
# CONCRETE LLM PROVIDERS
# ============================================================================

class OpenAIProvider(AbstractLLMProvider):
    """OpenAI GPT provider"""
    
    def __init__(self):
        super().__init__("OpenAI GPT")
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.client = None
        self._initialize()
    
    def _initialize(self):
        try:
            from openai import OpenAI
            if self.api_key:
                self.client = OpenAI(api_key=self.api_key)
                self.available = True
                logger.info("OpenAI provider initialized")
        except ImportError:
            logger.warning("OpenAI package not installed")
    
    def is_available(self) -> bool:
        return self.available and bool(self.api_key) and self.client is not None
    
    def generate(self, request: LLMRequest) -> Optional[str]:
        if not self.is_available():
            return None
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": request.system_prompt or "You are HadesAI, an expert security and exploitation assistant."},
                    {"role": "user", "content": request.prompt}
                ],
                max_tokens=request.max_tokens,
                temperature=request.temperature
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI error: {e}")
            return None


class MistralProvider(AbstractLLMProvider):
    """Mistral AI provider"""
    
    def __init__(self):
        super().__init__("Mistral AI")
        self.api_key = os.getenv("MISTRAL_API_KEY", "")
        self.client = None
        self._initialize()
    
    def _initialize(self):
        try:
            from mistralai import Mistral
            if self.api_key:
                self.client = Mistral(api_key=self.api_key)
                self.available = True
                logger.info("Mistral provider initialized")
        except ImportError:
            logger.warning("Mistral package not installed")
    
    def is_available(self) -> bool:
        return self.available and bool(self.api_key) and self.client is not None
    
    def generate(self, request: LLMRequest) -> Optional[str]:
        if not self.is_available():
            return None
        
        try:
            response = self.client.chat.complete(
                model="mistral-large-latest",
                messages=[
                    {"role": "system", "content": request.system_prompt or "You are HadesAI, an expert security and exploitation assistant."},
                    {"role": "user", "content": request.prompt}
                ],
                max_tokens=request.max_tokens,
                temperature=request.temperature
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Mistral error: {e}")
            return None


class OllamaProvider(AbstractLLMProvider):
    """Ollama local LLM provider"""
    
    def __init__(self, model: str = "mistral"):
        super().__init__("Ollama (Local)")
        self.model = model
        self.base_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.available = self._check_availability()
    
    def _check_availability(self) -> bool:
        try:
            import requests
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def is_available(self) -> bool:
        return self.available
    
    def generate(self, request: LLMRequest) -> Optional[str]:
        if not self.is_available():
            return None
        
        try:
            import requests
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": request.prompt,
                    "stream": False
                },
                timeout=30
            )
            data = response.json()
            return data.get("response", "")
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return None


class AzureOpenAIProvider(AbstractLLMProvider):
    """Azure OpenAI provider"""
    
    def __init__(self):
        super().__init__("Azure OpenAI")
        self.api_key = os.getenv("AZURE_OPENAI_API_KEY", "")
        self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.client = None
        self._initialize()
    
    def _initialize(self):
        try:
            from openai import AzureOpenAI
            if self.api_key and self.endpoint:
                self.client = AzureOpenAI(
                    api_key=self.api_key,
                    api_version="2024-02-15-preview",
                    azure_endpoint=self.endpoint
                )
                self.available = True
                logger.info("Azure OpenAI provider initialized")
        except ImportError:
            logger.warning("Azure OpenAI package not installed")
    
    def is_available(self) -> bool:
        return self.available and bool(self.api_key) and bool(self.endpoint)
    
    def generate(self, request: LLMRequest) -> Optional[str]:
        if not self.is_available():
            return None
        
        try:
            response = self.client.chat.completions.create(
                deployment_name="gpt-35-turbo",
                messages=[
                    {"role": "system", "content": request.system_prompt or "You are HadesAI, an expert security and exploitation assistant."},
                    {"role": "user", "content": request.prompt}
                ],
                max_tokens=request.max_tokens,
                temperature=request.temperature
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Azure OpenAI error: {e}")
            return None


class FallbackProvider(AbstractLLMProvider):
    """Fallback rule-based provider"""
    
    def __init__(self):
        super().__init__("Fallback (Rule-based)")
        self.available = True
    
    def is_available(self) -> bool:
        return True
    
    def generate(self, request: LLMRequest) -> Optional[str]:
        """Generate response using rule-based fallback logic"""
        prompt_lower = request.prompt.lower()
        
        # Route based on request content
        if "exploit" in prompt_lower or "vulnerability" in prompt_lower:
            return self._generate_exploit_analysis(request.prompt)
        elif "defend" in prompt_lower or "mitigation" in prompt_lower:
            return self._generate_defense_analysis(request.prompt)
        elif "learn" in prompt_lower or "web" in prompt_lower:
            return self._generate_learning_analysis(request.prompt)
        else:
            return self._generate_generic_response(request.prompt)
    
    def _generate_exploit_analysis(self, prompt: str) -> str:
        return """Based on the vulnerability analysis:

1. **Vulnerability Assessment**
   - Analysis Type: Code/System Vulnerability
   - Risk Level: Requires further investigation

2. **Exploitation Method**
   - Step 1: Identify attack surface
   - Step 2: Craft targeted payload
   - Step 3: Execute with proper error handling

3. **Detection & Prevention**
   - Implement input validation
   - Apply security patches
   - Monitor for suspicious patterns
   
4. **Mitigation Recommendations**
   - Update to latest secure version
   - Implement WAF/IDS rules
   - Apply principle of least privilege"""
    
    def _generate_defense_analysis(self, prompt: str) -> str:
        return """Defense & Mitigation Strategy:

1. **Detection Methods**
   - Pattern-based detection
   - Behavioral analysis
   - Anomaly detection

2. **Response Actions**
   - Immediate threat isolation
   - Log collection for analysis
   - Incident escalation

3. **Long-term Protection**
   - System hardening
   - Access control implementation
   - Regular security audits

4. **Monitoring & Prevention**
   - Real-time threat detection
   - Automated response systems
   - Continuous vulnerability assessment"""
    
    def _generate_learning_analysis(self, prompt: str) -> str:
        return """Web Learning Integration Summary:

1. **Knowledge Extraction**
   - CVE identification and tracking
   - Exploit technique documentation
   - Attack pattern recognition

2. **Knowledge Storage**
   - Indexed vulnerability database
   - Technique methodology repository
   - Pattern signature library

3. **Knowledge Application**
   - Context-aware recommendations
   - Adaptive security responses
   - Predictive threat analysis

4. **Continuous Learning**
   - New vulnerability detection
   - Pattern refinement
   - Strategy optimization"""
    
    def _generate_generic_response(self, prompt: str) -> str:
        return """Default Response:

I am HadesAI, a comprehensive security and penetration testing system.

**Available Capabilities:**
- Vulnerability detection and exploitation
- Web-based knowledge learning
- Enhanced defense systems
- Multi-LLM routing and optimization
- Exploit generation and analysis

**For specific assistance:**
1. Provide detailed context about your target
2. Specify vulnerability type or attack vector
3. Include relevant CVEs or attack patterns
4. Describe your security objectives

Please provide more specific information for targeted assistance."""


# ============================================================================
# REQUEST CACHE & HISTORY
# ============================================================================

class RequestCache:
    """Cache for LLM requests and responses"""
    
    def __init__(self, db_path: str = "llm_cache.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize cache database"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS llm_cache (
                    cache_id TEXT PRIMARY KEY,
                    prompt_hash TEXT UNIQUE,
                    request TEXT,
                    response TEXT,
                    provider TEXT,
                    created_at TEXT,
                    hits INTEGER DEFAULT 0
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS request_history (
                    id INTEGER PRIMARY KEY,
                    request_id TEXT,
                    provider TEXT,
                    tokens_used INTEGER,
                    latency_ms REAL,
                    success BOOLEAN,
                    error TEXT,
                    created_at TEXT
                )
            """)
            
            self.conn.commit()
        except Exception as e:
            logger.error(f"Cache initialization error: {e}")
    
    def get(self, prompt: str) -> Optional[str]:
        """Get cached response"""
        try:
            import hashlib
            prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
            
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT response FROM llm_cache
                WHERE prompt_hash = ?
            """, (prompt_hash,))
            
            result = cursor.fetchone()
            if result:
                cursor.execute("""
                    UPDATE llm_cache SET hits = hits + 1
                    WHERE prompt_hash = ?
                """, (prompt_hash,))
                self.conn.commit()
                return result[0]
            
            return None
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None
    
    def set(self, prompt: str, response: str, provider: str):
        """Cache response"""
        try:
            import hashlib
            import uuid
            prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO llm_cache
                (cache_id, prompt_hash, request, response, provider, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                prompt_hash,
                prompt[:1000],
                response[:5000],
                provider,
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
        except Exception as e:
            logger.error(f"Cache set error: {e}")
    
    def record_request(self, response: LLMResponse):
        """Record request metrics"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO request_history
                (request_id, provider, tokens_used, latency_ms, success, error, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                response.request_id,
                response.provider.value,
                response.tokens_used,
                response.latency_ms,
                response.success,
                response.error,
                response.timestamp.isoformat()
            ))
            
            self.conn.commit()
        except Exception as e:
            logger.error(f"History record error: {e}")


# ============================================================================
# UNIFIED LLM ROUTER
# ============================================================================

class UnifiedLLMRouter:
    """Main router for managing LLM requests across providers"""
    
    def __init__(self, config_path: str = ".hades_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.cache = RequestCache()
        self.providers: Dict[LLMProvider, AbstractLLMProvider] = {}
        self.provider_stats: Dict[LLMProvider, Dict] = {}
        self._initialize_providers()
        self.request_queue: List[LLMRequest] = []
        self.queue_lock = threading.Lock()
        self.current_provider = LLMProvider.MISTRAL
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Config load error: {e}")
        
        return {}
    
    def _initialize_providers(self):
        """Initialize all available providers"""
        providers_to_init = [
            (LLMProvider.MISTRAL, MistralProvider()),
            (LLMProvider.OPENAI, OpenAIProvider()),
            (LLMProvider.AZURE_OPENAI, AzureOpenAIProvider()),
            (LLMProvider.OLLAMA, OllamaProvider()),
            (LLMProvider.FALLBACK, FallbackProvider()),
        ]
        
        for provider_enum, provider_instance in providers_to_init:
            self.providers[provider_enum] = provider_instance
            self.provider_stats[provider_enum] = {
                'requests': 0,
                'successes': 0,
                'failures': 0,
                'total_latency': 0,
                'avg_latency': 0
            }
            
            if provider_instance.is_available():
                logger.info(f"✓ {provider_instance.name} available")
            else:
                logger.info(f"✗ {provider_instance.name} unavailable")
    
    def get_available_providers(self) -> List[str]:
        """Get list of available providers"""
        return [
            provider.name for provider in self.providers.values()
            if provider.is_available()
        ]
    
    def route_request(self, request: LLMRequest, preferred_provider: Optional[LLMProvider] = None) -> LLMResponse:
        """Route request to best available provider"""
        
        # Check cache first
        cached = self.cache.get(request.prompt)
        if cached:
            response = LLMResponse(
                request_id=request.request_id,
                provider=preferred_provider or self.current_provider,
                content=cached,
                cached=True
            )
            self.cache.record_request(response)
            return response
        
        # Determine provider to use
        provider_enum = preferred_provider or self._select_best_provider(request.priority)
        provider = self.providers.get(provider_enum)
        
        if not provider or not provider.is_available():
            # Fall back to fallback provider
            provider_enum = LLMProvider.FALLBACK
            provider = self.providers[provider_enum]
        
        # Generate response
        start_time = time.time()
        try:
            content = provider.generate(request)
            latency_ms = (time.time() - start_time) * 1000
            
            response = LLMResponse(
                request_id=request.request_id,
                provider=provider_enum,
                content=content or "",
                latency_ms=latency_ms,
                success=content is not None
            )
            
            if response.success:
                self.cache.set(request.prompt, content, provider_enum.value)
                self.provider_stats[provider_enum]['successes'] += 1
            else:
                self.provider_stats[provider_enum]['failures'] += 1
            
            self.provider_stats[provider_enum]['requests'] += 1
            self.provider_stats[provider_enum]['total_latency'] += latency_ms
            self.provider_stats[provider_enum]['avg_latency'] = (
                self.provider_stats[provider_enum]['total_latency'] /
                self.provider_stats[provider_enum]['requests']
            )
            
        except Exception as e:
            logger.error(f"Provider {provider.name} error: {e}")
            response = LLMResponse(
                request_id=request.request_id,
                provider=provider_enum,
                content="",
                success=False,
                error=str(e)
            )
            self.provider_stats[provider_enum]['failures'] += 1
            self.provider_stats[provider_enum]['requests'] += 1
        
        self.cache.record_request(response)
        return response
    
    def _select_best_provider(self, priority: RequestPriority) -> LLMProvider:
        """Select best provider based on priority and statistics"""
        available = [
            (enum, provider) for enum, provider in self.providers.items()
            if provider.is_available()
        ]
        
        if not available:
            return LLMProvider.FALLBACK
        
        if priority == RequestPriority.CRITICAL:
            # Use fastest available
            best = min(available, key=lambda x: self.provider_stats[x[0]].get('avg_latency', float('inf')))
            return best[0]
        elif priority == RequestPriority.HIGH:
            # Use most reliable
            best = max(available, key=lambda x: self.provider_stats[x[0]].get('successes', 0))
            return best[0]
        else:
            # Use configured default
            if self.current_provider in [e for e, _ in available]:
                return self.current_provider
            return available[0][0]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get router statistics"""
        return {
            'providers': {
                provider.value: stats
                for provider, stats in self.provider_stats.items()
            },
            'cache_stats': {
                'total_requests': sum(s['requests'] for s in self.provider_stats.values())
            }
        }
    
    def set_preferred_provider(self, provider: LLMProvider):
        """Set preferred provider"""
        if provider in self.providers and self.providers[provider].is_available():
            self.current_provider = provider
            logger.info(f"Preferred provider set to {provider.name}")
        else:
            logger.warning(f"Provider {provider} not available")


# ============================================================================
# INTEGRATION HELPER
# ============================================================================

def create_router() -> UnifiedLLMRouter:
    """Factory function to create unified router"""
    return UnifiedLLMRouter()


if __name__ == "__main__":
    # Test router
    router = UnifiedLLMRouter()
    
    print("Available Providers:", router.get_available_providers())
    
    test_request = LLMRequest(
        prompt="How would you exploit a SQL injection vulnerability?",
        priority=RequestPriority.NORMAL,
        system_prompt="You are HadesAI"
    )
    
    response = router.route_request(test_request)
    print(f"\nResponse from {response.provider.value}:")
    print(response.content[:500])
    print(f"\nLatency: {response.latency_ms:.2f}ms")
    print(f"\nProvider Stats:")
    import pprint
    pprint.pprint(router.get_stats())
