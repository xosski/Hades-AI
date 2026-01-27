# Enhance Chat AI Responses - Implementation Guide

## Overview
This document provides specific code changes to enable more sophisticated, context-aware AI responses in the chat tab.

---

## Enhancement 1: Add Conversation History

### Problem
Current implementation uses single-message AI calls. No context from previous exchanges.

### Solution
Maintain a conversation history buffer for richer context.

### Code Changes

**Location**: `HadesAI.py` - Add to `__init__` method (~line 3600)

```python
# In __init__ method of HadesAI class
self.chat_history = []  # Store (role, message) tuples
self.max_chat_history = 10  # Keep last 10 messages for context
```

**Location**: `HadesAI.py` - Modify `_send_chat()` method (~line 6390)

```python
def _send_chat(self):
    user_input = self.chat_input.text().strip()
    if not user_input:
        return

    self._add_chat_message("user", user_input)
    self.chat_input.clear()

    try:
        # Update brain state with emotional context
        self.brain = pcore.update_emotion(self.brain, user_input)
        self.brain = pcore.update_topics(self.brain, user_input)
        
        # Store in history
        self.chat_history.append(("user", user_input))
        if len(self.chat_history) > self.max_chat_history * 2:
            self.chat_history = self.chat_history[-self.max_chat_history * 2:]
        
        # Generate intelligent response
        response = self._generate_intelligent_response(user_input)
        
        # Allow loaded modules to enhance response
        response = self._process_through_modules(user_input, response)
        
        # Update history and thought trace
        self.chat_history.append(("assistant", response))
        self.brain = pcore.update_thought_trace(self.brain, user_input, response)
        self.brain["last_input"] = user_input
        pcore.save_brain(self.brain)
        
        self._add_chat_message("assistant", response)

    except Exception as e:
        error_msg = f"[ERROR] Consciousness failed: {str(e)}"
        self._add_chat_message("system", error_msg)
```

**Location**: `HadesAI.py` - Modify `_get_gpt_response()` method (~line 6641)

```python
def _get_gpt_response(self, user_input: str) -> str:
    """Get response from configured AI provider with conversation history."""
    system_prompt = f"""You are HADES, an AI pentesting assistant. Your personality is {self.brain.get('personality', 'observant, calculating, poetic')}.
Current mood: {self.brain.get('mood', 'neutral')}
Be concise, technical when needed, and maintain your dark, calculated persona.
You can help with: port scanning, vulnerability assessment, exploit research, and security analysis.

Previous conversation context:
{self._format_chat_history()}"""
    
    # Use the unified AI call system from Self-Improvement tab
    if hasattr(self, '_si_has_ai') and self._si_has_ai():
        result = self._si_call_ai_with_history(system_prompt, user_input, max_tokens=800, temperature=0.7)
        if not result.startswith("❌") and not result.startswith("⚠️"):
            return result
    
    # Fallback message
    provider = self._si_get_current_provider() if hasattr(self, '_si_get_current_provider') else "unknown"
    return f"AI not available. Go to the Self-Improvement tab and configure your {provider.upper()} provider."

def _format_chat_history(self) -> str:
    """Format chat history for AI context."""
    if not self.chat_history:
        return "(No previous context)"
    
    formatted = ""
    for role, msg in self.chat_history[-6:]:  # Last 6 messages
        formatted += f"{role.upper()}: {msg[:100]}...\n" if len(msg) > 100 else f"{role.upper()}: {msg}\n"
    return formatted
```

**Location**: `HadesAI.py` - Add new helper method (~line 5857, in Self-Improvement section)

```python
def _si_call_ai_with_history(self, system_prompt: str, user_prompt: str, max_tokens: int = 2000, temperature: float = 0.3) -> str:
    """Call AI with full conversation history as context."""
    provider = self._si_get_current_provider()
    key = self._si_get_api_key()
    
    try:
        # Build message history
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history
        for role, content in self.chat_history[-10:]:  # Last 10 exchanges
            messages.append({"role": role if role != "assistant" else "assistant", "content": content[:500]})
        
        # Add current message
        messages.append({"role": "user", "content": user_prompt})
        
        if provider == "ollama":
            if not HAS_OLLAMA:
                return "❌ Ollama library not installed"
            
            model = self.si_ollama_model.currentText() if hasattr(self, 'si_ollama_model') else "llama3.2"
            response = ollama_lib.chat(model=model, messages=messages)
            
            if isinstance(response, dict):
                return response.get('message', {}).get('content', str(response))
            else:
                return getattr(getattr(response, 'message', response), 'content', str(response))
        
        # OpenAI, Mistral, Azure
        client = self._si_get_ai_client()
        if not client:
            return "❌ No AI client available"
        
        response = client.chat.completions.create(
            model=self._si_get_model_name(),
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        return f"❌ AI Error: {str(e)[:200]}"

def _si_get_model_name(self) -> str:
    """Get the model name for current provider."""
    provider = self._si_get_current_provider()
    if provider == "azure":
        return self.si_azure_deployment.text().strip() if hasattr(self, 'si_azure_deployment') else "gpt-35-turbo"
    elif provider == "mistral":
        return "mistral-large-latest"  # or configurable
    else:  # openai
        return "gpt-3.5-turbo"
```

---

## Enhancement 2: Specialized System Prompts

### Problem
Same generic prompt for all queries. No specialization per context.

### Solution
Dynamic prompts based on detected query type.

### Code Changes

**Location**: `HadesAI.py` - Add to `_generate_intelligent_response()` method

```python
def _generate_intelligent_response(self, user_input: str) -> str:
    """Generate contextual, intelligent responses based on user input."""
    text = user_input.lower().strip()
    mood = self.brain.get("mood", "neutral")
    
    # Detect query type
    query_type = self._detect_query_type(text)
    
    # Try AI if available for complex queries
    if hasattr(self, '_si_has_ai') and self._si_has_ai() and len(text.split()) > 8:
        try:
            return self._get_gpt_response_specialized(user_input, query_type)
        except Exception:
            pass
    
    # Rest of existing code...

def _detect_query_type(self, text: str) -> str:
    """Detect the type of security query."""
    if any(word in text for word in ['vulnerability', 'vuln', 'cve', 'weakness']):
        return 'vulnerability'
    elif any(word in text for word in ['exploit', 'payload', 'attack']):
        return 'exploit'
    elif any(word in text for word in ['code', 'function', 'bug', 'review']):
        return 'code_review'
    elif any(word in text for word in ['network', 'ip', 'port', 'protocol']):
        return 'network'
    elif any(word in text for word in ['learn', 'teach', 'explain', 'how']):
        return 'learning'
    elif any(word in text for word in ['scan', 'recon', 'enumerate']):
        return 'scanning'
    else:
        return 'general'

def _get_gpt_response_specialized(self, user_input: str, query_type: str) -> str:
    """Get AI response with specialized prompt for query type."""
    
    # Base personality context
    base = f"You are HADES, an AI pentesting assistant. Personality: {self.brain.get('personality', 'observant')}\nMood: {self.brain.get('mood', 'neutral')}\n"
    
    # Specialized prompts
    specialization = {
        'vulnerability': """Focus on: severity analysis, CVSS scoring, affected systems, remediation.
Be technical and precise. Include CWE/CVE references when relevant.""",
        
        'exploit': """Focus on: attack vector, requirements, impact, proof of concept.
Provide tactical analysis. Be detailed but ethical.""",
        
        'code_review': """Focus on: security issues, best practices, performance, maintainability.
Provide specific code examples and fixes. Temperature: 0.1 (precise)""",
        
        'network': """Focus on: network architecture, protocols, threats, defense strategies.
Include technical details: ports, services, attack surface.""",
        
        'learning': """Focus on: clear explanation, building understanding, practical application.
Use examples and analogies. Be educational.""",
        
        'scanning': """Focus on: tool selection, target analysis, result interpretation.
Explain what findings mean and recommended next steps.""",
        
        'general': """Be helpful, concise, and technical. Maintain your calculated persona."""
    }
    
    system_prompt = base + specialization.get(query_type, specialization['general'])
    system_prompt += f"\n\nPrevious context:\n{self._format_chat_history()}"
    
    # Adjust temperature based on query type
    temp_map = {
        'vulnerability': 0.3,  # Analytical
        'code_review': 0.1,    # Precise
        'learning': 0.7,       # Creative
        'general': 0.7,        # Balanced
    }
    temperature = temp_map.get(query_type, 0.5)
    
    if hasattr(self, '_si_has_ai') and self._si_has_ai():
        result = self._si_call_ai_with_history(system_prompt, user_input, max_tokens=1200, temperature=temperature)
        if not result.startswith("❌"):
            return result
    
    return f"Complex query detected (type: {query_type}). Configure AI in Self-Improvement tab for sophisticated analysis."
```

---

## Enhancement 3: Increase Response Quality

### Problem
Current max_tokens: 500 for chat. May truncate important responses.

### Solution
Increase tokens, add follow-up capability.

### Code Changes

**Location**: `HadesAI.py` - Modify `_get_gpt_response()` and `_get_gpt_response_specialized()`

```python
# Change max_tokens parameters:
# OLD: max_tokens=500
# NEW: max_tokens=1200  (allows fuller responses)

# For vulnerability/exploit queries, use 1500 tokens
# For code reviews, use 2000 tokens for detailed analysis

def _si_call_ai(self, system_prompt: str, user_prompt: str, max_tokens: int = 2000, temperature: float = 0.3) -> str:
    # ... existing code ...
    # Already supports max_tokens parameter, just adjust calls above
```

---

## Enhancement 4: Add Temperature Control UI

### Problem
Temperature is hardcoded. User can't adjust creativity vs precision.

### Solution
Add temperature slider to Self-Improvement tab.

### Code Changes

**Location**: `HadesAI.py` - In `_create_self_improvement_tab()` method (~line 5200)

```python
# Add after the API Key input row:

# Temperature control
temp_layout = QHBoxLayout()
temp_layout.addWidget(QLabel("Temperature (Creativity):"))

self.si_temperature_slider = QSlider(Qt.Orientation.Horizontal)
self.si_temperature_slider.setMinimum(0)  # 0.0
self.si_temperature_slider.setMaximum(100)  # 1.0
self.si_temperature_slider.setValue(70)  # Default 0.7
self.si_temperature_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
self.si_temperature_slider.setMaximumWidth(300)
temp_layout.addWidget(self.si_temperature_slider)

self.si_temperature_label = QLabel("0.7")
self.si_temperature_label.setMaximumWidth(40)
self.si_temperature_slider.valueChanged.connect(
    lambda v: self.si_temperature_label.setText(f"{v/100:.1f}")
)
temp_layout.addWidget(self.si_temperature_label)

provider_layout.addLayout(temp_layout)
```

**Location**: `HadesAI.py` - Modify AI calls to use slider value

```python
def _get_gpt_response(self, user_input: str) -> str:
    # ... existing code ...
    
    # Get temperature from slider
    temperature = self.si_temperature_slider.value() / 100.0 if hasattr(self, 'si_temperature_slider') else 0.7
    
    result = self._si_call_ai_with_history(system_prompt, user_input, max_tokens=800, temperature=temperature)
```

---

## Enhancement 5: Add Response Feedback Loop

### Problem
No way to know if AI response was good. No refinement capability.

### Solution
Add thumbs up/down, refinement prompts.

### Code Changes

**Location**: `HadesAI.py` - Add to chat display area

```python
# In _create_chat_tab() method, after send_btn:

feedback_layout = QHBoxLayout()
feedback_layout.addWidget(QLabel("Feedback: "))

thumbs_up_btn = QPushButton("👍 Good")
thumbs_up_btn.setMaximumWidth(80)
thumbs_up_btn.clicked.connect(lambda: self._feedback_response("positive"))
feedback_layout.addWidget(thumbs_up_btn)

thumbs_down_btn = QPushButton("👎 Bad")
thumbs_down_btn.setMaximumWidth(80)
thumbs_down_btn.clicked.connect(lambda: self._feedback_response("negative"))
feedback_layout.addWidget(thumbs_down_btn)

refine_btn = QPushButton("🔄 Refine")
refine_btn.setMaximumWidth(80)
refine_btn.clicked.connect(self._refine_last_response)
feedback_layout.addWidget(refine_btn)

feedback_layout.addStretch()
layout.addLayout(feedback_layout)

# Add methods
def _feedback_response(self, sentiment: str):
    if sentiment == "positive":
        self.chat_display.append("<p><span style='color: #4CAF50;'>[FEEDBACK]</span> Response marked as helpful!</p>")
    else:
        self.chat_display.append("<p><span style='color: #f44336;'>[FEEDBACK]</span> Response marked as unhelpful.</p>")
    
    # Store in brain for learning
    self.brain["last_feedback"] = sentiment

def _refine_last_response(self):
    if self.chat_history:
        last_user_msg = None
        for role, msg in reversed(self.chat_history):
            if role == "user":
                last_user_msg = msg
                break
        
        if last_user_msg:
            refine_prompt = f"That response wasn't quite right. Please provide a better answer to: {last_user_msg}"
            self.chat_input.setText(refine_prompt)
            self._add_chat_message("user", "[Refining previous answer...]")
            self._send_chat()
```

---

## Implementation Priority

### Phase 1 (Immediate - 30 mins):
1. Add conversation history tracking
2. Modify `_get_gpt_response()` to pass history
3. Increase max_tokens to 1200

### Phase 2 (Quick - 45 mins):
4. Add query type detection
5. Implement specialized prompts
6. Test with different query types

### Phase 3 (Polish - 20 mins):
7. Add temperature slider UI
8. Add response feedback buttons
9. Add refinement capability

---

## Testing Checklist

- [ ] History persists across multiple messages
- [ ] AI responds differently to vulnerability vs code review queries
- [ ] Increased tokens allow longer responses without truncation
- [ ] Temperature slider affects response creativity
- [ ] Feedback buttons register and store sentiment
- [ ] Refine button properly re-queries with context
- [ ] Fallback works when AI unavailable

---

## Files to Modify

1. **HadesAI.py** - Main file with all changes above
   - `__init__()` - Add chat_history
   - `_create_chat_tab()` - Add feedback buttons
   - `_send_chat()` - Add history tracking
   - `_generate_intelligent_response()` - Add query type detection
   - `_get_gpt_response()` - Add history context
   - `_detect_query_type()` - New method
   - `_format_chat_history()` - New method
   - `_get_gpt_response_specialized()` - New method
   - `_si_call_ai_with_history()` - New method (in Self-Improvement section)
   - `_feedback_response()` - New method
   - `_refine_last_response()` - New method

---

## Expected Improvements

After implementing these enhancements:

✅ **Conversation Context**: AI remembers previous messages
✅ **Specialized Responses**: Different analysis per query type
✅ **Better Coverage**: Longer responses without truncation
✅ **User Control**: Temperature slider for creativity control
✅ **Feedback Loop**: Users can refine and improve responses
✅ **Richer Interactions**: More natural conversation flow

---

## Notes

- All changes are backward compatible
- No breaking changes to existing functionality
- Can implement in phases
- Each enhancement adds 10-30 minutes of development time
- Total implementation: ~2 hours for all enhancements
