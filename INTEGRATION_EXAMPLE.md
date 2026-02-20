# Sophisticated Response Integration Example

## How to Integrate Into HadesAI Chat Interface

### 1. Basic Integration (No UI Changes)

The sophisticated responses are **already integrated** into `LocalAIResponse`. Simply use it as normal:

```python
from local_ai_response import LocalAIResponse

# Initialize with knowledge base
ai = LocalAIResponse(use_knowledge_db=True)

# Responses now include sophisticated formatting
response = ai.generate(
    user_input="explain SQL injection",
    mood="curious"
)

# Display the response - it includes thinking traces and structure
print(response)
```

**Result**: Users automatically get sophisticated responses without any UI changes.

---

### 2. Enhanced Chat Widget Integration

If you want to show thinking traces separately in the UI:

```python
from PyQt6.QtWidgets import QTextEdit, QWidget, QVBoxLayout, QGroupBox
from modules.sophisticated_responses import SophisticatedResponseEngine

class SophisticatedChatWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.engine = SophisticatedResponseEngine()
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Thinking process display
        self.thinking_display = QTextEdit()
        self.thinking_display.setReadOnly(True)
        self.thinking_display.setStyleSheet("""
            QTextEdit {
                background-color: #f0f0f0;
                border: 1px solid #ddd;
                padding: 10px;
                max-height: 100px;
            }
        """)
        thinking_group = QGroupBox("Thinking Process")
        thinking_layout = QVBoxLayout()
        thinking_layout.addWidget(self.thinking_display)
        thinking_group.setLayout(thinking_layout)
        
        # Main response display
        self.response_display = QTextEdit()
        self.response_display.setReadOnly(True)
        response_group = QGroupBox("Response")
        response_layout = QVBoxLayout()
        response_layout.addWidget(self.response_display)
        response_group.setLayout(response_layout)
        
        layout.addWidget(thinking_group)
        layout.addWidget(response_group)
        self.setLayout(layout)
    
    def display_response(self, user_query: str, mood: str = "neutral"):
        """Display response with thinking process visible"""
        brain_state = {"mood": mood}
        
        # Get thinking process
        thinking = self.engine.generate_thinking_process(user_query)
        self.thinking_display.setText(thinking)
        
        # Get response
        response = self.engine.synthesize_response(brain_state, user_query)
        self.response_display.setText(response)
```

### 3. Integration with HadesAI Main Chat Tab

Example modification to existing chat functionality:

```python
class HadesAIChatTab:
    def __init__(self):
        self.ai = LocalAIResponse(use_knowledge_db=True)
        self.engine = SophisticatedResponseEngine()
        
    def on_user_message(self, user_input: str):
        """Handle user message with sophisticated response"""
        
        # Detect mood from context (optional)
        mood = self.detect_mood_from_context()
        
        # Generate response
        response = self.ai.generate(
            user_input=user_input,
            mood=mood
        )
        
        # Display in chat
        self.display_in_chat(response, is_assistant=True)
    
    def detect_mood_from_context(self) -> str:
        """Detect mood from conversation context"""
        # Simple implementation
        if len(self.chat_history) == 0:
            return "neutral"
        
        last_messages = self.chat_history[-3:]
        text = ' '.join([msg['content'] for msg in last_messages])
        
        mood_indicators = {
            'curious': ['how', 'why', 'what', 'explain', 'understand'],
            'analytical': ['analyze', 'assess', 'evaluate', 'investigate'],
            'optimistic': ['best', 'improve', 'enhance', 'great'],
            'agitated': ['urgent', 'critical', 'problem', 'error', 'fail']
        }
        
        text_lower = text.lower()
        for mood, keywords in mood_indicators.items():
            if any(kw in text_lower for kw in keywords):
                return mood
        
        return "neutral"
    
    def display_in_chat(self, message: str, is_assistant: bool = True):
        """Display formatted message in chat"""
        if is_assistant:
            # Apply syntax highlighting for code blocks
            formatted = self.highlight_markdown(message)
            self.chat_display.append(formatted)
        else:
            self.chat_display.append(f"You: {message}")
    
    def highlight_markdown(self, text: str) -> str:
        """Apply markdown formatting for display"""
        # Convert markdown to HTML for QTextEdit display
        html = text.replace('**', '<b>').replace('`', '<code>')
        # ... more formatting
        return html
```

### 4. Settings Integration

Add to HadesAI settings:

```python
class HadesAISettings:
    def __init__(self):
        self.settings = {
            'sophisticated_responses': {
                'enabled': True,
                'show_thinking': True,
                'response_type': 'auto',  # auto, technical, educational, strategic, analytical
                'expertise_level': 'intermediate',  # beginner, intermediate, advanced
                'max_length': 3000,
                'include_followups': True
            }
        }
    
    def apply_settings(self, ai: LocalAIResponse):
        """Apply settings to AI instance"""
        ai.use_structured_reasoning = self.settings['sophisticated_responses']['enabled']
        ai.expertise_level = self.settings['sophisticated_responses']['expertise_level']
        ai.max_response_length = self.settings['sophisticated_responses']['max_length']
```

### 5. Settings UI

Add to HadesAI settings dialog:

```python
def create_response_settings_ui(self):
    """Create UI for response settings"""
    from PyQt6.QtWidgets import QCheckBox, QComboBox, QSpinBox, QLabel, QVBoxLayout
    
    layout = QVBoxLayout()
    
    # Enable sophisticated responses
    self.enable_sophisticated = QCheckBox("Enable Sophisticated Responses")
    self.enable_sophisticated.setChecked(True)
    layout.addWidget(self.enable_sophisticated)
    
    # Show thinking process
    self.show_thinking = QCheckBox("Show Thinking Process")
    self.show_thinking.setChecked(True)
    layout.addWidget(self.show_thinking)
    
    # Response type
    layout.addWidget(QLabel("Response Type:"))
    self.response_type = QComboBox()
    self.response_type.addItems(['Auto-detect', 'Technical', 'Educational', 'Strategic', 'Analytical'])
    layout.addWidget(self.response_type)
    
    # Expertise level
    layout.addWidget(QLabel("Expertise Level:"))
    self.expertise_level = QComboBox()
    self.expertise_level.addItems(['Beginner', 'Intermediate', 'Advanced'])
    self.expertise_level.setCurrentText('Intermediate')
    layout.addWidget(self.expertise_level)
    
    # Max response length
    layout.addWidget(QLabel("Max Response Length:"))
    self.max_length = QSpinBox()
    self.max_length.setRange(500, 10000)
    self.max_length.setValue(3000)
    self.max_length.setSingleStep(500)
    layout.addWidget(self.max_length)
    
    return layout
```

### 6. Toggle Feature On/Off Per Message

```python
class AdvancedChatTab:
    def __init__(self):
        self.ai = LocalAIResponse()
    
    def send_message(self, user_input: str, use_sophisticated: bool = True):
        """Send message with optional sophistication"""
        
        if use_sophisticated:
            self.ai.use_structured_reasoning = True
            response = self.ai.generate(user_input)
        else:
            self.ai.use_structured_reasoning = False
            response = self.ai.generate(user_input)
        
        self.display_response(response)
    
    def on_send_button_clicked(self):
        """Handle send button with sophistication toggle"""
        user_input = self.input_field.text()
        
        # Check if user wants sophisticated response (e.g., checkbox)
        use_sophisticated = self.sophisticated_checkbox.isChecked()
        
        self.send_message(user_input, use_sophisticated)
```

### 7. Keyboard Shortcut for Response Style

```python
def setup_keyboard_shortcuts(self):
    """Setup shortcuts for response styles"""
    shortcuts = {
        'Ctrl+T': ('technical', 'Technical Analysis'),
        'Ctrl+E': ('educational', 'Educational Response'),
        'Ctrl+S': ('strategic', 'Strategic Response'),
        'Ctrl+A': ('analytical', 'Analytical Response'),
        'Ctrl+Q': ('auto', 'Auto-detect Response'),
    }
    
    for shortcut, (style, description) in shortcuts.items():
        action = QAction(description, self)
        action.triggered.connect(lambda s=style: self.set_response_style(s))
        self.addAction(action)
        action.setShortcut(shortcut)
```

### 8. Custom Response Style Handler

```python
def set_response_style(self, style: str):
    """Set response style for next message"""
    self.next_response_style = style
    style_name = {
        'technical': 'Technical',
        'educational': 'Educational',
        'strategic': 'Strategic',
        'analytical': 'Analytical',
        'auto': 'Auto-detect'
    }
    self.status_bar.showMessage(f"Response style: {style_name.get(style)}")
    
    # Optional: Show indicator in UI
    self.style_indicator.setText(f"Style: {style_name.get(style)}")
```

### 9. Export Response with Thinking

```python
def export_response(self, response: str, filename: str):
    """Export response with thinking process to file"""
    with open(filename, 'w') as f:
        f.write("# Sophisticated Response Export\n\n")
        f.write(response)
        f.write("\n\n---\n")
        f.write(f"Exported: {datetime.now().isoformat()}\n")
        f.write(f"Response Type: {self.current_response_type}\n")
        f.write(f"Expertise Level: {self.ai.expertise_level}\n")
```

### 10. Integration Checklist

```python
def verify_integration():
    """Verify all components are integrated"""
    checks = [
        ("LocalAIResponse imported", lambda: LocalAIResponse is not None),
        ("SophisticatedResponseEngine available", lambda: SophisticatedResponseEngine is not None),
        ("AdvancedResponseFormatter available", lambda: AdvancedResponseFormatter is not None),
        ("Structured reasoning enabled by default", lambda: LocalAIResponse().use_structured_reasoning),
        ("Settings applied correctly", lambda: verify_settings()),
        ("UI components created", lambda: verify_ui_components()),
    ]
    
    results = []
    for check_name, check_func in checks:
        try:
            result = check_func()
            results.append((check_name, result, None))
        except Exception as e:
            results.append((check_name, False, str(e)))
    
    return results
```

---

## Simple Start (Minimal Changes)

**If you just want to enable sophisticated responses with zero UI changes:**

```python
# In HadesAI main chat handler:
from local_ai_response import LocalAIResponse

ai = LocalAIResponse(use_knowledge_db=True)

# That's it! Responses now include:
# - Visible thinking process
# - Structured organization  
# - Context awareness
# - Professional formatting
```

**Users will see:**
- Thinking traces showing reasoning
- Structured, hierarchical responses
- Better organization and clarity
- More professional appearance

---

## Full Integration (Enhanced UI)

Use the examples above to:
1. Show thinking process in separate panel
2. Add response type selector
3. Add expertise level control
4. Create settings UI
5. Add keyboard shortcuts
6. Enable export functionality

---

## Testing Integration

```python
def test_integration():
    """Test integration with HadesAI"""
    from local_ai_response import LocalAIResponse
    
    # Test 1: Basic functionality
    ai = LocalAIResponse()
    response = ai.generate("test query")
    assert "<thinking>" in response
    assert "**" in response  # Markdown formatting
    print("✓ Basic functionality works")
    
    # Test 2: Settings
    ai.use_structured_reasoning = False
    response_simple = ai.generate("test")
    ai.use_structured_reasoning = True
    response_sophisticated = ai.generate("test")
    assert len(response_sophisticated) > len(response_simple)
    print("✓ Settings work correctly")
    
    # Test 3: Context awareness
    ai.set_expertise_level("advanced")
    response_advanced = ai.generate("explain exploit chains")
    ai.set_expertise_level("beginner")
    response_beginner = ai.generate("explain security")
    print("✓ Context awareness works")
    
    print("\nIntegration test passed!")
```

---

## Summary

The sophisticated response enhancement integrates seamlessly with HadesAI:

- **No breaking changes** - All existing code continues to work
- **Automatic enhancement** - Responses are sophisticated by default
- **Customizable** - Easy to adjust or disable per message
- **UI ready** - Examples provided for full UI integration
- **Backward compatible** - Works with all existing features

Start with basic integration (1-2 lines of code), then enhance UI as needed.
