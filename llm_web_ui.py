"""
LLM Web UI - Flask-based web interface for Hades AI conversations
Supports real-time streaming, conversation history, provider switching
"""

import os
import json
import logging
from flask import Flask, render_template, request, jsonify, stream_with_context, Response
from flask_cors import CORS
from functools import wraps
from datetime import datetime
from pathlib import Path

from llm_conversation_core import ConversationManager

logger = logging.getLogger("LLMWebUI")

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app = Flask(__name__)
CORS(app)

# Initialize conversation manager
conv_manager = ConversationManager()


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def require_conv_id(f):
    """Decorator to ensure conversation ID is provided"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        conv_id = request.args.get('conv_id') or request.form.get('conv_id') or request.json.get('conv_id')
        if not conv_id:
            return jsonify({"error": "Missing conversation ID"}), 400
        return f(*args, conv_id=conv_id, **kwargs)
    return decorated_function


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "available_providers": conv_manager.get_available_providers(),
        "timestamp": datetime.now().isoformat()
    }), 200


@app.route('/api/providers', methods=['GET'])
def get_providers():
    """Get available LLM providers"""
    providers = []
    for name, provider in conv_manager.providers.items():
        providers.append({
            "id": name,
            "name": provider.name,
            "available": provider.available
        })
    return jsonify(providers), 200


@app.route('/api/conversations', methods=['GET'])
def list_conversations():
    """List all conversations"""
    limit = request.args.get('limit', 50, type=int)
    conversations = conv_manager.list_conversations(limit)
    return jsonify({
        "conversations": conversations,
        "total": len(conversations)
    }), 200


@app.route('/api/conversations', methods=['POST'])
def create_conversation():
    """Create new conversation"""
    data = request.json or {}
    
    try:
        conv = conv_manager.create_conversation(
            title=data.get('title', 'New Conversation'),
            provider=data.get('provider', 'openai'),
            model=data.get('model', 'gpt-3.5-turbo'),
            system_prompt=data.get('system_prompt'),
            temperature=data.get('temperature', 0.7),
            max_tokens=data.get('max_tokens', 2000)
        )
        
        return jsonify({
            "id": conv.id,
            "title": conv.title,
            "created_at": conv.created_at.isoformat(),
            "provider": conv.provider,
            "model": conv.model
        }), 201
    except Exception as e:
        logger.error(f"Error creating conversation: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/conversations/<conv_id>', methods=['GET'])
def get_conversation(conv_id):
    """Get conversation details"""
    conv = conv_manager.conversations.get(conv_id)
    if not conv:
        conv = conv_manager.load_conversation(conv_id)
    
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    
    messages = [msg.to_dict() for msg in conv.messages]
    
    return jsonify({
        "id": conv.id,
        "title": conv.title,
        "created_at": conv.created_at.isoformat(),
        "updated_at": conv.updated_at.isoformat(),
        "provider": conv.provider,
        "model": conv.model,
        "temperature": conv.temperature,
        "max_tokens": conv.max_tokens,
        "system_prompt": conv.system_prompt,
        "messages": messages,
        "message_count": len(conv.messages)
    }), 200


@app.route('/api/conversations/<conv_id>', methods=['DELETE'])
def delete_conversation(conv_id):
    """Delete conversation"""
    success = conv_manager.delete_conversation(conv_id)
    
    if success:
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "Failed to delete conversation"}), 500


@app.route('/api/conversations/<conv_id>/messages', methods=['POST'])
def send_message(conv_id):
    """Send message to conversation"""
    data = request.json or {}
    content = data.get('content', '')
    use_stream = data.get('stream', False)
    
    if not content:
        return jsonify({"error": "Message content is required"}), 400
    
    try:
        if use_stream:
            def stream_response():
                try:
                    for chunk in conv_manager.send_message(content, conv_id, use_streaming=True):
                        yield json.dumps({"type": "chunk", "content": chunk}) + "\n"
                    yield json.dumps({"type": "done"}) + "\n"
                except Exception as e:
                    yield json.dumps({"type": "error", "error": str(e)}) + "\n"
            
            return Response(
                stream_with_context(stream_response()),
                mimetype='application/x-ndjson'
            ), 200
        else:
            response = conv_manager.send_message(content, conv_id, use_streaming=False)
            return jsonify({
                "role": "assistant",
                "content": response,
                "timestamp": datetime.now().isoformat()
            }), 200
    
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/conversations/<conv_id>/provider', methods=['PUT'])
def switch_provider(conv_id):
    """Switch LLM provider for conversation"""
    data = request.json or {}
    provider = data.get('provider')
    model = data.get('model')
    
    if not provider or not model:
        return jsonify({"error": "Provider and model are required"}), 400
    
    success = conv_manager.switch_provider(conv_id, provider, model)
    
    if success:
        return jsonify({"success": True, "provider": provider, "model": model}), 200
    else:
        return jsonify({"error": "Failed to switch provider"}), 500


@app.route('/api/conversations/<conv_id>/clear', methods=['POST'])
def clear_conversation(conv_id):
    """Clear all messages from conversation"""
    conv = conv_manager.conversations.get(conv_id)
    if not conv:
        conv = conv_manager.load_conversation(conv_id)
    
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    
    conv.messages = []
    conv_manager._save_conversation(conv)
    
    return jsonify({"success": True}), 200


@app.route('/api/conversations/<conv_id>/export', methods=['GET'])
def export_conversation(conv_id):
    """Export conversation as JSON"""
    conv = conv_manager.conversations.get(conv_id)
    if not conv:
        conv = conv_manager.load_conversation(conv_id)
    
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    
    export_data = {
        "id": conv.id,
        "title": conv.title,
        "created_at": conv.created_at.isoformat(),
        "updated_at": conv.updated_at.isoformat(),
        "provider": conv.provider,
        "model": conv.model,
        "temperature": conv.temperature,
        "max_tokens": conv.max_tokens,
        "system_prompt": conv.system_prompt,
        "messages": [msg.to_dict() for msg in conv.messages],
        "metadata": conv.metadata
    }
    
    return jsonify(export_data), 200


# ============================================================================
# WEB INTERFACE ROUTES
# ============================================================================

@app.route('/')
def index():
    """Main chat interface"""
    return render_template('chat.html')


@app.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html')


@app.route('/history')
def history():
    """Conversation history page"""
    return render_template('history.html')


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500


# ============================================================================
# TEMPLATE FUNCTIONS
# ============================================================================

def create_templates():
    """Create HTML templates"""
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    
    # Main chat template
    chat_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hades AI Chat</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
            color: #fff;
            height: 100vh;
            overflow: hidden;
        }
        
        .container {
            display: flex;
            height: 100vh;
        }
        
        .sidebar {
            width: 300px;
            background: #0f0f0f;
            border-right: 1px solid #333;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }
        
        .sidebar-header {
            padding: 20px;
            border-bottom: 1px solid #333;
        }
        
        .sidebar-header h1 {
            font-size: 18px;
            margin-bottom: 10px;
        }
        
        .new-chat-btn {
            width: 100%;
            padding: 10px;
            background: #10a37f;
            border: none;
            border-radius: 6px;
            color: white;
            cursor: pointer;
            font-weight: 500;
            transition: background 0.2s;
        }
        
        .new-chat-btn:hover {
            background: #1a9970;
        }
        
        .conversations-list {
            flex: 1;
            overflow-y: auto;
            padding: 10px;
        }
        
        .conversation-item {
            padding: 12px;
            margin-bottom: 5px;
            background: rgba(255,255,255,0.05);
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .conversation-item:hover {
            background: rgba(255,255,255,0.1);
        }
        
        .conversation-item.active {
            background: #10a37f;
        }
        
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        
        .chat-header {
            padding: 20px;
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .chat-header h2 {
            font-size: 18px;
        }
        
        .provider-selector {
            display: flex;
            gap: 10px;
        }
        
        .provider-selector select {
            padding: 8px 12px;
            background: #2d2d2d;
            color: white;
            border: 1px solid #444;
            border-radius: 6px;
            cursor: pointer;
        }
        
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .message {
            display: flex;
            gap: 10px;
            animation: slideIn 0.3s ease-in-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .message.user {
            justify-content: flex-end;
        }
        
        .message-content {
            max-width: 70%;
            padding: 12px 16px;
            border-radius: 12px;
            word-wrap: break-word;
        }
        
        .message.user .message-content {
            background: #10a37f;
            border-bottom-right-radius: 4px;
        }
        
        .message.assistant .message-content {
            background: #2d2d2d;
            border-bottom-left-radius: 4px;
        }
        
        .chat-input-area {
            padding: 20px;
            border-top: 1px solid #333;
            display: flex;
            gap: 10px;
        }
        
        .input-wrapper {
            flex: 1;
            display: flex;
            gap: 10px;
        }
        
        #messageInput {
            flex: 1;
            padding: 12px 16px;
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 6px;
            color: white;
            font-size: 14px;
            resize: none;
            max-height: 100px;
        }
        
        #messageInput:focus {
            outline: none;
            border-color: #10a37f;
        }
        
        #sendBtn {
            padding: 12px 24px;
            background: #10a37f;
            border: none;
            border-radius: 6px;
            color: white;
            cursor: pointer;
            font-weight: 500;
            transition: background 0.2s;
        }
        
        #sendBtn:hover:not(:disabled) {
            background: #1a9970;
        }
        
        #sendBtn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #10a37f;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .error-message {
            background: #ff4444;
            color: white;
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <div class="sidebar-header">
                <h1>🔥 Hades AI</h1>
                <button class="new-chat-btn" onclick="startNewChat()">New Chat</button>
            </div>
            <div class="conversations-list" id="conversationsList"></div>
        </div>
        
        <div class="main-content">
            <div class="chat-header">
                <h2 id="chatTitle">Start a new conversation</h2>
                <div class="provider-selector">
                    <select id="providerSelect" onchange="switchProvider()">
                        <option value="">Select Provider</option>
                    </select>
                    <select id="modelSelect">
                        <option value="">Select Model</option>
                    </select>
                </div>
            </div>
            
            <div class="chat-messages" id="chatMessages"></div>
            
            <div class="chat-input-area">
                <div class="input-wrapper">
                    <textarea id="messageInput" placeholder="Type your message..." rows="1"></textarea>
                    <button id="sendBtn" onclick="sendMessage()">Send</button>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentConvId = null;
        
        // Auto-resize textarea
        const textarea = document.getElementById('messageInput');
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 100) + 'px';
        });
        
        // Send on Ctrl+Enter
        textarea.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'Enter') {
                sendMessage();
            }
        });
        
        async function startNewChat() {
            try {
                const response = await fetch('/api/conversations', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title: `Chat - ${new Date().toLocaleString()}`,
                        provider: document.getElementById('providerSelect').value || 'openai'
                    })
                });
                
                if (!response.ok) throw new Error('Failed to create conversation');
                
                const conv = await response.json();
                currentConvId = conv.id;
                document.getElementById('chatTitle').textContent = conv.title;
                document.getElementById('chatMessages').innerHTML = '';
                
                loadConversations();
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function loadConversations() {
            try {
                const response = await fetch('/api/conversations?limit=20');
                const data = await response.json();
                
                const list = document.getElementById('conversationsList');
                list.innerHTML = '';
                
                data.conversations.forEach(conv => {
                    const div = document.createElement('div');
                    div.className = `conversation-item ${conv.id === currentConvId ? 'active' : ''}`;
                    div.textContent = conv.title;
                    div.onclick = () => loadConversation(conv.id);
                    list.appendChild(div);
                });
            } catch (error) {
                console.error('Error loading conversations:', error);
            }
        }
        
        async function loadConversation(convId) {
            try {
                const response = await fetch(`/api/conversations/${convId}`);
                if (!response.ok) throw new Error('Failed to load conversation');
                
                const conv = await response.json();
                currentConvId = conv.id;
                document.getElementById('chatTitle').textContent = conv.title;
                
                const messagesDiv = document.getElementById('chatMessages');
                messagesDiv.innerHTML = '';
                
                conv.messages.forEach(msg => {
                    addMessageToUI(msg.role, msg.content);
                });
                
                loadConversations();
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function sendMessage() {
            const content = document.getElementById('messageInput').value.trim();
            if (!content || !currentConvId) return;
            
            document.getElementById('messageInput').value = '';
            addMessageToUI('user', content);
            
            const sendBtn = document.getElementById('sendBtn');
            sendBtn.disabled = true;
            
            try {
                const response = await fetch(`/api/conversations/${currentConvId}/messages`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content, stream: true })
                });
                
                if (!response.ok) throw new Error('Failed to send message');
                
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let fullResponse = '';
                const messageId = Date.now();
                addMessageToUI('assistant', '', messageId);
                
                while (true) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    
                    const text = decoder.decode(value);
                    const lines = text.split('\\n');
                    
                    for (const line of lines) {
                        if (!line) continue;
                        try {
                            const data = JSON.parse(line);
                            if (data.type === 'chunk') {
                                fullResponse += data.content;
                                updateMessageInUI(messageId, fullResponse);
                            }
                        } catch (e) {}
                    }
                }
            } catch (error) {
                console.error('Error:', error);
                addMessageToUI('assistant', 'Error: ' + error.message);
            } finally {
                sendBtn.disabled = false;
                document.getElementById('messageInput').focus();
            }
        }
        
        function addMessageToUI(role, content, id = null) {
            const messagesDiv = document.getElementById('chatMessages');
            const msgDiv = document.createElement('div');
            msgDiv.className = `message ${role}`;
            msgDiv.id = id ? `msg-${id}` : '';
            
            const contentDiv = document.createElement('div');
            contentDiv.className = 'message-content';
            contentDiv.textContent = content;
            
            msgDiv.appendChild(contentDiv);
            messagesDiv.appendChild(msgDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        function updateMessageInUI(id, content) {
            const msgDiv = document.getElementById(`msg-${id}`);
            if (msgDiv) {
                msgDiv.querySelector('.message-content').textContent = content;
                document.getElementById('chatMessages').scrollTop = 
                    document.getElementById('chatMessages').scrollHeight;
            }
        }
        
        async function switchProvider() {
            // Implementation for switching provider
        }
        
        async function loadProviders() {
            try {
                const response = await fetch('/api/providers');
                const providers = await response.json();
                
                const select = document.getElementById('providerSelect');
                providers.forEach(p => {
                    if (p.available) {
                        const option = document.createElement('option');
                        option.value = p.id;
                        option.textContent = p.name;
                        select.appendChild(option);
                    }
                });
            } catch (error) {
                console.error('Error loading providers:', error);
            }
        }
        
        // Initialize
        loadProviders();
        loadConversations();
    </script>
</body>
</html>
"""
    
    (templates_dir / "chat.html").write_text(chat_html)
    logger.info("Templates created successfully")


# ============================================================================
# MAIN
# ============================================================================

def run_server(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """Run the Flask web server"""
    create_templates()
    logger.info(f"Starting LLM Web UI at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    run_server(debug=True)
