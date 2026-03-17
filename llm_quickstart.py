#!/usr/bin/env python3
"""
Hades AI LLM - Quick Start Script
Easy setup and testing of LLM conversation system
"""

import os
import sys
import subprocess
from pathlib import Path

class QuickStart:
    """Quick start helper"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
    
    def print_banner(self):
        """Print welcome banner"""
        print("""
╔═══════════════════════════════════════════════╗
║      🔥 HADES AI LLM QUICK START 🔥          ║
║    Multi-LLM Conversation System Setup        ║
╚═══════════════════════════════════════════════╝
""")
    
    def check_python(self):
        """Check Python version"""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 9):
            print("❌ Python 3.9+ required")
            return False
        print(f"✓ Python {version.major}.{version.minor} detected")
        return True
    
    def check_dependencies(self):
        """Check required dependencies"""
        print("\n📦 Checking dependencies...")
        
        required = {
            'flask': 'Flask web framework',
            'flask_cors': 'CORS support',
            'openai': 'OpenAI API (optional)',
            'mistralai': 'Mistral AI API (optional)',
            'ollama': 'Ollama client (optional)',
        }
        
        missing = []
        for package, description in required.items():
            try:
                __import__(package)
                print(f"  ✓ {package}: {description}")
            except ImportError:
                print(f"  ✗ {package}: {description}")
                if package not in ['openai', 'mistralai', 'ollama']:
                    missing.append(package)
        
        if missing:
            print(f"\n⚠️  Missing required packages: {', '.join(missing)}")
            install = input("Install them now? (y/n): ").strip().lower() == 'y'
            if install:
                self.install_dependencies()
        
        return True
    
    def install_dependencies(self):
        """Install required dependencies"""
        print("\n📥 Installing dependencies...")
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install',
            'flask', 'flask-cors', 'openai', 'mistralai', 'ollama', 'python-dotenv'
        ])
        print("✓ Dependencies installed")
    
    def setup_env(self):
        """Setup environment file"""
        env_file = self.base_dir / '.env'
        
        if env_file.exists():
            print("\n✓ .env file already exists")
            return
        
        print("\n⚙️  Setting up environment...")
        
        env_content = """# Hades AI LLM Configuration
# Copy your API keys here (optional)

# OpenAI API
# Get from: https://platform.openai.com/api-keys
OPENAI_API_KEY=

# Mistral AI API
# Get from: https://console.mistral.ai/api-keys
MISTRAL_API_KEY=

# Azure OpenAI
AZURE_OPENAI_API_KEY=
AZURE_OPENAI_ENDPOINT=

# Ollama (local, no key needed)
# Ollama: https://ollama.ai
OLLAMA_BASE_URL=http://localhost:11434
"""
        
        env_file.write_text(env_content)
        print(f"✓ Created .env file: {env_file}")
        print("  ⚠️  Add your API keys if using OpenAI/Mistral/Azure")
    
    def check_ollama(self):
        """Check if Ollama is running"""
        print("\n🤖 Checking Ollama (local LLM)...")
        
        try:
            import requests
            resp = requests.get("http://localhost:11434/api/tags", timeout=2)
            if resp.status_code == 200:
                print("  ✓ Ollama is running")
                models = resp.json().get('models', [])
                if models:
                    print(f"  ✓ Available models: {len(models)}")
                    for model in models[:3]:
                        print(f"    - {model.get('name', 'unknown')}")
                return True
            else:
                print("  ✗ Ollama not responding properly")
        except:
            print("  ℹ️  Ollama not running (optional)")
            print("     Install from: https://ollama.ai")
            print("     Run: ollama pull llama2 && ollama serve")
        
        return False
    
    def test_providers(self):
        """Test available providers"""
        print("\n🧪 Testing LLM providers...")
        
        try:
            from llm_conversation_core import ConversationManager
            
            manager = ConversationManager()
            available = manager.get_available_providers()
            
            if not available:
                print("  ⚠️  No providers available yet")
                print("  • Add API keys to .env and restart")
                print("  • Or install Ollama for free local LLM")
                return False
            
            print(f"  ✓ Available providers: {', '.join(available)}")
            
            for provider_name in available:
                provider = manager.providers[provider_name]
                status = "✓" if provider.available else "✗"
                print(f"    {status} {provider.name}")
            
            return True
        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
            return False
    
    def show_usage(self):
        """Show usage instructions"""
        print("""
╔═══════════════════════════════════════════════╗
║          🚀 QUICK START GUIDE                 ║
╚═══════════════════════════════════════════════╝

📱 WEB INTERFACE:
  python llm_web_ui.py
  → Visit http://localhost:5000 in your browser

💻 CLI INTERFACE:
  python llm_cli.py
  → Interactive terminal chat

📚 PYTHON API:
  from llm_conversation_core import ConversationManager
  manager = ConversationManager()
  conv = manager.create_conversation("My Chat")
  response = manager.send_message("Hello!", conv_id=conv.id)

🔗 INTEGRATION WITH HADES:
  # In HadesAI.py or other modules:
  from llm_conversation_core import ConversationManager
  conv_manager = ConversationManager()
  # Use for analysis, exploit generation, etc.

📖 DOCUMENTATION:
  See: LLM_INTEGRATION_GUIDE.md

🎯 RECOMMENDED SETUP:
  1. For free local LLM:
     - Install: pip install ollama
     - Download: ollama pull llama2
     - Run: ollama serve
  
  2. For cloud LLMs:
     - Get API keys from OpenAI/Mistral/Azure
     - Add to .env file
  
  3. Start using:
     - Try CLI: python llm_cli.py --new "Test"
     - Try Web: python llm_web_ui.py

🆘 TROUBLESHOOTING:
  • "No provider available" → Install Ollama or add API keys
  • "Database locked" → Close other instances
  • "Slow responses" → Use local Ollama instead of cloud

✨ FEATURES:
  ✓ Real-time streaming responses
  ✓ Conversation history & persistence
  ✓ Multiple LLM providers
  ✓ Automatic fallback
  ✓ Export conversations
  ✓ Web UI + CLI + Python API
""")
    
    def run(self):
        """Run quick start"""
        self.print_banner()
        
        steps = [
            ("Checking Python", self.check_python),
            ("Checking dependencies", self.check_dependencies),
            ("Setting up environment", self.setup_env),
            ("Checking Ollama", self.check_ollama),
            ("Testing providers", self.test_providers),
        ]
        
        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            try:
                step_func()
            except Exception as e:
                print(f"  ⚠️  {str(e)}")
        
        self.show_usage()
        
        print("\n✨ Setup complete! Ready to chat with Hades AI LLM\n")


if __name__ == "__main__":
    qs = QuickStart()
    qs.run()
