#!/usr/bin/env python3
"""
Multi-LLM Exploit Generator - Setup Verification Script
Checks that everything is installed and configured correctly
"""

import sys
import os
import subprocess
from pathlib import Path

def print_header(text):
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")

def print_status(status, message):
    symbol = "✓" if status else "✗"
    color = "\033[92m" if status else "\033[91m"
    reset = "\033[0m"
    print(f"{color}{symbol}{reset} {message}")

def check_python_version():
    """Check Python version"""
    print_header("Python Environment")
    
    version = sys.version_info
    py_version = f"Python {version.major}.{version.minor}.{version.micro}"
    
    ok = version.major >= 3 and version.minor >= 8
    print_status(ok, f"{py_version} {'(Good)' if ok else '(Need 3.8+)'}")
    
    print(f"Executable: {sys.executable}\n")
    return ok

def check_core_dependencies():
    """Check core dependencies"""
    print_header("Core Dependencies")
    
    dependencies = {
        'PyQt6': 'GUI Framework',
        'sqlite3': 'Database'
    }
    
    all_ok = True
    for module, description in dependencies.items():
        try:
            __import__(module)
            print_status(True, f"{module:20} - {description}")
        except ImportError:
            print_status(False, f"{module:20} - {description} (NOT INSTALLED)")
            all_ok = False
    
    print()
    return all_ok

def check_optional_llm_providers():
    """Check optional LLM providers"""
    print_header("Optional LLM Providers")
    
    providers = {
        'openai': 'OpenAI GPT',
        'mistralai': 'Mistral AI',
        'ollama': 'Ollama',
    }
    
    available = []
    for module, name in providers.items():
        try:
            __import__(module)
            print_status(True, f"{name:20} - Available")
            available.append(name)
        except ImportError:
            print_status(False, f"{name:20} - Not installed (optional)")
    
    print()
    return available

def check_api_keys():
    """Check API keys"""
    print_header("API Key Configuration")
    
    keys = {
        'OPENAI_API_KEY': 'OpenAI',
        'MISTRAL_API_KEY': 'Mistral',
        'AZURE_OPENAI_KEY': 'Azure OpenAI',
        'OLLAMA_BASE_URL': 'Ollama',
    }
    
    configured = []
    for key, service in keys.items():
        value = os.getenv(key)
        if value:
            # Hide actual key
            masked = value[:10] + "..." if len(value) > 10 else value
            print_status(True, f"{service:20} - Configured ({masked})")
            configured.append(service)
        else:
            print_status(False, f"{service:20} - Not configured")
    
    print()
    return configured

def check_module_exists():
    """Check if main module exists"""
    print_header("Module Files")
    
    files = {
        'exploit_generator_multi_llm.py': 'Main Module',
        'test_multi_llm_exploit_gen.py': 'Test Suite',
        'integrate_multi_llm_exploit_gen.py': 'Integration Tool',
    }
    
    all_ok = True
    for filename, description in files.items():
        exists = Path(filename).exists()
        print_status(exists, f"{filename:45} - {description}")
        all_ok = all_ok and exists
    
    print()
    return all_ok

def test_imports():
    """Test importing the module"""
    print_header("Module Import Test")
    
    try:
        from exploit_generator_multi_llm import (
            MultiLLMManager, EnhancedExploitGeneratorTab
        )
        print_status(True, "exploit_generator_multi_llm imported successfully")
        print_status(True, "MultiLLMManager available")
        print_status(True, "EnhancedExploitGeneratorTab available")
        print()
        return True
    except ImportError as e:
        print_status(False, f"Import failed: {e}")
        print()
        return False

def test_llm_manager():
    """Test LLM manager functionality"""
    print_header("LLM Manager Test")
    
    try:
        from exploit_generator_multi_llm import MultiLLMManager
        
        manager = MultiLLMManager()
        print_status(True, "MultiLLMManager instantiated")
        
        available = manager.get_available_providers()
        print_status(len(available) > 0, f"Available providers: {', '.join(available)}")
        
        # Test generation
        print("\nTesting fallback generation...")
        response, provider = manager.generate("test", preferred_provider="Fallback (Rule-based)")
        
        ok = response and len(response) > 0
        print_status(ok, f"Generation successful using {provider}")
        
        if ok:
            print(f"Response length: {len(response)} characters")
            print(f"First 100 chars: {response[:100]}...")
        
        print()
        return ok
    except Exception as e:
        print_status(False, f"Test failed: {e}")
        print()
        return False

def check_ollama_service():
    """Check if Ollama is running"""
    print_header("Ollama Service Check")
    
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            print_status(True, "Ollama is running on localhost:11434")
            print()
            return True
        else:
            print_status(False, "Ollama not responding properly")
            print()
            return False
    except:
        print_status(False, "Ollama not running (optional)")
        print()
        return False

def generate_recommendations():
    """Generate setup recommendations"""
    print_header("Setup Recommendations")
    
    recommendations = []
    
    # Check what's needed
    try:
        import PyQt6
    except ImportError:
        recommendations.append("pip install PyQt6")
    
    try:
        import openai
    except ImportError:
        recommendations.append("pip install openai  # For OpenAI GPT support")
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        recommendations.append("export OPENAI_API_KEY=sk-...  # Get key from openai.com")
    
    if not recommendations:
        print("✓ All recommended packages are installed!")
        print("✓ System is ready to generate exploits!")
        print()
        print("To get started:")
        print("1. Run: python exploit_generator_multi_llm.py")
        print("2. Or:  python HadesAI.py")
        return
    
    print("Recommended setup commands:\n")
    for i, cmd in enumerate(recommendations, 1):
        print(f"{i}. {cmd}")
    
    print()

def generate_summary(results):
    """Generate overall summary"""
    print_header("Setup Summary")
    
    python_ok, core_ok, llm_available, api_keys, files_ok, import_ok, manager_ok = results
    
    status_items = [
        ("Python Version", python_ok),
        ("Core Dependencies", core_ok),
        ("Module Files", files_ok),
        ("Module Import", import_ok),
        ("LLM Manager", manager_ok),
    ]
    
    print("Status Overview:\n")
    for name, status in status_items:
        print_status(status, name)
    
    if llm_available:
        print(f"\nAvailable LLM Providers ({len(llm_available)}):")
        for provider in llm_available:
            print(f"  • {provider}")
    
    if api_keys:
        print(f"\nConfigured API Keys ({len(api_keys)}):")
        for key in api_keys:
            print(f"  • {key}")
    
    print()
    
    # Determine ready status
    critical_ok = python_ok and core_ok and files_ok and import_ok and manager_ok
    
    if critical_ok:
        print("="*70)
        print("✓ SYSTEM READY FOR EXPLOIT GENERATION!")
        print("="*70)
        
        if llm_available:
            print(f"\n✓ Ready to use: {', '.join(llm_available)}")
        else:
            print("\n⚠ No API keys configured - will use fallback LLM (basic)")
        
        print("\nNext steps:")
        print("1. python exploit_generator_multi_llm.py          # Standalone")
        print("2. python HadesAI.py                              # With HadesAI")
        print("3. python test_multi_llm_exploit_gen.py           # Run tests")
    else:
        print("="*70)
        print("✗ SYSTEM NOT READY - PLEASE FIX ISSUES ABOVE")
        print("="*70)
    
    print()
    return critical_ok

def main():
    """Run all checks"""
    print("\n")
    print("#" * 70)
    print("#  HADES Multi-LLM Exploit Generator - Setup Verification")
    print("#" * 70)
    
    # Run all checks
    python_ok = check_python_version()
    core_ok = check_core_dependencies()
    llm_available = check_optional_llm_providers()
    api_keys = check_api_keys()
    files_ok = check_module_exists()
    import_ok = test_imports()
    manager_ok = test_llm_manager()
    
    # Check Ollama (informational only)
    check_ollama_service()
    
    # Generate recommendations
    generate_recommendations()
    
    # Summary
    results = (python_ok, core_ok, llm_available, api_keys, files_ok, import_ok, manager_ok)
    ready = generate_summary(results)
    
    return 0 if ready else 1

if __name__ == "__main__":
    sys.exit(main())
