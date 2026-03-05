#!/usr/bin/env python3
"""
Verify AI is actually being used for exploit generation
Debug script to check if AI generators are initialized properly
"""

import os
import json
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
logger = logging.getLogger("VerifyAI")

def check_config():
    """Check .hades_config.json exists and is valid"""
    print("\n" + "="*60)
    print("STEP 1: Checking Configuration File")
    print("="*60)
    
    config_path = ".hades_config.json"
    
    if not Path(config_path).exists():
        print(f"✗ {config_path} NOT FOUND")
        print("  Run: python setup_exploit_generator_ai.py")
        return False
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        print(f"✓ Config file found and valid")
        
        # Check for API keys
        has_openai = 'openai_api_key' in config and config['openai_api_key']
        has_mistral = 'mistral_api_key' in config and config['mistral_api_key']
        has_azure = 'azure_openai_api_key' in config and config['azure_openai_api_key']
        
        print(f"  OpenAI key: {'✓' if has_openai else '✗'}")
        print(f"  Mistral key: {'✓' if has_mistral else '✗'}")
        print(f"  Azure key: {'✓' if has_azure else '✗'}")
        
        if config.get('ai_provider'):
            print(f"  Preferred provider: {config['ai_provider']}")
        
        if not (has_openai or has_mistral or has_azure):
            print("✗ No API keys configured!")
            return False
        
        return True
    
    except Exception as e:
        print(f"✗ Error reading config: {e}")
        return False


def check_providers():
    """Check which AI providers are available"""
    print("\n" + "="*60)
    print("STEP 2: Checking Available AI Providers")
    print("="*60)
    
    try:
        from enhanced_exploit_template import AIProviderConfig
        
        # Setup from config
        AIProviderConfig.setup_from_config()
        available = AIProviderConfig.get_available_providers()
        
        print(f"Available providers: {available if available else 'NONE'}")
        
        if not available:
            print("✗ No AI providers detected!")
            print("  Make sure:")
            print("  - .hades_config.json has API keys")
            print("  - Environment variables are set")
            print("  - Ollama is installed (optional)")
            return False
        
        for provider in available:
            print(f"  ✓ {provider.upper()}")
        
        return True
    
    except Exception as e:
        print(f"✗ Error checking providers: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_ai_generator():
    """Check if AI generator initializes correctly"""
    print("\n" + "="*60)
    print("STEP 3: Testing AI Generator Initialization")
    print("="*60)
    
    try:
        from enhanced_exploit_template import AIExploitGenerator, AIProviderConfig
        
        # Setup config
        AIProviderConfig.setup_from_config()
        
        # Create generator
        gen = AIExploitGenerator()
        print(f"✓ AI Generator initialized")
        print(f"  Provider: {gen.provider.upper()}")
        print(f"  Client: {type(gen.client).__name__}")
        
        if not gen.client:
            print("✗ Client failed to initialize!")
            return False
        
        return True
    
    except Exception as e:
        print(f"✗ Error initializing AI generator: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_exploit_template():
    """Check if ExploitTemplate initializes with AI"""
    print("\n" + "="*60)
    print("STEP 4: Testing ExploitTemplate with AI")
    print("="*60)
    
    try:
        from enhanced_exploit_template import ExploitTemplate, AIProviderConfig
        
        # Setup config
        AIProviderConfig.setup_from_config()
        
        # Create template
        template = ExploitTemplate(use_ai=True)
        print(f"✓ ExploitTemplate initialized")
        
        if not template.ai_gen:
            print("✗ AI generator is None!")
            return False
        
        print(f"  AI enabled: {template.use_ai}")
        print(f"  AI provider: {template.ai_gen.provider.upper()}")
        print(f"  AI client: {type(template.ai_gen.client).__name__}")
        
        return True
    
    except Exception as e:
        print(f"✗ Error with ExploitTemplate: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ai_generation():
    """Test actual AI generation"""
    print("\n" + "="*60)
    print("STEP 5: Testing Actual AI Generation")
    print("="*60)
    
    try:
        from enhanced_exploit_template import AIExploitGenerator, AIProviderConfig
        
        # Setup config
        AIProviderConfig.setup_from_config()
        
        # Create generator
        gen = AIExploitGenerator()
        
        # Simple test prompt
        prompt = "Write one line of Python code to print 'test'"
        
        print(f"Testing with {gen.provider.upper()}...")
        print(f"Prompt: {prompt}")
        print("Calling AI...", end=' ')
        
        response = gen.generate_exploit(prompt, max_tokens=100)
        
        if not response:
            print("✗ No response from AI")
            return False
        
        if len(response) < 10:
            print("✗ Response too short")
            return False
        
        print(f"✓ Generated {len(response)} characters")
        print(f"Response: {response[:100]}...")
        
        return True
    
    except Exception as e:
        print(f"✗ AI generation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all verification checks"""
    print("\n" + "="*60)
    print("VERIFYING AI EXPLOIT GENERATOR SETUP")
    print("="*60)
    
    checks = [
        ("Configuration", check_config),
        ("Providers", check_providers),
        ("AI Generator", check_ai_generator),
        ("ExploitTemplate", check_exploit_template),
        ("AI Generation", test_ai_generation),
    ]
    
    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"✗ {name} check failed with exception: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "="*60)
    print("VERIFICATION SUMMARY")
    print("="*60)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(result for _, result in results)
    
    print("\n" + "="*60)
    if all_passed:
        print("✓ ALL CHECKS PASSED - AI IS PROPERLY CONFIGURED")
        print("\nRestart HadesAI and:")
        print("1. Load a binary file")
        print("2. Click 'Analyze'")
        print("3. Click 'Generate Exploits'")
        print("4. You should see AI-generated exploit code")
    else:
        print("✗ SOME CHECKS FAILED - SEE ABOVE FOR DETAILS")
        print("\nTo fix:")
        print("1. Run: python setup_exploit_generator_ai.py")
        print("2. Verify .hades_config.json has your API key")
        print("3. Run this script again to verify")
    print("="*60 + "\n")
    
    return all_passed


if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)
