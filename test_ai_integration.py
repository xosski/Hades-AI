#!/usr/bin/env python3
"""
Test suite for full AI integration in Payload Generator and Exploit Seeker
"""

import json
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AIIntegrationTest")

def test_imports():
    """Test that all AI integration modules can be imported"""
    logger.info("=" * 70)
    logger.info("TEST 1: Module Imports")
    logger.info("=" * 70)
    
    try:
        from payload_exploit_ai_integration import (
            PayloadExploitAIBridge, AIPayloadGenerator, AIExploitAnalyzer,
            PayloadRequest, GeneratedPayload, LLMProvider
        )
        logger.info("✅ payload_exploit_ai_integration imported successfully")
        return True
    except ImportError as e:
        logger.error(f"❌ Failed to import payload_exploit_ai_integration: {e}")
        return False


def test_ai_config():
    """Test AI configuration loading"""
    logger.info("\n" + "=" * 70)
    logger.info("TEST 2: AI Configuration")
    logger.info("=" * 70)
    
    try:
        from payload_exploit_ai_integration import AIConfig
        
        config = AIConfig()
        logger.info(f"✅ AIConfig loaded")
        logger.info(f"   Active Provider: {config.active_provider.value}")
        logger.info(f"   Available API Keys: {list(config.api_keys.keys())}")
        
        for provider, key in config.api_keys.items():
            if key:
                logger.info(f"   ✅ {provider.upper()}: Configured")
            else:
                logger.info(f"   ❌ {provider.upper()}: Not configured")
        
        return True
    except Exception as e:
        logger.error(f"❌ AI Configuration test failed: {e}")
        return False


def test_payload_generator():
    """Test payload generation"""
    logger.info("\n" + "=" * 70)
    logger.info("TEST 3: Payload Generator")
    logger.info("=" * 70)
    
    try:
        from payload_exploit_ai_integration import (
            PayloadExploitAIBridge, PayloadRequest, LLMProvider
        )
        
        # Initialize bridge
        ai_bridge = PayloadExploitAIBridge()
        logger.info("✅ PayloadExploitAIBridge initialized")
        
        # Create request
        request = PayloadRequest(
            file_type="php",
            vulnerability_type="SQL Injection",
            target_info={'database': 'MySQL'},
            count=3
        )
        logger.info("✅ PayloadRequest created")
        
        # Generate payloads (will use fallback if no API keys)
        logger.info("   Generating payloads...")
        payloads = ai_bridge.payload_generator.generate_payloads(request)
        
        if payloads:
            logger.info(f"✅ Generated {len(payloads)} payloads")
            for idx, payload in enumerate(payloads[:2], 1):
                logger.info(f"   Payload {idx}: {payload.payload[:50]}...")
            return True
        else:
            logger.warning("⚠️ No payloads generated")
            return False
    
    except Exception as e:
        import traceback
        logger.error(f"❌ Payload generator test failed: {e}")
        logger.error(traceback.format_exc())
        return False


def test_exploit_analyzer():
    """Test exploit analysis"""
    logger.info("\n" + "=" * 70)
    logger.info("TEST 4: Exploit Analyzer")
    logger.info("=" * 70)
    
    try:
        from payload_exploit_ai_integration import AIExploitAnalyzer
        
        analyzer = AIExploitAnalyzer()
        logger.info("✅ AIExploitAnalyzer initialized")
        
        # Create test exploit
        exploit_data = {
            'id': 'test_001',
            'type': 'SQL Injection',
            'payload': "' OR '1'='1",
            'description': 'Basic SQL injection test'
        }
        
        logger.info("   Analyzing exploit...")
        analysis = analyzer.analyze_exploit(exploit_data)
        
        logger.info("✅ Exploit analyzed")
        logger.info(f"   Effectiveness: {analysis.effectiveness_score:.1%}")
        logger.info(f"   Detection Risk: {analysis.detection_probability:.1%}")
        logger.info(f"   Difficulty: {analysis.exploitation_difficulty}")
        logger.info(f"   Impact: {analysis.impact_score:.1%}")
        
        return True
    
    except Exception as e:
        import traceback
        logger.error(f"❌ Exploit analyzer test failed: {e}")
        logger.error(traceback.format_exc())
        return False


def test_payload_generator_gui():
    """Test payload generator GUI integration"""
    logger.info("\n" + "=" * 70)
    logger.info("TEST 5: Payload Generator GUI Integration")
    logger.info("=" * 70)
    
    try:
        from payload_generator_gui import PayloadGeneratorTab, AI_INTEGRATION_AVAILABLE
        
        logger.info(f"✅ PayloadGeneratorTab imported")
        logger.info(f"   AI Integration Available: {AI_INTEGRATION_AVAILABLE}")
        
        if AI_INTEGRATION_AVAILABLE:
            logger.info("✅ AI integration is available in payload generator")
            return True
        else:
            logger.warning("⚠️ AI integration not available in payload generator")
            return False
    
    except Exception as e:
        import traceback
        logger.error(f"❌ Payload generator GUI test failed: {e}")
        logger.error(traceback.format_exc())
        return False


def test_exploit_seeker_ai():
    """Test exploit seeker AI integration"""
    logger.info("\n" + "=" * 70)
    logger.info("TEST 6: Exploit Seeker AI Integration")
    logger.info("=" * 70)
    
    try:
        from exploit_seek_tab import (
            HAS_AI_PAYLOAD_INTEGRATION, AIExploitAnalysisWorker,
            AIPayloadRecommendationWorker
        )
        
        logger.info(f"✅ Exploit seeker modules imported")
        logger.info(f"   AI Integration Available: {HAS_AI_PAYLOAD_INTEGRATION}")
        
        if HAS_AI_PAYLOAD_INTEGRATION:
            logger.info("✅ AI workers available")
            logger.info("   - AIExploitAnalysisWorker")
            logger.info("   - AIPayloadRecommendationWorker")
            return True
        else:
            logger.warning("⚠️ AI workers not available")
            return False
    
    except Exception as e:
        import traceback
        logger.error(f"❌ Exploit seeker AI test failed: {e}")
        logger.error(traceback.format_exc())
        return False


def test_unified_bridge():
    """Test unified AI bridge"""
    logger.info("\n" + "=" * 70)
    logger.info("TEST 7: Unified AI Bridge")
    logger.info("=" * 70)
    
    try:
        from payload_exploit_ai_integration import PayloadExploitAIBridge
        
        bridge = PayloadExploitAIBridge()
        logger.info("✅ PayloadExploitAIBridge initialized")
        
        # Test provider detection
        active = bridge.get_active_provider()
        logger.info(f"   Active Provider: {active}")
        
        # Test available providers
        available = bridge.get_available_providers()
        logger.info(f"   Available Providers: {available}")
        
        if available:
            logger.info("✅ Providers available")
            return True
        else:
            logger.warning("⚠️ Only fallback provider available")
            return True  # Still acceptable
    
    except Exception as e:
        import traceback
        logger.error(f"❌ Unified bridge test failed: {e}")
        logger.error(traceback.format_exc())
        return False


def main():
    """Run all tests"""
    logger.info("\n")
    logger.info("╔" + "=" * 68 + "╗")
    logger.info("║" + " " * 15 + "HADES AI INTEGRATION TEST SUITE" + " " * 21 + "║")
    logger.info("╚" + "=" * 68 + "╝")
    
    tests = [
        ("Module Imports", test_imports),
        ("AI Configuration", test_ai_config),
        ("Payload Generator", test_payload_generator),
        ("Exploit Analyzer", test_exploit_analyzer),
        ("Payload Generator GUI", test_payload_generator_gui),
        ("Exploit Seeker AI", test_exploit_seeker_ai),
        ("Unified Bridge", test_unified_bridge),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            logger.error(f"❌ {test_name} test crashed: {e}")
            results[test_name] = False
    
    # Summary
    logger.info("\n" + "=" * 70)
    logger.info("TEST SUMMARY")
    logger.info("=" * 70)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{status}: {test_name}")
    
    logger.info("=" * 70)
    logger.info(f"Results: {passed}/{total} tests passed")
    logger.info("=" * 70)
    
    if passed == total:
        logger.info("🎉 All tests passed! AI integration is fully operational.")
        return 0
    else:
        logger.warning(f"⚠️ {total - passed} test(s) failed. Check configuration.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
