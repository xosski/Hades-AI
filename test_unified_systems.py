#!/usr/bin/env python3
"""
Test script for unified systems integration
Tests all three core systems: LLM Router, Defense System, Web Learning Integration
"""

import sys
import json
from datetime import datetime
import io

# Fix encoding for Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("=" * 70)
print("HadesAI UNIFIED SYSTEMS VERIFICATION")
print("=" * 70)


def test_unified_llm_router():
    """Test Unified LLM Router"""
    print("\n[1/3] Testing Unified LLM Router...")
    print("-" * 70)
    
    try:
        from unified_llm_router import (
            UnifiedLLMRouter, LLMRequest, LLMProvider, RequestPriority
        )
        
        # Initialize router
        router = UnifiedLLMRouter()
        print("✓ Router initialized")
        
        # Check available providers
        available = router.get_available_providers()
        print(f"✓ Available providers: {available}")
        
        if not available:
            print("⚠ Warning: No providers available (fallback will be used)")
        
        # Test request routing
        request = LLMRequest(
            prompt="What is the OWASP Top 10?",
            priority=RequestPriority.NORMAL,
            system_prompt="You are a security expert"
        )
        
        response = router.route_request(request)
        print(f"✓ Request routed to: {response.provider.value if response.provider else 'Unknown'}")
        print(f"✓ Response received: {len(response.content)} chars")
        print(f"✓ Latency: {response.latency_ms:.2f}ms")
        print(f"✓ Cache hit: {response.cached}")
        
        # Get statistics
        stats = router.get_stats()
        print(f"✓ Total requests tracked: {stats['cache_stats']['total_requests']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_enhanced_defense_system():
    """Test Enhanced Defense System"""
    print("\n[2/3] Testing Enhanced Defense System...")
    print("-" * 70)
    
    try:
        from enhanced_defense_system import (
            EnhancedDefenseSystem, ThreatLevel, DefenseAction
        )
        
        # Initialize defense system
        defense = EnhancedDefenseSystem()
        print("✓ Defense system initialized")
        
        # Test 1: SQL Injection detection
        sqli_content = "SELECT * FROM users WHERE id = ' OR '1'='1"
        event = defense.scan_content(sqli_content, {"source_ip": "192.168.1.100"})
        
        if event:
            print(f"✓ SQL Injection detected!")
            print(f"  - Threat Type: {event.threat_type}")
            print(f"  - Severity: {event.threat_level.name}")
            print(f"  - Response Actions: {[a.value for a in event.response_actions]}")
        else:
            print("⚠ No threat detected in SQL injection test")
        
        # Test 2: XSS detection
        xss_content = "<script>alert('xss')</script>"
        event = defense.scan_content(xss_content)
        
        if event:
            print(f"✓ XSS detected!")
            print(f"  - Threat Type: {event.threat_type}")
            print(f"  - Severity: {event.threat_level.name}")
        else:
            print("⚠ No threat detected in XSS test")
        
        # Test 3: Clean content
        clean_content = "This is normal, safe content"
        event = defense.scan_content(clean_content)
        
        if not event:
            print("✓ Clean content correctly passed through")
        
        # Get security status
        status = defense.get_security_status()
        print(f"✓ Security Status:")
        print(f"  - Recent Events (24h): {status['recent_events_24h']}")
        print(f"  - Active Blocks: {status['active_blocks']}")
        print(f"  - Threat Distribution: {status['threat_distribution']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_web_learning_integration():
    """Test Web Learning Integration"""
    print("\n[3/3] Testing Web Learning Integration...")
    print("-" * 70)
    
    try:
        from web_learning_integration import create_integrated_system
        
        # Initialize integrated system
        integrator = create_integrated_system()
        print("✓ Web learning integration initialized")
        
        # Test learning with security scanning
        test_content = """
        CVE-2024-1234: Critical SQL Injection Vulnerability
        
        Affected Component: User Authentication Module
        Severity: CRITICAL (CVSS 9.8)
        
        Vulnerable Code:
        SELECT * FROM users WHERE username = '{input}' AND password = '{pwd}'
        
        Exploitation:
        username: admin' OR '1'='1'--
        password: anything
        
        This allows authentication bypass.
        
        Mitigation:
        - Use parameterized queries
        - Implement input validation
        - Update to version 2.0
        
        Related CWE:
        CWE-89: Improper Neutralization of Special Elements used in an SQL Command
        CWE-78: Improper Neutralization of Special Elements used in an OS Command
        """
        
        context = integrator.learn_and_defend_webpage(
            "https://example.com/cve-2024-1234",
            test_content,
            {"title": "CVE Security Advisory"}
        )
        
        print(f"✓ Learning complete")
        print(f"  - Knowledge items learned: {context.learned_knowledge['total_items_learned']}")
        print(f"  - CVEs found: {len(context.learned_knowledge.get('cves', []))}")
        print(f"  - Exploits found: {len(context.learned_knowledge.get('exploits', []))}")
        print(f"  - Techniques found: {len(context.learned_knowledge.get('techniques', []))}")
        print(f"  - Patterns found: {len(context.learned_knowledge.get('patterns', []))}")
        
        # Check defense results
        if context.defense_scan_results:
            print(f"✓ Security threat detected during learning!")
            print(f"  - Threat Type: {context.defense_scan_results['threat_type']}")
            print(f"  - Threat Level: {context.defense_scan_results['threat_level']}")
            print(f"  - Actions Taken: {context.defense_scan_results['actions_taken']}")
        else:
            print("✓ No critical threats detected in learning content")
        
        # Check AI enhancements
        if context.ai_enhancements:
            print(f"✓ AI analysis generated")
            print(f"  - Provider: {context.ai_enhancements.get('provider', 'Unknown')}")
            print(f"  - Confidence: {context.ai_enhancements.get('confidence', 0):.2f}")
            print(f"  - Analysis length: {len(context.ai_enhancements.get('analysis', ''))} chars")
        
        # Get system statistics
        stats = integrator.get_learning_statistics()
        print(f"✓ System Statistics:")
        print(f"  - Learning contexts: {stats.get('total_contexts', 0)}")
        print(f"  - Total CVEs learned: {stats.get('learned_cves', 0)}")
        print(f"  - Total exploits learned: {stats.get('learned_exploits', 0)}")
        print(f"  - Total techniques learned: {stats.get('learned_techniques', 0)}")
        print(f"  - Web sources processed: {stats.get('web_sources_processed', 0)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_integration():
    """Test cross-system integration"""
    print("\n[BONUS] Testing Cross-System Integration...")
    print("-" * 70)
    
    try:
        from web_learning_integration import create_integrated_system
        from unified_llm_router import LLMRequest, RequestPriority
        
        integrator = create_integrated_system()
        
        # Simulate a complete security analysis workflow
        vulnerability_info = """
        CVE-2024-5678: Remote Code Execution in Web Framework
        
        A critical vulnerability in the template engine allows
        arbitrary code execution through specially crafted input.
        
        CVSS Score: 9.9 (Critical)
        """
        
        # Step 1: Learn and defend
        print("→ Learning from security advisory...")
        context = integrator.learn_and_defend_webpage(
            "https://example.com/advisory",
            vulnerability_info
        )
        
        # Step 2: Request LLM analysis using learned context
        print("→ Requesting AI analysis...")
        analysis_prompt = f"""
        Analyze the following vulnerability:
        {vulnerability_info}
        
        Provide:
        1. Exploitation difficulty (1-10)
        2. Detection methods
        3. Mitigation strategies
        4. Historical exploit patterns
        """
        
        request = LLMRequest(
            prompt=analysis_prompt,
            priority=RequestPriority.HIGH,
            system_prompt="You are HadesAI, a security analysis expert"
        )
        
        response = integrator.router.route_request(request)
        print(f"✓ Analysis received from {response.provider.value}")
        print(f"  - Response length: {len(response.content)} chars")
        
        # Step 3: Security verification
        print("→ Verifying security...")
        threat_event = integrator.defense.scan_content(vulnerability_info)
        if threat_event:
            print(f"✓ Security check found issues: {threat_event.threat_type}")
        
        print("✓ Complete workflow executed successfully!")
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    
    results = {
        "LLM Router": test_unified_llm_router(),
        "Defense System": test_enhanced_defense_system(),
        "Web Learning": test_web_learning_integration(),
        "Integration": test_integration()
    }
    
    # Summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    
    for system, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {system}")
    
    all_passed = all(results.values())
    
    print("\n" + "=" * 70)
    if all_passed:
        print("✓ ALL SYSTEMS OPERATIONAL")
        print("\nHadesAI unified systems are ready for deployment!")
    else:
        print("✗ SOME SYSTEMS FAILED")
        print("\nPlease check errors above and verify configuration.")
    
    print("=" * 70)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
