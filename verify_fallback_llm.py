#!/usr/bin/env python3
"""Verify fallback LLM functionality - comprehensive check"""

import sys

def test_imports():
    """Test that modules import correctly"""
    try:
        from fallback_llm import FallbackLLM
        from exploit_generator_multi_llm import FallbackLLMProvider
        return True
    except Exception as e:
        print(f"[FAIL] Import error: {e}")
        return False

def test_agent_fallback():
    """Test autonomous agent fallback"""
    from fallback_llm import FallbackLLM
    
    llm = FallbackLLM()
    
    tests = [
        ("Planning", "Provide a plan", "Goals: analyze code"),
        ("Action", "Choose next action", "Goals: fix bugs"),
        ("Reflection", "Update plan", "Observations: errors"),
    ]
    
    for name, system, user in tests:
        try:
            result = llm(system, user)
            if not result or not isinstance(result, str):
                print(f"[FAIL] {name} - Invalid output type")
                return False
            if len(result) < 10:
                print(f"[FAIL] {name} - Output too short")
                return False
        except Exception as e:
            print(f"[FAIL] {name} - {e}")
            return False
    
    return True

def test_exploit_detection():
    """Test vulnerability detection"""
    from exploit_generator_multi_llm import FallbackLLMProvider
    
    provider = FallbackLLMProvider()
    
    tests = [
        ("SQL injection in query", "sql_injection"),
        ("Buffer overflow in strcpy", "buffer_overflow"),
        ("Command injection via system", "command_injection"),
        ("XSS in eval", "xss"),
        ("Path traversal via file", "path_traversal"),
        ("Weak authentication", "authentication"),
        ("Pickle deserialization", "deserialization"),
        ("Unknown issue", "generic"),
    ]
    
    for analysis, expected in tests:
        try:
            detected = provider._detect_vulnerability_type(analysis)
            if detected != expected:
                print(f"[FAIL] Detection - Expected {expected}, got {detected}")
                return False
        except Exception as e:
            print(f"[FAIL] Detection - {e}")
            return False
    
    return True

def test_exploit_generation():
    """Test that exploits are generated"""
    from exploit_generator_multi_llm import FallbackLLMProvider
    
    provider = FallbackLLMProvider()
    
    vuln_types = [
        "SQL injection in database query",
        "Buffer overflow vulnerability",
        "Command execution vulnerability",
        "XSS payload injection",
        "Path traversal attack",
        "Authentication bypass",
        "Unsafe deserialization",
    ]
    
    for vuln in vuln_types:
        try:
            exploit = provider.generate(vuln)
            if not exploit:
                print(f"[FAIL] Generation - No output for {vuln[:20]}...")
                return False
            if len(exploit) < 100:
                print(f"[FAIL] Generation - Output too small for {vuln[:20]}...")
                return False
            if "import" not in exploit.lower() and "class" not in exploit.lower():
                print(f"[FAIL] Generation - Invalid Python code for {vuln[:20]}...")
                return False
        except Exception as e:
            print(f"[FAIL] Generation - {e}")
            return False
    
    return True

def test_integrated():
    """Test both systems working together"""
    from fallback_llm import FallbackLLM
    from exploit_generator_multi_llm import FallbackLLMProvider
    
    try:
        agent = FallbackLLM()
        exploit = FallbackLLMProvider()
        
        # Simulate workflow
        plan = agent("plan", "Goals: exploit")
        action = agent("action", "Goals: find")
        analysis = "Found SQL injection vulnerability"
        vuln = exploit._detect_vulnerability_type(analysis)
        code = exploit.generate(analysis)
        
        if not (plan and action and vuln == "sql_injection" and code):
            print("[FAIL] Integration - Workflow failed")
            return False
            
        return True
    except Exception as e:
        print(f"[FAIL] Integration - {e}")
        return False

def main():
    print("=" * 70)
    print("FALLBACK LLM VERIFICATION SUITE")
    print("=" * 70)
    
    tests = [
        ("Module Imports", test_imports),
        ("Agent Fallback", test_agent_fallback),
        ("Vulnerability Detection", test_exploit_detection),
        ("Exploit Generation", test_exploit_generation),
        ("Integrated System", test_integrated),
    ]
    
    results = []
    for test_name, test_func in tests:
        sys.stdout.write(f"[*] {test_name}... ")
        sys.stdout.flush()
        
        try:
            passed = test_func()
            if passed:
                print("[PASS]")
                results.append(True)
            else:
                print("[FAIL]")
                results.append(False)
        except Exception as e:
            print(f"[ERROR] {e}")
            results.append(False)
    
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    
    if all(results):
        print("Status: ALL SYSTEMS OPERATIONAL")
        print("=" * 70)
        return 0
    else:
        print("Status: SOME TESTS FAILED")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    sys.exit(main())
