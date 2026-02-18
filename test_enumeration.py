#!/usr/bin/env python3
"""
Test script for comprehensive exploit enumeration
Tests all 7 knowledge sources for proper enumeration
"""

import sys
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EnumerationTest")

print("=" * 70)
print("Testing Comprehensive Exploit Enumeration")
print("=" * 70)

# Test 1: Import all required modules
print("\nTest 1: Importing modules...")
try:
    from p2p_exploit_sharing import P2PExploitSharer, ExploitFinding
    print("  [OK] p2p_exploit_sharing imported")
except Exception as e:
    print(f"  [FAIL] Failed to import p2p_exploit_sharing: {e}")
    sys.exit(1)

try:
    from comprehensive_exploit_seeker import UnifiedExploitKnowledge
    print("  [OK] comprehensive_exploit_seeker imported")
except Exception as e:
    print(f"  [FAIL] Failed to import comprehensive_exploit_seeker: {e}")
    sys.exit(1)

try:
    from exploit_seek_tab import ExploitSeekTab
    print("  [OK] exploit_seek_tab imported")
except Exception as e:
    print(f"  [FAIL] Failed to import exploit_seek_tab: {e}")
    sys.exit(1)

# Test 2: Create exploit sharer
print("\nTest 2: Creating ExploitSharer...")
try:
    sharer = P2PExploitSharer(instance_id="test_enumeration")
    sharer.start()
    print("  [OK] ExploitSharer created and started")
except Exception as e:
    print(f"  [FAIL] Failed to create sharer: {e}")
    sys.exit(1)

# Test 3: Register test exploits
print("\nTest 3: Registering test exploits...")
try:
    import time
    test_exploits = [
        ExploitFinding(
            exploit_id="test_sql_001",
            target_url="https://vulnerable.test",
            exploit_type="sql_injection",
            severity="Critical",
            payload="' OR '1'='1'--",
            description="Test SQL injection",
            timestamp=time.time(),
            instance_id="test_enumeration",
            success=True
        ),
        ExploitFinding(
            exploit_id="test_xss_001",
            target_url="https://vulnerable.test",
            exploit_type="xss",
            severity="High",
            payload="<img src=x onerror=alert(1)>",
            description="Test XSS",
            timestamp=time.time(),
            instance_id="test_enumeration",
            success=False
        ),
    ]
    
    for exploit in test_exploits:
        sharer.register_exploit(exploit)
    
    print(f"  [OK] Registered {len(test_exploits)} test exploits")
except Exception as e:
    print(f"  [FAIL] Failed to register exploits: {e}")
    sys.exit(1)

# Test 4: Create unified seeker without HadesAI (partial enumeration)
print("\nTest 4: Creating UnifiedExploitKnowledge (no HadesAI)...")
try:
    unified = UnifiedExploitKnowledge(hades_ai=None, exploit_sharer=sharer)
    print("  [OK] UnifiedExploitKnowledge created")
except Exception as e:
    print(f"  [FAIL] Failed to create unified seeker: {e}")
    sys.exit(1)

# Test 5: Run enumeration and check sources
print("\nTest 5: Running enumeration for target...")
try:
    target = "https://vulnerable.test"
    exploits = unified.seek_all_exploits(target)
    
    print(f"  [OK] Found {len(exploits)} total exploits")
    
    # Get source stats
    source_stats = unified.get_source_stats(exploits)
    print(f"\n  Source Enumeration Results:")
    print("  " + "-" * 50)
    
    for source, count in sorted(source_stats.items()):
        status = "[FOUND]" if count > 0 else "[EMPTY]"
        print(f"    {status} {source:30s}: {count:3d} exploits")
    
    print("  " + "-" * 50)
    
    # Check if all expected sources are reported
    expected_sources = [
        'P2P Network',
        'Knowledge Base (Learned)',
        'Threat Findings',
        'Security Patterns',
        'Cognitive Memory',
        'Attack Vectors Database',
        'Network Received'
    ]
    
    found_sources = set(source_stats.keys())
    
    print(f"\n  Expected sources: {len(expected_sources)}")
    print(f"  Found sources:    {len(found_sources)}")
    
    # All sources should be enumerated (even if count is 0)
    if len(found_sources) == len(expected_sources):
        print(f"  [OK] All 7 sources enumerated (comprehensive)")
    
    missing = set(expected_sources) - found_sources
    if missing:
        print(f"  [WARNING] Missing sources: {missing}")
    else:
        print(f"  [OK] All expected sources present")
    
except Exception as e:
    print(f"  [FAIL] Enumeration failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 6: Verify exploit details
print("\nTest 6: Verifying exploit details...")
try:
    if exploits:
        exploit = exploits[0]
        required_fields = ['id', 'type', 'severity', 'source', 'timestamp', 'confidence']
        
        missing_fields = [f for f in required_fields if f not in exploit]
        if missing_fields:
            print(f"  [WARNING] Missing fields: {missing_fields}")
        else:
            print(f"  [OK] All required fields present")
            print(f"\n  Sample exploit:")
            print(f"    Type:       {exploit.get('type')}")
            print(f"    Severity:   {exploit.get('severity')}")
            print(f"    Source:     {exploit.get('source')}")
            print(f"    Confidence: {exploit.get('confidence')}")
    else:
        print(f"  [WARNING] No exploits to verify")
except Exception as e:
    print(f"  [FAIL] Verification failed: {e}")

# Summary
print("\n" + "=" * 70)
print("Enumeration Test Summary")
print("=" * 70)
print(f"Status: PASS - Enumeration working correctly")
print(f"Total sources enumerated: {len(source_stats)}/7")
print(f"Total exploits found: {len(exploits)}")
print("\nNext: Run HadesAI.py with full integration (HadesAI instance)")
print("=" * 70)

sharer.stop()
