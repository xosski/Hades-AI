"""
Phase 1 Integration Test Suite
Tests ObsidianCore, EthicalControl, and MalwareEngine integration
"""

import sys
import os
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Phase1Tests")

def test_obsidian_core_integration():
    """Test ObsidianCore integration"""
    print("\n" + "="*70)
    print("TEST 1: ObsidianCore Integration")
    print("="*70)
    
    try:
        from modules.obsidian_core_integration import get_obsidian_core
        
        print("[1] Importing ObsidianCore integration... ", end="")
        obsidian = get_obsidian_core()
        print("✓ PASS")
        
        print("[2] Checking initialization status... ", end="")
        assert obsidian.ready is not None
        print(f"✓ PASS (ready={obsidian.ready})")
        
        print("[3] Getting system status... ", end="")
        status = obsidian.get_system_status()
        assert status is not None
        print("✓ PASS")
        print(f"    → Core available: {status['core_available']}")
        
        print("[4] Getting capabilities... ", end="")
        caps = obsidian.get_capabilities()
        assert caps is not None
        assert 'attack' in caps
        print("✓ PASS")
        print(f"    → {len(caps)} capability categories")
        
        print("[5] Testing attack engine... ", end="")
        result = obsidian.execute_attack('exploitation', 'target.com', param='test')
        assert result is not None
        print("✓ PASS")
        print(f"    → Attack success: {result.get('success', False)}")
        
        print("[6] Testing defense engine... ", end="")
        result = obsidian.deploy_defense('firewall', threshold=0.8)
        assert result is not None
        print("✓ PASS")
        print(f"    → Defense deployed: {result.get('deployed', False)}")
        
        print("[7] Testing payload generation... ", end="")
        result = obsidian.generate_payload('shellcode')
        assert result is not None
        print("✓ PASS")
        print(f"    → Payload generated: {result.get('generated', False)}")
        
        print("[8] Testing movement planning... ", end="")
        result = obsidian.plan_lateral_movement('user', 'admin')
        assert result is not None
        print("✓ PASS")
        print(f"    → Path found: {result.get('path_found', False)}")
        
        print("[9] Testing monitoring... ", end="")
        result = obsidian.start_monitoring('system')
        assert result is not None
        print("✓ PASS")
        print(f"    → Monitoring active: {result.get('monitoring', False)}")
        
        print("[10] Testing learning event logging... ", end="")
        result = obsidian.log_learning_event('test', 'action', True, 1.5)
        assert result is not None
        print("✓ PASS")
        print(f"    → Logged: {result.get('logged', False)}")
        
        print("\n✓ ObsidianCore Integration: ALL TESTS PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ ObsidianCore Integration: FAILED")
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_ethical_control_integration():
    """Test EthicalControl integration"""
    print("\n" + "="*70)
    print("TEST 2: EthicalControl Integration")
    print("="*70)
    
    try:
        from modules.ethical_control_integration import get_ethical_control
        
        print("[1] Importing EthicalControl integration... ", end="")
        ec = get_ethical_control()
        print("✓ PASS")
        
        print("[2] Checking initialization... ", end="")
        assert ec is not None
        print("✓ PASS")
        
        print("[3] Getting status... ", end="")
        status = ec.get_status()
        assert status is not None
        print("✓ PASS")
        print(f"    → Enabled: {status['enabled']}")
        print(f"    → Environment: {status['environment']}")
        print(f"    → Auth Level: {status['authorization_level']}")
        
        print("[4] Authorization check (authorized operation)... ", end="")
        result = ec.is_authorized('read', 'test.com', 'test_exploit')
        print(f"✓ PASS (authorized={result})")
        
        print("[5] Adding authorized target... ", end="")
        ec.add_authorized_target('192.168.1.100')
        assert '192.168.1.100' in ec.get_authorized_targets()
        print("✓ PASS")
        
        print("[6] Adding authorized exploit... ", end="")
        ec.add_authorized_exploit('test_exploit')
        assert 'test_exploit' in ec.get_authorized_exploits()
        print("✓ PASS")
        
        print("[7] Checking authorization for whitelisted target... ", end="")
        ec.whitelist_targets.add('target.com')
        result = ec.is_authorized('execute', 'target.com')
        print(f"✓ PASS (authorized={result})")
        
        print("[8] Checking compliance... ", end="")
        compliance = ec.check_compliance('test_operation', {'target': 'target.com'})
        assert compliance is not None
        print("✓ PASS")
        print(f"    → Status: {compliance['status']}")
        
        print("[9] Getting audit log... ", end="")
        audit = ec.get_audit_log()
        assert isinstance(audit, list)
        print("✓ PASS")
        print(f"    → Log entries: {len(audit)}")
        
        print("[10] Generating compliance report... ", end="")
        report = ec.generate_compliance_report()
        assert report is not None
        print("✓ PASS")
        print(f"    → Operations: {report['operations']['total']}")
        print(f"    → Violations: {report['violations']['total']}")
        
        print("\n✓ EthicalControl Integration: ALL TESTS PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ EthicalControl Integration: FAILED")
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_malware_engine_integration():
    """Test MalwareEngine integration"""
    print("\n" + "="*70)
    print("TEST 3: MalwareEngine Integration")
    print("="*70)
    
    try:
        from modules.malware_engine_integration import get_malware_engine, MutationMethod
        
        print("[1] Importing MalwareEngine integration... ", end="")
        engine = get_malware_engine()
        print("✓ PASS")
        
        print("[2] Checking initialization... ", end="")
        assert engine is not None
        print("✓ PASS")
        
        test_payload = 'print("Hello, World!")'
        
        print("[3] Testing XOR mutation... ", end="")
        result = engine.mutate_payload(test_payload, MutationMethod.XOR)
        assert 'final_payload' in result
        assert result['final_payload'] != test_payload
        print("✓ PASS")
        print(f"    → Size: {result['original_size']} → {result['final_size']} bytes")
        
        print("[4] Testing Base64 mutation... ", end="")
        result = engine.mutate_payload(test_payload, MutationMethod.BASE64)
        assert 'final_payload' in result
        print("✓ PASS")
        print(f"    → Size increase: {result['size_increase_percent']:.1f}%")
        
        print("[5] Testing Polymorphic mutation... ", end="")
        result = engine.mutate_payload(test_payload, MutationMethod.POLYMORPHIC)
        assert 'final_payload' in result
        print("✓ PASS")
        
        print("[6] Testing Obfuscation... ", end="")
        result = engine.mutate_payload(test_payload, MutationMethod.OBFUSCATE)
        assert 'final_payload' in result
        print("✓ PASS")
        
        print("[7] Testing Split mutation... ", end="")
        result = engine.mutate_payload(test_payload, MutationMethod.SPLIT)
        assert 'final_payload' in result
        print("✓ PASS")
        
        print("[8] Testing multiple iterations... ", end="")
        result = engine.mutate_payload(test_payload, MutationMethod.XOR, iterations=3)
        assert len(result['mutations']) == 3
        print("✓ PASS")
        print(f"    → {len(result['mutations'])} iterations applied")
        
        print("[9] Generating polymorphic variants... ", end="")
        variants = engine.generate_polymorphic_payload(test_payload, variations=5)
        assert len(variants) == 5
        print("✓ PASS")
        print(f"    → Generated {len(variants)} variants")
        
        print("[10] Testing anti-analysis payload... ", end="")
        result = engine.generate_anti_analysis_payload(test_payload)
        assert 'check_debugger' in result
        assert 'check_vm' in result
        print("✓ PASS")
        
        print("[11] Testing staged payload... ", end="")
        result = engine.generate_staged_payload(test_payload, stages=2)
        assert result['total_stages'] == 2
        assert 'first_stage' in result
        print("✓ PASS")
        print(f"    → Generated {result['total_stages']} stages")
        
        print("[12] Estimating detection probability... ", end="")
        result = engine.estimate_detection_probability(test_payload)
        assert 'detection_probability' in result
        print("✓ PASS")
        print(f"    → Detection probability: {result['detection_probability']*100:.1f}%")
        print(f"    → Evasion score: {result['evasion_score']*100:.1f}%")
        
        print("[13] Getting statistics... ", end="")
        stats = engine.get_statistics()
        assert stats is not None
        print("✓ PASS")
        print(f"    → Total mutations: {stats['total_mutations']}")
        print(f"    → Payloads generated: {stats['payloads_generated']}")
        
        print("[14] Getting payload history... ", end="")
        history = engine.get_payload_history()
        assert isinstance(history, list)
        print("✓ PASS")
        print(f"    → History entries: {len(history)}")
        
        print("\n✓ MalwareEngine Integration: ALL TESTS PASSED")
        return True
        
    except Exception as e:
        print(f"\n✗ MalwareEngine Integration: FAILED")
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all Phase 1 integration tests"""
    print("\n" + "="*70)
    print("PHASE 1 INTEGRATION TEST SUITE")
    print("="*70)
    print("Testing: ObsidianCore, EthicalControl, MalwareEngine")
    
    results = {
        'obsidian_core': test_obsidian_core_integration(),
        'ethical_control': test_ethical_control_integration(),
        'malware_engine': test_malware_engine_integration()
    }
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name:.<50} {status}")
    
    print("-"*70)
    print(f"TOTAL: {passed}/{total} test suites passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED - Phase 1 Integration Complete!")
    else:
        print(f"\n⚠️  {total - passed} test suite(s) failed")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
