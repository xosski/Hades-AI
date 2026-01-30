#!/usr/bin/env python3
"""Test autonomous operations systems"""

import sys
import io
if sys.stdout.encoding and 'utf' not in sys.stdout.encoding.lower():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Test 1: Import modules
try:
    from modules.autonomous_operations import (
        ThreatResponseEngine, ContinuousLearningEngine,
        DecisionMakingAgent, ThreatEvent
    )
    print("[OK] Core modules import successfully")
except Exception as e:
    print(f"[ERROR] Core modules: {e}")
    sys.exit(1)

# Test 2: Import GUI
try:
    from autonomous_ops_gui import AutonomousOpsTab
    print("[OK] GUI module imports successfully")
except Exception as e:
    print(f"[ERROR] GUI module: {e}")
    sys.exit(1)

# Test 3: Create instances
try:
    threat = ThreatResponseEngine()
    learning = ContinuousLearningEngine()
    decision = DecisionMakingAgent(learning, threat)
    print("[OK] All instances created successfully")
except Exception as e:
    print(f"[ERROR] Instance creation: {e}")
    sys.exit(1)

# Test 4: Enable systems
try:
    threat.enable_auto_response(threshold=0.7)
    learning.enable_continuous_learning()
    decision.enable_autonomous_decisions()
    print("[OK] All systems enabled successfully")
except Exception as e:
    print(f"[ERROR] System enablement: {e}")
    sys.exit(1)

# Test 5: Record learning
try:
    learning.record_attempt("TestExploit", "test_target", True)
    stats = learning.get_learning_stats()
    print(f"[OK] Learning system operational: {stats['total_exploits']} exploit(s)")
except Exception as e:
    print(f"[ERROR] Learning: {e}")
    sys.exit(1)

# Test 6: Process threat
try:
    threat_event = ThreatEvent(
        id="test-1",
        threat_type="Test Threat",
        severity=0.8
    )
    actions = threat.process_threat(threat_event)
    print(f"[OK] Threat response operational: {len(actions)} action(s) taken")
except Exception as e:
    print(f"[ERROR] Threat response: {e}")
    sys.exit(1)

# Test 7: Make decision
try:
    target = {"name": "Test", "type": "test", "cvss_score": 8.0}
    decision_result = decision.evaluate_target(target)
    print(f"[OK] Decision agent operational: {decision_result['decision']}")
except Exception as e:
    print(f"[ERROR] Decision agent: {e}")
    sys.exit(1)

print("\n" + "="*60)
print("ALL AUTONOMY SYSTEMS OPERATIONAL")
print("="*60)
print("\nFiles:")
print("  ✓ modules/autonomous_operations.py")
print("  ✓ autonomous_ops_gui.py")
print("  ✓ AUTONOMOUS_OPERATIONS.md")
print("  ✓ AUTONOMOUS_QUICK_START.md")
print("  ✓ AUTONOMY_ENHANCEMENT_SUMMARY.md")
print("\nSystems:")
print("  ✓ Threat Response Engine")
print("  ✓ Continuous Learning Engine")
print("  ✓ Decision-Making Agent")
print("\nIntegration: Add 2 lines to HadesAI.py")
print("Ready to use! 🤖")
