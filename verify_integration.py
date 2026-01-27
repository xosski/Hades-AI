#!/usr/bin/env python3
import sys

with open('HadesAI.py', 'r', encoding='utf-8') as f:
    content = f.read()
    
checks = {
    '_create_agent_tab method': '_create_agent_tab' in content,
    'HAS_AUTONOMOUS_AGENT import': 'HAS_AUTONOMOUS_AGENT' in content,
    'Autonomous Coder tab': 'Autonomous Coder' in content,
    'AutonomousCodingAgent import': 'AutonomousCodingAgent' in content,
    '_start_agent method': '_start_agent' in content,
    '_on_agent_log method': '_on_agent_log' in content,
}

all_ok = True
for check_name, result in checks.items():
    status = "[PASS]" if result else "[FAIL]"
    print(f"{status} {check_name}")
    if not result:
        all_ok = False

if all_ok:
    print("\n[SUCCESS] All agent integration checks passed!")
    sys.exit(0)
else:
    print("\n[ERROR] Some checks failed!")
    sys.exit(1)
