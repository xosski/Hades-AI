#!/usr/bin/env python3
import sys

with open('autonomouscoding.py', 'r', encoding='utf-8') as f:
    content = f.read()
    lines = content.split('\n')

print(f"Total lines: {len(lines)}")
print(f"Last line: {lines[-1][:60] if lines[-1] else '(empty)'}")

checks = {
    'AutonomousCodingAgent class': 'class AutonomousCodingAgent' in content,
    'run method': 'def run(self):' in content,
    '_initial_plan method': 'def _initial_plan(self)' in content,
    '_decide_next_action method': 'def _decide_next_action(self)' in content,
    '_dispatch_tool method': 'def _dispatch_tool(self)' in content,
    '_tool_read_file method': 'def _tool_read_file(self)' in content,
    '_tool_write_file method': 'def _tool_write_file(self)' in content,
    '_tool_run_tests method': 'def _tool_run_tests(self)' in content,
    '_tool_search_code method': 'def _tool_search_code(self)' in content,
    'PyQt6 signals': 'pyqtSignal' in content,
    'No HadesAI integration code': 'QMessageBox' not in content and '_agent_llm' not in content,
}

all_ok = True
for check_name, result in checks.items():
    status = "[PASS]" if result else "[FAIL]"
    print(f"{status} {check_name}")
    if not result:
        all_ok = False

if all_ok:
    print("\n[SUCCESS] autonomouscoding.py is correctly formatted!")
    sys.exit(0)
else:
    print("\n[ERROR] Some checks failed!")
    sys.exit(1)
