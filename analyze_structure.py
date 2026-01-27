#!/usr/bin/env python3
"""Analyze HadesAI.py structure for refactoring"""

import re

with open('HadesAI.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find all class definitions
classes = []
for i, line in enumerate(lines):
    if line.startswith('class '):
        match = re.match(r'class (\w+)', line)
        if match:
            classes.append((i+1, match.group(1)))

# Find imports section
imports = []
for i, line in enumerate(lines[:200]):
    if 'import' in line and not line.strip().startswith('#'):
        imports.append((i+1, line.strip()[:70]))

print("=" * 70)
print("HADESAI.PY STRUCTURE ANALYSIS")
print("=" * 70)

print(f"\nFile Stats:")
print(f"  Total lines: {len(lines)}")
print(f"  Total classes: {len(classes)}")
print(f"  Import statements: ~{len([i for i in imports if i[1]])}")

print(f"\n\nCLASSES IN FILE:")
print("-" * 70)
for line_no, name in classes:
    print(f"  {line_no:5d} | {name}")

print(f"\n\nREFACTORING OPPORTUNITIES:")
print("-" * 70)

opportunities = [
    "1. Extract utility functions into separate modules",
    "2. Group related classes by functionality",
    "3. Create config/constants module",
    "4. Separate UI from business logic",
    "5. Create dedicated modules for:",
    "   - Network operations",
    "   - Database/KB operations",
    "   - AI/LLM operations",
    "   - Exploitation/Security tools",
    "   - UI components",
    "6. Improve docstrings and type hints",
    "7. Add logging module",
    "8. Create configuration management",
]

for opp in opportunities:
    print(f"  {opp}")

print("\n" + "=" * 70)
