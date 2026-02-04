import re

with open('hadesai.py', 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

# For lines 4300+ that are over-indented, fix them
output_lines = []

for i, line in enumerate(lines):
    if i >= 4299:  # Line 4300 onwards (0-indexed)
        # Check leading whitespace
        if line.strip():  # Not blank
            match = re.match(r'^(\s*)(.*)$', line)
            if match:
                indent, content = match.groups()
                indent_count = len(indent)
                
                # Fix method definitions - should be 4 spaces
                if content.startswith('def '):
                    if indent_count != 4:
                        line = '    ' + content + '\n'
                # Fix docstrings and content under method defs - should be 8 spaces
                elif indent_count > 8:
                    # Over-indented, reduce by 4
                    line = ' ' * 8 + content + '\n'
    
    output_lines.append(line)

with open('hadesai.py', 'w', encoding='utf-8') as f:
    f.writelines(output_lines)

print("Fixed all indentation issues")
