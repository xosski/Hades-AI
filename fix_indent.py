import re

with open('hadesai.py', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

lines = content.split('\n')
fixed_lines = []

for i, line in enumerate(lines):
    # For lines 4305 onwards (0-indexed is 4304+)
    if i >= 4304:
        # Check if line starts with excessive indentation
        if line and not line.startswith('    def '):
            stripped = line.lstrip()
            indent_len = len(line) - len(stripped)
            
            # If line has 13+ spaces, dedent to appropriate level
            if indent_len >= 13 and stripped:  # Not blank
                # Dedent by 4-8 spaces to get to 8-12
                fixed_lines.append('        ' + stripped)
            elif indent_len == 12 and stripped and not stripped.startswith('#'):
                # 12 spaces should be 8 for methods or 4 for inner statements
                # If it's a method def, keep as is, else dedent
                if stripped.startswith('def '):
                    fixed_lines.append('    ' + stripped)
                else:
                    fixed_lines.append('        ' + stripped)
            else:
                fixed_lines.append(line)
        else:
            fixed_lines.append(line)
    else:
        fixed_lines.append(line)

with open('hadesai.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(fixed_lines))

print("Fixed indentation")
