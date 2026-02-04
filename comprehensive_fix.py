import re

with open('hadesai.py', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Replace all instances of 8 leading spaces in method definitions with 4
# And fix indentation inconsistencies in method bodies

lines = content.split('\n')
fixed = []

for i, line in enumerate(lines):
    if i >= 4299:  # From line 4300 onwards
        if not line.strip():  # Blank line
            fixed.append(line)
        else:
            # Count leading spaces
            stripped = line.lstrip()
            spaces = len(line) - len(stripped)
            
            # If it's a method definition with wrong indentation
            if stripped.startswith('def ') and spaces == 8:
                fixed.append('    ' + stripped)
            # If it's an if/for/while/else statement with wrong indentation
            elif any(stripped.startswith(x) for x in ['if ', 'elif ', 'else:', 'for ', 'while ', 'try:', 'except', 'finally:']) and spaces == 8:
                fixed.append('        ' + stripped)
            # If it's a statement that should be indented 12 under if/for/while
            elif spaces == 8 and not any(stripped.startswith(x) for x in ['if ', 'elif ', 'else:', 'for ', 'while ', 'try:', 'except', 'finally:', 'def ', '@', '#']):
                fixed.append('            ' + stripped)
            else:
                fixed.append(line)
    else:
        fixed.append(line)

with open('hadesai.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(fixed))

print("Comprehensive fix applied")
