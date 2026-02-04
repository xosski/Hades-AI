#!/usr/bin/env python3
import re

def fix_indentation(filename):
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    fixed_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Check for statements that need proper body indentation
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        
        # Lines starting with if/elif/else/for/while/try/except/finally
        control_words = ['if ', 'elif ', 'else:', 'for ', 'while ', 'try:', 'except', 'finally:']
        
        if any(stripped.startswith(w) for w in control_words) and line.rstrip().endswith(':'):
            fixed_lines.append(line)
            # Check if next line is properly indented
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                next_stripped = next_line.lstrip()
                next_indent = len(next_line) - len(next_stripped)
                
                # Next line should be indented 4 more than current
                expected_indent = indent + 4
                
                if next_stripped and next_indent == indent and not any(next_stripped.startswith(w) for w in control_words):
                    # Fix it
                    lines[i + 1] = ' ' * expected_indent + next_stripped
            i += 1
        else:
            fixed_lines.append(line)
            i += 1
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)
    
    print(f"Fixed {filename}")

fix_indentation('hadesai.py')
