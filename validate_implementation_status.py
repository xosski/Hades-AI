#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validation script for Current Implementation integration status
Checks all components and provides integration readiness report
"""

import os
import sys
import io
from pathlib import Path

# Fix console encoding on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from modules.current_implementation_loader import (
    SafeComponentLoader, 
    ComponentValidator,
    INTEGRATION_MANIFEST
)

def print_header(text, level=1):
    """Print formatted header"""
    chars = '=' * 60 if level == 1 else '-' * 60
    print(f"\n{chars}")
    print(f"  {text}")
    print(f"{chars}\n")

def validate_all_components():
    """Validate all components in Current Implementation folder"""
    print_header("HADES-AI IMPLEMENTATION INTEGRATION STATUS", 1)
    
    loader = SafeComponentLoader()
    validator = ComponentValidator()
    
    results = {
        'total': 0,
        'valid': 0,
        'invalid': 0,
        'critical_issues': [],
        'warnings': [],
        'by_priority': {}
    }
    
    # Get all Python files
    impl_path = Path(loader.base_path)
    py_files = list(impl_path.glob('*.py'))
    
    print(f"Found {len(py_files)} Python files in Current Implementation\n")
    
    # Validate each file
    for py_file in py_files:
        results['total'] += 1
        filename = py_file.name
        
        print(f"Validating: {filename}")
        validation = validator.validate_component(str(py_file))
        
        if validation.get('error'):
            results['invalid'] += 1
            results['critical_issues'].append(f"{filename}: {validation['error']}")
            print(f"  [FAILED] - {validation['error']}\n")
            continue
        
        # Check for issues
        has_syntax_error = validation.get('has_syntax_errors', False)
        has_dangerous = validation.get('has_dangerous_patterns', False)
        lacks_error_handling = not validation.get('has_error_handling', False)
        lacks_logging = not validation.get('has_logging', False)
        lacks_docs = not validation.get('is_properly_documented', False)
        
        if has_syntax_error:
            results['critical_issues'].append(f"{filename}: Syntax error")
            results['invalid'] += 1
            print(f"  [ERROR] Syntax Error\n")
            continue
        
        # Count as valid but note issues
        results['valid'] += 1
        status = "[OK] VALID"
        
        if has_dangerous or lacks_error_handling or lacks_logging or lacks_docs:
            status = "[WARN] VALID (with issues)"
            issues = []
            if has_dangerous:
                issues.append("dangerous patterns")
            if lacks_error_handling:
                issues.append("no error handling")
            if lacks_logging:
                issues.append("no logging")
            if lacks_docs:
                issues.append("no docstring")
            
            results['warnings'].append(f"{filename}: {', '.join(issues)}")
            print(f"  {status}")
            print(f"    Issues: {', '.join(issues)}\n")
        else:
            print(f"  {status}\n")
    
    print_header("VALIDATION SUMMARY", 1)
    print(f"Total Components:    {results['total']}")
    print(f"Valid:              {results['valid']} ({100*results['valid']//results['total']}%)")
    print(f"Invalid:            {results['invalid']} ({100*results['invalid']//results['total']}%)")
    
    if results['critical_issues']:
        print_header("CRITICAL ISSUES", 2)
        for issue in results['critical_issues']:
            print(f"  [CRITICAL] {issue}")
    
    if results['warnings']:
        print_header("WARNINGS", 2)
        for warning in results['warnings'][:10]:  # Show first 10
            print(f"  [WARN] {warning}")
        if len(results['warnings']) > 10:
            print(f"  ... and {len(results['warnings']) - 10} more warnings")
    
    return results

def check_integration_manifest():
    """Check which components from manifest are available"""
    print_header("INTEGRATION MANIFEST STATUS", 1)
    
    impl_path = Path(SafeComponentLoader().base_path)
    py_files = {f.name for f in impl_path.glob('*.py')}
    
    for priority, components in INTEGRATION_MANIFEST.items():
        print(f"\n{priority} Priority:")
        print("-" * 40)
        
        available = 0
        for component in components:
            if component in py_files:
                print(f"  [OK] {component}")
                available += 1
            else:
                print(f"  [MISSING] {component} (NOT FOUND)")
        
        print(f"  Status: {available}/{len(components)} available")

def check_dependencies():
    """Check if required dependencies are installed"""
    print_header("DEPENDENCY CHECK", 1)
    
    critical_deps = [
        'numpy',
        'psutil',
        'sklearn',
        'scipy',
        'networkx',
        'cryptography',
        'pefile'
    ]
    
    windows_deps = [
        'pywin32',
        'wmi',
        'winreg'
    ]
    
    optional_deps = [
        'tensorflow',
        'fastapi',
        'uvicorn',
        'flask',
        'websocket',
        'contractions',
        'sentence_transformers',
        'spellchecker',
        'python-docx'
    ]
    
    def check_module(name, human_name=None):
        try:
            __import__(name)
            return True
        except ImportError:
            return False
    
    print("\nCRITICAL DEPENDENCIES:")
    for dep in critical_deps:
        status = "[OK]" if check_module(dep) else "[MISSING]"
        print(f"  {status} {dep}")
    
    print("\nWINDOWS-SPECIFIC DEPENDENCIES:")
    for dep in windows_deps:
        status = "[OK]" if check_module(dep) else "[MISSING]"
        print(f"  {status} {dep}")
    
    print("\nOPTIONAL DEPENDENCIES:")
    missing_optional = []
    for dep in optional_deps:
        if check_module(dep):
            print(f"  [OK] {dep}")
        else:
            print(f"  [MISSING] {dep}")
            missing_optional.append(dep)
    
    if missing_optional:
        print(f"\n[WARN] Missing {len(missing_optional)} optional dependencies")
        print("To install: pip install " + " ".join(missing_optional))

def check_integration_files():
    """Check if integration files exist"""
    print_header("INTEGRATION SETUP CHECK", 1)
    
    checks = [
        ('modules/current_implementation_loader.py', 'Integration Loader'),
        ('CURRENT_IMPLEMENTATION_AUDIT.md', 'Audit Document'),
        ('IMPLEMENTATION_INTEGRATION_GUIDE.md', 'Integration Guide'),
    ]
    
    for filepath, name in checks:
        exists = os.path.exists(filepath)
        status = "[OK]" if exists else "[MISSING]"
        print(f"  {status} {name}")

def generate_action_items():
    """Generate prioritized action items"""
    print_header("RECOMMENDED ACTION ITEMS", 1)
    
    print("\n1. IMMEDIATE (Do Now):")
    print("   ✓ Review CURRENT_IMPLEMENTATION_AUDIT.md")
    print("   ✓ Read IMPLEMENTATION_INTEGRATION_GUIDE.md")
    print("   ✓ Install missing optional dependencies")
    
    print("\n2. PHASE 1 (Critical - Days 1-3):")
    print("   [ ] Extract and refactor EthicalControl.py")
    print("   [ ] Test current_implementation_loader.py")
    print("   [ ] Create modules/ethical_controls.py")
    print("   [ ] Integrate ethical gates into HadesAI.py")
    
    print("\n3. PHASE 2 (High Priority - Days 4-7):")
    print("   [ ] Refactor ObsidianCore.py into modular engines")
    print("   [ ] Integrate AIAttackDecisionMaking.py into seek_tab")
    print("   [ ] Enhance AdaptiveCounterMeasures.py")
    print("   [ ] Create comprehensive test suite")
    
    print("\n4. TESTING & VALIDATION:")
    print("   [ ] Create tests/test_implementation_integration.py")
    print("   [ ] Run validation: python validate_implementation_status.py")
    print("   [ ] Integration testing with existing modules")
    
    print("\n5. DOCUMENTATION:")
    print("   [ ] Document all refactored components")
    print("   [ ] Create component integration examples")
    print("   [ ] Update HadesAI.py documentation")

def main():
    """Run all checks"""
    try:
        # Run validation
        results = validate_all_components()
        
        # Check manifest
        check_integration_manifest()
        
        # Check dependencies
        check_dependencies()
        
        # Check integration files
        check_integration_files()
        
        # Generate action items
        generate_action_items()
        
        # Final status
        print_header("INTEGRATION READINESS", 1)
        if results['invalid'] == 0:
            print("[OK] All components are syntactically valid")
        else:
            print(f"[WARN] {results['invalid']} component(s) have syntax errors")
        
        if results['warnings']:
            print(f"[WARN] {len(results['warnings'])} component(s) have quality issues")
        
        print("\nReadiness: PARTIAL - Ready for Phase 1 integration")
        print("Next step: Follow IMPLEMENTATION_INTEGRATION_GUIDE.md\n")
        
    except Exception as e:
        print(f"\n[ERROR] Error during validation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
