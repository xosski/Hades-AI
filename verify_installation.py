#!/usr/bin/env python3
"""
Verify Network Share feature installation
Run after setup to confirm all files present and dependencies ready
"""

import os
import sys

files_required = {
    'Core Code': [
        'modules/knowledge_network.py',
        'network_share_gui.py',
    ],
    'Setup/Utilities': [
        'migrate_db_for_network.py',
        'verify_network_deps.py',
        'install_network_deps.bat',
        'install_network_deps.sh',
    ],
    'Configuration': [
        'network_config.json',
    ],
    'Documentation': [
        'NETWORK_SHARE_INDEX.md',
        'QUICK_START_NETWORK.md',
        'NETWORK_INTEGRATION.md',
        'HADES_INTEGRATION_SNIPPET.md',
        'NETWORK_SHARE.md',
        'NETWORK_DEPENDENCIES.md',
        'NETWORK_SHARE_SUMMARY.md',
        'NETWORK_SHARE_FILES_MANIFEST.md',
        'DEPLOYMENT_CHECKLIST.md',
    ]
}

def check_files():
    """Check all required files exist"""
    total = 0
    missing = []
    
    print('=' * 70)
    print('Network Share Feature - Installation Verification')
    print('=' * 70)
    
    for category, file_list in files_required.items():
        print(f'\n{category}:')
        for filename in file_list:
            exists = os.path.exists(filename)
            status = '[OK]' if exists else '[MISS]'
            print(f'  {status} {filename}')
            if exists:
                total += 1
            else:
                missing.append(filename)
    
    expected = sum(len(v) for v in files_required.values())
    
    print('\n' + '=' * 70)
    print(f'Files: {total}/{expected} present')
    
    if missing:
        print(f'\nMissing {len(missing)} files:')
        for f in missing:
            print(f'  - {f}')
        return False
    
    print('[OK] All files present!')
    return True


def check_dependencies():
    """Check Python dependencies"""
    print('\nDependencies:')
    
    deps = [
        ('sqlite3', 'stdlib'),
        ('ssl', 'stdlib'),
        ('socket', 'stdlib'),
        ('json', 'stdlib'),
        ('threading', 'stdlib'),
    ]
    
    all_ok = True
    for module, source in deps:
        try:
            __import__(module)
            print(f'  [OK] {module} ({source})')
        except ImportError:
            print(f'  [MISS] {module} ({source})')
            all_ok = False
    
    # Check cryptography (may not be installed yet)
    try:
        import cryptography
        print(f'  [OK] cryptography (external)')
    except ImportError:
        print(f'  [WARN] cryptography (will auto-install on first use)')
    
    return all_ok


def check_integration():
    """Check if HadesAI.py is ready"""
    print('\nHadesAI.py integration:')
    
    if not os.path.exists('HadesAI.py'):
        print('  [WARN] HadesAI.py not found (might be in different location)')
        return None
    
    try:
        with open('HadesAI.py', 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        print('  [WARN] Could not read HadesAI.py')
        return None
    
    checks = {
        'from network_share_gui import NetworkShareTab': 'Import statement',
        'NetworkShareTab': 'Tab reference',
    }
    
    integrated = True
    for check, desc in checks.items():
        if check in content:
            print(f'  [OK] {desc}')
        else:
            print(f'  [MISS] {desc}')
            integrated = False
    
    if not integrated:
        print('\n  [INFO] HadesAI.py not yet integrated')
        print('  Run: See HADES_INTEGRATION_SNIPPET.md for instructions')
    
    return integrated


def main():
    files_ok = check_files()
    deps_ok = check_dependencies()
    integration = check_integration()
    
    print('\n' + '=' * 70)
    
    if files_ok and deps_ok:
        print('[OK] Installation ready!')
        
        if integration is False:
            print('\nNext steps:')
            print('  1. Read: HADES_INTEGRATION_SNIPPET.md')
            print('  2. Edit: HadesAI.py (add import and tab)')
            print('  3. Run: python migrate_db_for_network.py')
            print('  4. Start: python HadesAI.py')
        elif integration is None:
            print('\nNext steps (HadesAI.py location unknown):')
            print('  1. Find HadesAI.py')
            print('  2. Read: HADES_INTEGRATION_SNIPPET.md')
            print('  3. Edit: Add import and tab creation')
            print('  4. Run: python migrate_db_for_network.py')
            print('  5. Start: python HadesAI.py')
        else:
            print('\nNext steps:')
            print('  1. Run: python migrate_db_for_network.py')
            print('  2. Start: python HadesAI.py')
            print('  3. Enable: Network Share in GUI')
        
        return 0
    else:
        print('[ERROR] Installation incomplete!')
        if not files_ok:
            print('  Missing required files - check above')
        if not deps_ok:
            print('  Missing dependencies - run: python verify_network_deps.py')
        return 1


if __name__ == '__main__':
    sys.exit(main())
