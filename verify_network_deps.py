#!/usr/bin/env python3
"""
Verify and install network sharing dependencies
Run this before enabling network share feature
"""

import sys
import subprocess
import importlib.util

# Fix Windows encoding issues
if sys.stdout.encoding and 'utf' not in sys.stdout.encoding.lower():
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def check_module(module_name, pip_name=None):
    """Check if module is installed"""
    pip_name = pip_name or module_name
    spec = importlib.util.find_spec(module_name)
    
    if spec is None:
        print(f"❌ {module_name} not found")
        return False
    else:
        try:
            mod = importlib.import_module(module_name)
            version = getattr(mod, '__version__', 'unknown')
            print(f"✓ {module_name} (v{version})")
            return True
        except Exception as e:
            print(f"⚠ {module_name} found but error loading: {e}")
            return False


def install_module(pip_name):
    """Install module via pip"""
    try:
        print(f"   Installing {pip_name}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pip_name, "-q"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"   ✓ Installed {pip_name}")
        return True
    except Exception as e:
        print(f"   ❌ Failed to install {pip_name}: {e}")
        return False


def main():
    print("=" * 60)
    print("HadesAI Network Share - Dependency Verification")
    print("=" * 60)
    
    dependencies = [
        ("cryptography", "cryptography"),
        ("sqlite3", None),  # stdlib
        ("ssl", None),      # stdlib
        ("socket", None),   # stdlib
        ("http.server", None),  # stdlib
    ]
    
    print("\nChecking dependencies...")
    missing = []
    
    for module_name, pip_name in dependencies:
        if not check_module(module_name, pip_name):
            if pip_name:
                missing.append(pip_name)
    
    if not missing:
        print("\n✓ All dependencies satisfied!")
        print("\nYou can now use Network Share feature:")
        print("  1. Enable in HadesAI GUI -> Network Share tab")
        print("  2. Configure instance ID and ports")
        print("  3. Add trusted peers")
        print("  4. Sync databases")
        return True
    
    print(f"\n❌ Missing {len(missing)} dependencies")
    print("\nAttempting auto-install...")
    
    failed = []
    for pip_name in missing:
        if not install_module(pip_name):
            failed.append(pip_name)
    
    if failed:
        print(f"\n❌ Failed to install: {', '.join(failed)}")
        print(f"\nManual install:")
        for name in failed:
            print(f"  pip install {name}")
        return False
    
    print("\n✓ All dependencies installed successfully!")
    print("\nYou can now use Network Share feature.")
    return True


if __name__ == "__main__":
    success = main()
    print("=" * 60)
    sys.exit(0 if success else 1)
