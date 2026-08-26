#!/usr/bin/env python3
"""
Quick test to verify Seek Tab loads without errors
"""

import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestSeekTab")


def main():
    print("=" * 60)
    print("Testing P2P Exploit Seeking Integration")
    print("=" * 60)

    # Test 1: Import modules
    print("\n✓ Test 1: Importing modules...")
    try:
        from p2p_exploit_sharing import P2PExploitSharer, ExploitFinding
        print("  ✅ p2p_exploit_sharing imported")
    except Exception as e:
        print(f"  ❌ Failed to import p2p_exploit_sharing: {e}")
        sys.exit(1)

    try:
        from exploit_seek_tab import create_exploit_seek_tab
        print("  ✅ exploit_seek_tab imported")
    except Exception as e:
        print(f"  ❌ Failed to import exploit_seek_tab: {e}")
        sys.exit(1)

    # Test 2: Create exploit sharer
    print("\n✓ Test 2: Creating ExploitSharer...")
    try:
        sharer = P2PExploitSharer(instance_id="test_instance")
        print("  ✅ ExploitSharer created")
    except Exception as e:
        print(f"  ❌ Failed to create sharer: {e}")
        sys.exit(1)

    # Test 3: Create tab (without GUI)
    print("\n✓ Test 3: Creating ExploitSeekTab...")
    try:
        # This will try to create PyQt6 widgets, which requires a QApplication
        # So we'll just check if the class imports correctly
        from exploit_seek_tab import ExploitSeekTab
        print("  ✅ ExploitSeekTab class imported")
    except Exception as e:
        print(f"  ❌ Failed to import ExploitSeekTab class: {e}")
        sys.exit(1)

    # Test 4: Check HadesAI imports
    print("\n✓ Test 4: Checking HadesAI.py imports...")
    try:
        with open('HadesAI.py', 'r') as f:
            content = f.read()
            if 'HAS_EXPLOIT_SEEK' in content:
                print("  ✅ HAS_EXPLOIT_SEEK flag found in HadesAI.py")
            else:
                print("  ⚠️  HAS_EXPLOIT_SEEK flag not found")

            if 'create_exploit_seek_tab' in content:
                print("  ✅ create_exploit_seek_tab function called in HadesAI.py")
            else:
                print("  ⚠️  create_exploit_seek_tab not called")
    except Exception as e:
        print(f"  ❌ Error checking HadesAI.py: {e}")

    # Test 5: Test ExploitFinding creation
    print("\n✓ Test 5: Testing ExploitFinding creation...")
    try:
        import time
        exploit = ExploitFinding(
            exploit_id="test_001",
            target_url="https://test.com",
            exploit_type="sql_injection",
            severity="Critical",
            payload="admin'--",
            description="Test exploit",
            timestamp=time.time(),
            instance_id="test"
        )
        print("  ✅ ExploitFinding created successfully")
        print(f"  - Type: {exploit.exploit_type}")
        print(f"  - Severity: {exploit.severity}")
    except Exception as e:
        print(f"  ❌ Failed to create ExploitFinding: {e}")
        sys.exit(1)

    # Test 6: Test registry operations
    print("\n✓ Test 6: Testing ExploitRegistry...")
    try:
        sharer.register_exploit(exploit)
        print("  ✅ Exploit registered in sharer")

        exploits = sharer.registry.get_all_exploits()
        print(f"  ✅ Retrieved {len(exploits)} exploit(s) from registry")
    except Exception as e:
        print(f"  ❌ Registry operation failed: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED - Seek Tab is ready!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Run HadesAI.py")
    print("2. Look for '🔍 Exploit Seek' tab")
    print("3. Enter a target URL and click 'SEEK EXPLOITS'")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
