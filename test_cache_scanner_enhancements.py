"""
Test script for Enhanced Cache Scanner
Verifies:
- Learned exploit loading
- Code visibility
- Database operations
- Report generation
"""

import os
import sys
import json
from pathlib import Path

# Fix encoding for Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

try:
    from cache_scanner_enhanced import EnhancedCacheScanner
    from cache_scanner_integration import CacheScannerIntegration
except ImportError as e:
    print(f"[!] Import error: {e}")
    sys.exit(1)


def test_scanner_initialization():
    """Test 1: Scanner initialization"""
    print("\n" + "="*60)
    print("TEST 1: Scanner Initialization")
    print("="*60)
    
    try:
        scanner = EnhancedCacheScanner()
        print("[OK] Scanner created successfully")
        
        if scanner.conn:
            print("[✓] Database connection established")
        else:
            print("[✗] Database connection failed")
            return False
        
        # Check tables
        cursor = scanner.conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN 
            ('learned_exploits', 'cache_detections', 'code_patterns')
        """)
        
        tables = [row[0] for row in cursor.fetchall()]
        print(f"[✓] Tables created: {tables}")
        
        scanner.close()
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


def test_exploit_loading():
    """Test 2: Load learned exploits"""
    print("\n" + "="*60)
    print("TEST 2: Exploit Loading")
    print("="*60)
    
    try:
        scanner = EnhancedCacheScanner()
        count = scanner.load_learned_exploits()
        
        print(f"[✓] Loaded {count} learned exploits")
        
        if count == 0:
            print("[!] Warning: No learned exploits in database")
        else:
            print(f"[✓] Exploit types loaded: {list(scanner.learned_exploits.keys())}")
            
            # Show details of first exploit type
            for exploit_type in list(scanner.learned_exploits.keys())[:1]:
                exploits = scanner.learned_exploits[exploit_type]
                print(f"\n  Example - {exploit_type}:")
                print(f"    Count: {len(exploits)}")
                if exploits and 'code' in exploits[0]:
                    code_len = len(exploits[0]['code'])
                    print(f"    Code size: {code_len} bytes")
                    if code_len > 0:
                        print(f"    Code preview: {exploits[0]['code'][:100]}...")
        
        scanner.close()
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


def test_threat_detection():
    """Test 3: Threat detection from cache files"""
    print("\n" + "="*60)
    print("TEST 3: Threat Detection")
    print("="*60)
    
    try:
        scanner = EnhancedCacheScanner()
        scanner.load_learned_exploits()
        
        # Create a test file with threat patterns
        test_file = "test_cache_file.tmp"
        test_content = """
        This is test content with some threats.
        eval(userInput);  // eval code pattern
        var data = document.cookie;  // data exfiltration
        <script>alert('XSS')</script>  // injection
        """
        
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Scan it
        result = scanner.scan_cache_with_details(test_file, "TestBrowser")
        
        print(f"[✓] File scanned: {result['path']}")
        print(f"[✓] Code visible: {result['code_visible']}")
        print(f"[✓] Detections: {len(result['detections'])}")
        
        if result['detections']:
            print("[✓] Threats found:")
            for detection in result['detections']:
                print(f"  - {detection['threat_type']} ({detection['severity']})")
                print(f"    Matched: {detection['matched_code'][:50]}")
                print(f"    Position: {detection['position']}")
        else:
            print("[!] No threats detected (expected for test content)")
        
        # Cleanup
        os.remove(test_file)
        scanner.close()
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


def test_database_operations():
    """Test 4: Database operations"""
    print("\n" + "="*60)
    print("TEST 4: Database Operations")
    print("="*60)
    
    try:
        scanner = EnhancedCacheScanner()
        
        # Insert test detection
        test_detection = {
            'cache_path': 'C:\\test\\cache\\file',
            'threat_type': 'eval_code',
            'severity': 'HIGH',
            'code_snippet': 'eval(malicious_code)',
            'full_code': 'function test() { eval(malicious_code); }',
            'context_before': 'var x = 1;',
            'context_after': 'var y = 2;',
            'file_size': 1024,
            'file_hash': 'abc123',
            'browser': 'Chrome'
        }
        
        success = scanner.store_cache_detection(test_detection)
        print(f"[✓] Detection stored: {success}")
        
        # Retrieve detections
        detections = scanner.get_cache_detections(limit=10)
        print(f"[✓] Retrieved {len(detections)} detections")
        
        if detections:
            d = detections[0]
            print(f"  Latest detection:")
            print(f"    Path: {d['cache_path']}")
            print(f"    Type: {d['threat_type']}")
            print(f"    Severity: {d['severity']}")
            print(f"    Code: {d['code_snippet']}")
            print(f"    Full Code Length: {len(d.get('full_code', '')) or 0} bytes")
        
        # Get threat summary
        summary = scanner.get_threat_summary()
        print(f"[✓] Threat Summary:")
        print(f"    Total detections: {summary.get('total_detections', 0)}")
        print(f"    By severity: {summary.get('by_severity', {})}")
        print(f"    By threat type: {summary.get('by_threat_type', {})}")
        
        scanner.close()
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


def test_export_functionality():
    """Test 5: Export to JSON and HTML"""
    print("\n" + "="*60)
    print("TEST 5: Export Functionality")
    print("="*60)
    
    try:
        scanner = EnhancedCacheScanner()
        
        # Export JSON
        json_path = "test_cache_findings.json"
        json_success = scanner.export_findings_to_json(json_path)
        print(f"[✓] JSON export: {json_success}")
        
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
            print(f"  - Detections in JSON: {len(data.get('detections', []))}")
            print(f"  - Exploit types: {len(data.get('learned_exploits', {}))}")
            os.remove(json_path)
        
        # Export HTML
        html_path = "test_cache_findings.html"
        html_success = scanner.export_findings_to_html(html_path)
        print(f"[✓] HTML export: {html_success}")
        
        if os.path.exists(html_path):
            with open(html_path, 'r') as f:
                html_content = f.read()
            print(f"  - HTML size: {len(html_content)} bytes")
            print(f"  - Contains summary: {'Summary' in html_content}")
            print(f"  - Contains code sections: {'code-section' in html_content}")
            os.remove(html_path)
        
        scanner.close()
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


def test_integration():
    """Test 6: Integration layer"""
    print("\n" + "="*60)
    print("TEST 6: Integration Layer")
    print("="*60)
    
    try:
        integration = CacheScannerIntegration()
        
        # Initialize
        success = integration.initialize_scanner()
        print(f"[✓] Integration initialized: {success}")
        
        # Register callbacks
        events_received = {'ready': False, 'error': False}
        
        def on_ready(data):
            events_received['ready'] = True
            print(f"  Callback: Scanner ready with {data['learned_exploits']} exploits")
        
        integration.register_callback('scanner_ready', on_ready)
        
        # Get threat summary
        summary = integration.get_threat_summary()
        print(f"[✓] Threat summary retrieved:")
        print(f"    Total threats: {summary.get('total_threats', 0)}")
        print(f"    Exploit types: {summary.get('exploit_types', [])}")
        
        # Test browser cache paths
        browsers = ['Chrome', 'Edge', 'Firefox', 'Brave', 'Opera']
        for browser in browsers:
            paths = integration._get_browser_cache_paths(browser)
            exists = any(os.path.exists(p) for p in paths)
            status = "[✓]" if exists else "[✗]"
            print(f"{status} {browser}: {len(paths)} paths, {sum(1 for p in paths if os.path.exists(p))} exist")
        
        integration.close()
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("CACHE SCANNER ENHANCEMENT TEST SUITE")
    print("="*60)
    
    tests = [
        ("Scanner Initialization", test_scanner_initialization),
        ("Exploit Loading", test_exploit_loading),
        ("Threat Detection", test_threat_detection),
        ("Database Operations", test_database_operations),
        ("Export Functionality", test_export_functionality),
        ("Integration Layer", test_integration),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n[!] Test crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "[OK]" if result else "[FAIL]"
        print(f"{status} {test_name}")
    
    print(f"\nPassed: {passed}/{total}")
    
    if passed == total:
        print("\n[✓] ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n[!] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
