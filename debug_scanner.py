#!/usr/bin/env python3
"""
Debug script to see what's happening in the scanner
Shows all progress, errors, and test results in real-time
"""

import sys
import json
from ai_vulnerability_tester_fixed import AIVulnerabilityTester

def main():
    print("=" * 80)
    print("SCANNER DEBUG - AI VULNERABILITY TESTER")
    print("=" * 80)
    print()
    
    # Get target from user or use default
    target = input("Enter target URL (default: https://syfe.com): ").strip()
    if not target:
        target = "https://syfe.com"
    
    print()
    print(f"[*] Target: {target}")
    print(f"[*] Scanner: AI Vulnerability Tester (Fixed)")
    print()
    print("-" * 80)
    print("STARTING ASSESSMENT - ALL PROGRESS SHOWN BELOW")
    print("-" * 80)
    print()
    
    # Create scanner with aggressive timeout settings
    tester = AIVulnerabilityTester()
    tester.timeout = 15  # Generous timeout
    
    # Progress callback to show everything
    def progress(msg):
        print(msg)
        sys.stdout.flush()
    
    # Run tests with verbose output
    print("[+] Initializing test categories...")
    print(f"    Available categories: {list(tester.VULNERABILITY_TESTS.keys())}")
    print()
    
    try:
        print("[+] Running assessment...")
        print()
        
        results = tester.test_website(target, callback=progress)
        
        print()
        print("=" * 80)
        print("ASSESSMENT RESULTS SUMMARY")
        print("=" * 80)
        print()
        
        # Summary
        print(f"Target: {results['target']}")
        print(f"Total Tests Run: {results['total_tests_run']}")
        print(f"Vulnerabilities Found: {results['total_vulnerabilities']}")
        print()
        
        # Severity breakdown
        print("Severity Breakdown:")
        for severity, count in results['severity_summary'].items():
            if count > 0:
                print(f"  {severity}: {count}")
        print()
        
        # List all findings
        if results['findings']:
            print("=" * 80)
            print("DETAILED FINDINGS")
            print("=" * 80)
            
            for i, finding in enumerate(results['findings'], 1):
                print()
                print(f"[{i}] {finding['title']}")
                print(f"    ID: {finding['id']}")
                print(f"    Type: {finding['type']}")
                print(f"    Severity: {finding['severity']}")
                print(f"    Confidence: {finding['confidence']}")
                print()
                print(f"    Description: {finding['description']}")
                print()
                print(f"    Proof Points:")
                for j, proof in enumerate(finding['proof_points'], 1):
                    print(f"      {j}. {proof}")
                print()
                print(f"    HTTP Evidence:")
                print(f"      URL: {finding['http_evidence']['url']}")
                print(f"      Status: {finding['http_evidence']['status_code']}")
                print(f"      Time: {finding['http_evidence']['response_time']}")
                print()
                
                # Show first 5 headers
                headers = finding['http_evidence']['headers']
                print(f"    Response Headers ({len(headers)} total):")
                for j, (header, value) in enumerate(list(headers.items())[:5], 1):
                    print(f"      {header}: {value}")
                if len(headers) > 5:
                    print(f"      ... and {len(headers) - 5} more headers")
        else:
            print()
            print("[+] No vulnerabilities detected - target appears secure!")
        
        # Export results
        print()
        print("=" * 80)
        filename = tester.export_results()
        print(f"[+] Full results exported to: {filename}")
        print("[+] Review JSON file for complete details")
        
    except Exception as e:
        print()
        print("=" * 80)
        print(f"[ERROR] Assessment failed: {e}")
        print("=" * 80)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    print()
    print("[+] Assessment complete!")

if __name__ == '__main__':
    main()
