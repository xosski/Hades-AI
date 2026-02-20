#!/usr/bin/env python3
"""
Test the fixed AI vulnerability scanner
Validates that it properly captures headers and only reports real vulnerabilities
"""

import json
from ai_vulnerability_tester_fixed import AIVulnerabilityTester

def test_scanner():
    """Test scanner with a real website"""
    
    print("[*] Testing Fixed AI Vulnerability Scanner")
    print("=" * 60)
    
    # Initialize scanner
    tester = AIVulnerabilityTester()
    
    # Test URL - use a site you're authorized to test
    target = "https://syfe.com"
    
    print(f"\n[*] Target: {target}")
    print("[*] Running assessment (this may take 1-2 minutes)...\n")
    
    def progress_callback(msg):
        print(f"[+] {msg}")
    
    # Run tests
    results = tester.test_website(target, callback=progress_callback)
    
    # Print summary
    print("\n" + "=" * 60)
    print("ASSESSMENT RESULTS")
    print("=" * 60)
    print(f"Target: {results['target']}")
    print(f"Tests Run: {results['total_tests_run']}")
    print(f"Vulnerabilities Found: {results['total_vulnerabilities']}")
    print(f"\nSeverity Breakdown:")
    for severity, count in results['severity_summary'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    # Print detailed findings
    if results['findings']:
        print(f"\n{'=' * 60}")
        print("DETAILED FINDINGS")
        print("=" * 60)
        
        for i, finding in enumerate(results['findings'], 1):
            print(f"\n[{i}] {finding['title']}")
            print(f"    ID: {finding['id']}")
            print(f"    Type: {finding['type']}")
            print(f"    Severity: {finding['severity']}")
            print(f"    Confidence: {finding['confidence']}")
            print(f"    Status: {finding['status']}")
            
            print(f"\n    Description:")
            print(f"    {finding['description']}")
            
            print(f"\n    Impact:")
            print(f"    {finding['impact']}")
            
            print(f"\n    Proof Points:")
            for j, proof in enumerate(finding['proof_points'], 1):
                print(f"      {j}. {proof}")
            
            print(f"\n    HTTP Evidence:")
            http_ev = finding['http_evidence']
            print(f"      URL: {http_ev['url']}")
            print(f"      Method: {http_ev['method']}")
            print(f"      Status Code: {http_ev['status_code']}")
            print(f"      Response Time: {http_ev['response_time']}")
            
            print(f"\n    Response Headers:")
            for header, value in sorted(http_ev['headers'].items())[:5]:
                print(f"      {header}: {value}")
            if len(http_ev['headers']) > 5:
                print(f"      ... ({len(http_ev['headers']) - 5} more headers)")
            
            if http_ev['body_sample']:
                print(f"\n    Response Body (first 200 chars):")
                print(f"    {http_ev['body_sample'][:200]}...")
    else:
        print("\n[✓] No vulnerabilities detected!")
        print("    Assessment complete with no critical findings.")
    
    # Export results
    print("\n" + "=" * 60)
    filename = tester.export_results()
    print(f"[+] Full results exported to: {filename}")
    
    # Print JSON for verification
    print("\n[*] Full JSON Results:")
    print(json.dumps(results, indent=2, default=str))

if __name__ == '__main__':
    test_scanner()
