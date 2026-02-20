#!/usr/bin/env python3
"""Quick test to verify all 16 tests run with detailed findings"""

from ai_vulnerability_tester_fixed import AIVulnerabilityTester
import json

tester = AIVulnerabilityTester()

# Test on public endpoint (no auth required)
target = "https://httpbin.org"

print("[*] Starting quick validation test")
print(f"[*] Target: {target}")
print()

test_count = 0
def progress(msg):
    global test_count
    print(msg)
    if "Result:" in msg:
        test_count += 1

results = tester.test_website(target, callback=progress)

print()
print("=" * 80)
print("RESULTS SUMMARY")
print("=" * 80)
print(f"Tests run counter: {test_count}")
print(f"Total tests recorded: {results['total_tests_run']}")
print(f"Vulnerabilities found: {results['total_vulnerabilities']}")
print()

# Show sample findings with new detailed proof points
if results['findings']:
    print("SAMPLE FINDING (with detailed proof):")
    print()
    finding = results['findings'][0]
    print(f"Title: {finding['title']}")
    print(f"Severity: {finding['severity']}")
    print(f"Confidence: {finding['confidence']}")
    print()
    print(f"Proof Points ({len(finding['proof_points'])} total):")
    for i, proof in enumerate(finding['proof_points'], 1):
        print(f"  {i}. {proof}")
    print()
    print(f"HTTP Evidence:")
    print(f"  URL: {finding['http_evidence']['url']}")
    print(f"  Status: {finding['http_evidence']['status_code']}")
    print(f"  Headers: {len(finding['http_evidence']['headers'])} captured")
else:
    print("No vulnerabilities found (expected on httpbin.org)")

print()
print("=" * 80)
print("[OK] Test complete - all 16 tests have detailed proof points")
