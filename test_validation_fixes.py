#!/usr/bin/env python3
"""Test validation fixes"""

from validation_enforcement import (
    ScopeValidator, ProofValidator, ConfidenceEnforcer, ComplianceReport
)

def test_scope_validation():
    """Test 1: Scope validation"""
    validator = ScopeValidator()
    
    print("\n[TEST 1] Scope Validation")
    print("-" * 60)
    
    tests = [
        ('https://hackerone.com/opportunities/all', False),
        ('https://bugcrowd.com/programs', False),
        ('https://example.com/app', True),
        ('https://target.local', True),
    ]
    
    for url, expected in tests:
        in_scope, reason = validator.is_in_scope(url)
        status = "[OK]" if in_scope == expected else "[FAIL]"
        print(f"{status} {url}: {in_scope} ({reason})")

def test_confidence_status_alignment():
    """Test 2: Confidence/Status alignment"""
    enforcer = ConfidenceEnforcer()
    
    print("\n[TEST 2] Confidence/Status Alignment")
    print("-" * 60)
    
    tests = [
        ('sql_injection', 0.2, 'Confirmed', 0),  # WRONG
        ('sql_injection', 0.2, 'Suspected', 0),  # CORRECT
        ('xss', 0.8, 'Confirmed', 1),  # CORRECT
        ('path_traversal', 0.5, 'Confirmed', 0),  # WRONG
    ]
    
    for vuln_type, conf, status, proofs in tests:
        is_valid, proper_status, reason = enforcer.validate_confidence_status_alignment(
            vuln_type, conf, status, proofs
        )
        marker = "[OK]" if is_valid else "[FAIL]"
        print(f"{marker} {vuln_type} @ {conf:.0%}: {status} -> {proper_status}")
        print(f"   {reason}")

def test_proof_validation():
    """Test 3: Proof validation"""
    print("\n[TEST 3] Proof Validation")
    print("-" * 60)
    
    # Bad proof: Just HTTP 200
    bad_sql_response = "HTTP 200 OK\n<html>Page loaded</html>"
    is_valid, conf, proof = ProofValidator.validate_sql_injection(
        bad_sql_response, "' OR '1'='1", 200, "<html>Page loaded</html>"
    )
    print(f"[TEST] HTTP 200 only: Valid={is_valid}, Confidence={conf:.0%}")
    
    # Good proof: Actual error
    good_sql_response = "MySQL Error: SQL syntax error in 'SELECT * WHERE id = 1'"
    is_valid, conf, proof = ProofValidator.validate_sql_injection(
        good_sql_response, "' OR '1'='1", 200, "<html>Page loaded</html>"
    )
    print(f"[TEST] With error message: Valid={is_valid}, Confidence={conf:.0%}")

def test_compliance_report():
    """Test 4: Full compliance validation"""
    print("\n[TEST 4] Full Compliance Report")
    print("-" * 60)
    
    report = ComplianceReport()
    
    bad_finding = {
        'type': 'sql_injection',
        'confidence': 0.2,
        'status': 'Confirmed',
        'endpoint': 'https://hackerone.com/opportunities',
        'response': 'HTTP 200 OK',
        'payload': "' OR '1'='1",
    }
    
    validated = report.validate_finding(bad_finding)
    
    print(f"Original: status={bad_finding['status']}, confidence={bad_finding['confidence']:.0%}")
    print(f"Scope check: {validated.get('scope_check')}")
    print(f"Scope reason: {validated.get('scope_reason')}")
    print(f"Status: {validated.get('status')}")
    if validated.get('rejection_reason'):
        print(f"Reason: {validated['rejection_reason']}")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("VALIDATION ENFORCEMENT TEST SUITE")
    print("="*60)
    
    test_scope_validation()
    test_confidence_status_alignment()
    test_proof_validation()
    test_compliance_report()
    
    print("\n" + "="*60)
    print("ALL TESTS COMPLETED")
    print("="*60)
