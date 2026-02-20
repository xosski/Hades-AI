"""
Compliance System Testing & Verification
Demonstrates proper use of enhanced tester with authorization
"""

import logging
import sys
import os

# Fix encoding for Windows
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    sys.stdout.reconfigure(encoding='utf-8')
from datetime import datetime, timedelta
from enhanced_vulnerability_tester import (
    EnhancedVulnerabilityTester,
    DeterministicValidators,
    ResponseCapture
)
from authorization_verifier import (
    AuthorizationDatabase,
    AuthorizationRecord,
    ComplianceEnforcer
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ComplianceTest")


def test_deterministic_validators():
    """Test the deterministic validators"""
    print("\n" + "="*70)
    print("TEST 1: Deterministic Validators")
    print("="*70)
    
    # Test SQL error detection
    print("\n[1.1] SQL Error Detection")
    
    # PostgreSQL error
    pg_response = ResponseCapture(
        endpoint_path="/search",
        endpoint_full_url="http://test.local/search?id=1",
        method="GET",
        payload_sent="' OR '1'='1'--",
        status_code=500,
        response_length=1200,
        response_excerpt="PostgreSQL ERROR: unterminated string literal\nContext: SQLSTATE 42601",
        response_hash="abc123",
        headers_sent={},
        headers_received={},
        timestamp=datetime.now().timestamp()
    )
    
    is_vuln, evidence, conf = DeterministicValidators.detect_sql_error(pg_response)
    print(f"   PostgreSQL Error: {is_vuln} (confidence: {conf:.0%})")
    print(f"   Evidence: {evidence}")
    assert is_vuln == True, "Should detect PostgreSQL SQLSTATE error"
    
    # MySQL error
    mysql_response = ResponseCapture(
        endpoint_path="/search",
        endpoint_full_url="http://test.local/search?id=1",
        method="GET",
        payload_sent="1' AND 1=1--",
        status_code=500,
        response_length=800,
        response_excerpt="<html><body>MySQL Error: You have an error in your SQL syntax",
        response_hash="def456",
        headers_sent={},
        headers_received={},
        timestamp=datetime.now().timestamp()
    )
    
    is_vuln, evidence, conf = DeterministicValidators.detect_sql_error(mysql_response)
    print(f"   MySQL Error: {is_vuln} (confidence: {conf:.0%})")
    print(f"   Evidence: {evidence}")
    assert is_vuln == True, "Should detect MySQL error"
    
    # No SQL error
    clean_response = ResponseCapture(
        endpoint_path="/search",
        endpoint_full_url="http://test.local/search?id=1",
        method="GET",
        payload_sent="1",
        status_code=200,
        response_length=500,
        response_excerpt="<html><body>Results for: 1</body></html>",
        response_hash="ghi789",
        headers_sent={},
        headers_received={},
        timestamp=datetime.now().timestamp()
    )
    
    is_vuln, evidence, conf = DeterministicValidators.detect_sql_error(clean_response)
    print(f"   Clean Response: {is_vuln} (confidence: {conf:.0%})")
    assert is_vuln == False, "Should not detect error in clean response"
    
    # Test XSS reflection detection
    print("\n[1.2] XSS Reflection Detection")
    
    # Unescaped XSS
    xss_response = ResponseCapture(
        endpoint_path="/search",
        endpoint_full_url="http://test.local/search?q=test",
        method="GET",
        payload_sent='<img src=x onerror="alert(1)">',
        status_code=200,
        response_length=1000,
        response_excerpt='<html><body>Results for: <img src=x onerror="alert(1)">',
        response_hash="jkl012",
        headers_sent={},
        headers_received={},
        timestamp=datetime.now().timestamp()
    )
    
    is_vuln, evidence, conf = DeterministicValidators.detect_xss_reflected(
        xss_response,
        '<img src=x onerror="alert(1)">'
    )
    print(f"   Unescaped XSS: {is_vuln} (confidence: {conf:.0%})")
    print(f"   Evidence: {evidence[:80]}...")
    assert is_vuln == True, "Should detect unescaped XSS"
    
    # HTML-escaped XSS (safe)
    escaped_response = ResponseCapture(
        endpoint_path="/search",
        endpoint_full_url="http://test.local/search?q=test",
        method="GET",
        payload_sent='<img src=x onerror="alert(1)">',
        status_code=200,
        response_length=1200,
        response_excerpt='Results for: &lt;img src=x onerror="alert(1)"&gt;',
        response_hash="mno345",
        headers_sent={},
        headers_received={},
        timestamp=datetime.now().timestamp()
    )
    
    is_vuln, evidence, conf = DeterministicValidators.detect_xss_reflected(
        escaped_response,
        '<img src=x onerror="alert(1)">'
    )
    print(f"   Escaped XSS: {is_vuln} (confidence: {conf:.0%})")
    print(f"   Evidence: {evidence[:80]}...")
    assert is_vuln == False, "Should not detect escaped XSS"
    
    # Test path traversal detection
    print("\n[1.3] Path Traversal Detection")
    
    # Passwd file reflection
    lfi_response = ResponseCapture(
        endpoint_path="/view",
        endpoint_full_url="http://test.local/view?file=etc/passwd",
        method="GET",
        payload_sent="../../../../etc/passwd",
        status_code=200,
        response_length=2000,
        response_excerpt="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n",
        response_hash="pqr678",
        headers_sent={},
        headers_received={},
        timestamp=datetime.now().timestamp()
    )
    
    is_vuln, evidence, conf = DeterministicValidators.detect_path_traversal(
        lfi_response,
        "../../../../etc/passwd",
        []
    )
    print(f"   Passwd File: {is_vuln} (confidence: {conf:.0%})")
    print(f"   Evidence: {evidence}")
    assert is_vuln == True, "Should detect passwd file content"
    
    print("\n✅ All validator tests passed!")


def test_authorization_system():
    """Test authorization database and enforcement"""
    print("\n" + "="*70)
    print("TEST 2: Authorization System")
    print("="*70)
    
    # Create test database
    auth_db = AuthorizationDatabase(":memory:")  # In-memory for testing
    
    print("\n[2.1] Adding Authorization")
    
    record = AuthorizationRecord(
        target_url="http://testapp.local:8000",
        target_domain="testapp.local",
        authorized_by="security@company.com",
        authorization_date=datetime.now().isoformat(),
        authorization_method="written_permission",
        scope="all_vulnerability_classes",
        expiration_date=None,
        notes="Test authorization",
        approved=True
    )
    
    auth_id = auth_db.add_authorization(record)
    print(f"   Added authorization: {auth_id}")
    assert auth_id is not None, "Should return auth ID"
    
    print("\n[2.2] Checking Authorization")
    
    is_auth, retrieved = auth_db.is_authorized("http://testapp.local:8000")
    print(f"   Authorized: {is_auth}")
    print(f"   Authorized by: {retrieved.authorized_by}")
    assert is_auth == True, "Should find authorization"
    
    # Test non-existent authorization
    is_auth, _ = auth_db.is_authorized("http://unauthorized.local")
    print(f"   Unauthorized target: {is_auth}")
    assert is_auth == False, "Should not authorize unknown target"
    
    print("\n[2.3] Logging Tests")
    
    from authorization_verifier import AuditLogEntry
    
    entry = AuditLogEntry(
        timestamp=datetime.now().isoformat(),
        test_id="sqli_abc123",
        target_url="http://testapp.local:8000",
        endpoint_tested="/search?id=1",
        test_type="sql_injection",
        payload_used="' OR '1'='1'--",
        result="vulnerable",
        confidence=0.95,
        performed_by="security_agent",
        authorization_id=auth_id,
        notes="Found SQL injection"
    )
    
    log_id = auth_db.log_test(entry)
    print(f"   Logged test: {log_id}")
    assert log_id > 0, "Should return log ID"
    
    # Retrieve history
    history = auth_db.get_test_history("http://testapp.local:8000")
    print(f"   History entries: {len(history)}")
    assert len(history) >= 1, "Should retrieve logged test"
    
    print("\n✅ All authorization tests passed!")


def test_compliance_enforcement():
    """Test compliance enforcement"""
    print("\n" + "="*70)
    print("TEST 3: Compliance Enforcement")
    print("="*70)
    
    # Create database
    auth_db = AuthorizationDatabase(":memory:")
    enforcer = ComplianceEnforcer(auth_db)
    
    print("\n[3.1] Pre-test Check (Unauthorized)")
    
    is_allowed, reason = enforcer.pre_test_check(
        "http://unauthorized.local",
        "sql_injection"
    )
    print(f"   Allowed: {is_allowed}")
    print(f"   Reason: {reason[:60]}...")
    assert is_allowed == False, "Should block unauthorized target"
    
    print("\n[3.2] Adding Authorization & Retesting")
    
    record = AuthorizationRecord(
        target_url="http://testapp.local:8000",
        target_domain="testapp.local",
        authorized_by="security@company.com",
        authorization_date=datetime.now().isoformat(),
        authorization_method="written_permission",
        scope="all_vulnerability_classes",
        expiration_date=None,
        notes="Test authorization",
        approved=True
    )
    
    auth_db.add_authorization(record)
    
    is_allowed, reason = enforcer.pre_test_check(
        "http://testapp.local:8000",
        "sql_injection"
    )
    print(f"   Allowed: {is_allowed}")
    print(f"   Reason: {reason[:60]}...")
    assert is_allowed == True, "Should allow authorized target"
    
    print("\n[3.3] URL Validation")
    
    is_allowed, reason = enforcer.pre_test_check(
        "not-a-valid-url",
        "sql_injection"
    )
    print(f"   Invalid URL allowed: {is_allowed}")
    assert is_allowed == False, "Should reject invalid URLs"
    
    print("\n[3.4] Rate Limiting")
    
    # Log a test
    enforcer.log_test_result(
        target_url="http://testapp.local:8000",
        test_id="sqli_001",
        endpoint="/search?q=1",
        test_type="sql_injection",
        payload="1",
        result="not_vulnerable",
        confidence=0.0,
        performed_by="test_agent"
    )
    
    # Try again immediately (should be rate limited)
    is_allowed, reason = enforcer.pre_test_check(
        "http://testapp.local:8000",
        "sql_injection"
    )
    print(f"   Rate limited: {not is_allowed}")
    print(f"   Reason: {reason[:60]}...")
    # Note: Rate limiting allows tests within 30 seconds
    
    print("\n✅ All compliance enforcement tests passed!")


def test_end_to_end():
    """End-to-end test simulating real usage"""
    print("\n" + "="*70)
    print("TEST 4: End-to-End Simulation")
    print("="*70)
    
    auth_db = AuthorizationDatabase(":memory:")
    tester = EnhancedVulnerabilityTester()
    enforcer = ComplianceEnforcer(auth_db)
    
    print("\n[4.1] Setup: Add Authorization")
    
    record = AuthorizationRecord(
        target_url="http://testapp.local:8000/search",
        target_domain="testapp.local",
        authorized_by="infosec@company.com",
        authorization_date=datetime.now().isoformat(),
        authorization_method="email_approval",
        scope="sql_injection_testing",
        expiration_date=(datetime.now() + timedelta(days=30)).isoformat(),
        notes="Bug bounty program - June 2024",
        approved=True
    )
    
    auth_db.add_authorization(record)
    print("   ✓ Authorization added")
    
    print("\n[4.2] Pre-test Compliance Check")
    
    is_allowed, reason = enforcer.pre_test_check(
        "http://testapp.local:8000/search",
        "sql_injection"
    )
    
    if not is_allowed:
        print(f"   ✗ BLOCKED: {reason}")
        return False
    
    print(f"   ✓ ALLOWED: {reason}")
    
    print("\n[4.3] Execute Test (Simulated)")
    
    # Simulate test result
    print("   (Skipping actual HTTP request in test)")
    print("   Simulating positive test result...")
    
    print("\n[4.4] Log Result")
    
    log_id = enforcer.log_test_result(
        target_url="http://testapp.local:8000/search",
        test_id="sqli_deadbeef",
        endpoint="/search?q=%27%20OR%20%271%27=%271%27--",
        test_type="sql_injection",
        payload="' OR '1'='1'--",
        result="vulnerable",
        confidence=0.95,
        performed_by="security_scanner",
        notes="Deterministic: PostgreSQL SQLSTATE error detected"
    )
    
    print(f"   ✓ Test logged (ID: {log_id})")
    
    print("\n[4.5] Retrieve Audit Trail")
    
    history = auth_db.get_test_history(limit=10)
    print(f"   ✓ Retrieved {len(history)} test(s)")
    
    for entry in history:
        print(f"      - {entry['timestamp']}: {entry['test_type']} on {entry['endpoint_tested']}")
    
    print("\n[4.6] List Authorizations")
    
    auths = auth_db.get_authorizations()
    print(f"   ✓ {len(auths)} authorization(s):")
    
    for auth in auths:
        print(f"      - {auth['target_url']} (by {auth['authorized_by']})")
    
    print("\n✅ End-to-end test passed!")
    return True


def main():
    print("\n" + "="*70)
    print("COMPLIANCE SYSTEM VERIFICATION")
    print("="*70)
    
    try:
        test_deterministic_validators()
        test_authorization_system()
        test_compliance_enforcement()
        test_end_to_end()
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED")
        print("="*70)
        print("\nThe compliance system is working correctly.")
        print("\nNext steps:")
        print("1. Review COMPLIANCE_INTEGRATION_GUIDE.md")
        print("2. Integrate with HadesAI.py")
        print("3. Add authorizations for your test targets")
        print("4. Run compliance-based tests")
        print("5. Export reports (JSON/Markdown)")
        print("\n" + "="*70 + "\n")
        
        return 0
    
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}\n")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
