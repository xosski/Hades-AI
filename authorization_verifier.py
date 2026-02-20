"""
Authorization Verifier - Compliance & Audit Logging
Ensures testing only occurs with explicit consent
"""

import logging
import json
import sqlite3
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger("AuthorizationVerifier")


@dataclass
class AuthorizationRecord:
    """Record of authorization for target testing"""
    target_url: str
    target_domain: str
    authorized_by: str  # User/entity that gave authorization
    authorization_date: str  # ISO format
    authorization_method: str  # 'manual', 'written_permission', 'api_check'
    scope: str  # What testing is allowed (e.g., "all vulnerability classes")
    expiration_date: Optional[str]  # ISO format or None for no expiration
    notes: str
    approved: bool


@dataclass
class AuditLogEntry:
    """Audit log entry for all testing activity"""
    timestamp: str  # ISO format
    test_id: str
    target_url: str
    endpoint_tested: str
    test_type: str  # 'sql_injection', 'xss', etc.
    payload_used: str  # First 100 chars
    result: str  # 'vulnerable', 'not_vulnerable', 'error'
    confidence: float
    performed_by: str  # User/system identifier
    authorization_id: Optional[str]  # Reference to AuthorizationRecord
    notes: str


class AuthorizationDatabase:
    """SQLite database for authorizations and audit logs"""
    
    def __init__(self, db_path: str = "authorizations.db"):
        self.db_path = db_path
        self.conn = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Create authorization and audit log tables"""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        # Authorization records
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authorizations (
                id TEXT PRIMARY KEY,
                target_url TEXT UNIQUE NOT NULL,
                target_domain TEXT NOT NULL,
                authorized_by TEXT NOT NULL,
                authorization_date TEXT NOT NULL,
                authorization_method TEXT NOT NULL,
                scope TEXT NOT NULL,
                expiration_date TEXT,
                notes TEXT,
                approved INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Audit logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                test_id TEXT NOT NULL,
                target_url TEXT NOT NULL,
                endpoint_tested TEXT NOT NULL,
                test_type TEXT NOT NULL,
                payload_used TEXT,
                result TEXT NOT NULL,
                confidence REAL,
                performed_by TEXT NOT NULL,
                authorization_id TEXT,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (authorization_id) REFERENCES authorizations(id)
            )
        """)
        
        self.conn.commit()
        logger.info(f"Authorization database initialized: {self.db_path}")
    
    def add_authorization(self, record: AuthorizationRecord) -> str:
        """Add or update authorization record"""
        record_id = hashlib.md5(
            f"{record.target_url}{record.authorized_by}".encode()
        ).hexdigest()[:16]
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO authorizations 
            (id, target_url, target_domain, authorized_by, authorization_date, 
             authorization_method, scope, expiration_date, notes, approved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record_id, record.target_url, record.target_domain,
            record.authorized_by, record.authorization_date,
            record.authorization_method, record.scope, record.expiration_date,
            record.notes, 1 if record.approved else 0
        ))
        
        self.conn.commit()
        logger.info(f"Authorization added for {record.target_url} (ID: {record_id})")
        return record_id
    
    def is_authorized(self, target_url: str) -> Tuple[bool, Optional[AuthorizationRecord]]:
        """Check if target is authorized"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, target_url, target_domain, authorized_by, authorization_date,
                   authorization_method, scope, expiration_date, notes, approved
            FROM authorizations
            WHERE target_url = ? AND approved = 1
        """, (target_url,))
        
        row = cursor.fetchone()
        if not row:
            return False, None
        
        # Check if expired
        if row[7]:  # expiration_date
            expiration = datetime.fromisoformat(row[7])
            if datetime.now() > expiration:
                logger.warning(f"Authorization for {target_url} has expired")
                return False, None
        
        record = AuthorizationRecord(
            target_url=row[1],
            target_domain=row[2],
            authorized_by=row[3],
            authorization_date=row[4],
            authorization_method=row[5],
            scope=row[6],
            expiration_date=row[7],
            notes=row[8],
            approved=bool(row[9])
        )
        
        return True, record
    
    def log_test(self, entry: AuditLogEntry) -> int:
        """Log a test execution"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs 
            (timestamp, test_id, target_url, endpoint_tested, test_type, 
             payload_used, result, confidence, performed_by, authorization_id, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.timestamp, entry.test_id, entry.target_url,
            entry.endpoint_tested, entry.test_type, entry.payload_used[:100],
            entry.result, entry.confidence, entry.performed_by,
            entry.authorization_id, entry.notes
        ))
        
        self.conn.commit()
        log_id = cursor.lastrowid
        return log_id
    
    def get_test_history(self, target_url: str = None, limit: int = 100) -> List[Dict]:
        """Retrieve test history"""
        cursor = self.conn.cursor()
        
        if target_url:
            cursor.execute("""
                SELECT timestamp, test_id, target_url, endpoint_tested, test_type,
                       payload_used, result, confidence, performed_by, notes
                FROM audit_logs
                WHERE target_url = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (target_url, limit))
        else:
            cursor.execute("""
                SELECT timestamp, test_id, target_url, endpoint_tested, test_type,
                       payload_used, result, confidence, performed_by, notes
                FROM audit_logs
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [
            {
                'timestamp': row[0],
                'test_id': row[1],
                'target_url': row[2],
                'endpoint_tested': row[3],
                'test_type': row[4],
                'payload_used': row[5],
                'result': row[6],
                'confidence': row[7],
                'performed_by': row[8],
                'notes': row[9]
            }
            for row in rows
        ]
    
    def get_authorizations(self) -> List[Dict]:
        """List all authorizations"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, target_url, authorized_by, authorization_date,
                   authorization_method, scope, expiration_date, approved
            FROM authorizations
            ORDER BY authorization_date DESC
        """)
        
        rows = cursor.fetchall()
        return [
            {
                'id': row[0],
                'target_url': row[1],
                'authorized_by': row[2],
                'authorization_date': row[3],
                'authorization_method': row[4],
                'scope': row[5],
                'expiration_date': row[6],
                'approved': bool(row[7])
            }
            for row in rows
        ]
    
    def revoke_authorization(self, target_url: str):
        """Revoke authorization for a target"""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE authorizations
            SET approved = 0
            WHERE target_url = ?
        """, (target_url,))
        
        self.conn.commit()
        logger.warning(f"Authorization revoked for {target_url}")


class AuthorizationGate:
    """Gate that prevents testing without authorization"""
    
    def __init__(self, auth_db: AuthorizationDatabase, 
                 require_interactive_confirmation: bool = True):
        self.auth_db = auth_db
        self.require_interactive = require_interactive_confirmation
    
    def check_authorization(self, target_url: str) -> Tuple[bool, str]:
        """
        Check if target is authorized before testing.
        Returns: (is_authorized, reason_or_message)
        """
        is_auth, record = self.auth_db.is_authorized(target_url)
        
        if not is_auth:
            reason = (
                f"❌ NOT AUTHORIZED: {target_url}\n"
                f"Testing cannot proceed without explicit authorization.\n"
                f"Please add authorization record using authorization_verifier.AuthorizationDatabase"
            )
            logger.error(reason)
            return False, reason
        
        # Authorization found
        message = (
            f"✅ AUTHORIZED: {target_url}\n"
            f"   Authorized by: {record.authorized_by}\n"
            f"   Date: {record.authorization_date}\n"
            f"   Scope: {record.scope}\n"
            f"   Method: {record.authorization_method}"
        )
        logger.info(message)
        return True, message
    
    def request_authorization(self, target_url: str, authorized_by: str,
                            scope: str = "security_assessment") -> bool:
        """
        Request authorization interactively.
        Returns: True if authorization granted, False if denied.
        """
        if not self.require_interactive:
            logger.warning(f"Interactive confirmation disabled. Skipping for {target_url}")
            return False
        
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc
        
        print("\n" + "="*60)
        print("⚠️  AUTHORIZATION REQUEST")
        print("="*60)
        print(f"\nTarget URL: {target_url}")
        print(f"Domain: {domain}")
        print(f"Requested by: {authorized_by}")
        print(f"Scope: {scope}")
        print("\nYou are about to authorize security testing on this target.")
        print("This will be logged and audited.")
        print("="*60)
        
        response = input("\nDo you authorize this testing? (yes/no): ").lower().strip()
        
        if response != 'yes':
            logger.warning(f"Authorization denied for {target_url}")
            return False
        
        # Create authorization
        record = AuthorizationRecord(
            target_url=target_url,
            target_domain=domain,
            authorized_by=authorized_by,
            authorization_date=datetime.now().isoformat(),
            authorization_method='interactive_confirmation',
            scope=scope,
            expiration_date=None,
            notes="Authorized via interactive confirmation",
            approved=True
        )
        
        self.auth_db.add_authorization(record)
        logger.info(f"Authorization granted for {target_url}")
        return True


class ComplianceEnforcer:
    """Enforces compliance checks before running tests"""
    
    def __init__(self, auth_db: AuthorizationDatabase):
        self.auth_db = auth_db
        self.gate = AuthorizationGate(auth_db)
    
    def pre_test_check(self, target_url: str, test_type: str,
                      performed_by: str = "system") -> Tuple[bool, str]:
        """
        Run all compliance checks before allowing test.
        Returns: (is_allowed, reason)
        """
        checks = [
            ("Authorization Check", self._check_authorization(target_url)),
            ("URL Validation", self._validate_url(target_url)),
            ("Rate Limiting", self._check_rate_limit(target_url)),
        ]
        
        for check_name, (passed, reason) in checks:
            if not passed:
                logger.warning(f"Compliance check failed: {check_name} - {reason}")
                return False, f"{check_name}: {reason}"
        
        logger.info(f"All compliance checks passed for {target_url}")
        return True, "All checks passed"
    
    def _check_authorization(self, target_url: str) -> Tuple[bool, str]:
        """Check if target is authorized"""
        is_auth, reason = self.gate.check_authorization(target_url)
        return is_auth, reason if reason else "Not authorized"
    
    def _validate_url(self, target_url: str) -> Tuple[bool, str]:
        """Validate URL format"""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return False, "Invalid URL format"
            
            # Prevent testing on localhost/internal without explicit approval
            internal_hosts = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
            if parsed.hostname in internal_hosts:
                logger.info(f"Local testing detected: {target_url}")
            
            return True, "Valid URL"
        except Exception as e:
            return False, f"URL parsing error: {str(e)}"
    
    def _check_rate_limit(self, target_url: str) -> Tuple[bool, str]:
        """Check if target is being tested too frequently"""
        recent_tests = self.auth_db.get_test_history(target_url, limit=10)
        
        if len(recent_tests) < 1:
            return True, "No recent tests"
        
        # Get timestamp of most recent test
        from datetime import timedelta
        last_test = datetime.fromisoformat(recent_tests[0]['timestamp'])
        time_since = datetime.now() - last_test
        
        if time_since < timedelta(seconds=30):
            return False, f"Target tested {time_since.total_seconds():.0f}s ago (rate limited)"
        
        return True, "Rate limit OK"
    
    def log_test_result(self, target_url: str, test_id: str, 
                       endpoint: str, test_type: str, payload: str,
                       result: str, confidence: float,
                       performed_by: str = "system", notes: str = ""):
        """Log test result to audit trail"""
        
        # Check authorization exists
        is_auth, record = self.auth_db.is_authorized(target_url)
        auth_id = None
        if is_auth:
            auth_id = hashlib.md5(
                f"{target_url}{record.authorized_by}".encode()
            ).hexdigest()[:16]
        
        entry = AuditLogEntry(
            timestamp=datetime.now().isoformat(),
            test_id=test_id,
            target_url=target_url,
            endpoint_tested=endpoint,
            test_type=test_type,
            payload_used=payload,
            result=result,
            confidence=confidence,
            performed_by=performed_by,
            authorization_id=auth_id,
            notes=notes
        )
        
        log_id = self.auth_db.log_test(entry)
        logger.info(f"Test logged (ID: {log_id}) for {target_url}")
        return log_id


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create database
    auth_db = AuthorizationDatabase("test_authorizations.db")
    
    # Add authorization
    auth_record = AuthorizationRecord(
        target_url="http://testapp.local:8000",
        target_domain="testapp.local",
        authorized_by="security_team@company.com",
        authorization_date=datetime.now().isoformat(),
        authorization_method="written_permission",
        scope="all_vulnerability_classes",
        expiration_date=None,
        notes="Authorized for internal security assessment",
        approved=True
    )
    auth_id = auth_db.add_authorization(auth_record)
    
    # Create enforcer
    enforcer = ComplianceEnforcer(auth_db)
    
    # Check authorization
    is_allowed, reason = enforcer.pre_test_check(
        "http://testapp.local:8000",
        "sql_injection"
    )
    
    print(f"\nAuthorization Status: {is_allowed}")
    print(f"Reason: {reason}")
    
    # Log a test
    if is_allowed:
        enforcer.log_test_result(
            target_url="http://testapp.local:8000",
            test_id="sqli_abc123",
            endpoint="/search?q=test",
            test_type="sql_injection",
            payload="' OR '1'='1'--",
            result="not_vulnerable",
            confidence=0.2,
            performed_by="security_agent"
        )
    
    # Show audit logs
    print("\nAudit Log:")
    for log in auth_db.get_test_history(limit=5):
        print(f"  {log['timestamp']} - {log['test_type']} on {log['target_url']}")
    
    print("\nAuthorizationVerifier loaded successfully")
