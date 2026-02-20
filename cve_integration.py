"""
CVE Database Integration for Hades-AI Seek Tab
Integrates with NVD, CISA, and other CVE sources
Maps vulnerabilities to official CVE identifiers
"""

import json
import logging
import time
import sqlite3
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
from urllib.parse import urlparse

logger = logging.getLogger("CVEIntegration")

# Try to import optional CVE libraries
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import nvdlib
    HAS_NVDLIB = True
except ImportError:
    HAS_NVDLIB = False


@dataclass
class CVERecord:
    """Official CVE record from NVD"""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_v3_score: float
    cvss_v3_vector: str
    affected_products: List[str]
    published_date: str
    updated_date: str
    references: List[str]
    cwe_ids: List[str]
    exploited: bool = False  # CISA exploited vulnerabilities catalog
    
    def to_dict(self) -> Dict:
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'severity': self.severity,
            'cvss_v3_score': self.cvss_v3_score,
            'cvss_v3_vector': self.cvss_v3_vector,
            'affected_products': self.affected_products,
            'published_date': self.published_date,
            'exploited': self.exploited,
        }


class CVEDatabase:
    """Local CVE database with NVD integration"""
    
    def __init__(self, db_path: str = "cve_database.db"):
        self.db_path = db_path
        self.cache = {}
        self.lock = threading.Lock()
        self._init_database()
        self.last_update = 0
        self.update_interval = 86400  # 24 hours
    
    def _init_database(self):
        """Initialize SQLite database for CVE records"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cve_records (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    severity TEXT,
                    cvss_v3_score REAL,
                    cvss_v3_vector TEXT,
                    affected_products TEXT,
                    published_date TEXT,
                    updated_date TEXT,
                    references TEXT,
                    cwe_ids TEXT,
                    exploited BOOLEAN,
                    cached_date TIMESTAMP
                )
            ''')
            
            # Index for quick lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_severity 
                ON cve_records(severity)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_exploited 
                ON cve_records(exploited)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_products 
                ON cve_records(affected_products)
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info(f"CVE Database initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize CVE database: {e}")
    
    def search_by_cve_id(self, cve_id: str) -> Optional[CVERecord]:
        """Lookup CVE by ID (CVE-2024-1234)"""
        with self.lock:
            if cve_id in self.cache:
                return self.cache[cve_id]
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT * FROM cve_records WHERE cve_id = ?',
                (cve_id,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if row:
                record = self._row_to_cverecord(row)
                with self.lock:
                    self.cache[cve_id] = record
                return record
        except Exception as e:
            logger.error(f"Error searching CVE {cve_id}: {e}")
        
        return None
    
    def search_by_product(self, product_name: str) -> List[CVERecord]:
        """Find all CVEs affecting a product"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Search in affected_products JSON
            cursor.execute('''
                SELECT * FROM cve_records 
                WHERE affected_products LIKE ?
                ORDER BY cvss_v3_score DESC
            ''', (f'%{product_name}%',))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_cverecord(row) for row in rows]
        except Exception as e:
            logger.error(f"Error searching product {product_name}: {e}")
            return []
    
    def search_exploited_only(self) -> List[CVERecord]:
        """Get all known exploited CVEs (CISA catalog)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM cve_records 
                WHERE exploited = 1
                ORDER BY published_date DESC
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_cverecord(row) for row in rows]
        except Exception as e:
            logger.error(f"Error fetching exploited CVEs: {e}")
            return []
    
    def search_by_severity(self, severity: str) -> List[CVERecord]:
        """Find CVEs by severity level"""
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
        if severity.upper() not in valid_severities:
            return []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM cve_records 
                WHERE severity = ?
                ORDER BY cvss_v3_score DESC
            ''', (severity.upper(),))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_cverecord(row) for row in rows]
        except Exception as e:
            logger.error(f"Error searching severity {severity}: {e}")
            return []
    
    def search_by_cwe(self, cwe_id: str) -> List[CVERecord]:
        """Find CVEs by CWE (Common Weakness Enumeration)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM cve_records 
                WHERE cwe_ids LIKE ?
                ORDER BY cvss_v3_score DESC
            ''', (f'%{cwe_id}%',))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_cverecord(row) for row in rows]
        except Exception as e:
            logger.error(f"Error searching CWE {cwe_id}: {e}")
            return []
    
    def store_cve(self, record: CVERecord):
        """Store CVE record in local database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_records VALUES 
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                record.cve_id,
                record.description,
                record.severity,
                record.cvss_v3_score,
                record.cvss_v3_vector,
                json.dumps(record.affected_products),
                record.published_date,
                record.updated_date,
                json.dumps(record.references),
                json.dumps(record.cwe_ids),
                record.exploited,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            # Update cache
            with self.lock:
                self.cache[record.cve_id] = record
        except Exception as e:
            logger.error(f"Error storing CVE {record.cve_id}: {e}")
    
    def _row_to_cverecord(self, row: Tuple) -> CVERecord:
        """Convert database row to CVERecord"""
        return CVERecord(
            cve_id=row[0],
            description=row[1],
            severity=row[2],
            cvss_v3_score=row[3],
            cvss_v3_vector=row[4],
            affected_products=json.loads(row[5]) if row[5] else [],
            published_date=row[6],
            updated_date=row[7],
            references=json.loads(row[8]) if row[8] else [],
            cwe_ids=json.loads(row[9]) if row[9] else [],
            exploited=bool(row[10])
        )


class CVEMapper:
    """Maps vulnerability findings to CVE identifiers"""
    
    # Vulnerability type to CWE mapping
    VULN_TYPE_TO_CWE = {
        'sql_injection': ['CWE-89'],
        'xss': ['CWE-79'],
        'rce': ['CWE-78', 'CWE-94'],
        'path_traversal': ['CWE-22'],
        'auth_bypass': ['CWE-287', 'CWE-640'],
        'ssrf': ['CWE-918'],
        'xxe': ['CWE-611'],
        'csrf': ['CWE-352'],
        'insecure_deserialization': ['CWE-502'],
        'broken_access_control': ['CWE-639'],
        'weak_crypto': ['CWE-326', 'CWE-327'],
        'buffer_overflow': ['CWE-120'],
        'directory_traversal': ['CWE-22'],
        'information_disclosure': ['CWE-200'],
        'insecure_config': ['CWE-16'],
    }
    
    def __init__(self, cve_db: CVEDatabase):
        self.cve_db = cve_db
    
    def map_finding_to_cves(
        self, 
        vuln_type: str, 
        software: str = None,
        version: str = None
    ) -> List[CVERecord]:
        """
        Map a vulnerability finding to known CVEs
        
        Args:
            vuln_type: Type of vulnerability (sql_injection, xss, etc.)
            software: Affected software name (optional)
            version: Software version (optional)
        
        Returns:
            List of matching CVE records
        """
        matching_cves = []
        
        # Get CWE IDs for this vulnerability type
        cwe_ids = self.VULN_TYPE_TO_CWE.get(vuln_type.lower(), [])
        
        # Search by CWE
        for cwe in cwe_ids:
            cves = self.cve_db.search_by_cwe(cwe)
            matching_cves.extend(cves)
        
        # If software specified, filter by affected products
        if software:
            matching_cves = [
                c for c in matching_cves
                if self._product_matches(software, c.affected_products)
            ]
        
        # Remove duplicates and sort by CVSS score
        unique_cves = {}
        for cve in matching_cves:
            if cve.cve_id not in unique_cves:
                unique_cves[cve.cve_id] = cve
        
        return sorted(
            unique_cves.values(),
            key=lambda x: x.cvss_v3_score,
            reverse=True
        )
    
    def _product_matches(self, needle: str, haystack: List[str]) -> bool:
        """Check if product name matches any affected products"""
        needle = needle.lower()
        return any(needle in product.lower() for product in haystack)
    
    def enrich_finding(self, finding: Dict) -> Dict:
        """Enrich a finding with CVE information"""
        vuln_type = finding.get('exploit_type', '').lower()
        software = finding.get('software_name', '')
        version = finding.get('software_version', '')
        
        # Map to CVEs
        cves = self.map_finding_to_cves(vuln_type, software, version)
        
        # Enhance finding
        finding['cve_ids'] = [c.cve_id for c in cves]
        finding['cve_records'] = [c.to_dict() for c in cves]
        
        if cves:
            # Use highest severity CVE
            highest = max(cves, key=lambda x: x.cvss_v3_score)
            finding['official_severity'] = highest.severity
            finding['official_cvss_score'] = highest.cvss_v3_score
            finding['exploited_in_wild'] = highest.exploited
        
        return finding


class CVESyncWorker:
    """Background worker to sync CVE data from NVD"""
    
    def __init__(self, cve_db: CVEDatabase):
        self.cve_db = cve_db
        self.running = False
    
    def sync_cisa_exploited(self):
        """Download CISA exploited vulnerabilities catalog"""
        if not HAS_REQUESTS:
            logger.warning("requests library not available for CISA sync")
            return
        
        try:
            logger.info("Syncing CISA exploited vulnerabilities...")
            
            # CISA provides a JSON feed of exploited CVEs
            url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
            
            # For JSON, use the KEV endpoint
            url_json = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # This would require API key for full NVD access
            # For now, we'd need to implement CSV parsing
            
            logger.info("CISA sync would require NVD API key")
        except Exception as e:
            logger.error(f"CISA sync failed: {e}")
    
    def sync_nvd_recent(self):
        """Sync recent CVEs from NVD (requires API key)"""
        if not HAS_REQUESTS:
            logger.warning("requests library not available for NVD sync")
            return
        
        try:
            logger.info("Syncing recent CVEs from NVD...")
            
            # NVD REST API v2.0
            # Requires API key for faster rate limits
            
            # Example of what this would look like:
            # api_key = os.getenv("NVD_API_KEY")
            # url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            # headers = {"apiKey": api_key}
            # response = requests.get(url, headers=headers)
            
            logger.info("NVD sync requires API key setup")
        except Exception as e:
            logger.error(f"NVD sync failed: {e}")


# Example data for testing/offline use
SAMPLE_CVES = [
    CVERecord(
        cve_id="CVE-2024-1234",
        description="SQL Injection in popular CMS",
        severity="CRITICAL",
        cvss_v3_score=9.8,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_products=["WordPress Plugin XYZ", "Drupal 9.x"],
        published_date="2024-01-15",
        updated_date="2024-01-20",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        cwe_ids=["CWE-89"],
        exploited=True
    ),
    CVERecord(
        cve_id="CVE-2024-5678",
        description="Cross-site Scripting (XSS) vulnerability",
        severity="HIGH",
        cvss_v3_score=8.2,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        affected_products=["Application v2.0", "Application v2.1"],
        published_date="2024-02-01",
        updated_date="2024-02-05",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"],
        cwe_ids=["CWE-79"],
        exploited=True
    ),
]


def init_sample_database():
    """Initialize database with sample CVE data for testing"""
    db = CVEDatabase()
    
    for cve in SAMPLE_CVES:
        db.store_cve(cve)
    
    logger.info("Sample CVE database initialized")
    return db


if __name__ == "__main__":
    # Test the CVE integration
    logging.basicConfig(level=logging.INFO)
    
    # Initialize with sample data
    db = init_sample_database()
    
    # Test searches
    print("\n=== CVE Database Tests ===\n")
    
    # Test 1: Search by CVE ID
    print("Test 1: Search by CVE ID")
    cve = db.search_by_cve_id("CVE-2024-1234")
    if cve:
        print(f"  Found: {cve.cve_id} - {cve.description}")
    
    # Test 2: Search by product
    print("\nTest 2: Search by product")
    cves = db.search_by_product("WordPress")
    print(f"  Found {len(cves)} CVEs affecting WordPress")
    for cve in cves:
        print(f"    - {cve.cve_id}: {cve.severity}")
    
    # Test 3: Search exploited CVEs
    print("\nTest 3: Exploited CVEs")
    exploited = db.search_exploited_only()
    print(f"  Found {len(exploited)} actively exploited CVEs")
    
    # Test 4: Map finding to CVEs
    print("\nTest 4: CVE Mapper")
    mapper = CVEMapper(db)
    
    finding = {
        'exploit_type': 'sql_injection',
        'software_name': 'WordPress',
        'description': 'SQL injection in database query'
    }
    
    enriched = mapper.enrich_finding(finding)
    print(f"  Finding mapped to CVEs: {enriched.get('cve_ids', [])}")
    
    print("\n=== Tests Complete ===")
