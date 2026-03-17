"""
Real-time Threat Intelligence Integrator for HadesAI Phase 2
Integrates live CVE feeds, exploit databases, and threat correlations
"""

import sqlite3
import json
import hashlib
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime, timedelta
import queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== ENUMS ====================

class ThreatSource(Enum):
    """Threat intelligence sources"""
    NVD_CVE = "nvd_cve"
    EXPLOIT_DB = "exploit_db"
    SECURITYFOCUS = "securityfocus"
    SHODAN = "shodan"
    CENSYS = "censys"
    ALIENVAULT_OTX = "alienvault_otx"
    INTERNAL_INTEL = "internal_intel"


class IntelligenceType(Enum):
    """Types of intelligence"""
    CVE = "cve"
    EXPLOIT = "exploit"
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    INDICATOR_OF_COMPROMISE = "ioc"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"


class SeverityRating(Enum):
    """CVSS severity ratings"""
    NONE = 0.0
    LOW = 3.9
    MEDIUM = 6.9
    HIGH = 8.9
    CRITICAL = 10.0


# ==================== DATA CLASSES ====================

@dataclass
class ThreatIntelligence:
    """Unified threat intelligence record"""
    id: str
    source: ThreatSource
    intel_type: IntelligenceType
    title: str
    description: str
    severity: SeverityRating
    confidence: float
    cvss_score: float = 0.0
    cvss_vector: str = ""
    affected_products: List[str] = field(default_factory=list)
    exploit_code_available: bool = False
    public: bool = True
    discovered_date: str = ""
    published_date: str = ""
    last_updated: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    correlation_score: float = 0.0
    related_threats: List[str] = field(default_factory=list)


@dataclass
class CVERecord:
    """CVE-specific record"""
    cve_id: str
    title: str
    description: str
    cvss_v3_score: float = 0.0
    cvss_v3_vector: str = ""
    cvss_v2_score: float = 0.0
    cvss_v2_vector: str = ""
    published_date: str = ""
    last_modified: str = ""
    affected_versions: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    metasploit_available: bool = False
    data_source_id: str = "NVD"


@dataclass
class ExploitRecord:
    """Exploit-specific record"""
    exploit_id: str
    title: str
    description: str
    target_cve: Optional[str] = None
    vulnerability_type: str = ""
    exploit_type: str = ""
    platform: str = ""
    author: str = ""
    code_url: Optional[str] = None
    difficulty: str = "medium"
    published_date: str = ""
    verified: bool = False
    success_rate: float = 0.0


@dataclass
class ThreatCorrelation:
    """Correlation between multiple threats"""
    correlation_id: str
    threat_ids: List[str]
    confidence: float
    pattern: str
    threat_actor: Optional[str] = None
    campaign_name: Optional[str] = None
    geographic_info: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)


# ==================== THREAT INTELLIGENCE INTEGRATOR ====================

class ThreatIntelligenceIntegrator:
    """Integrates real-time threat intelligence from multiple sources"""
    
    def __init__(self, db_path: str = "phase2_threat_intel.db"):
        self.db_path = db_path
        self.threat_cache: Dict[str, ThreatIntelligence] = {}
        self.cve_cache: Dict[str, CVERecord] = {}
        self.exploit_cache: Dict[str, ExploitRecord] = {}
        self.correlations: Dict[str, ThreatCorrelation] = {}
        
        self.update_queue = queue.Queue()
        self.running = False
        self.update_thread = None
        self.last_update = {}
        self.update_interval_hours = 24
        
        self._init_db()
        self._load_sample_intelligence()
    
    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                source TEXT,
                intel_type TEXT,
                title TEXT,
                description TEXT,
                severity REAL,
                confidence REAL,
                cvss_score REAL,
                exploit_available INTEGER,
                published_date TEXT,
                last_updated TEXT,
                tags TEXT
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                cvss_v3_score REAL,
                cvss_v3_vector TEXT,
                published_date TEXT,
                last_modified TEXT,
                affected_versions TEXT,
                exploit_available INTEGER,
                metasploit_available INTEGER
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                exploit_id TEXT PRIMARY KEY,
                title TEXT,
                target_cve TEXT,
                vulnerability_type TEXT,
                exploit_type TEXT,
                platform TEXT,
                difficulty TEXT,
                published_date TEXT,
                verified INTEGER,
                success_rate REAL
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS correlations (
                correlation_id TEXT PRIMARY KEY,
                threat_ids TEXT,
                confidence REAL,
                pattern TEXT,
                threat_actor TEXT,
                campaign_name TEXT
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS source_updates (
                source TEXT PRIMARY KEY,
                last_update REAL,
                threat_count INTEGER,
                cve_count INTEGER,
                exploit_count INTEGER
            )
            """)
            
            conn.commit()
    
    def _load_sample_intelligence(self):
        """Load sample threat intelligence data"""
        # Sample CVEs
        sample_cves = [
            CVERecord(
                cve_id="CVE-2024-0001",
                title="Critical RCE in Apache Log4j",
                description="Remote code execution vulnerability in Apache Log4j 2.x",
                cvss_v3_score=9.8,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                published_date="2024-03-01T00:00:00Z",
                last_modified="2024-03-15T00:00:00Z",
                cwe_ids=["CWE-502"],
                exploit_available=True,
                metasploit_available=True
            ),
            CVERecord(
                cve_id="CVE-2024-0002",
                title="SQL Injection in Django ORM",
                description="SQL injection vulnerability in Django QuerySet",
                cvss_v3_score=8.6,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                published_date="2024-02-28T00:00:00Z",
                exploit_available=True,
                metasploit_available=False
            ),
            CVERecord(
                cve_id="CVE-2024-0003",
                title="XXE in XML Parser",
                description="XML External Entity injection in libxml2",
                cvss_v3_score=7.5,
                cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                published_date="2024-02-15T00:00:00Z",
                exploit_available=True
            ),
        ]
        
        for cve in sample_cves:
            self.cve_cache[cve.cve_id] = cve
            self._store_cve(cve)
        
        # Sample Exploits
        sample_exploits = [
            ExploitRecord(
                exploit_id="EDB-54321",
                title="Apache Log4j RCE Exploit",
                description="Working exploit for CVE-2024-0001",
                target_cve="CVE-2024-0001",
                vulnerability_type="RCE",
                exploit_type="remote",
                platform="linux/windows",
                author="SecurityResearcher",
                code_url="https://github.com/example/log4j-exploit",
                difficulty="easy",
                published_date="2024-03-01T00:00:00Z",
                verified=True,
                success_rate=0.95
            ),
            ExploitRecord(
                exploit_id="EDB-54322",
                title="Django QuerySet SQL Injection",
                description="Practical exploit for CVE-2024-0002",
                target_cve="CVE-2024-0002",
                vulnerability_type="SQL Injection",
                exploit_type="remote",
                platform="web",
                difficulty="medium",
                published_date="2024-02-29T00:00:00Z",
                verified=True,
                success_rate=0.82
            ),
        ]
        
        for exploit in sample_exploits:
            self.exploit_cache[exploit.exploit_id] = exploit
            self._store_exploit(exploit)
        
        logger.info(f"Loaded {len(self.cve_cache)} CVEs and {len(self.exploit_cache)} exploits")
    
    def start_live_feed(self):
        """Start live threat intelligence feed"""
        if not self.running:
            self.running = True
            self.update_thread = threading.Thread(
                target=self._update_worker,
                daemon=True
            )
            self.update_thread.start()
            logger.info("Live threat intelligence feed started")
    
    def stop_live_feed(self):
        """Stop live threat intelligence feed"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        logger.info("Live threat intelligence feed stopped")
    
    def _update_worker(self):
        """Background worker for threat intelligence updates"""
        while self.running:
            try:
                # Check for sources that need updating
                current_time = time.time()
                
                for source in ThreatSource:
                    last_update = self.last_update.get(source.value, 0)
                    hours_since_update = (current_time - last_update) / 3600
                    
                    if hours_since_update > self.update_interval_hours:
                        self._update_source(source)
                        self.last_update[source.value] = current_time
                
                time.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Error in update worker: {e}")
                time.sleep(60)
    
    def _update_source(self, source: ThreatSource):
        """Update threat intelligence from a specific source"""
        logger.info(f"Updating threat intelligence from {source.value}")
        
        # In production, this would call actual APIs
        # For now, simulate updates
        update_info = {
            "source": source.value,
            "last_update": time.time(),
            "threat_count": len(self.threat_cache),
            "cve_count": len(self.cve_cache),
            "exploit_count": len(self.exploit_cache),
        }
        
        self._store_source_update(update_info)
    
    def get_cve_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """Retrieve CVE by ID"""
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        # Try loading from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            if row:
                cve = CVERecord(
                    cve_id=row[0],
                    title=row[1],
                    description=row[2],
                    cvss_v3_score=row[3],
                    cvss_v3_vector=row[4],
                    published_date=row[5],
                    last_modified=row[6],
                    exploit_available=bool(row[8])
                )
                self.cve_cache[cve_id] = cve
                return cve
        
        return None
    
    def get_exploits_for_cve(self, cve_id: str) -> List[ExploitRecord]:
        """Get all exploits for a CVE"""
        exploits = [
            exploit for exploit in self.exploit_cache.values()
            if exploit.target_cve == cve_id
        ]
        return exploits
    
    def search_threats(self, query: str, limit: int = 10) -> List[ThreatIntelligence]:
        """Search for threats by keyword"""
        results = []
        query_lower = query.lower()
        
        for threat in self.threat_cache.values():
            if (query_lower in threat.title.lower() or
                query_lower in threat.description.lower() or
                any(query_lower in tag.lower() for tag in threat.tags)):
                results.append(threat)
        
        return sorted(results, key=lambda x: x.confidence, reverse=True)[:limit]
    
    def correlate_threats(self, threat_ids: List[str]) -> ThreatCorrelation:
        """Correlate multiple threats"""
        correlation_id = f"corr_{hashlib.md5(''.join(threat_ids).encode()).hexdigest()[:8]}"
        
        # Analyze common patterns
        common_patterns = []
        common_cwe = {}
        
        for threat_id in threat_ids:
            if threat_id in self.cve_cache:
                cve = self.cve_cache[threat_id]
                for cwe in cve.cwe_ids:
                    common_cwe[cwe] = common_cwe.get(cwe, 0) + 1
        
        if common_cwe:
            primary_cwe = max(common_cwe.items(), key=lambda x: x[1])[0]
            common_patterns.append(primary_cwe)
        
        # Calculate correlation confidence
        confidence = min(len(threat_ids) * 0.25, 1.0)
        
        correlation = ThreatCorrelation(
            correlation_id=correlation_id,
            threat_ids=threat_ids,
            confidence=confidence,
            pattern=", ".join(common_patterns) if common_patterns else "related_vulnerabilities"
        )
        
        self.correlations[correlation_id] = correlation
        return correlation
    
    def get_active_threats(self, min_severity: float = 7.0) -> List[Dict[str, Any]]:
        """Get currently active threats above severity threshold"""
        active_threats = []
        
        for cve_id, cve in self.cve_cache.items():
            if cve.cvss_v3_score >= min_severity:
                active_threats.append({
                    "cve_id": cve_id,
                    "title": cve.title,
                    "severity_score": cve.cvss_v3_score,
                    "exploit_available": cve.exploit_available,
                    "published": cve.published_date,
                    "exploits": len(self.get_exploits_for_cve(cve_id))
                })
        
        return sorted(active_threats, key=lambda x: x["severity_score"], reverse=True)
    
    def score_threat_impact(self, cve_id: str, context: Dict[str, Any] = None) -> float:
        """Score threat impact considering context"""
        cve = self.get_cve_by_id(cve_id)
        if not cve:
            return 0.0
        
        impact_score = cve.cvss_v3_score / 10.0  # Normalize to 0-1
        
        # Boost score if exploit available
        if cve.exploit_available:
            impact_score *= 1.3
        
        # Boost score if Metasploit available
        if cve.metasploit_available:
            impact_score *= 1.2
        
        # Contextualize if product info available
        if context and "affected_product" in context:
            product = context["affected_product"]
            if any(product.lower() in av.lower() for av in cve.affected_versions):
                impact_score *= 1.4
        
        return min(impact_score, 1.0)
    
    def get_intelligence_summary(self) -> Dict[str, Any]:
        """Get summary of current threat intelligence"""
        active_threats = self.get_active_threats()
        
        return {
            "total_cves": len(self.cve_cache),
            "total_exploits": len(self.exploit_cache),
            "active_critical": sum(1 for t in active_threats if t["severity_score"] >= 9.0),
            "active_high": sum(1 for t in active_threats if 7.0 <= t["severity_score"] < 9.0),
            "exploits_available": sum(1 for t in active_threats if t["exploit_available"]),
            "last_update": max(self.last_update.values()) if self.last_update else 0,
            "top_threats": active_threats[:5]
        }
    
    def _store_cve(self, cve: CVERecord):
        """Store CVE in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO cves
                (cve_id, title, description, cvss_v3_score, cvss_v3_vector,
                 published_date, last_modified, affected_versions, exploit_available, metasploit_available)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve.cve_id, cve.title, cve.description,
                    cve.cvss_v3_score, cve.cvss_v3_vector,
                    cve.published_date, cve.last_modified,
                    json.dumps(cve.affected_versions),
                    int(cve.exploit_available),
                    int(cve.metasploit_available)
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing CVE: {e}")
    
    def _store_exploit(self, exploit: ExploitRecord):
        """Store exploit in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO exploits
                (exploit_id, title, target_cve, vulnerability_type, exploit_type,
                 platform, difficulty, published_date, verified, success_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    exploit.exploit_id, exploit.title, exploit.target_cve,
                    exploit.vulnerability_type, exploit.exploit_type,
                    exploit.platform, exploit.difficulty,
                    exploit.published_date, int(exploit.verified),
                    exploit.success_rate
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing exploit: {e}")
    
    def _store_source_update(self, update_info: Dict[str, Any]):
        """Store source update information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO source_updates
                (source, last_update, threat_count, cve_count, exploit_count)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    update_info["source"],
                    update_info["last_update"],
                    update_info["threat_count"],
                    update_info["cve_count"],
                    update_info["exploit_count"]
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing source update: {e}")


# ==================== EXAMPLE USAGE ====================

def demo_threat_intel():
    """Demonstrate threat intelligence integrator"""
    print("=" * 80)
    print("Threat Intelligence Integrator Demo")
    print("=" * 80)
    
    intel = ThreatIntelligenceIntegrator()
    intel.start_live_feed()
    
    # Get active threats
    print("\nActive Threats (CVSS >= 7.0):")
    print("-" * 80)
    active = intel.get_active_threats()
    for threat in active[:5]:
        print(f"  {threat['cve_id']}: {threat['title']}")
        print(f"    Severity: {threat['severity_score']}/10.0")
        print(f"    Exploit Available: {threat['exploit_available']}")
        print(f"    Public Exploits: {threat['exploits']}")
        print()
    
    # Get specific CVE
    print("-" * 80)
    print("CVE Details: CVE-2024-0001")
    print("-" * 80)
    cve = intel.get_cve_by_id("CVE-2024-0001")
    if cve:
        print(f"Title: {cve.title}")
        print(f"CVSS v3: {cve.cvss_v3_score}")
        print(f"Published: {cve.published_date}")
        
        exploits = intel.get_exploits_for_cve("CVE-2024-0001")
        if exploits:
            print(f"\nAvailable Exploits:")
            for exploit in exploits:
                print(f"  - {exploit.title}")
                print(f"    Success Rate: {exploit.success_rate:.0%}")
    
    # Intelligence summary
    print("\n" + "=" * 80)
    print("Intelligence Summary")
    print("=" * 80)
    summary = intel.get_intelligence_summary()
    for key, value in summary.items():
        if key != "top_threats":
            print(f"{key}: {value}")
    
    intel.stop_live_feed()


if __name__ == "__main__":
    demo_threat_intel()
