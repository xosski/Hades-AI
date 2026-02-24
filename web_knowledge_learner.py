"""
Web Knowledge Learner for HadesAI
Enables the AI to learn from webpages it scans/seeks and enhance knowledge base
Extracts security information, CVEs, exploits, techniques and stores them for future use
"""

import sqlite3
import json
import re
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urlparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WebKnowledgeLearner")


class WebContentExtractor:
    """Extract relevant security information from webpage content"""
    
    def __init__(self):
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        self.cwe_pattern = re.compile(r'CWE-\d+', re.IGNORECASE)
        self.severity_pattern = re.compile(r'\b(critical|high|medium|low|cvss[:\s]+[\d.]+)\b', re.IGNORECASE)
        
    def extract_cves(self, content: str) -> List[Dict]:
        """Extract CVE information from content"""
        cves = []
        matches = self.cve_pattern.findall(content)
        
        for match in set(matches):
            # Find surrounding context
            idx = content.find(match)
            context_start = max(0, idx - 200)
            context_end = min(len(content), idx + 200)
            context = content[context_start:context_end].strip()
            
            cves.append({
                'cve_id': match,
                'context': context,
                'severity': self._extract_severity(context),
                'found_date': datetime.now().isoformat()
            })
        
        return cves
    
    def extract_cwes(self, content: str) -> List[Dict]:
        """Extract CWE (Common Weakness Enumeration) information"""
        cwes = []
        matches = self.cwe_pattern.findall(content)
        
        for match in set(matches):
            idx = content.find(match)
            context_start = max(0, idx - 150)
            context_end = min(len(content), idx + 150)
            context = content[context_start:context_end].strip()
            
            cwes.append({
                'cwe_id': match,
                'context': context,
                'found_date': datetime.now().isoformat()
            })
        
        return cwes
    
    def extract_exploits(self, content: str, source_url: str) -> List[Dict]:
        """Extract exploit-related information"""
        exploits = []
        
        # Look for code blocks or technical details
        code_blocks = re.findall(r'```[\s\S]*?```|<code>[\s\S]*?</code>', content)
        
        exploit_keywords = ['payload', 'shellcode', 'poc', 'exploit', 'injection', 'bypass', 'buffer', 'rce', 'sqli', 'xss']
        
        for keyword in exploit_keywords:
            if keyword.lower() in content.lower():
                # Find context around keyword
                pattern = re.compile(f'(.{{0,150}}{keyword}.{{0,150}})', re.IGNORECASE)
                matches = pattern.findall(content)
                
                for match in matches[:3]:  # Limit to 3 instances per keyword
                    exploits.append({
                        'type': keyword.upper(),
                        'code_snippet': match.strip(),
                        'source_url': source_url,
                        'found_date': datetime.now().isoformat()
                    })
        
        # Also capture actual code blocks
        for idx, code in enumerate(code_blocks):
            exploits.append({
                'type': 'CODE_SAMPLE',
                'code_snippet': code[:500],  # Limit size
                'source_url': source_url,
                'found_date': datetime.now().isoformat()
            })
        
        return exploits
    
    def extract_techniques(self, content: str, source_url: str) -> List[Dict]:
        """Extract pentesting techniques and methodologies"""
        techniques = []
        
        technique_keywords = {
            'enumeration': ['reconnaissance', 'scan', 'map', 'discover', 'enumerate'],
            'exploitation': ['exploit', 'execute', 'execute code', 'rce', 'privilege escalation'],
            'privilege_escalation': ['priv esc', 'privilege escalation', 'sudo', 'suid', 'kernel'],
            'persistence': ['persistence', 'backdoor', 'reverse shell', 'webshell'],
            'lateral_movement': ['lateral movement', 'pivot', 'hop', 'move', 'spread'],
            'exfiltration': ['data exfiltration', 'steal', 'extract', 'exfil', 'download'],
            'defense_evasion': ['evasion', 'obfuscation', 'bypass', 'evade', 'stealth']
        }
        
        for category, keywords in technique_keywords.items():
            for keyword in keywords:
                if keyword.lower() in content.lower():
                    pattern = re.compile(f'(.{{0,200}}{keyword}.{{0,200}})', re.IGNORECASE)
                    matches = pattern.findall(content)
                    
                    for match in matches[:2]:
                        techniques.append({
                            'category': category,
                            'name': keyword.upper(),
                            'description': match.strip(),
                            'source_url': source_url,
                            'found_date': datetime.now().isoformat()
                        })
        
        return techniques
    
    def extract_vulnerability_patterns(self, content: str) -> List[Dict]:
        """Extract security vulnerability patterns"""
        patterns = []
        
        vuln_types = {
            'SQL_INJECTION': ['sql injection', 'sqli', 'sql', 'database injection'],
            'XSS': ['xss', 'cross-site scripting', 'javascript injection'],
            'CSRF': ['csrf', 'cross-site request forgery'],
            'IDOR': ['idor', 'insecure direct object reference'],
            'AUTH_BYPASS': ['authentication bypass', 'auth bypass', 'unauthorized access'],
            'SSRF': ['ssrf', 'server-side request forgery'],
            'RCE': ['rce', 'remote code execution', 'remote execution'],
            'XXE': ['xxe', 'xml external entity'],
            'INSECURE_DESERIALIZATION': ['deserialization', 'unserialize'],
            'BROKEN_ACCESS': ['broken access control', 'access control'],
        }
        
        for vuln_type, keywords in vuln_types.items():
            for keyword in keywords:
                if keyword.lower() in content.lower():
                    pattern = re.compile(f'(.{{0,300}}{keyword}.{{0,300}})', re.IGNORECASE)
                    matches = pattern.findall(content)
                    
                    if matches:
                        patterns.append({
                            'pattern_type': vuln_type,
                            'signature': keyword,
                            'context': matches[0].strip()[:500],
                            'confidence': min(0.95, len(matches) * 0.3),  # Higher confidence with more matches
                            'found_date': datetime.now().isoformat()
                        })
        
        return patterns
    
    def _extract_severity(self, content: str) -> Optional[str]:
        """Extract severity level from content"""
        match = self.severity_pattern.search(content)
        if match:
            severity_text = match.group(1).lower()
            if 'critical' in severity_text:
                return 'CRITICAL'
            elif 'high' in severity_text:
                return 'HIGH'
            elif 'medium' in severity_text:
                return 'MEDIUM'
            elif 'low' in severity_text:
                return 'LOW'
            elif 'cvss' in severity_text:
                # Try to extract CVSS score
                cvss_match = re.search(r'[\d.]+', severity_text)
                if cvss_match:
                    score = float(cvss_match.group())
                    if score >= 9.0:
                        return 'CRITICAL'
                    elif score >= 7.0:
                        return 'HIGH'
                    elif score >= 4.0:
                        return 'MEDIUM'
                    else:
                        return 'LOW'
        return 'UNKNOWN'


class WebKnowledgeStore:
    """Store and manage learned knowledge from webpages"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.db_path = db_path
        self.conn = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database with learning tables"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            
            # Web sources table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS web_sources (
                    source_id TEXT PRIMARY KEY,
                    url TEXT UNIQUE,
                    domain TEXT,
                    content_hash TEXT,
                    title TEXT,
                    accessed_date TEXT,
                    learning_status TEXT DEFAULT 'processed'
                )
            """)
            
            # Learned CVEs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learned_cves (
                    cve_id TEXT PRIMARY KEY,
                    severity TEXT,
                    description TEXT,
                    context TEXT,
                    source_urls TEXT,
                    learned_date TEXT,
                    confidence REAL DEFAULT 0.8
                )
            """)
            
            # Learned exploits from web
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS web_learned_exploits (
                    exploit_id TEXT PRIMARY KEY,
                    exploit_type TEXT,
                    code_snippet TEXT,
                    source_url TEXT,
                    related_cve TEXT,
                    learned_date TEXT,
                    relevance_score REAL DEFAULT 0.8
                )
            """)
            
            # Learned techniques
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learned_techniques (
                    technique_id TEXT PRIMARY KEY,
                    category TEXT,
                    name TEXT,
                    description TEXT,
                    source_urls TEXT,
                    learned_date TEXT,
                    effectiveness_score REAL DEFAULT 0.7
                )
            """)
            
            # Learned vulnerability patterns
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS web_learned_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    pattern_type TEXT,
                    signature TEXT,
                    context TEXT,
                    source_url TEXT,
                    learned_date TEXT,
                    confidence REAL DEFAULT 0.8
                )
            """)
            
            # Learning analytics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learning_analytics (
                    analytics_id TEXT PRIMARY KEY,
                    metric_type TEXT,
                    value REAL,
                    timestamp TEXT,
                    description TEXT
                )
            """)
            
            self.conn.commit()
            logger.info("Knowledge store initialized")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def store_cve(self, cve_data: Dict) -> bool:
        """Store learned CVE information"""
        try:
            cve_id = cve_data.get('cve_id')
            cursor = self.conn.cursor()
            
            # Check if already exists
            cursor.execute("SELECT * FROM learned_cves WHERE cve_id = ?", (cve_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update with new source
                cursor.execute("""
                    UPDATE learned_cves 
                    SET source_urls = ?, learned_date = ?
                    WHERE cve_id = ?
                """, (
                    cve_data.get('source_url'),
                    datetime.now().isoformat(),
                    cve_id
                ))
            else:
                # Insert new CVE
                cursor.execute("""
                    INSERT INTO learned_cves 
                    (cve_id, severity, description, context, source_urls, learned_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    cve_id,
                    cve_data.get('severity'),
                    cve_data.get('summary', ''),
                    cve_data.get('context', ''),
                    cve_data.get('source_url'),
                    datetime.now().isoformat()
                ))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to store CVE: {e}")
            return False
    
    def store_exploit(self, exploit_data: Dict) -> bool:
        """Store learned exploit"""
        try:
            exploit_id = hashlib.md5(
                f"{exploit_data.get('type')}{exploit_data.get('code_snippet')}".encode()
            ).hexdigest()
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO web_learned_exploits
                (exploit_id, exploit_type, code_snippet, source_url, learned_date)
                VALUES (?, ?, ?, ?, ?)
            """, (
                exploit_id,
                exploit_data.get('type'),
                exploit_data.get('code_snippet'),
                exploit_data.get('source_url'),
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to store exploit: {e}")
            return False
    
    def store_technique(self, technique_data: Dict) -> bool:
        """Store learned pentesting technique"""
        try:
            technique_id = hashlib.md5(
                f"{technique_data.get('name')}{technique_data.get('category')}".encode()
            ).hexdigest()
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO learned_techniques
                (technique_id, category, name, description, source_urls, learned_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                technique_id,
                technique_data.get('category'),
                technique_data.get('name'),
                technique_data.get('description'),
                technique_data.get('source_url'),
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to store technique: {e}")
            return False
    
    def store_vulnerability_pattern(self, pattern_data: Dict) -> bool:
        """Store learned vulnerability pattern"""
        try:
            pattern_id = hashlib.md5(
                f"{pattern_data.get('pattern_type')}{pattern_data.get('signature')}".encode()
            ).hexdigest()
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO web_learned_patterns
                (pattern_id, pattern_type, signature, context, source_url, learned_date, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern_id,
                pattern_data.get('pattern_type'),
                pattern_data.get('signature'),
                pattern_data.get('context'),
                pattern_data.get('source_url'),
                datetime.now().isoformat(),
                pattern_data.get('confidence', 0.8)
            ))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to store vulnerability pattern: {e}")
            return False
    
    def record_web_source(self, url: str, content_hash: str, title: str = "") -> bool:
        """Record that a webpage has been processed"""
        try:
            source_id = hashlib.md5(url.encode()).hexdigest()
            domain = urlparse(url).netloc
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO web_sources
                (source_id, url, domain, content_hash, title, accessed_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                source_id,
                url,
                domain,
                content_hash,
                title,
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to record web source: {e}")
            return False
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get statistics about what has been learned"""
        try:
            cursor = self.conn.cursor()
            
            stats = {}
            
            # Count CVEs learned
            cursor.execute("SELECT COUNT(*) FROM learned_cves")
            stats['cves_learned'] = cursor.fetchone()[0]
            
            # Count exploits learned
            cursor.execute("SELECT COUNT(*) FROM web_learned_exploits")
            stats['exploits_learned'] = cursor.fetchone()[0]
            
            # Count techniques learned
            cursor.execute("SELECT COUNT(*) FROM learned_techniques")
            stats['techniques_learned'] = cursor.fetchone()[0]
            
            # Count patterns learned
            cursor.execute("SELECT COUNT(*) FROM web_learned_patterns")
            stats['patterns_learned'] = cursor.fetchone()[0]
            
            # Count web sources processed
            cursor.execute("SELECT COUNT(*) FROM web_sources")
            stats['sources_processed'] = cursor.fetchone()[0]
            
            return stats
        except Exception as e:
            logger.error(f"Failed to get learning stats: {e}")
            return {}
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


class WebKnowledgeLearner:
    """Main class that orchestrates web learning"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.extractor = WebContentExtractor()
        self.store = WebKnowledgeStore(db_path)
    
    def learn_from_content(self, url: str, content: str, metadata: Dict = None) -> Dict[str, Any]:
        """
        Learn from webpage content
        Returns summary of what was learned
        """
        
        if not metadata:
            metadata = {}
        
        learning_summary = {
            'url': url,
            'cves': [],
            'exploits': [],
            'techniques': [],
            'patterns': [],
            'total_items_learned': 0
        }
        
        logger.info(f"Learning from: {url}")
        
        # Extract CVEs
        cves = self.extractor.extract_cves(content)
        for cve in cves:
            cve['source_url'] = url
            if self.store.store_cve(cve):
                learning_summary['cves'].append(cve['cve_id'])
        
        # Extract CWEs (store as patterns context)
        cwes = self.extractor.extract_cwes(content)
        for cwe in cwes:
            logger.info(f"Found {cwe['cwe_id']}")
        
        # Extract exploits
        exploits = self.extractor.extract_exploits(content, url)
        for exploit in exploits:
            if self.store.store_exploit(exploit):
                learning_summary['exploits'].append(exploit['type'])
        
        # Extract techniques
        techniques = self.extractor.extract_techniques(content, url)
        for technique in techniques:
            if self.store.store_technique(technique):
                learning_summary['techniques'].append(
                    f"{technique['category']}: {technique['name']}"
                )
        
        # Extract vulnerability patterns
        patterns = self.extractor.extract_vulnerability_patterns(content)
        for pattern in patterns:
            pattern['source_url'] = url
            if self.store.store_vulnerability_pattern(pattern):
                learning_summary['patterns'].append(pattern['pattern_type'])
        
        # Record this source as processed
        content_hash = hashlib.md5(content.encode()).hexdigest()
        self.store.record_web_source(url, content_hash, metadata.get('title', ''))
        
        # Calculate total items learned
        learning_summary['total_items_learned'] = (
            len(learning_summary['cves']) +
            len(learning_summary['exploits']) +
            len(learning_summary['techniques']) +
            len(learning_summary['patterns'])
        )
        
        logger.info(f"Learning complete: {learning_summary['total_items_learned']} items learned")
        
        return learning_summary
    
    def get_knowledge_context_for_query(self, query: str) -> str:
        """
        Get relevant learned knowledge for a specific query
        Used to enhance AI responses with learned information
        """
        try:
            cursor = self.store.conn.cursor()
            context_parts = []
            
            # Search learned CVEs
            cursor.execute("""
                SELECT cve_id, severity, context FROM learned_cves
                WHERE cve_id LIKE ? OR context LIKE ?
                LIMIT 5
            """, (f"%{query}%", f"%{query}%"))
            
            cves = cursor.fetchall()
            if cves:
                context_parts.append("**Learned CVEs:**")
                for cve in cves:
                    context_parts.append(f"- {cve[0]} (Severity: {cve[1]})")
            
            # Search learned exploits
            cursor.execute("""
                SELECT exploit_type, code_snippet FROM web_learned_exploits
                WHERE exploit_type LIKE ? OR code_snippet LIKE ?
                LIMIT 3
            """, (f"%{query}%", f"%{query}%"))
            
            exploits = cursor.fetchall()
            if exploits:
                context_parts.append("\n**Learned Exploits:**")
                for exploit in exploits:
                    snippet = exploit[1][:100] if exploit[1] else "N/A"
                    context_parts.append(f"- {exploit[0]}: {snippet}...")
            
            # Search learned techniques
            cursor.execute("""
                SELECT category, name, description FROM learned_techniques
                WHERE category LIKE ? OR name LIKE ? OR description LIKE ?
                LIMIT 3
            """, (f"%{query}%", f"%{query}%", f"%{query}%"))
            
            techniques = cursor.fetchall()
            if techniques:
                context_parts.append("\n**Learned Techniques:**")
                for tech in techniques:
                    context_parts.append(f"- [{tech[0]}] {tech[1]}")
            
            # Search learned patterns
            cursor.execute("""
                SELECT pattern_type, signature, context FROM web_learned_patterns
                WHERE pattern_type LIKE ? OR signature LIKE ?
                LIMIT 3
            """, (f"%{query}%", f"%{query}%"))
            
            patterns = cursor.fetchall()
            if patterns:
                context_parts.append("\n**Learned Vulnerability Patterns:**")
                for pattern in patterns:
                    context_parts.append(f"- {pattern[0]} ({pattern[1]})")
            
            return "\n".join(context_parts) if context_parts else ""
        
        except Exception as e:
            logger.error(f"Failed to get knowledge context: {e}")
            return ""
    
    def close(self):
        """Close all connections"""
        self.store.close()


# Example usage
if __name__ == "__main__":
    learner = WebKnowledgeLearner()
    
    # Example content from a security blog
    example_content = """
    CVE-2024-1234 is a critical SQL injection vulnerability in WebApp v1.2
    This CVE-2024-1234 allows remote code execution through improper input validation.
    The vulnerability has a CVSS score of 9.8 (critical).
    
    Exploitation Techniques:
    - SQL injection payload: ' OR '1'='1
    - Basic RCE through exec() functions
    
    CWE-89: SQL Injection
    CWE-78: OS Command Injection
    """
    
    result = learner.learn_from_content(
        "https://example.com/cve-report",
        example_content,
        {'title': 'CVE Analysis Report'}
    )
    
    print("Learning Summary:")
    print(json.dumps(result, indent=2))
    
    print("\nKnowledge Stats:")
    stats = learner.store.get_learning_stats()
    print(json.dumps(stats, indent=2))
    
    learner.close()
