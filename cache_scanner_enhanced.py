"""
Enhanced Cache Scanner with Learned Exploit Loading & Detailed Code Visibility
- Properly loads learned exploits from database
- Shows full code snippets with context
- Tracks exploit detection history
- Exports detailed findings
"""

import sqlite3
import os
import re
import hashlib
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path


class EnhancedCacheScanner:
    """Enhanced cache scanner with full exploit visibility and learning"""
    
    def __init__(self, db_path: str = "hades_knowledge.db", cache_limit: int = 500000):
        self.db_path = db_path
        self.cache_limit = cache_limit  # Max code length to store
        self.conn = None
        self.learned_exploits = {}
        self.cache_findings = []
        self._connect()
        self._initialize_tables()
        
    def _connect(self):
        """Connect to knowledge database"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        except Exception as e:
            print(f"[!] Failed to connect to knowledge DB: {e}")
            self.conn = None
    
    def _initialize_tables(self):
        """Ensure all necessary tables exist"""
        if not self.conn:
            return
        
        cursor = self.conn.cursor()
        
        # Check if table exists and has code_hash column
        cursor.execute("""
            PRAGMA table_info(learned_exploits)
        """)
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'learned_exploits' in self._get_table_names() and 'code_hash' not in columns:
            # Add missing code_hash column
            try:
                cursor.execute("ALTER TABLE learned_exploits ADD COLUMN code_hash TEXT")
            except:
                pass
        
        # Table for learned exploits with full details
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learned_exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exploit_type TEXT NOT NULL,
                code TEXT NOT NULL,
                code_hash TEXT,
                source_url TEXT,
                description TEXT,
                severity TEXT,
                learned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_found TIMESTAMP,
                occurrence_count INTEGER DEFAULT 1
            )
        """)
        
        # Table for cache detection history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_path TEXT,
                threat_type TEXT,
                severity TEXT,
                code_snippet TEXT,
                full_code TEXT,
                context_before TEXT,
                context_after TEXT,
                file_size INTEGER,
                file_hash TEXT,
                browser TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                matched_exploit_id INTEGER,
                FOREIGN KEY(matched_exploit_id) REFERENCES learned_exploits(id)
            )
        """)
        
        # Table for code patterns
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_hash TEXT UNIQUE,
                pattern_type TEXT,
                code_signature TEXT,
                severity TEXT,
                detections INTEGER DEFAULT 1,
                last_seen TIMESTAMP,
                mitigation_notes TEXT
            )
        """)
        
        self.conn.commit()
    
    def _get_table_names(self) -> list:
        """Get list of existing tables"""
        if not self.conn:
            return []
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return [row[0] for row in cursor.fetchall()]
    
    def load_learned_exploits(self) -> int:
        """Load all learned exploits from database"""
        if not self.conn:
            return 0
        
        try:
            cursor = self.conn.cursor()
            
            # Check what columns exist
            cursor.execute("PRAGMA table_info(learned_exploits)")
            columns = {col[1] for col in cursor.fetchall()}
            
            # Build query based on available columns
            select_cols = ['id', 'exploit_type', 'code', 'source_url', 'learned_at']
            if 'code_hash' in columns:
                select_cols.insert(3, 'code_hash')
            if 'description' in columns:
                select_cols.insert(5, 'description')
            if 'severity' in columns:
                select_cols.insert(6, 'severity')
            
            query = f"SELECT {', '.join(select_cols)} FROM learned_exploits ORDER BY learned_at DESC"
            cursor.execute(query)
            
            results = cursor.fetchall()
            self.learned_exploits = {}
            
            for row in results:
                exploit_id = row['id']
                exploit_type = row['exploit_type']
                
                if exploit_type not in self.learned_exploits:
                    self.learned_exploits[exploit_type] = []
                
                exploit_data = {
                    'id': exploit_id,
                    'code': row['code'] if 'code' in row.keys() else '',
                    'source_url': row['source_url'] if 'source_url' in row.keys() else '',
                    'learned_at': row['learned_at'] if 'learned_at' in row.keys() else ''
                }
                
                # Add optional columns if they exist
                if 'code_hash' in columns and 'code_hash' in row.keys():
                    exploit_data['code_hash'] = row['code_hash']
                if 'description' in columns and 'description' in row.keys():
                    exploit_data['description'] = row['description']
                if 'severity' in columns and 'severity' in row.keys():
                    exploit_data['severity'] = row['severity']
                
                self.learned_exploits[exploit_type].append(exploit_data)
            
            return len(results)
        except Exception as e:
            print(f"[!] Error loading learned exploits: {e}")
            return 0
    
    def get_exploit_details(self, exploit_type: str) -> List[Dict]:
        """Get full details of learned exploits by type"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            
            # Check available columns
            cursor.execute("PRAGMA table_info(learned_exploits)")
            columns = {col[1] for col in cursor.fetchall()}
            
            # Build query
            select_cols = ['id', 'exploit_type', 'code', 'source_url', 'learned_at']
            if 'description' in columns:
                select_cols.insert(3, 'description')
            if 'severity' in columns:
                select_cols.insert(4, 'severity')
            if 'occurrence_count' in columns:
                select_cols.append('occurrence_count')
            else:
                select_cols.append('1 as occurrence_count')
            
            query = f"SELECT {', '.join(select_cols)} FROM learned_exploits WHERE exploit_type = ?"
            if 'occurrence_count' in columns:
                query += " ORDER BY occurrence_count DESC, learned_at DESC"
            else:
                query += " ORDER BY learned_at DESC"
            
            cursor.execute(query, (exploit_type,))
            
            results = cursor.fetchall()
            return [dict(row) for row in results]
        except Exception as e:
            print(f"[!] Error getting exploit details: {e}")
            return []
    
    def store_cache_detection(self, detection: Dict) -> bool:
        """Store detailed cache detection with full code"""
        if not self.conn:
            return False
        
        try:
            cursor = self.conn.cursor()
            
            # Extract details
            code_snippet = detection.get('code_snippet', '')[:1000]
            full_code = detection.get('full_code', '')[:self.cache_limit]
            code_hash = hashlib.sha256(full_code.encode()).hexdigest() if full_code else None
            
            # Find matching learned exploit
            matched_exploit_id = self._find_matching_exploit(
                detection.get('threat_type'),
                code_snippet
            )
            
            cursor.execute("""
                INSERT INTO cache_detections 
                (cache_path, threat_type, severity, code_snippet, full_code,
                 context_before, context_after, file_size, file_hash, browser, 
                 matched_exploit_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                detection.get('cache_path'),
                detection.get('threat_type'),
                detection.get('severity'),
                code_snippet,
                full_code,
                detection.get('context_before', '')[:500],
                detection.get('context_after', '')[:500],
                detection.get('file_size'),
                detection.get('file_hash'),
                detection.get('browser'),
                matched_exploit_id
            ))
            
            self.conn.commit()
            return True
        except Exception as e:
            print(f"[!] Error storing cache detection: {e}")
            return False
    
    def _find_matching_exploit(self, threat_type: str, code_snippet: str) -> Optional[int]:
        """Find if this code matches a learned exploit"""
        if not self.conn or threat_type not in self.learned_exploits:
            return None
        
        try:
            for exploit in self.learned_exploits[threat_type]:
                if code_snippet in exploit['code']:
                    # Update occurrence count
                    cursor = self.conn.cursor()
                    cursor.execute("""
                        UPDATE learned_exploits 
                        SET occurrence_count = occurrence_count + 1,
                            last_found = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (exploit['id'],))
                    self.conn.commit()
                    return exploit['id']
        except Exception as e:
            print(f"[!] Error finding matching exploit: {e}")
        
        return None
    
    def scan_cache_with_details(self, filepath: str, browser: str) -> Dict:
        """Scan a cache file and return detailed findings"""
        result = {
            'path': filepath,
            'browser': browser,
            'detections': [],
            'full_content': '',
            'code_visible': False
        }
        
        try:
            if not os.path.exists(filepath):
                return result
            
            stat = os.stat(filepath)
            result['size'] = stat.st_size
            result['modified'] = stat.st_mtime
            
            # Skip very large files
            if stat.st_size > 5_000_000:
                return result
            
            with open(filepath, 'rb') as f:
                raw_content = f.read()
            
            try:
                content = raw_content.decode('utf-8', errors='ignore')
                result['full_content'] = content
                result['code_visible'] = True
            except:
                result['code_visible'] = False
                content = raw_content.decode('latin-1', errors='ignore')
            
            file_hash = hashlib.md5(raw_content[:1000]).hexdigest()[:8]
            result['file_hash'] = file_hash
            
            # Scan for threats
            threat_patterns = [
                ('malware', r'malware|virus|trojan|ransomware', 'HIGH'),
                ('exploit', r'exploit|overflow|shellcode|payload', 'HIGH'),
                ('eval_code', r'eval\s*\(|exec\s*\(|Function\s*\(', 'HIGH'),
                ('obfuscation', r'fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|atob\s*\(', 'MEDIUM'),
                ('data_exfil', r'document\.cookie|localStorage|sessionStorage', 'MEDIUM'),
                ('injection', r'<script|javascript:|on\w+\s*=', 'MEDIUM'),
                ('crypto', r'crypto|bitcoin|wallet|miner', 'MEDIUM'),
                ('backdoor', r'backdoor|c2|command.*control|reverse.*shell', 'HIGH'),
            ]
            
            for threat_name, pattern, severity in threat_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Get context
                    start = max(0, match.start() - 200)
                    end = min(len(content), match.end() + 200)
                    
                    context_before = content[start:match.start()]
                    matched_code = content[match.start():match.end()]
                    context_after = content[match.end():end]
                    
                    detection = {
                        'threat_type': threat_name,
                        'severity': severity,
                        'matched_code': matched_code,
                        'context_before': context_before,
                        'context_after': context_after,
                        'full_context': content[start:end],
                        'position': match.start(),
                        'length': match.end() - match.start()
                    }
                    
                    result['detections'].append(detection)
                    
                    # Store in database
                    self.store_cache_detection({
                        'cache_path': filepath,
                        'threat_type': threat_name,
                        'severity': severity,
                        'code_snippet': matched_code,
                        'full_code': content,
                        'context_before': context_before,
                        'context_after': context_after,
                        'file_size': stat.st_size,
                        'file_hash': file_hash,
                        'browser': browser
                    })
        
        except Exception as e:
            print(f"[!] Error scanning {filepath}: {e}")
        
        return result
    
    def get_cache_detections(self, limit: int = 100) -> List[Dict]:
        """Get recent cache detections with full code visibility"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, cache_path, threat_type, severity, 
                       code_snippet, full_code, context_before, context_after,
                       file_size, file_hash, browser, detected_at, matched_exploit_id
                FROM cache_detections
                ORDER BY detected_at DESC
                LIMIT ?
            """, (limit,))
            
            results = cursor.fetchall()
            return [dict(row) for row in results]
        except Exception as e:
            print(f"[!] Error getting cache detections: {e}")
            return []
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of all cache threats found"""
        if not self.conn:
            return {}
        
        try:
            cursor = self.conn.cursor()
            
            # Count by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM cache_detections
                GROUP BY severity
            """)
            severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # Count by threat type
            cursor.execute("""
                SELECT threat_type, COUNT(*) as count
                FROM cache_detections
                GROUP BY threat_type
                ORDER BY count DESC
            """)
            threat_counts = {row['threat_type']: row['count'] for row in cursor.fetchall()}
            
            # Count by browser
            cursor.execute("""
                SELECT browser, COUNT(*) as count
                FROM cache_detections
                GROUP BY browser
            """)
            browser_counts = {row['browser']: row['count'] for row in cursor.fetchall()}
            
            # Total detections
            cursor.execute("SELECT COUNT(*) as total FROM cache_detections")
            total = cursor.fetchone()['total']
            
            return {
                'total_detections': total,
                'by_severity': severity_counts,
                'by_threat_type': threat_counts,
                'by_browser': browser_counts,
                'learned_exploits_count': len(self.learned_exploits),
                'exploit_types': list(self.learned_exploits.keys())
            }
        except Exception as e:
            print(f"[!] Error getting threat summary: {e}")
            return {}
    
    def export_findings_to_json(self, output_path: str) -> bool:
        """Export all findings with full code to JSON"""
        try:
            detections = self.get_cache_detections(limit=1000)
            summary = self.get_threat_summary()
            
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'summary': summary,
                'detections': detections,
                'learned_exploits': self.learned_exploits
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            print(f"[+] Exported findings to {output_path}")
            return True
        except Exception as e:
            print(f"[!] Error exporting findings: {e}")
            return False
    
    def export_findings_to_html(self, output_path: str) -> bool:
        """Export findings as detailed HTML report with code highlighting"""
        try:
            detections = self.get_cache_detections(limit=500)
            summary = self.get_threat_summary()
            
            html = """
            <html>
            <head>
                <title>Cache Scanner Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .summary { background: #f0f0f0; padding: 15px; margin-bottom: 20px; }
                    .detection { border: 1px solid #ccc; padding: 15px; margin-bottom: 15px; }
                    .threat-high { background: #ffcccc; }
                    .threat-medium { background: #ffffcc; }
                    .threat-low { background: #ccffcc; }
                    .code-section { background: #f5f5f5; padding: 10px; margin: 10px 0; 
                                   border-left: 3px solid #333; overflow-x: auto; }
                    .code-before { color: #999; }
                    .code-matched { background: #ffff00; font-weight: bold; }
                    .code-after { color: #999; }
                    h3 { margin-top: 0; }
                    .meta { color: #666; font-size: 0.9em; }
                </style>
            </head>
            <body>
                <h1>Cache Scanner Report</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total Detections: <strong>{}</strong></p>
                    <h3>By Severity:</h3>
                    <ul>
            """.format(summary.get('total_detections', 0))
            
            for severity, count in summary.get('by_severity', {}).items():
                html += f"<li>{severity}: {count}</li>"
            
            html += "</ul><h3>By Threat Type:</h3><ul>"
            for threat, count in summary.get('by_threat_type', {}).items():
                html += f"<li>{threat}: {count}</li>"
            
            html += "</ul></div>"
            
            # Add detections
            for detection in detections:
                severity_class = f"threat-{detection['severity'].lower()}"
                html += f"""
                <div class="detection {severity_class}">
                    <h3>{detection['threat_type']} ({detection['severity']})</h3>
                    <div class="meta">
                        Path: {detection['cache_path']}<br>
                        Browser: {detection['browser']}<br>
                        Detected: {detection['detected_at']}<br>
                        File: {detection['file_hash']}
                    </div>
                    <div class="code-section">
                        <div class="code-before">{self._escape_html(detection['context_before'][-100:])}</div>
                        <span class="code-matched">{self._escape_html(detection['code_snippet'])}</span>
                        <div class="code-after">{self._escape_html(detection['context_after'][:100])}</div>
                    </div>
                    <p><strong>Full Code Preview:</strong></p>
                    <pre class="code-section">{self._escape_html(detection['full_code'][:1000])}</pre>
                </div>
                """
            
            html += """
            </body>
            </html>
            """
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            
            print(f"[+] Exported HTML report to {output_path}")
            return True
        except Exception as e:
            print(f"[!] Error exporting HTML: {e}")
            return False
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#39;'))
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


# Test and demonstration
if __name__ == "__main__":
    scanner = EnhancedCacheScanner()
    
    # Load learned exploits
    count = scanner.load_learned_exploits()
    print(f"[+] Loaded {count} learned exploits")
    
    # Show available exploit types
    print(f"\n[+] Available exploit types: {list(scanner.learned_exploits.keys())}")
    
    # Get summary
    summary = scanner.get_threat_summary()
    print(f"\n[+] Threat Summary:")
    print(f"    Total Detections: {summary.get('total_detections', 0)}")
    print(f"    By Severity: {summary.get('by_severity', {})}")
    print(f"    By Threat Type: {summary.get('by_threat_type', {})}")
    
    # Get recent detections
    detections = scanner.get_cache_detections(limit=5)
    print(f"\n[+] Recent Detections ({len(detections)}):")
    for d in detections:
        print(f"    {d['threat_type']} - {d['severity']} - {d['cache_path']}")
        print(f"    Code: {d['code_snippet'][:50]}...")
        print(f"    Full Code Available: {len(d.get('full_code', '')) > 0} chars")
        print()
    
    # Export findings
    scanner.export_findings_to_json("cache_findings.json")
    scanner.export_findings_to_html("cache_findings.html")
    
    scanner.close()
