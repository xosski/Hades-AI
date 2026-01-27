"""
Knowledge Lookup System for HadesAI Chat
Allows AI to search/retrieve information from local knowledge base during chat
"""

import sqlite3
import re
from typing import List, Dict, Any, Optional
from pathlib import Path


class KnowledgeLookup:
    """
    Search and retrieve information from HadesAI's knowledge base.
    Used by chat AI to access learned exploits, patterns, techniques, CVEs, etc.
    """
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.db_path = db_path
        self.conn = None
        self._connect()
    
    def _connect(self):
        """Connect to knowledge database"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        except Exception as e:
            print(f"[!] Failed to connect to knowledge DB: {e}")
            self.conn = None
    
    def search_exploits(self, query: str, limit: int = 5) -> List[Dict]:
        """Search for learned exploits by type or keyword"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            # Search in exploit code and type
            cursor.execute("""
                SELECT DISTINCT exploit_type, code, source_url, learned_at
                FROM learned_exploits
                WHERE exploit_type LIKE ? OR code LIKE ?
                ORDER BY learned_at DESC
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", limit))
            
            results = cursor.fetchall()
            return [dict(row) for row in results]
        except Exception as e:
            print(f"[!] Exploit search error: {e}")
            return []
    
    def search_vulnerabilities(self, query: str, limit: int = 5) -> List[Dict]:
        """Search for vulnerability patterns and info"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT pattern_id, pattern_type, signature, confidence, countermeasures
                FROM security_patterns
                WHERE pattern_type LIKE ? OR signature LIKE ?
                ORDER BY confidence DESC
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", limit))
            
            results = cursor.fetchall()
            return [dict(row) for row in results]
        except Exception as e:
            print(f"[!] Vulnerability search error: {e}")
            return []
    
    def search_cves(self, query: str, limit: int = 5) -> List[Dict]:
        """Search CVE database"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM cve_database
                WHERE cve_id LIKE ? OR summary LIKE ? OR description LIKE ?
                ORDER BY cvss DESC
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
            
            results = cursor.fetchall()
            return [dict(row) for row in results]
        except Exception as e:
            print(f"[!] CVE search error: {e}")
            return []
    
    def search_techniques(self, query: str, limit: int = 5) -> List[Dict]:
        """Search pentesting techniques database"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT technique_id, name, category, description, references
                FROM techniques
                WHERE name LIKE ? OR category LIKE ? OR description LIKE ?
                ORDER BY name
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
            
            results = cursor.fetchall()
            return [dict(row) for row in results]
        except Exception as e:
            print(f"[!] Technique search error: {e}")
            return []
    
    def search_all(self, query: str) -> Dict[str, List]:
        """Search all knowledge bases"""
        return {
            'exploits': self.search_exploits(query, limit=3),
            'vulnerabilities': self.search_vulnerabilities(query, limit=3),
            'cves': self.search_cves(query, limit=2),
            'techniques': self.search_techniques(query, limit=3),
        }
    
    def get_exploit_details(self, exploit_type: str) -> List[Dict]:
        """Get detailed info about specific exploit type"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM learned_exploits
                WHERE exploit_type = ?
                ORDER BY learned_at DESC
                LIMIT 10
            """, (exploit_type,))
            
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"[!] Exploit details error: {e}")
            return []
    
    def get_pattern_countermeasures(self, pattern_type: str) -> List[str]:
        """Get countermeasures for vulnerability pattern"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT countermeasures FROM security_patterns
                WHERE pattern_type = ?
                LIMIT 1
            """, (pattern_type,))
            
            result = cursor.fetchone()
            if result and result[0]:
                # Parse countermeasures (stored as JSON or comma-separated)
                import json
                try:
                    return json.loads(result[0])
                except:
                    return result[0].split(',')
            return []
        except Exception as e:
            print(f"[!] Countermeasure search error: {e}")
            return []
    
    def extract_keywords(self, text: str) -> List[str]:
        """Extract searchable keywords from user query"""
        # Remove common words
        stop_words = {'what', 'how', 'when', 'where', 'why', 'is', 'are', 'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'from', 'about', 'by', 'me', 'you', 'he', 'she', 'it', 'we', 'they', 'this', 'that', 'do', 'does', 'can', 'could', 'would', 'should', 'will', 'have', 'has', 'had', 'be', 'been', 'being'}
        
        # Tokenize and clean
        words = re.findall(r'\b\w+\b', text.lower())
        keywords = [w for w in words if w not in stop_words and len(w) > 2]
        return list(set(keywords))  # Remove duplicates
    
    def format_results_for_ai(self, results: Dict[str, List]) -> str:
        """Format search results as context string for AI"""
        context = ""
        
        if results['exploits']:
            context += "**Learned Exploits:**\n"
            for exploit in results['exploits'][:2]:
                context += f"- {exploit.get('exploit_type', 'Unknown')}: {exploit.get('code', '')[:100]}...\n"
        
        if results['vulnerabilities']:
            context += "\n**Vulnerability Patterns:**\n"
            for vuln in results['vulnerabilities'][:2]:
                context += f"- {vuln.get('pattern_type', 'Unknown')} (Confidence: {vuln.get('confidence', 0):.1f})\n"
                context += f"  Countermeasures: {', '.join(vuln.get('countermeasures', [])[:3])}\n"
        
        if results['cves']:
            context += "\n**CVE Information:**\n"
            for cve in results['cves'][:1]:
                context += f"- {cve.get('cve_id', 'Unknown')}: {cve.get('summary', '')[:150]}...\n"
                context += f"  CVSS: {cve.get('cvss', 'N/A')}\n"
        
        if results['techniques']:
            context += "\n**Pentesting Techniques:**\n"
            for tech in results['techniques'][:2]:
                context += f"- {tech.get('name', 'Unknown')} ({tech.get('category', 'Unknown')})\n"
        
        return context if context else "No knowledge base results found."
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


# Example usage
if __name__ == "__main__":
    lookup = KnowledgeLookup()
    
    # Search for SQL injection information
    results = lookup.search_all("sql injection")
    print("Search results:", results)
    
    # Format for AI
    context = lookup.format_results_for_ai(results)
    print("\nFormatted for AI:")
    print(context)
    
    lookup.close()
