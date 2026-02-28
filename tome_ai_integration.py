"""
Exploit Tome AI Integration - Makes the tome fluid and accessible to the AI
Allows AI to read from tome, combine info from multiple sources, and craft new exploits
"""

import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ExploitTemplate:
    """Template for AI-generated exploits"""
    name: str
    category: str
    target_type: str
    vulnerability_type: str
    cve_ids: List[str]
    payload_template: str  # Template with placeholders
    prerequisites: List[str]
    success_indicators: List[str]
    references: List[str]
    tags: List[str]
    difficulty: str  # easy, medium, hard, expert


class TomeAIBridge:
    """
    Bridge between Exploit Tome and AI System
    Allows AI to access, analyze, and create exploits
    """
    
    def __init__(self, tome_db_path: str = "exploit_tome.db"):
        self.db_path = tome_db_path
        self.conn = None
        self._init_connection()
    
    def _init_connection(self):
        """Initialize database connection"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
    
    # ========== TOME ACCESS FOR AI ==========
    
    def get_exploit_knowledge_base(self) -> Dict[str, Any]:
        """
        Get all exploit data as knowledge base for AI
        Returns structured data that AI can analyze and learn from
        """
        try:
            cursor = self.conn.cursor()
            
            # Get all exploits
            cursor.execute('SELECT * FROM exploits ORDER BY success_count DESC')
            rows = cursor.fetchall()
            
            knowledge_base = {
                'total_exploits': len(rows),
                'exploits_by_category': {},
                'exploits_by_cve': {},
                'high_success_exploits': [],
                'exploit_patterns': [],
                'all_exploits': []
            }
            
            for row in rows:
                exploit_data = dict(row)
                exploit_data['tags'] = json.loads(exploit_data.get('tags', '[]'))
                exploit_data['cve_ids'] = json.loads(exploit_data.get('cve_ids', '[]'))
                exploit_data['reference_links'] = json.loads(exploit_data.get('reference_links', '[]'))
                
                knowledge_base['all_exploits'].append(exploit_data)
                
                # Group by category
                cat = exploit_data['category']
                if cat not in knowledge_base['exploits_by_category']:
                    knowledge_base['exploits_by_category'][cat] = []
                knowledge_base['exploits_by_category'][cat].append(exploit_data)
                
                # Group by CVE
                for cve in exploit_data['cve_ids']:
                    if cve not in knowledge_base['exploits_by_cve']:
                        knowledge_base['exploits_by_cve'][cve] = []
                    knowledge_base['exploits_by_cve'][cve].append(exploit_data)
                
                # High success exploits
                if exploit_data['success_count'] >= 3:
                    knowledge_base['high_success_exploits'].append({
                        'name': exploit_data['name'],
                        'category': exploit_data['category'],
                        'success_rate': self._calc_success_rate(
                            exploit_data['success_count'],
                            exploit_data['fail_count']
                        ),
                        'payload': exploit_data['payload'],
                        'cves': exploit_data['cve_ids']
                    })
            
            return knowledge_base
        except Exception as e:
            logger.error(f"Failed to get knowledge base: {e}")
            return {}
    
    def get_exploits_by_category(self, category: str) -> List[Dict]:
        """Get all exploits in a category - useful for AI to find similar patterns"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT * FROM exploits WHERE category = ? ORDER BY success_count DESC',
                (category,)
            )
            
            exploits = []
            for row in cursor.fetchall():
                exploit_data = dict(row)
                exploit_data['tags'] = json.loads(exploit_data.get('tags', '[]'))
                exploit_data['cve_ids'] = json.loads(exploit_data.get('cve_ids', '[]'))
                exploit_data['reference_links'] = json.loads(exploit_data.get('reference_links', '[]'))
                exploits.append(exploit_data)
            
            return exploits
        except Exception as e:
            logger.error(f"Failed to get exploits by category: {e}")
            return []
    
    def get_exploits_by_cve(self, cve_id: str) -> List[Dict]:
        """Get all exploits for a specific CVE"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM exploits WHERE cve_ids LIKE ? ORDER BY success_count DESC",
                (f"%{cve_id}%",)
            )
            
            exploits = []
            for row in cursor.fetchall():
                exploit_data = dict(row)
                exploit_data['tags'] = json.loads(exploit_data.get('tags', '[]'))
                exploit_data['cve_ids'] = json.loads(exploit_data.get('cve_ids', '[]'))
                exploit_data['reference_links'] = json.loads(exploit_data.get('reference_links', '[]'))
                exploits.append(exploit_data)
            
            return exploits
        except Exception as e:
            logger.error(f"Failed to get exploits by CVE: {e}")
            return []
    
    def search_exploit_patterns(self, keyword: str) -> List[Dict]:
        """
        Search for exploit patterns by keyword
        Useful for AI to find similar exploits and adapt them
        """
        try:
            cursor = self.conn.cursor()
            pattern = f"%{keyword}%"
            cursor.execute(
                """SELECT * FROM exploits 
                   WHERE name LIKE ? OR payload LIKE ? OR notes LIKE ? OR tags LIKE ?
                   ORDER BY success_count DESC""",
                (pattern, pattern, pattern, pattern)
            )
            
            exploits = []
            for row in cursor.fetchall():
                exploit_data = dict(row)
                exploit_data['tags'] = json.loads(exploit_data.get('tags', '[]'))
                exploit_data['cve_ids'] = json.loads(exploit_data.get('cve_ids', '[]'))
                exploit_data['reference_links'] = json.loads(exploit_data.get('reference_links', '[]'))
                exploits.append(exploit_data)
            
            return exploits
        except Exception as e:
            logger.error(f"Failed to search patterns: {e}")
            return []
    
    def analyze_exploit_patterns(self) -> Dict[str, Any]:
        """
        Analyze patterns across all exploits
        Returns insights about what works, what doesn't
        """
        try:
            cursor = self.conn.cursor()
            
            # Most successful categories
            cursor.execute("""
                SELECT category, COUNT(*) as count, AVG(success_count) as avg_success
                FROM exploits
                GROUP BY category
                ORDER BY avg_success DESC
            """)
            
            category_analysis = [
                {
                    'category': row[0],
                    'count': row[1],
                    'avg_success_rate': row[2]
                }
                for row in cursor.fetchall()
            ]
            
            # Most common tags
            cursor.execute("SELECT tags FROM exploits")
            all_tags = []
            for row in cursor.fetchall():
                tags = json.loads(row[0])
                all_tags.extend(tags)
            
            tag_frequency = {}
            for tag in all_tags:
                tag_frequency[tag] = tag_frequency.get(tag, 0) + 1
            
            return {
                'category_performance': category_analysis,
                'tag_frequency': tag_frequency,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to analyze patterns: {e}")
            return {}
    
    # ========== AI-CRAFTED EXPLOITS ==========
    
    def create_exploit_from_ai(self, exploit_template: ExploitTemplate) -> Dict[str, Any]:
        """
        Create a new exploit entry from AI-generated template
        This allows AI to craft and store its own exploits
        """
        try:
            cursor = self.conn.cursor()
            
            # Generate unique ID
            exploit_id = f"ai_{exploit_template.category.lower().replace(' ', '_')}_{int(datetime.now().timestamp())}"
            
            exploit_data = {
                'id': exploit_id,
                'name': exploit_template.name,
                'category': exploit_template.category,
                'target': exploit_template.target_type,
                'payload': exploit_template.payload_template,
                'status': 'testing',  # AI-generated exploits start in testing
                'notes': f"AI-generated exploit\nVulnerability: {exploit_template.vulnerability_type}\nPrerequisites: {', '.join(exploit_template.prerequisites)}",
                'tags': json.dumps(exploit_template.tags + ['ai-generated']),
                'cve_ids': json.dumps(exploit_template.cve_ids),
                'reference_links': json.dumps(exploit_template.references),
                'created_at': datetime.now().isoformat(),
                'success_count': 0,
                'fail_count': 0
            }
            
            columns = ', '.join(exploit_data.keys())
            placeholders = ', '.join(['?' for _ in exploit_data])
            
            cursor.execute(
                f'INSERT INTO exploits ({columns}) VALUES ({placeholders})',
                list(exploit_data.values())
            )
            self.conn.commit()
            
            logger.info(f"AI created exploit: {exploit_template.name} (ID: {exploit_id})")
            
            return {
                'success': True,
                'exploit_id': exploit_id,
                'message': f"Exploit '{exploit_template.name}' created and stored in Tome"
            }
        except Exception as e:
            logger.error(f"Failed to create AI exploit: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def combine_exploits_for_ai(self, exploit_ids: List[str]) -> Optional[Dict]:
        """
        Combine multiple exploits for AI analysis
        AI can use this to create hybrid exploits or understand exploit chains
        """
        try:
            cursor = self.conn.cursor()
            
            combined_data = {
                'source_exploits': [],
                'combined_payloads': [],
                'combined_cves': set(),
                'combined_categories': set(),
                'combined_tags': set(),
                'success_rate': 0
            }
            
            total_success = 0
            total_attempts = 0
            
            for exploit_id in exploit_ids:
                cursor.execute('SELECT * FROM exploits WHERE id = ?', (exploit_id,))
                row = cursor.fetchone()
                
                if row:
                    exploit_data = dict(row)
                    exploit_data['tags'] = json.loads(exploit_data.get('tags', '[]'))
                    exploit_data['cve_ids'] = json.loads(exploit_data.get('cve_ids', '[]'))
                    exploit_data['reference_links'] = json.loads(exploit_data.get('reference_links', '[]'))
                    
                    combined_data['source_exploits'].append(exploit_data)
                    combined_data['combined_payloads'].append(exploit_data['payload'])
                    combined_data['combined_cves'].update(exploit_data['cve_ids'])
                    combined_data['combined_categories'].add(exploit_data['category'])
                    combined_data['combined_tags'].update(exploit_data['tags'])
                    
                    total_success += exploit_data['success_count']
                    total_attempts += exploit_data['success_count'] + exploit_data['fail_count']
            
            if total_attempts > 0:
                combined_data['success_rate'] = (total_success / total_attempts) * 100
            
            combined_data['combined_cves'] = list(combined_data['combined_cves'])
            combined_data['combined_categories'] = list(combined_data['combined_categories'])
            combined_data['combined_tags'] = list(combined_data['combined_tags'])
            
            return combined_data
        except Exception as e:
            logger.error(f"Failed to combine exploits: {e}")
            return None
    
    def update_exploit_from_execution(self, exploit_id: str, execution_result: Dict):
        """
        Update exploit with execution result
        AI can use this to track what works and what doesn't
        """
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('SELECT success_count, fail_count FROM exploits WHERE id = ?', (exploit_id,))
            row = cursor.fetchone()
            
            if row:
                success_count = row[0]
                fail_count = row[1]
                
                if execution_result.get('success', False):
                    success_count += 1
                else:
                    fail_count += 1
                
                cursor.execute(
                    """UPDATE exploits 
                       SET success_count = ?, fail_count = ?, last_used = ?
                       WHERE id = ?""",
                    (success_count, fail_count, datetime.now().isoformat(), exploit_id)
                )
                self.conn.commit()
                
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to update exploit: {e}")
            return False
    
    # ========== HELPER METHODS ==========
    
    def _calc_success_rate(self, success: int, fail: int) -> float:
        """Calculate success rate percentage"""
        total = success + fail
        return (success / total * 100) if total > 0 else 0
    
    def get_exploit_recommendations_for_target(self, target_info: Dict) -> List[Dict]:
        """
        Get recommended exploits based on target information
        AI can use this to select the best exploits for a target
        """
        try:
            recommendations = []
            
            # Extract target info
            target_type = target_info.get('type', '')
            cves = target_info.get('cves', [])
            services = target_info.get('services', [])
            
            cursor = self.conn.cursor()
            
            # First, look for exploits matching CVEs
            for cve in cves:
                exploits = self.get_exploits_by_cve(cve)
                for exploit in exploits:
                    if exploit not in recommendations:
                        recommendations.append({
                            **exploit,
                            'reason': f"Directly targets {cve}",
                            'score': 10 * (exploit['success_count'] / max(1, exploit['success_count'] + exploit['fail_count']))
                        })
            
            # Then look for category-based exploits
            for service in services:
                category_exploits = self.get_exploits_by_category(service)
                for exploit in category_exploits:
                    if exploit not in recommendations:
                        recommendations.append({
                            **exploit,
                            'reason': f"Matches service type: {service}",
                            'score': 5 * (exploit['success_count'] / max(1, exploit['success_count'] + exploit['fail_count']))
                        })
            
            # Sort by score
            recommendations.sort(key=lambda x: x['score'], reverse=True)
            
            return recommendations[:10]  # Top 10 recommendations
        except Exception as e:
            logger.error(f"Failed to get recommendations: {e}")
            return []
    
    def export_knowledge_for_ai(self, filename: str = "ai_exploit_knowledge.json") -> bool:
        """
        Export all exploit knowledge in a format optimized for AI training/analysis
        """
        try:
            knowledge = self.get_exploit_knowledge_base()
            analysis = self.analyze_exploit_patterns()
            
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'knowledge_base': knowledge,
                'pattern_analysis': analysis,
                'stats': {
                    'total_exploits': knowledge['total_exploits'],
                    'categories': len(knowledge['exploits_by_category']),
                    'cves': len(knowledge['exploits_by_cve'])
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Exported knowledge to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to export knowledge: {e}")
            return False


class TomeAccessor:
    """
    Simple interface for AI to access the tome
    Used in AI prompts and decision-making
    """
    
    def __init__(self, bridge: TomeAIBridge):
        self.bridge = bridge
    
    def get_similar_exploits(self, query: str, limit: int = 5) -> List[Dict]:
        """Get exploits similar to the query"""
        exploits = self.bridge.search_exploit_patterns(query)
        return exploits[:limit]
    
    def get_successful_exploits(self, category: str = None, limit: int = 10) -> List[Dict]:
        """Get most successful exploits, optionally by category"""
        if category:
            exploits = self.bridge.get_exploits_by_category(category)
        else:
            knowledge = self.bridge.get_exploit_knowledge_base()
            exploits = knowledge.get('all_exploits', [])
        
        # Sort by success rate
        exploits.sort(
            key=lambda x: (x['success_count'] / max(1, x['success_count'] + x['fail_count'])),
            reverse=True
        )
        
        return exploits[:limit]
    
    def get_cve_exploits(self, cve_id: str) -> List[Dict]:
        """Get all exploits for a CVE"""
        return self.bridge.get_exploits_by_cve(cve_id)
    
    def get_payload_templates(self, category: str) -> List[str]:
        """Get payload templates by category"""
        exploits = self.bridge.get_exploits_by_category(category)
        return [e['payload'] for e in exploits]
    
    def analyze_tactics(self) -> Dict:
        """Analyze what tactics work best"""
        return self.bridge.analyze_exploit_patterns()


def create_tome_bridge() -> TomeAIBridge:
    """Factory function to create the bridge"""
    return TomeAIBridge()
