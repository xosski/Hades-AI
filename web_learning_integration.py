"""
Enhanced Web Learning Integration for HadesAI
Seamlessly integrates web-based knowledge with LLM routing and defense systems
"""

import logging
import json
import sqlite3
import threading
import time
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass
import hashlib

from web_knowledge_learner import (
    WebKnowledgeLearner, WebContentExtractor, WebKnowledgeStore
)
from unified_llm_router import UnifiedLLMRouter, LLMRequest, RequestPriority
from enhanced_defense_system import EnhancedDefenseSystem, ThreatLevel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WebLearningIntegration")


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class LearningContext:
    """Context for enhanced learning"""
    url: str
    content: str
    metadata: Dict[str, Any]
    learned_knowledge: Dict[str, Any]
    ai_enhancements: Dict[str, Any]
    defense_scan_results: Optional[Dict] = None
    llm_analysis: Optional[str] = None


# ============================================================================
# ENHANCED WEB LEARNING INTEGRATION
# ============================================================================

class EnhancedWebLearningIntegrator:
    """Integrate web learning with LLM routing and defense"""
    
    def __init__(self):
        self.learner = WebKnowledgeLearner()
        self.router = UnifiedLLMRouter()
        self.defense = EnhancedDefenseSystem()
        self.integration_db = self._init_integration_db()
        self.learning_callbacks: List[Callable] = []
    
    def _init_integration_db(self) -> str:
        """Initialize integration database"""
        db_path = "learning_integration.db"
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learning_contexts (
                    context_id TEXT PRIMARY KEY,
                    url TEXT,
                    timestamp TEXT,
                    learned_items INTEGER,
                    security_issues INTEGER,
                    ai_enhancements TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS web_security_findings (
                    finding_id TEXT PRIMARY KEY,
                    url TEXT,
                    threat_level TEXT,
                    finding_type TEXT,
                    description TEXT,
                    remediation TEXT,
                    timestamp TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learned_and_secured_knowledge (
                    knowledge_id TEXT PRIMARY KEY,
                    knowledge_type TEXT,
                    content TEXT,
                    source_url TEXT,
                    security_verified BOOLEAN,
                    defense_scanned BOOLEAN,
                    ai_enhanced BOOLEAN,
                    timestamp TEXT
                )
            """)
            
            conn.commit()
            conn.close()
            return db_path
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            return db_path
    
    def learn_and_defend_webpage(self, url: str, content: str, metadata: Dict = None) -> LearningContext:
        """
        Integrated learning process:
        1. Extract knowledge from content
        2. Scan for security threats
        3. Enhance with LLM analysis
        4. Store integrated knowledge
        """
        
        if not metadata:
            metadata = {}
        
        import uuid
        context_id = f"ctx_{uuid.uuid4().hex[:8]}"
        
        logger.info(f"[{context_id}] Starting integrated learning: {url}")
        
        # Step 1: Learn from content
        learned = self.learner.learn_from_content(url, content, metadata)
        logger.info(f"[{context_id}] Extracted {learned['total_items_learned']} knowledge items")
        
        # Step 2: Security scanning
        defense_results = self.defense.scan_content(content, {"source_url": url})
        security_issues = 0
        if defense_results:
            security_issues = 1
            logger.warning(f"[{context_id}] Security threat detected: {defense_results.threat_type}")
        
        # Step 3: LLM-based enhancement
        ai_enhancements = self._get_ai_enhancements(learned, url, content)
        logger.info(f"[{context_id}] AI enhancements generated")
        
        # Step 4: Store integrated knowledge
        context = LearningContext(
            url=url,
            content=content[:1000],  # Store summary
            metadata=metadata,
            learned_knowledge=learned,
            ai_enhancements=ai_enhancements,
            defense_scan_results=self._serialize_defense_results(defense_results) if defense_results else None,
            llm_analysis=ai_enhancements.get('analysis')
        )
        
        self._store_context(context)
        logger.info(f"[{context_id}] Integration complete")
        
        # Trigger callbacks
        for callback in self.learning_callbacks:
            try:
                callback(context)
            except Exception as e:
                logger.error(f"Callback error: {e}")
        
        return context
    
    def _get_ai_enhancements(self, learned: Dict, url: str, content: str) -> Dict[str, Any]:
        """Get AI-powered enhancements for learned knowledge"""
        
        # Build context about what was learned
        learning_summary = f"""
        URL: {url}
        
        Extracted Knowledge:
        - CVEs: {len(learned.get('cves', []))}
        - Exploits: {len(learned.get('exploits', []))}
        - Techniques: {len(learned.get('techniques', []))}
        - Patterns: {len(learned.get('patterns', []))}
        
        Content Preview:
        {content[:500]}
        
        Please provide:
        1. Security risk assessment
        2. Exploitation potential
        3. Defense recommendations
        4. Knowledge application scenarios
        """
        
        request = LLMRequest(
            prompt=learning_summary,
            priority=RequestPriority.NORMAL,
            system_prompt="You are HadesAI Security Analyst. Analyze security knowledge and provide actionable insights.",
            max_tokens=1500
        )
        
        response = self.router.route_request(request)
        
        return {
            "analysis": response.content,
            "provider": response.provider.value if response.provider else "unknown",
            "confidence": 0.8 if response.success else 0.3,
            "generated_at": datetime.now().isoformat(),
            "cached": response.cached
        }
    
    def _serialize_defense_results(self, event) -> Dict:
        """Serialize defense event for storage"""
        if not event:
            return None
        
        return {
            "event_id": event.event_id,
            "threat_level": event.threat_level.name,
            "threat_type": event.threat_type,
            "description": event.description,
            "actions_taken": [a.value for a in event.response_actions]
        }
    
    def _store_context(self, context: LearningContext):
        """Store learning context"""
        try:
            conn = sqlite3.connect(self.integration_db)
            cursor = conn.cursor()
            
            import uuid
            context_id = f"ctx_{uuid.uuid4().hex[:8]}"
            
            cursor.execute("""
                INSERT INTO learning_contexts
                (context_id, url, timestamp, learned_items, security_issues, ai_enhancements)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                context_id,
                context.url,
                datetime.now().isoformat(),
                context.learned_knowledge.get('total_items_learned', 0),
                1 if context.defense_scan_results else 0,
                json.dumps(context.ai_enhancements)
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to store context: {e}")
    
    def register_learning_callback(self, callback: Callable):
        """Register callback for learning events"""
        self.learning_callbacks.append(callback)
    
    def get_knowledge_by_threat_level(self, threat_level: str) -> List[Dict]:
        """Retrieve knowledge items by threat level"""
        try:
            conn = sqlite3.connect(self.integration_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM web_security_findings
                WHERE threat_level = ?
                ORDER BY timestamp DESC
                LIMIT 20
            """, (threat_level,))
            
            results = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Query error: {e}")
            return []
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get comprehensive learning statistics"""
        try:
            conn = sqlite3.connect(self.integration_db)
            cursor = conn.cursor()
            
            # Total learning contexts
            cursor.execute("SELECT COUNT(*) FROM learning_contexts")
            total_contexts = cursor.fetchone()[0]
            
            # Security findings
            cursor.execute("SELECT COUNT(*) FROM web_security_findings")
            total_findings = cursor.fetchone()[0]
            
            # Knowledge items
            cursor.execute("SELECT COUNT(*) FROM learned_and_secured_knowledge")
            total_knowledge = cursor.fetchone()[0]
            
            # Threat distribution
            cursor.execute("""
                SELECT threat_level, COUNT(*) as count
                FROM web_security_findings
                GROUP BY threat_level
            """)
            
            threat_dist = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Get base learner stats
            learner_stats = self.learner.store.get_learning_stats()
            
            conn.close()
            
            return {
                "total_contexts": total_contexts,
                "total_security_findings": total_findings,
                "total_knowledge_items": total_knowledge,
                "threat_distribution": threat_dist,
                "learned_cves": learner_stats.get('cves_learned', 0),
                "learned_exploits": learner_stats.get('exploits_learned', 0),
                "learned_techniques": learner_stats.get('techniques_learned', 0),
                "learned_patterns": learner_stats.get('patterns_learned', 0),
                "web_sources_processed": learner_stats.get('sources_processed', 0),
                "llm_provider_stats": self.router.get_stats()
            }
        except Exception as e:
            logger.error(f"Statistics error: {e}")
            return {}


# ============================================================================
# AUTOMATED LEARNING WORKER
# ============================================================================

class AutomatedLearningWorker(threading.Thread):
    """Background worker for continuous learning"""
    
    def __init__(self, integrator: EnhancedWebLearningIntegrator, batch_size: int = 5):
        super().__init__(daemon=True)
        self.integrator = integrator
        self.batch_size = batch_size
        self.running = False
        self.learning_queue: List[Dict] = []
        self.queue_lock = threading.Lock()
    
    def add_url_to_learn(self, url: str, metadata: Dict = None):
        """Add URL to learning queue"""
        with self.queue_lock:
            self.learning_queue.append({
                "url": url,
                "metadata": metadata or {}
            })
    
    def run(self):
        """Main worker loop"""
        self.running = True
        logger.info("Automated learning worker started")
        
        while self.running:
            with self.queue_lock:
                if self.learning_queue:
                    batch = self.learning_queue[:self.batch_size]
                    self.learning_queue = self.learning_queue[self.batch_size:]
            
            if batch:
                for item in batch:
                    try:
                        # Fetch content from URL
                        import requests
                        response = requests.get(item["url"], timeout=10)
                        
                        if response.status_code == 200:
                            self.integrator.learn_and_defend_webpage(
                                item["url"],
                                response.text,
                                item["metadata"]
                            )
                    except Exception as e:
                        logger.error(f"Failed to learn from {item['url']}: {e}")
                    
                    time.sleep(1)  # Rate limiting
            else:
                time.sleep(5)
    
    def stop(self):
        """Stop worker"""
        self.running = False


# ============================================================================
# INTEGRATION HELPER FUNCTIONS
# ============================================================================

def create_integrated_system() -> EnhancedWebLearningIntegrator:
    """Factory function to create integrated system"""
    return EnhancedWebLearningIntegrator()


if __name__ == "__main__":
    # Test integrated system
    import time
    
    integrator = create_integrated_system()
    
    # Example learning
    test_content = """
    CVE-2024-1234 - Critical SQL Injection in WebApp v1.0
    
    Vulnerability Details:
    A SQL injection vulnerability exists in the user authentication module.
    The vulnerability allows unauthenticated remote attackers to execute arbitrary SQL queries.
    
    CVSS Score: 9.8 (Critical)
    
    Exploitation:
    POST /login
    username=' OR '1'='1'--&password=x
    
    This bypass allows access without valid credentials.
    
    Mitigation:
    - Update to version 2.0
    - Use parameterized queries
    - Implement input validation
    """
    
    context = integrator.learn_and_defend_webpage(
        "https://example.com/vulnerability-report",
        test_content,
        {"title": "Critical Vulnerability Report"}
    )
    
    print(f"\n=== Learning Integration Complete ===")
    print(f"Learned Items: {context.learned_knowledge['total_items_learned']}")
    print(f"Security Issues: {'Yes' if context.defense_scan_results else 'No'}")
    print(f"AI Analysis:\n{context.ai_enhancements.get('analysis', 'N/A')[:500]}")
    
    print(f"\n=== System Statistics ===")
    import pprint
    stats = integrator.get_learning_statistics()
    pprint.pprint(stats)
