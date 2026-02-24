"""
AI Knowledge Enhancer
Integrates web learning with LLM responses to enhance AI intelligence
Enables the AI to use learned information to provide better answers
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from web_knowledge_learner import WebKnowledgeLearner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AIKnowledgeEnhancer")


class AIKnowledgeEnhancer:
    """
    Enhances AI responses by injecting learned knowledge from webpage scans
    Works with any LLM (OpenAI, Ollama, etc.) to provide richer context
    """
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.learner = WebKnowledgeLearner(db_path)
        self.response_cache = {}
        self.learning_stats = {
            'queries_enhanced': 0,
            'knowledge_items_used': 0,
            'last_enhanced': None
        }
    
    def enhance_prompt(self, user_query: str, system_prompt: str = "") -> Dict[str, str]:
        """
        Enhance user prompt with learned knowledge context
        Returns enhanced system and user prompts
        """
        
        logger.info(f"Enhancing prompt: {user_query[:50]}...")
        
        # Get relevant learned knowledge
        knowledge_context = self.learner.get_knowledge_context_for_query(user_query)
        
        enhanced_system = system_prompt
        enhanced_user = user_query
        
        if knowledge_context:
            # Add knowledge context to system prompt
            enhanced_system = f"""{system_prompt}

---CONTEXT FROM LEARNED SECURITY KNOWLEDGE---
{knowledge_context}

Use the above learned information to provide more informed and accurate responses. Reference specific CVEs, exploits, and techniques when relevant.
---END LEARNED CONTEXT---"""
            
            # Update stats
            self.learning_stats['queries_enhanced'] += 1
            self.learning_stats['last_enhanced'] = datetime.now().isoformat()
            
            logger.info(f"Prompt enhanced with learned context")
        
        return {
            'system': enhanced_system,
            'user': enhanced_user,
            'has_context': bool(knowledge_context),
            'context_summary': self._summarize_context(knowledge_context)
        }
    
    def learn_from_scan_results(self, scan_results: Dict[str, Any], source_url: str) -> Dict[str, Any]:
        """
        Process scan results from security scanners and learn from them
        Integrates with seek_tab, exploit_seek, etc.
        """
        
        logger.info(f"Learning from scan results: {source_url}")
        
        learning_summary = {
            'source': source_url,
            'items_processed': 0,
            'items_learned': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        # Process vulnerability findings
        if 'vulnerabilities' in scan_results:
            for vuln in scan_results['vulnerabilities']:
                # Extract relevant details
                content = json.dumps(vuln)  # Convert to string for extraction
                result = self.learner.learn_from_content(
                    source_url,
                    content,
                    {'type': 'vulnerability_finding'}
                )
                learning_summary['items_learned'] += result['total_items_learned']
                learning_summary['items_processed'] += 1
        
        # Process exploit findings
        if 'exploits' in scan_results:
            for exploit in scan_results['exploits']:
                content = json.dumps(exploit)
                result = self.learner.learn_from_content(
                    source_url,
                    content,
                    {'type': 'exploit_finding'}
                )
                learning_summary['items_learned'] += result['total_items_learned']
                learning_summary['items_processed'] += 1
        
        # Process CVE information
        if 'cves' in scan_results:
            for cve_info in scan_results['cves']:
                content = json.dumps(cve_info)
                result = self.learner.learn_from_content(
                    source_url,
                    content,
                    {'type': 'cve_finding'}
                )
                learning_summary['items_learned'] += result['total_items_learned']
                learning_summary['items_processed'] += 1
        
        # Process raw content if provided
        if 'raw_content' in scan_results:
            result = self.learner.learn_from_content(
                source_url,
                scan_results['raw_content'],
                scan_results.get('metadata', {})
            )
            learning_summary['items_learned'] += result['total_items_learned']
            learning_summary['items_processed'] += 1
        
        logger.info(f"Scan learning complete: {learning_summary['items_learned']} items learned")
        
        return learning_summary
    
    def get_ai_response_with_knowledge(self, user_query: str, ai_response: str) -> str:
        """
        Enhance AI response by adding learned knowledge citations and recommendations
        """
        
        knowledge_context = self.learner.get_knowledge_context_for_query(user_query)
        
        if knowledge_context:
            enhanced_response = f"""{ai_response}

---INFORMED BY LEARNED SECURITY KNOWLEDGE---
{knowledge_context}

Based on the above learned information, this response has been contextualized with real-world CVE data, exploitation techniques, and pentesting methodologies discovered during security research.
---END KNOWLEDGE ENHANCEMENT---"""
            return enhanced_response
        
        return ai_response
    
    def create_learning_report(self) -> str:
        """Generate a comprehensive report of what has been learned"""
        
        stats = self.learner.store.get_learning_stats()
        
        report = f"""
=== WEB LEARNING KNOWLEDGE REPORT ===
Generated: {datetime.now().isoformat()}

LEARNING STATISTICS:
- Total CVEs Learned: {stats.get('cves_learned', 0)}
- Total Exploits Learned: {stats.get('exploits_learned', 0)}
- Total Techniques Learned: {stats.get('techniques_learned', 0)}
- Total Patterns Learned: {stats.get('patterns_learned', 0)}
- Web Sources Processed: {stats.get('sources_processed', 0)}

AI ENHANCEMENT STATISTICS:
- Queries Enhanced with Knowledge: {self.learning_stats['queries_enhanced']}
- Total Knowledge Items Used: {self.learning_stats['knowledge_items_used']}
- Last Enhancement: {self.learning_stats['last_enhanced']}

KNOWLEDGE UTILIZATION:
The AI system now has enhanced capabilities through learned security intelligence.
This enables:
1. Real-world vulnerability context in responses
2. Accurate CVE and CWE references
3. Practical exploitation techniques
4. Pentesting methodologies and approaches
5. Informed security recommendations

RECOMMENDATIONS:
- Continue scanning security research sites to expand knowledge base
- Regularly run scans on target environments to learn from findings
- Use learned patterns to improve pattern detection
- Reference learned CVEs when providing security advice
"""
        
        return report
    
    def _summarize_context(self, context: str) -> Dict[str, int]:
        """Create a summary of context items"""
        summary = {
            'cves': context.count('CVE-'),
            'techniques': context.count('**Learned Techniques:**'),
            'patterns': context.count('**Learned Vulnerability Patterns:**'),
            'exploits': context.count('**Learned Exploits:**')
        }
        return summary
    
    def export_learned_knowledge(self, output_format: str = 'json') -> str:
        """Export all learned knowledge for analysis or sharing"""
        
        try:
            cursor = self.learner.store.conn.cursor()
            knowledge = {}
            
            # Export CVEs
            cursor.execute("SELECT * FROM learned_cves")
            knowledge['cves'] = [dict(zip([d[0] for d in cursor.description], row)) 
                                 for row in cursor.fetchall()]
            
            # Export exploits
            cursor.execute("SELECT * FROM web_learned_exploits")
            knowledge['exploits'] = [dict(zip([d[0] for d in cursor.description], row)) 
                                     for row in cursor.fetchall()]
            
            # Export techniques
            cursor.execute("SELECT * FROM learned_techniques")
            knowledge['techniques'] = [dict(zip([d[0] for d in cursor.description], row)) 
                                       for row in cursor.fetchall()]
            
            # Export patterns
            cursor.execute("SELECT * FROM web_learned_patterns")
            knowledge['patterns'] = [dict(zip([d[0] for d in cursor.description], row)) 
                                     for row in cursor.fetchall()]
            
            if output_format == 'json':
                return json.dumps(knowledge, indent=2, default=str)
            else:
                return str(knowledge)
        
        except Exception as e:
            logger.error(f"Failed to export knowledge: {e}")
            return "{}"
    
    def close(self):
        """Close all connections"""
        self.learner.close()


class ChatAIKnowledgeMiddleware:
    """
    Middleware for integrating knowledge enhancement into chat interactions
    Works with any LLM backend
    """
    
    def __init__(self, llm_backend=None, db_path: str = "hades_knowledge.db"):
        self.enhancer = AIKnowledgeEnhancer(db_path)
        self.llm = llm_backend
        self.chat_history = []
    
    def process_user_message(self, user_message: str, system_prompt: str = "") -> Dict[str, Any]:
        """
        Process user message with knowledge enhancement
        Returns processed context for LLM
        """
        
        enhanced = self.enhancer.enhance_prompt(user_message, system_prompt)
        
        return {
            'original_query': user_message,
            'enhanced_system': enhanced['system'],
            'enhanced_user': enhanced['user'],
            'has_context': enhanced['has_context'],
            'context_items': enhanced['context_summary']
        }
    
    def process_llm_response(self, user_query: str, llm_response: str) -> Dict[str, Any]:
        """
        Process LLM response to add knowledge context
        """
        
        enhanced_response = self.enhancer.get_ai_response_with_knowledge(
            user_query, llm_response
        )
        
        return {
            'original_response': llm_response,
            'enhanced_response': enhanced_response,
            'knowledge_added': enhanced_response != llm_response
        }
    
    def learn_from_interaction(self, user_query: str, ai_response: str, 
                               metadata: Dict = None) -> bool:
        """
        Optionally learn from successful interactions
        Useful for reinforcement learning
        """
        
        try:
            # Treat the interaction as content to learn from
            content = f"Query: {user_query}\nResponse: {ai_response}"
            
            result = self.enhancer.learner.learn_from_content(
                "internal_chat_interaction",
                content,
                metadata or {}
            )
            
            return result['total_items_learned'] > 0
        except Exception as e:
            logger.error(f"Failed to learn from interaction: {e}")
            return False
    
    def close(self):
        """Close middleware"""
        self.enhancer.close()


# Example usage
if __name__ == "__main__":
    enhancer = AIKnowledgeEnhancer()
    
    # Example: Enhance a security query
    user_query = "How do I exploit SQL injection vulnerabilities?"
    system_prompt = "You are a cybersecurity expert AI assistant."
    
    enhanced = enhancer.enhance_prompt(user_query, system_prompt)
    
    print("ORIGINAL QUERY:")
    print(user_query)
    print("\nENHANCED SYSTEM PROMPT:")
    print(enhanced['system'][:500] + "...")
    print(f"\nContext Added: {enhanced['has_context']}")
    print(f"Context Summary: {enhanced['context_summary']}")
    
    # Example: Process scan results
    scan_results = {
        'vulnerabilities': [
            {
                'type': 'SQL Injection',
                'cve': 'CVE-2024-1234',
                'severity': 'CRITICAL',
                'endpoint': '/api/search'
            }
        ],
        'raw_content': 'CVE-2024-1234 is a critical vulnerability...'
    }
    
    learning = enhancer.learn_from_scan_results(scan_results, "https://target.com/scan")
    print(f"\nLearning Summary: {learning}")
    
    # Get learning report
    report = enhancer.create_learning_report()
    print(report)
    
    enhancer.close()
