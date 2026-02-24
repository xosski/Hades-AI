#!/usr/bin/env python3
"""
Practical Web Learning Integration Example
Shows how to integrate web learning into HadesAI components
"""

import json
from typing import Dict, List, Any
from ai_knowledge_enhancer import AIKnowledgeEnhancer, ChatAIKnowledgeMiddleware


class HadesAIWithLearning:
    """
    Enhanced HadesAI with web learning capabilities
    Integrates knowledge learning into all major components
    """
    
    def __init__(self):
        self.enhancer = AIKnowledgeEnhancer()
        self.middleware = ChatAIKnowledgeMiddleware()
        print("[*] HadesAI initialized with web learning capabilities")
    
    # ========================================================================
    # SEEK TAB INTEGRATION
    # ========================================================================
    
    def process_seek_tab_results(self, seek_results: List[Dict]) -> Dict[str, Any]:
        """
        Process results from exploit_seek_tab with learning
        
        Example integration point in exploit_seek_tab.py:
        After line ~200 where results are generated
        """
        
        print(f"\n[*] Processing {len(seek_results)} seek results with learning...")
        
        learning_summary = {
            'total_exploits': len(seek_results),
            'learned_exploits': 0,
            'learned_cves': 0,
            'learned_techniques': 0
        }
        
        for result in seek_results:
            # Build content from seek result
            content = f"""
            Exploit Type: {result.get('type', 'Unknown')}
            Target: {result.get('target', 'Unknown')}
            Vulnerability: {result.get('vulnerability', 'Unknown')}
            CVE: {result.get('cve', 'Unknown')}
            Description: {result.get('description', '')}
            """
            
            # Learn from this result
            learn_result = self.enhancer.learner.learn_from_content(
                url=result.get('source_url', 'seek_tab:internal'),
                content=content,
                metadata={'type': 'seek_result', 'target': result.get('target')}
            )
            
            learning_summary['learned_exploits'] += len(learn_result['exploits'])
            learning_summary['learned_cves'] += len(learn_result['cves'])
            learning_summary['learned_techniques'] += len(learn_result['techniques'])
        
        print(f"[+] Learned from {len(seek_results)} seek results:")
        print(f"    - CVEs: {learning_summary['learned_cves']}")
        print(f"    - Exploits: {learning_summary['learned_exploits']}")
        print(f"    - Techniques: {learning_summary['learned_techniques']}")
        
        return learning_summary
    
    # ========================================================================
    # VULNERABILITY SCANNER INTEGRATION
    # ========================================================================
    
    def process_scanner_results(self, scanner_results: Dict) -> Dict[str, Any]:
        """
        Process vulnerability scanner results with learning
        
        Example integration point:
        After any vulnerability scanner completes
        """
        
        print(f"\n[*] Processing scanner results with learning...")
        
        # Transform scanner results into learning format
        scan_learning = {
            'vulnerabilities': scanner_results.get('vulnerabilities', []),
            'cves': [v for v in scanner_results.get('vulnerabilities', []) if 'cve' in v],
            'raw_content': json.dumps(scanner_results, indent=2)
        }
        
        # Learn from scan
        learning = self.enhancer.learn_from_scan_results(
            scan_learning,
            source_url=f"scanner:{scanner_results.get('target', 'unknown')}"
        )
        
        print(f"[+] Learned from scanner results:")
        print(f"    - Items processed: {learning['items_processed']}")
        print(f"    - Items learned: {learning['items_learned']}")
        
        return learning
    
    # ========================================================================
    # CHAT INTERFACE ENHANCEMENT
    # ========================================================================
    
    def handle_chat_message(self, user_message: str, system_prompt: str = "") -> Dict[str, Any]:
        """
        Handle chat messages with knowledge enhancement
        
        Integration in chat handler:
        def on_chat_message(msg):
            result = hades.handle_chat_message(msg, system_prompt)
            enhanced_prompt = result['processed']['enhanced_system']
            enhanced_user = result['processed']['enhanced_user']
            ai_response = call_llm(enhanced_prompt, enhanced_user)
            final = hades.enhance_chat_response(user_message, ai_response)
            return final['enhanced_response']
        """
        
        print(f"\n[*] Processing chat message with knowledge...")
        print(f"    User: {user_message[:80]}...")
        
        # Process with middleware
        processed = self.middleware.process_user_message(user_message, system_prompt)
        
        context_summary = {
            'has_knowledge': processed['has_context'],
            'cves': processed['context_items'].get('cves', 0),
            'techniques': processed['context_items'].get('techniques', 0),
            'patterns': processed['context_items'].get('patterns', 0)
        }
        
        print(f"[+] Knowledge enhancement applied:")
        print(f"    - Has context: {context_summary['has_knowledge']}")
        print(f"    - CVEs in context: {context_summary['cves']}")
        print(f"    - Techniques in context: {context_summary['techniques']}")
        print(f"    - Patterns in context: {context_summary['patterns']}")
        
        return {
            'processed': processed,
            'context_summary': context_summary
        }
    
    def enhance_chat_response(self, user_query: str, ai_response: str) -> Dict[str, str]:
        """
        Enhance AI response with knowledge context
        
        Call after receiving LLM response
        """
        
        print(f"\n[*] Enhancing AI response with knowledge...")
        
        enhanced = self.middleware.process_llm_response(user_query, ai_response)
        
        print(f"[+] Response enhanced: {enhanced['knowledge_added']}")
        if enhanced['knowledge_added']:
            original_len = len(enhanced['original_response'])
            enhanced_len = len(enhanced['enhanced_response'])
            print(f"    - Original length: {original_len}")
            print(f"    - Enhanced length: {enhanced_len}")
            print(f"    - Context added: {enhanced_len - original_len} chars")
        
        return enhanced
    
    # ========================================================================
    # AI RESPONSE ENHANCEMENT
    # ========================================================================
    
    def enhance_llm_prompt(self, user_query: str, system_prompt: str = "") -> Dict[str, str]:
        """
        Prepare enhanced prompts for LLM
        
        Usage in any LLM call:
        enhanced = hades.enhance_llm_prompt(user_query)
        response = llm(enhanced['system'], enhanced['user'])
        """
        
        print(f"\n[*] Enhancing LLM prompt with knowledge...")
        
        enhanced = self.enhancer.enhance_prompt(user_query, system_prompt)
        
        print(f"[+] Prompt enhancement applied:")
        print(f"    - Has context: {enhanced['has_context']}")
        print(f"    - Context items: {enhanced['context_summary']}")
        
        return {
            'system': enhanced['system'],
            'user': enhanced['user']
        }
    
    # ========================================================================
    # ANALYTICS & MONITORING
    # ========================================================================
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get current learning statistics"""
        return self.enhancer.learner.store.get_learning_stats()
    
    def generate_learning_report(self) -> str:
        """Generate comprehensive learning report"""
        return self.enhancer.create_learning_report()
    
    def export_knowledge(self, format: str = 'json') -> str:
        """Export learned knowledge"""
        return self.enhancer.export_learned_knowledge(format)
    
    # ========================================================================
    # AUTONOMOUS CODING AGENT INTEGRATION
    # ========================================================================
    
    def enhance_agent_query(self, agent_query: str) -> Dict[str, str]:
        """
        Enhance autonomous coding agent with security knowledge
        
        Integration in AutonomousCodingAgent:
        enhanced = hades.enhance_agent_query(query)
        system_prompt = enhanced['system']
        """
        
        print(f"\n[*] Enhancing autonomous agent query...")
        
        system_prompt = f"""
You are an advanced autonomous coding and security analysis agent.
You have access to a growing knowledge base of security vulnerabilities, exploits, and techniques.

SECURITY KNOWLEDGE CONTEXT:
{self.enhancer.learner.get_knowledge_context_for_query(agent_query)}

When analyzing code or systems, reference learned vulnerability patterns and exploitation techniques when relevant.
Provide practical security recommendations grounded in discovered vulnerabilities.
"""
        
        return {
            'system': system_prompt,
            'user': agent_query
        }
    
    # ========================================================================
    # PAYLOAD GENERATOR INTEGRATION
    # ========================================================================
    
    def get_payload_knowledge(self, payload_type: str) -> str:
        """
        Get learned knowledge about specific payload types
        
        Integration in payload_generator:
        knowledge = hades.get_payload_knowledge(payload_type)
        # Use knowledge to inform payload generation
        """
        
        print(f"\n[*] Looking up knowledge for {payload_type}...")
        
        context = self.enhancer.learner.get_knowledge_context_for_query(payload_type)
        
        return context if context else f"No specific knowledge found for {payload_type}"
    
    # ========================================================================
    # REAL-TIME LEARNING CALLBACKS
    # ========================================================================
    
    def on_cve_discovered(self, cve_id: str, description: str, severity: str):
        """Called when a new CVE is discovered during scanning"""
        content = f"CVE {cve_id}: {description} (Severity: {severity})"
        self.enhancer.learner.learn_from_content(
            url="internal:cve_discovery",
            content=content,
            metadata={'type': 'discovered_cve', 'severity': severity}
        )
        print(f"[+] Learned about {cve_id}")
    
    def on_exploit_found(self, exploit_type: str, code: str, target: str):
        """Called when an exploit is discovered"""
        content = f"Exploit Type: {exploit_type}\nCode:\n{code}"
        self.enhancer.learner.learn_from_content(
            url=f"internal:exploit:{target}",
            content=content,
            metadata={'type': 'discovered_exploit', 'target': target}
        )
        print(f"[+] Learned about {exploit_type} exploit")
    
    def on_vulnerability_found(self, vuln_type: str, endpoint: str, description: str):
        """Called when a vulnerability is found"""
        content = f"Vulnerability: {vuln_type}\nEndpoint: {endpoint}\n{description}"
        self.enhancer.learner.learn_from_content(
            url=f"internal:vulnerability:{endpoint}",
            content=content,
            metadata={'type': 'discovered_vulnerability', 'endpoint': endpoint}
        )
        print(f"[+] Learned about {vuln_type} vulnerability")
    
    def close(self):
        """Clean up resources"""
        self.enhancer.close()
        self.middleware.close()


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

def example_seek_tab_integration():
    """Example: Integrating with seek_tab"""
    print("\n" + "="*70)
    print("EXAMPLE: SEEK TAB INTEGRATION")
    print("="*70)
    
    hades = HadesAIWithLearning()
    
    # Simulate seek_tab results
    seek_results = [
        {
            'type': 'SQL Injection',
            'target': 'example.com',
            'vulnerability': 'Unvalidated user input in search parameter',
            'cve': 'CVE-2024-1234',
            'description': 'The search endpoint accepts SQL commands without validation',
            'source_url': 'https://security-research.com/exploit-1'
        },
        {
            'type': 'Remote Code Execution',
            'target': 'example.com',
            'vulnerability': 'Unsafe file upload handling',
            'cve': 'CVE-2024-5678',
            'description': 'File upload functionality executes uploaded scripts',
            'source_url': 'https://security-research.com/exploit-2'
        }
    ]
    
    hades.process_seek_tab_results(seek_results)
    hades.close()


def example_scanner_integration():
    """Example: Integrating with vulnerability scanner"""
    print("\n" + "="*70)
    print("EXAMPLE: VULNERABILITY SCANNER INTEGRATION")
    print("="*70)
    
    hades = HadesAIWithLearning()
    
    # Simulate scanner results
    scanner_results = {
        'target': 'target.com',
        'vulnerabilities': [
            {
                'type': 'SQL Injection',
                'endpoint': '/api/search',
                'severity': 'CRITICAL',
                'cve': 'CVE-2024-9999'
            },
            {
                'type': 'Cross-Site Scripting',
                'endpoint': '/profile',
                'severity': 'HIGH',
                'cve': 'CVE-2024-8888'
            }
        ]
    }
    
    hades.process_scanner_results(scanner_results)
    hades.close()


def example_chat_integration():
    """Example: Integrating with chat interface"""
    print("\n" + "="*70)
    print("EXAMPLE: CHAT INTERFACE INTEGRATION")
    print("="*70)
    
    hades = HadesAIWithLearning()
    
    # First, learn something
    print("\n[Step 1] Teaching AI about SQL injection...")
    hades.enhancer.learner.learn_from_content(
        url="https://security-blog.com/sql-injection",
        content="""
        SQL Injection (CVE-2024-TEST) is a critical vulnerability.
        Attackers can bypass authentication using: ' OR '1'='1
        The exploitation technique involves payload injection through user input.
        """
    )
    
    # Now process a chat message
    print("\n[Step 2] Processing user chat message...")
    result = hades.handle_chat_message(
        user_message="How do I test for SQL injection vulnerabilities?",
        system_prompt="You are a cybersecurity expert"
    )
    
    # Simulate LLM response
    print("\n[Step 3] Enhancing AI response...")
    ai_response = "To test for SQL injection, try common payloads like ' OR '1'='1"
    enhanced = hades.enhance_chat_response(
        user_query="How do I test for SQL injection vulnerabilities?",
        ai_response=ai_response
    )
    
    print("\n[Final Response]:")
    print(enhanced['enhanced_response'][:500] + "...")
    
    hades.close()


def example_analytics():
    """Example: Getting learning analytics"""
    print("\n" + "="*70)
    print("EXAMPLE: ANALYTICS & REPORTING")
    print("="*70)
    
    hades = HadesAIWithLearning()
    
    # Learn some things first
    print("[*] Learning from various sources...")
    for i in range(3):
        hades.enhancer.learner.learn_from_content(
            url=f"https://security-research.com/article-{i}",
            content=f"CVE-2024-{1000+i} is a critical vulnerability affecting..."
        )
    
    # Get statistics
    print("\n[*] Learning Statistics:")
    stats = hades.get_learning_stats()
    for key, value in stats.items():
        print(f"    {key}: {value}")
    
    # Generate report
    print("\n[*] Learning Report:")
    report = hades.generate_learning_report()
    print(report[:500] + "...")
    
    hades.close()


def example_event_callbacks():
    """Example: Real-time learning callbacks"""
    print("\n" + "="*70)
    print("EXAMPLE: EVENT-BASED LEARNING")
    print("="*70)
    
    hades = HadesAIWithLearning()
    
    # Simulate real-time events during testing
    print("\n[*] Simulating real-time discovery events...")
    
    hades.on_cve_discovered(
        cve_id="CVE-2024-LIVE",
        description="Critical vulnerability in authentication module",
        severity="CRITICAL"
    )
    
    hades.on_exploit_found(
        exploit_type="SQL Injection",
        code="' UNION SELECT * FROM users--",
        target="example.com"
    )
    
    hades.on_vulnerability_found(
        vuln_type="Broken Access Control",
        endpoint="/admin/settings",
        description="Admin pages accessible without authentication"
    )
    
    hades.close()


if __name__ == "__main__":
    print("\n" + "#"*70)
    print("# HADES-AI WEB LEARNING INTEGRATION EXAMPLES")
    print("#"*70)
    
    # Run all examples
    example_seek_tab_integration()
    example_scanner_integration()
    example_chat_integration()
    example_analytics()
    example_event_callbacks()
    
    print("\n" + "#"*70)
    print("# ALL EXAMPLES COMPLETED")
    print("#"*70)
