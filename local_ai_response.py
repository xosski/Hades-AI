"""
Local AI Response Generator
Mimics Mistral-like responses without requiring API keys.
Uses knowledge lookup + pattern-based response generation with context awareness.
"""

import re
from typing import Optional, Dict, List, Tuple
from knowledge_lookup import KnowledgeLookup
from datetime import datetime


class LocalAIResponse:
    """
    Generate AI-like responses without API keys.
    Combines knowledge lookup with template-based reasoning and context awareness.
    """
    
    def __init__(self, use_knowledge_db: bool = True):
        self.lookup = KnowledgeLookup() if use_knowledge_db else None
        self.personality = "technical, security-focused, analytical"
        self.max_response_length = 2000
        self.conversation_history: List[Dict] = []
        self.context_stack: List[Dict] = []
        self.follow_up_questions: Dict[str, List[str]] = {}
        self.expertise_level = "intermediate"
    
    def generate(self, user_input: str, system_prompt: str = "", mood: str = "neutral") -> str:
        """
        Generate response to user input with context awareness.
        
        Args:
            user_input: User's message
            system_prompt: System context (personality, instructions)
            mood: Current mood (affects tone)
        
        Returns:
            Generated response
        """
        
        # Store in conversation history
        self._add_to_history(user_input, "user")
        
        # Detect query type and sophistication
        query_type = self._detect_query_type(user_input)
        sophistication_level = self._assess_sophistication(user_input)
        
        # Get context from conversation history
        conversation_context = self._build_conversation_context()
        
        # Look up relevant knowledge
        knowledge_context = ""
        if self.lookup:
            keywords = self.lookup.extract_keywords(user_input)
            if keywords:
                results = self.lookup.search_all(" ".join(keywords[:3]))
                knowledge_context = self.lookup.format_results_for_ai(results)
        
        # Generate response based on type and context
        if query_type == "vulnerability":
            response = self._respond_vulnerability(user_input, knowledge_context, mood, conversation_context)
        elif query_type == "exploit":
            response = self._respond_exploit(user_input, knowledge_context, mood, conversation_context)
        elif query_type == "technique":
            response = self._respond_technique(user_input, knowledge_context, mood, conversation_context)
        elif query_type == "defense":
            response = self._respond_defense(user_input, knowledge_context, mood, conversation_context)
        elif query_type == "general_security":
            response = self._respond_general_security(user_input, knowledge_context, mood, conversation_context)
        else:
            response = self._respond_general(user_input, mood, conversation_context)
        
        # Add follow-up suggestions
        response_with_followups = self._add_intelligent_followups(response, query_type)
        
        # Store response in history
        self._add_to_history(response_with_followups, "assistant")
        
        return response_with_followups
    
    def _detect_query_type(self, text: str) -> str:
        """Detect the type of security query"""
        text_lower = text.lower()
        
        # Vulnerability-focused
        if any(word in text_lower for word in ['vulnerability', 'vulnerable', 'weakness', 'flaw', 'cve', 'cvss']):
            return "vulnerability"
        
        # Exploit-focused
        if any(word in text_lower for word in ['exploit', 'payload', 'shellcode', 'poc', 'attack']):
            return "exploit"
        
        # Technique-focused
        if any(word in text_lower for word in ['scan', 'enumerate', 'recon', 'assessment', 'penetrat']):
            return "technique"
        
        # Defense-focused
        if any(word in text_lower for word in ['prevent', 'protect', 'defend', 'mitigate', 'secure', 'fix', 'patch']):
            return "defense"
        
        # General security
        if any(word in text_lower for word in ['security', 'attack', 'threat', 'risk', 'intrusion']):
            return "general_security"
        
        return "general"
    
    def _add_to_history(self, message: str, role: str) -> None:
        """Add message to conversation history"""
        self.conversation_history.append({
            'role': role,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        # Keep history to last 20 messages to avoid memory bloat
        if len(self.conversation_history) > 20:
            self.conversation_history = self.conversation_history[-20:]
    
    def _build_conversation_context(self) -> str:
        """Build context from recent conversation history"""
        if len(self.conversation_history) < 2:
            return ""
        
        # Get last few exchanges for context
        recent = self.conversation_history[-4:] if len(self.conversation_history) >= 4 else self.conversation_history
        context = "Recent conversation context:\n"
        for msg in recent:
            role = "You" if msg['role'] == "user" else "Assistant"
            context += f"- {role}: {msg['message'][:100]}...\n"
        return context
    
    def _assess_sophistication(self, text: str) -> str:
        """Assess the sophistication level of the query"""
        advanced_terms = ['CVE', 'CVSS', 'exploit chain', 'privilege escalation', 
                         'zero-day', 'kernel', 'shellcode', 'ROP', 'ASLR', 'DEP']
        
        count = sum(1 for term in advanced_terms if term.lower() in text.lower())
        
        if count >= 3:
            self.expertise_level = "advanced"
            return "advanced"
        elif count >= 1:
            self.expertise_level = "intermediate"
            return "intermediate"
        else:
            self.expertise_level = "beginner"
            return "beginner"
    
    def _add_intelligent_followups(self, response: str, query_type: str) -> str:
        """Add intelligent follow-up questions to responses"""
        followups = {
            'vulnerability': [
                "Would you like to know about mitigation strategies for this vulnerability?",
                "Are you interested in real-world exploitation techniques?",
                "Do you want to understand the underlying root cause?"
            ],
            'exploit': [
                "Would you like to learn about detection methods?",
                "Are you interested in defensive countermeasures?",
                "Do you want to understand the underlying vulnerability?"
            ],
            'technique': [
                "Would you like to learn about evasion techniques?",
                "Are you interested in defensive detection methods?",
                "Do you want advanced variations of this technique?"
            ],
            'defense': [
                "Would you like specific implementation guidance?",
                "Are you interested in deployment best practices?",
                "Do you want to learn about related defense techniques?"
            ],
            'general': [
                "Would you like me to go deeper into any specific aspect?",
                "Are you interested in related topics?",
                "Do you want more technical details?"
            ]
        }
        
        questions = followups.get(query_type, followups['general'])
        import random
        followup = "\n\n**💡 Follow-up:** " + random.choice(questions)
        return response + followup
    
    def _respond_vulnerability(self, query: str, context: str, mood: str, conv_context: str = "") -> str:
        """Generate response about vulnerabilities"""
        
        # Extract vulnerability type
        vuln_type = self._extract_topic(query)
        
        response = f"**{vuln_type.title()} Vulnerability Analysis**\n\n"
        
        # Add conversation context if available
        if conv_context and self.expertise_level == "advanced":
            response += f"{conv_context}\n\n"
        
        # Add knowledge from database
        if context:
            response += f"**From Knowledge Base:**\n{context}\n\n"
        
        # Provide analysis based on detected type
        if "sql" in query.lower() and "injection" in query.lower():
            response += """**What is SQL Injection?**

SQL Injection is a code injection attack where attackers insert malicious SQL statements into input fields. This allows them to:
- Extract sensitive data from the database
- Modify or delete database records
- Potentially execute commands on the database server

**How It Works:**
1. Attacker finds an input field that connects to a database query
2. Instead of normal input, attacker enters: `' OR '1'='1`
3. The SQL query becomes: `SELECT * FROM users WHERE username = '' OR '1'='1'`
4. Since '1'='1' is always true, all records are returned

**Countermeasures:**
- Use parameterized queries (prepared statements)
- Implement input validation and sanitization
- Apply the principle of least privilege to database accounts
- Use Web Application Firewalls (WAF)
- Implement error handling that doesn't expose database details"""
        
        elif "xss" in query.lower() or "cross-site" in query.lower():
            response += """**What is Cross-Site Scripting (XSS)?**

XSS is a client-side vulnerability where attackers inject malicious scripts into web pages viewed by other users.

**Types:**
- Stored XSS: Malicious code stored in database
- Reflected XSS: Malicious code in URL parameters
- DOM-based XSS: JavaScript code manipulates page structure

**Impact:**
- Steal session cookies
- Perform actions on behalf of users
- Deface websites
- Distribute malware

**Prevention:**
- HTML encode all user input
- Use Content Security Policy (CSP) headers
- Validate and sanitize input
- Use secure templates
- Implement httpOnly cookies"""
        
        else:
            response += f"""**About {vuln_type}:**

This is a security weakness that can be exploited to compromise systems. Analysis requires understanding:
1. Attack vector: How the vulnerability is triggered
2. Impact: What damage can occur
3. Likelihood: How easy it is to exploit
4. Remediation: How to fix it

Looking up detailed information from security databases...
""" + (context if context else "No specific database entries found. Recommend checking CVE databases for detailed information.")
        
        return response[:self.max_response_length]
    
    def _respond_exploit(self, query: str, context: str, mood: str, conv_context: str = "") -> str:
        """Generate response about exploits"""
        
        response = "**Exploit Analysis**\n\n"
        
        # Adjust depth based on expertise level
        if self.expertise_level == "advanced":
            response += "*(Advanced Analysis - Deep technical breakdown)*\n\n"
        
        if context:
            response += f"**Known Exploits:**\n{context}\n\n"
        
        response += """An exploit is a piece of code or technique that takes advantage of a vulnerability.

**Exploit Components:**
1. **Vulnerability**: The weakness being exploited
2. **Payload**: The code/action that runs after exploitation
3. **Delivery**: How the exploit reaches the target
4. **Execution**: How the payload executes

**Proof of Concept (PoC):**
A PoC demonstrates that a vulnerability can be exploited but typically doesn't cause real damage.

**Responsible Disclosure:**
- Do NOT use exploits without authorization
- Report vulnerabilities privately to vendors
- Allow time for patching before public disclosure
- Follow coordinated vulnerability disclosure practices"""
        
        return response[:self.max_response_length]
    
    def _respond_technique(self, query: str, context: str, mood: str, conv_context: str = "") -> str:
        """Generate response about techniques"""
        
        response = "**Pentesting Technique Analysis**\n\n"
        
        if context:
            response += f"**Relevant Techniques:**\n{context}\n\n"
        elif self.expertise_level == "advanced":
            response += "*Providing advanced technique guidance based on your expertise level.*\n\n"
        
        response += """Penetration testing techniques are structured methods for finding and exploiting vulnerabilities in systems.

**Common Phases:**
1. **Reconnaissance**: Gather information about target
2. **Scanning**: Identify open ports and services
3. **Enumeration**: Detailed probing of discovered services
4. **Vulnerability Analysis**: Identify weaknesses
5. **Exploitation**: Attempt to exploit vulnerabilities
6. **Post-Exploitation**: Maintain access and extract data
7. **Reporting**: Document findings and recommendations

**Important**: Only conduct penetration testing on systems you have authorization to test. Unauthorized access is illegal."""
        
        return response[:self.max_response_length]
    
    def _respond_defense(self, query: str, context: str, mood: str, conv_context: str = "") -> str:
        """Generate response about defenses"""
        
        response = "**Security Defense Strategy**\n\n"
        
        if context:
            response += f"**Relevant Defenses:**\n{context}\n\n"
        elif self.expertise_level == "advanced":
            response += "*Advanced defensive strategies for expert practitioners.*\n\n"
        
        response += """Implementing effective defenses requires a multi-layered approach:

**Defense in Depth Layers:**
1. **Perimeter Security**: Firewalls, WAF, IDS/IPS
2. **Network Security**: VLANs, network segmentation, DLP
3. **Host Security**: Endpoint protection, hardening
4. **Application Security**: Secure coding, input validation, authentication
5. **Data Protection**: Encryption at rest and in transit
6. **Access Control**: Principle of least privilege, RBAC
7. **Monitoring**: Logging, alerting, security monitoring
8. **Incident Response**: Detection, containment, recovery

**Best Practices:**
- Keep systems patched and updated
- Implement strong authentication (MFA)
- Regular security assessments
- Security awareness training
- Incident response planning"""
        
        return response[:self.max_response_length]
    
    def _respond_general_security(self, query: str, context: str, mood: str, conv_context: str = "") -> str:
        """Generate response about general security topics"""
        
        response = "**Security Overview**\n\n"
        
        if context:
            response += f"**Related Information:**\n{context}\n\n"
        elif self.expertise_level == "advanced":
            response += "*Detailed technical overview for advanced users.*\n\n"
        
        response += """Cybersecurity is the practice of protecting systems and networks from unauthorized access and attacks.

**Key Principles:**
- Confidentiality: Only authorized people can access data
- Integrity: Data cannot be modified without authorization
- Availability: Systems remain operational and accessible

**Security Domains:**
- Network Security
- Application Security
- Cloud Security
- Identity & Access Management
- Data Protection
- Incident Response
- Threat Intelligence
- Compliance & Governance

**Stay Informed:**
- Follow security news and advisories
- Participate in security communities
- Conduct regular training
- Share knowledge responsibly"""
        
        return response[:self.max_response_length]
    
    def _respond_general(self, query: str, mood: str, conv_context: str = "") -> str:
        """Generate general response with context awareness"""
        
        mood_responses = {
            'curious': "That's an interesting question. Let me analyze that for you...",
            'optimistic': "Great question! Here's what I can tell you...",
            'analytical': "Based on the information available...",
            'neutral': "Regarding your question...",
        }
        
        prefix = mood_responses.get(mood, mood_responses['neutral'])
        
        # Try to find related security topics from the query
        security_keywords = self._extract_security_keywords(query)
        suggestion = ""
        if security_keywords:
            suggestion = f"\n\nBased on your query, you might be interested in: {', '.join(security_keywords[:3])}"
        
        response = f"{prefix}\n\nUnfortunately, I don't have specific knowledge about this topic in my current database. However, you could:\n\n1. Provide more details or keywords\n2. Ask about related security topics\n3. Specify what you'd like to learn about\n\nI'm best at discussing security vulnerabilities, exploits, techniques, and defenses.{suggestion}"
        
        return response
    
    def _extract_security_keywords(self, text: str) -> List[str]:
        """Extract security-related keywords from query"""
        security_terms = [
            'SQL Injection', 'XSS', 'CSRF', 'RCE', 'Authentication',
            'Encryption', 'Firewall', 'IDS/IPS', 'Malware', 'Ransomware'
        ]
        
        found_terms = []
        text_lower = text.lower()
        for term in security_terms:
            if term.lower() in text_lower:
                found_terms.append(term)
        
        return found_terms
    
    def _extract_topic(self, text: str) -> str:
        """Extract main topic from query"""
        # Look for common security terms
        security_terms = [
            'sql injection', 'xss', 'cross-site scripting', 'csrf',
            'authentication', 'authorization', 'encryption', 'firewall',
            'buffer overflow', 'privilege escalation', 'dos', 'ddos',
            'ransomware', 'malware', 'trojan', 'virus', 'worm'
        ]
        
        text_lower = text.lower()
        for term in security_terms:
            if term in text_lower:
                return term
        
        # Extract first noun-like word
        words = re.findall(r'\b[A-Z][a-z]+\b', text)
        return words[0] if words else "Security Topic"
    
    def set_expertise_level(self, level: str) -> None:
        """Manually set the expertise level (beginner, intermediate, advanced)"""
        valid_levels = ["beginner", "intermediate", "advanced"]
        if level in valid_levels:
            self.expertise_level = level
    
    def get_conversation_summary(self) -> str:
        """Get a summary of the conversation"""
        if not self.conversation_history:
            return "No conversation history yet."
        
        summary = f"Conversation Summary ({len(self.conversation_history)} messages):\n"
        summary += f"Expertise Level: {self.expertise_level.upper()}\n"
        summary += f"Last Exchange:\n"
        
        for msg in self.conversation_history[-2:]:
            role = "User" if msg['role'] == "user" else "Assistant"
            summary += f"- {role}: {msg['message'][:75]}...\n"
        
        return summary
    
    def clear_history(self) -> None:
        """Clear conversation history"""
        self.conversation_history = []
        self.context_stack = []
    
    def close(self):
        """Clean up resources"""
        if self.lookup:
            self.lookup.close()


# Example usage
if __name__ == "__main__":
    ai = LocalAIResponse(use_knowledge_db=True)
    
    # Test vulnerability query
    response = ai.generate("explain sql injection attacks", mood="curious")
    print("Response to 'explain sql injection attacks':")
    print(response)
    print("\n" + "="*80 + "\n")
    
    # Test defense query
    response = ai.generate("how do I prevent XSS vulnerabilities", mood="neutral")
    print("Response to 'how do I prevent XSS vulnerabilities':")
    print(response)
    
    ai.close()
