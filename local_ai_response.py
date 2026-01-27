"""
Local AI Response Generator
Mimics Mistral-like responses without requiring API keys.
Uses knowledge lookup + pattern-based response generation.
"""

import re
from typing import Optional, Dict, List
from knowledge_lookup import KnowledgeLookup


class LocalAIResponse:
    """
    Generate AI-like responses without API keys.
    Combines knowledge lookup with template-based reasoning.
    """
    
    def __init__(self, use_knowledge_db: bool = True):
        self.lookup = KnowledgeLookup() if use_knowledge_db else None
        self.personality = "technical, security-focused, analytical"
        self.max_response_length = 1500
    
    def generate(self, user_input: str, system_prompt: str = "", mood: str = "neutral") -> str:
        """
        Generate response to user input.
        
        Args:
            user_input: User's message
            system_prompt: System context (personality, instructions)
            mood: Current mood (affects tone)
        
        Returns:
            Generated response
        """
        
        # Detect query type
        query_type = self._detect_query_type(user_input)
        
        # Look up relevant knowledge
        knowledge_context = ""
        if self.lookup:
            keywords = self.lookup.extract_keywords(user_input)
            if keywords:
                results = self.lookup.search_all(" ".join(keywords[:3]))
                knowledge_context = self.lookup.format_results_for_ai(results)
        
        # Generate response based on type
        if query_type == "vulnerability":
            return self._respond_vulnerability(user_input, knowledge_context, mood)
        elif query_type == "exploit":
            return self._respond_exploit(user_input, knowledge_context, mood)
        elif query_type == "technique":
            return self._respond_technique(user_input, knowledge_context, mood)
        elif query_type == "defense":
            return self._respond_defense(user_input, knowledge_context, mood)
        elif query_type == "general_security":
            return self._respond_general_security(user_input, knowledge_context, mood)
        else:
            return self._respond_general(user_input, mood)
    
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
    
    def _respond_vulnerability(self, query: str, context: str, mood: str) -> str:
        """Generate response about vulnerabilities"""
        
        # Extract vulnerability type
        vuln_type = self._extract_topic(query)
        
        response = f"**{vuln_type.title()} Vulnerability Analysis**\n\n"
        
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
    
    def _respond_exploit(self, query: str, context: str, mood: str) -> str:
        """Generate response about exploits"""
        
        response = "**Exploit Analysis**\n\n"
        
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
    
    def _respond_technique(self, query: str, context: str, mood: str) -> str:
        """Generate response about techniques"""
        
        response = "**Pentesting Technique Analysis**\n\n"
        
        if context:
            response += f"**Relevant Techniques:**\n{context}\n\n"
        
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
    
    def _respond_defense(self, query: str, context: str, mood: str) -> str:
        """Generate response about defenses"""
        
        response = "**Security Defense Strategy**\n\n"
        
        if context:
            response += f"**Relevant Defenses:**\n{context}\n\n"
        
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
    
    def _respond_general_security(self, query: str, context: str, mood: str) -> str:
        """Generate response about general security topics"""
        
        response = "**Security Overview**\n\n"
        
        if context:
            response += f"**Related Information:**\n{context}\n\n"
        
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
    
    def _respond_general(self, query: str, mood: str) -> str:
        """Generate general response"""
        
        mood_responses = {
            'curious': "That's an interesting question. Let me analyze that for you...",
            'optimistic': "Great question! Here's what I can tell you...",
            'analytical': "Based on the information available...",
            'neutral': "Regarding your question...",
        }
        
        prefix = mood_responses.get(mood, mood_responses['neutral'])
        
        return f"{prefix}\n\nUnfortunately, I don't have specific knowledge about this topic in my current database. However, you could:\n\n1. Provide more details or keywords\n2. Ask about related security topics\n3. Specify what you'd like to learn about\n\nI'm best at discussing security vulnerabilities, exploits, techniques, and defenses."
    
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
