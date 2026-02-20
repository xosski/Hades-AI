"""
Credibility Enforcement Layer
Fixes:
1. Confidence/Status alignment
2. Proof requirements (error messages, stack traces, behavioral evidence)
3. Scope filtering (block non-target domains, whitelist)
4. CVE detection (framework detection + payload echo/execution)
5. Status accuracy (Confirmed vs Suspected mapping)
"""

import logging
import re
from typing import Dict, List, Tuple, Optional
from enum import Enum
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger("ValidationEnforcement")


class VulnerabilityStatus(Enum):
    """Proper status classification based on confidence"""
    SUSPECTED = "Suspected"  # 0.0-0.4 confidence
    LIKELY = "Likely"  # 0.4-0.7 confidence
    CONFIRMED = "Confirmed"  # 0.7-1.0 confidence with real proof


@dataclass
class ProofRequirement:
    """Proof requirement for a vulnerability type"""
    vuln_type: str
    required_proof_types: List[str]
    min_confidence: float
    allows_status: str  # Only this status or lower


class ScopeValidator:
    """Validates that scan targets are actually in scope"""
    
    BLOCKED_DOMAINS = {
        'hackerone.com',
        'bugcrowd.com',
        'intigriti.com',
        'yeswehack.com',
        'synack.com',
        'zerocopter.nl',
        'safehats.com',
        'securitypage.com',
        'cobalt.io',
        'federacy.com',
        'vulneralabs.com',
        'bountypay.h4ck.me',
        'register.bountypay.h4ck.me',
        'github.com',
        'google.com',
        'microsoft.com',
        'amazon.com',
        'apple.com',
        'facebook.com',
        'twitter.com',
        'linkedin.com',
    }
    
    def __init__(self, allowed_targets: Optional[List[str]] = None):
        """
        Initialize scope validator.
        
        Args:
            allowed_targets: List of domains/IPs that are in scope
        """
        self.allowed_targets = set(allowed_targets or [])
        self.blocked_domains = self.BLOCKED_DOMAINS.copy()
    
    def is_in_scope(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL is in scope.
        
        Returns:
            (is_in_scope, reason)
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Check explicitly blocked domains
        if domain in self.blocked_domains:
            return False, f"Domain {domain} is a bug bounty platform (blocked)"
        
        # Check if on whitelist
        if self.allowed_targets:
            for target in self.allowed_targets:
                if domain == target or domain.endswith(f".{target}"):
                    return True, "In scope whitelist"
            return False, f"Domain {domain} not in whitelist"
        
        # If no whitelist, only check blocklist
        return True, "Not explicitly blocked"
    
    def add_allowed_target(self, domain: str):
        """Add domain to allowed list"""
        self.allowed_targets.add(domain.lower())
    
    def add_blocked_domain(self, domain: str):
        """Add domain to blocked list"""
        self.blocked_domains.add(domain.lower())


class ProofValidator:
    """Validates that vulnerabilities have actual proof"""
    
    # Real proof patterns for each vulnerability type
    PROOF_PATTERNS = {
        'sql_injection': {
            'database_errors': [
                r'SQLSTATE\[',  # PostgreSQL
                r'ORA-\d{5}',  # Oracle
                r'MySQL Error \d+',
                r'MSSQL Error',
                r'sqlite3\.OperationalError',
                r"SQL syntax error",
                r"you have an error in your sql syntax",
                r'constraint violation',
            ],
            'payload_echo': [
                # Only valid if payload appears in SQL context
                r"SELECT.*'[^']*'",
                r"WHERE.*'[^']*'",
            ],
            'time_delay': [
                # Response time increased significantly
            ]
        },
        'xss': {
            'payload_reflected': [
                # Payload must be unescaped in HTML context
            ],
            'javascript_execution': [
                r'<script[^>]*>',
                r'on\w+\s*=',
            ],
            'dom_change': [],
        },
        'path_traversal': {
            'file_content': [
                r'root:[^:]*:0:0:',  # /etc/passwd
                r'root:.*:.*:.*:',
                r'\[fonts\]',  # win.ini
                r'\[drivers\]',
                r'-----BEGIN PRIVATE KEY-----',  # SSH keys
            ],
        },
        'authentication_bypass': {
            'protected_content_access': [
                # Must find content unique to authenticated users
            ],
            'session_manipulation': [],
        },
        'rce': {
            'command_execution': [
                r'uid=\d+',  # `id` command output
                r'gid=\d+',
                r'bin/bash',
                r'C:\\Windows',
            ],
            'log_shell': [
                # Payload echo in logs, code execution path
            ],
        },
        'cvss_info_disclosure': {
            'version_detection': [
                # Must detect actual framework/version
            ],
            'error_stack': [
                r'Traceback.*File',  # Python
                r'at .*:\d+:\d+',  # JavaScript
                r'at \w+\.\w+\(',  # Java
            ],
        }
    }
    
    @staticmethod
    def validate_sql_injection(response_text: str, payload: str, 
                              status_code: int, baseline_response: str) -> Tuple[bool, float, str]:
        """
        Validate SQL injection with actual proof.
        
        Returns:
            (is_valid, confidence, proof_summary)
        """
        response_lower = response_text.lower()
        baseline_lower = baseline_response.lower()
        
        # Check 1: Database error message
        for error_pattern in ProofValidator.PROOF_PATTERNS['sql_injection']['database_errors']:
            if re.search(error_pattern, response_text, re.IGNORECASE):
                # Verify error appears ONLY in attack response, not baseline
                if not re.search(error_pattern, baseline_response, re.IGNORECASE):
                    return True, 0.95, f"Database error message detected: {error_pattern}"
        
        # Check 2: Payload echo (but only if in SQL context)
        # This is RISKY - only if we see clear SQL syntax
        if payload in response_text:
            # Find context around payload
            idx = response_text.find(payload)
            context = response_text[max(0, idx-50):idx+len(payload)+50]
            
            # Check if payload is in SQL statement
            sql_keywords = ['SELECT', 'WHERE', 'FROM', 'INSERT', 'UPDATE', 'DELETE']
            if any(kw in context.upper() for kw in sql_keywords):
                # Verify baseline doesn't have payload
                if payload not in baseline_response:
                    return True, 0.85, f"Payload echoed in SQL context: {context[:100]}"
        
        # Check 3: Response delta (weak proof, only if error + delta)
        if len(response_text) != len(baseline_response) and abs(len(response_text) - len(baseline_response)) > 100:
            # Response changed significantly
            for error_pattern in ProofValidator.PROOF_PATTERNS['sql_injection']['database_errors']:
                if re.search(error_pattern, response_text, re.IGNORECASE):
                    return True, 0.80, "Significant response delta + error message"
        
        return False, 0.0, "No valid SQL injection proof found"
    
    @staticmethod
    def validate_xss(response_text: str, payload: str, 
                     baseline_response: str) -> Tuple[bool, float, str]:
        """
        Validate XSS with actual proof.
        
        Returns:
            (is_valid, confidence, proof_summary)
        """
        # Check 1: Payload reflected unescaped
        if payload not in response_text:
            return False, 0.0, "Payload not reflected in response"
        
        # Find the reflection
        idx = response_text.find(payload)
        context = response_text[max(0, idx-20):idx+len(payload)+50]
        
        # Check if escaped
        html_entities = ['&lt;', '&gt;', '&#', '%3C', '%3E']
        if any(ent in context for ent in html_entities):
            return False, 0.0, f"Payload is HTML/URL-encoded (safe): {context[:80]}"
        
        # Check if in executable context
        executable_contexts = [
            'href=',
            'src=',
            '<script',
            'onload=',
            'onerror=',
            'onclick=',
            'onmouseover=',
        ]
        
        before_payload = response_text[max(0, idx-100):idx]
        after_payload = response_text[idx+len(payload):idx+len(payload)+100]
        context_full = before_payload + payload + after_payload
        
        for ctx in executable_contexts:
            if ctx.lower() in context_full.lower():
                return True, 0.95, f"Unescaped payload in {ctx} context"
        
        # Payload unescaped but in HTML - still XSS if <> present
        if '<' in payload or '>' in payload:
            return True, 0.85, f"Unescaped HTML payload reflected"
        
        return False, 0.0, "Payload reflected but in safe context"
    
    @staticmethod
    def validate_path_traversal(response_text: str, payload: str) -> Tuple[bool, float, str]:
        """
        Validate path traversal with file content proof.
        
        Returns:
            (is_valid, confidence, proof_summary)
        """
        # Check for passwd file indicators
        passwd_indicators = ['root:', 'bin:', 'daemon:', 'nobody:', 'systemd-', '_apt:']
        passwd_found = sum(1 for ind in passwd_indicators if ind in response_text)
        
        if passwd_found >= 2:
            return True, 0.95, f"Found {passwd_found} /etc/passwd entries"
        
        # Check for Windows file indicators
        windows_indicators = ['[fonts]', '[extensions]', '[drivers]', '[system]']
        windows_found = sum(1 for ind in windows_indicators if ind in response_text)
        
        if windows_found >= 1:
            return True, 0.9, f"Found Windows config file content"
        
        # Check for SSH key
        if '-----BEGIN' in response_text and 'PRIVATE KEY' in response_text:
            return True, 0.95, "Found private key material"
        
        # Check for known file patterns
        if '../' in payload or '..\\' in payload:
            # If we got the file, content should differ from error
            if len(response_text) > 100 and 'not found' not in response_text.lower():
                return True, 0.7, "File traversal path accepted, content returned"
        
        return False, 0.0, "No valid file content detected"
    
    @staticmethod
    def validate_rce(response_text: str, payload: str) -> Tuple[bool, float, str]:
        """
        Validate RCE with actual command execution proof.
        
        Returns:
            (is_valid, confidence, proof_summary)
        """
        # Check for command output
        for cmd_pattern in ProofValidator.PROOF_PATTERNS['rce']['command_execution']:
            if re.search(cmd_pattern, response_text):
                # Verify it's actual command output, not random content
                if 'uid=' in response_text and 'gid=' in response_text:
                    return True, 0.95, "Command execution output detected (`id` command)"
                if 'bin/bash' in response_text:
                    return True, 0.9, "Shell environment detected"
        
        # Check for error from code execution
        error_patterns = ProofValidator.PROOF_PATTERNS['rce']['log_shell']
        for pattern in error_patterns:
            if re.search(pattern, response_text):
                return True, 0.85, "Code execution error detected"
        
        return False, 0.0, "No valid RCE proof found"
    
    @staticmethod
    def validate_cve(response_text: str, payload: str, cve_type: str) -> Tuple[bool, float, str]:
        """
        Validate CVE-specific vulnerabilities.
        
        Requires:
        - Framework/version detection
        - Payload echo in logs or execution path
        - No generic "200 OK" responses
        
        Returns:
            (is_valid, confidence, proof_summary)
        """
        response_lower = response_text.lower()
        
        if cve_type.lower() == 'log4shell':
            # Requires: Log4j detected + JNDI payload echo
            if 'log4j' not in response_lower and 'logging' not in response_lower:
                return False, 0.0, "Log4j not detected in framework identification"
            
            # Check for JNDI payload reflection
            if '${' in response_text and payload in response_text:
                return True, 0.9, "Log4j JNDI payload detected in logs"
            
            return False, 0.0, "Log4j detected but no payload execution proof"
        
        elif cve_type.lower() == 'struts2_rce':
            # Requires: Apache Struts detected + OGNL payload execution
            if 'struts' not in response_lower and 'action' not in response_lower:
                return False, 0.0, "Apache Struts not detected"
            
            if payload in response_text or 'ognl' in response_lower:
                return True, 0.9, "Struts2 RCE payload detected"
            
            return False, 0.0, "Struts detected but no OGNL execution proof"
        
        elif cve_type.lower() == 'spring4shell':
            # Requires: Spring detected + SpEL payload execution
            if 'spring' not in response_lower and 'springframework' not in response_lower:
                return False, 0.0, "Spring Framework not detected"
            
            if payload in response_text:
                return True, 0.9, "Spring4Shell SpEL payload detected"
            
            return False, 0.0, "Spring detected but no SpEL execution proof"
        
        return False, 0.0, f"Unknown CVE type: {cve_type}"


class ConfidenceEnforcer:
    """Enforces confidence/status alignment"""
    
    PROOF_REQUIREMENTS = {
        'sql_injection': {
            'min_confidence': 0.7,
            'required_proof': ['database_error', 'payload_echo', 'response_delta'],
            'allows_status': VulnerabilityStatus.CONFIRMED
        },
        'xss': {
            'min_confidence': 0.7,
            'required_proof': ['payload_reflected_unescaped'],
            'allows_status': VulnerabilityStatus.CONFIRMED
        },
        'path_traversal': {
            'min_confidence': 0.75,
            'required_proof': ['file_content'],
            'allows_status': VulnerabilityStatus.CONFIRMED
        },
        'authentication_bypass': {
            'min_confidence': 0.8,
            'required_proof': ['protected_content_access'],
            'allows_status': VulnerabilityStatus.CONFIRMED
        },
        'rce': {
            'min_confidence': 0.85,
            'required_proof': ['command_execution', 'code_execution'],
            'allows_status': VulnerabilityStatus.CONFIRMED
        },
        'cve_exploit': {
            'min_confidence': 0.9,
            'required_proof': ['version_detection', 'payload_execution'],
            'allows_status': VulnerabilityStatus.CONFIRMED
        },
    }
    
    @staticmethod
    def validate_confidence_status_alignment(vuln_type: str, confidence: float, 
                                           status: str, proof_count: int) -> Tuple[bool, str, str]:
        """
        Validate that confidence and status are aligned.
        
        Returns:
            (is_valid, corrected_status, reason)
        """
        requirement = ConfidenceEnforcer.PROOF_REQUIREMENTS.get(
            vuln_type.lower(), 
            {'min_confidence': 0.7, 'required_proof': ['evidence']}
        )
        
        # Map confidence to proper status
        if confidence < 0.4:
            proper_status = VulnerabilityStatus.SUSPECTED.value
            reason = f"Confidence {confidence:.0%} is too low for '{status}' - should be 'Suspected'"
        elif confidence < 0.7:
            proper_status = VulnerabilityStatus.LIKELY.value
            reason = f"Confidence {confidence:.0%} should be 'Likely' not '{status}'"
        else:
            # High confidence - check if proof is adequate
            if proof_count == 0 and status == "Confirmed":
                proper_status = VulnerabilityStatus.SUSPECTED.value
                reason = f"Status 'Confirmed' requires proof, but found none"
            else:
                proper_status = VulnerabilityStatus.CONFIRMED.value
                reason = f"Confidence {confidence:.0%} + proof warrants 'Confirmed'"
        
        is_valid = proper_status == status
        return is_valid, proper_status, reason
    
    @staticmethod
    def enforce_minimum_proof(vuln_type: str, confidence: float) -> Tuple[bool, str]:
        """
        Check if confidence is high enough for the vulnerability type.
        
        For RCE/CVE: requires 0.85+ confidence
        For SQLi/XSS/LFI: requires 0.7+ confidence
        For generic findings: requires 0.5+ confidence
        
        Returns:
            (meets_minimum, reason)
        """
        requirement = ConfidenceEnforcer.PROOF_REQUIREMENTS.get(vuln_type.lower())
        
        if not requirement:
            min_conf = 0.5
            reason = f"Generic finding: {confidence:.0%} >= {min_conf:.0%} (OK)"
        else:
            min_conf = requirement['min_confidence']
            reason = f"{vuln_type}: {confidence:.0%} >= {min_conf:.0%}"
        
        return confidence >= min_conf, reason


class ComplianceReport:
    """Generates compliance-ready vulnerability reports"""
    
    def __init__(self):
        self.scope_validator = ScopeValidator()
        self.proof_validator = ProofValidator()
        self.confidence_enforcer = ConfidenceEnforcer()
    
    def validate_finding(self, finding: Dict) -> Dict:
        """
        Validate and correct a vulnerability finding.
        
        Returns updated finding with validated status/confidence.
        """
        vuln_type = finding.get('type', 'unknown').lower()
        confidence = finding.get('confidence', 0.0)
        status = finding.get('status', 'Suspected')
        
        # 1. Scope check
        target_url = finding.get('endpoint', '')
        if target_url:
            in_scope, scope_reason = self.scope_validator.is_in_scope(target_url)
            finding['scope_check'] = in_scope
            finding['scope_reason'] = scope_reason
            
            if not in_scope:
                finding['status'] = 'EXCLUDED_OUT_OF_SCOPE'
                return finding
        
        # 2. Proof validation
        proof_count = 0
        proof_details = []
        
        response_text = finding.get('response', '')
        payload = finding.get('payload', '')
        baseline_response = finding.get('baseline_response', '')
        
        if vuln_type == 'sql_injection':
            is_valid, conf, proof = self.proof_validator.validate_sql_injection(
                response_text, payload, 
                finding.get('status_code', 200),
                baseline_response
            )
            if is_valid:
                proof_count += 1
                proof_details.append(proof)
                confidence = max(confidence, conf)
        
        elif vuln_type in ['xss', 'cross-site scripting']:
            is_valid, conf, proof = self.proof_validator.validate_xss(
                response_text, payload, baseline_response
            )
            if is_valid:
                proof_count += 1
                proof_details.append(proof)
                confidence = max(confidence, conf)
        
        elif vuln_type in ['path_traversal', 'lfi']:
            is_valid, conf, proof = self.proof_validator.validate_path_traversal(
                response_text, payload
            )
            if is_valid:
                proof_count += 1
                proof_details.append(proof)
                confidence = max(confidence, conf)
        
        elif vuln_type == 'rce':
            is_valid, conf, proof = self.proof_validator.validate_rce(response_text, payload)
            if is_valid:
                proof_count += 1
                proof_details.append(proof)
                confidence = max(confidence, conf)
        
        # 3. Confidence/Status alignment
        is_aligned, corrected_status, alignment_reason = (
            self.confidence_enforcer.validate_confidence_status_alignment(
                vuln_type, confidence, status, proof_count
            )
        )
        
        # 4. Minimum proof check
        meets_minimum, proof_reason = self.confidence_enforcer.enforce_minimum_proof(
            vuln_type, confidence
        )
        
        # Update finding
        finding['validated_confidence'] = confidence
        finding['validated_status'] = corrected_status
        finding['proof_count'] = proof_count
        finding['proof_details'] = proof_details
        finding['validation_notes'] = {
            'alignment': alignment_reason,
            'proof_requirement': proof_reason,
            'in_scope': in_scope if target_url else True,
        }
        
        if not meets_minimum:
            finding['validation_result'] = 'REJECTED'
            finding['rejection_reason'] = f"Confidence {confidence:.0%} below minimum for {vuln_type}"
        else:
            finding['validation_result'] = 'ACCEPTED'
        
        return finding


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test scope validation
    validator = ScopeValidator(allowed_targets=['example.com', 'target.local'])
    
    print("Scope tests:")
    print(validator.is_in_scope('https://example.com/path'))
    print(validator.is_in_scope('https://hackerone.com/opportunities'))
    print(validator.is_in_scope('https://evil.com'))
    
    # Test proof validation
    bad_proof_response = "HTTP 200 OK<html>Powered by WordPress 5.0</html>"
    payload = "' OR '1'='1"
    
    is_valid, conf, proof = ProofValidator.validate_sql_injection(
        bad_proof_response,
        payload,
        200,
        "<html>Normal response</html>"
    )
    print(f"\nSQL Injection validation: Valid={is_valid}, Confidence={conf:.0%}, Proof={proof}")
    
    # Test confidence enforcement
    is_aligned, status, reason = ConfidenceEnforcer.validate_confidence_status_alignment(
        'sql_injection',
        0.2,
        'Confirmed',
        0
    )
    print(f"\nConfidence alignment: Aligned={is_aligned}, Status={status}, Reason={reason}")
