"""
Unified Attack Vectors & Threat Simulations Engine
Ties attack vectors to threat scenarios for comprehensive pentesting training
"""

import json
from enum import Enum
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime


class AttackPhase(Enum):
    """MITRE ATT&CK Framework phases"""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_CONTROL = "Command & Control"
    ACTIONS = "Actions on Objectives"


class VulnerabilityType(Enum):
    """CWE-based vulnerability categories"""
    INJECTION = "CWE-89 Injection"
    BROKEN_AUTH = "CWE-287 Broken Authentication"
    SENSITIVE_DATA = "CWE-200 Sensitive Data Exposure"
    XML_EXTERNAL = "CWE-611 XML External Entity"
    BROKEN_ACCESS = "CWE-284 Broken Access Control"
    CSRF = "CWE-352 CSRF"
    INSECURE_DESERIAL = "CWE-502 Deserialization"
    INSUFFICIENT_LOGGING = "CWE-778 Insufficient Logging"
    COMMAND_INJECTION = "CWE-78 Command Injection"
    SSRF = "CWE-918 SSRF"


@dataclass
class AttackVector:
    """Represents a single attack vector"""
    name: str
    vector_id: str
    description: str
    vuln_type: VulnerabilityType
    phase: AttackPhase
    tools: List[str]
    payloads: List[str]
    cve_refs: List[str]
    difficulty: str  # Easy, Medium, Hard, Expert
    detection_signals: List[str]
    mitigation: List[str]
    references: List[str]
    
    def to_dict(self):
        return {
            'name': self.name,
            'vector_id': self.vector_id,
            'description': self.description,
            'vuln_type': self.vuln_type.value,
            'phase': self.phase.value,
            'tools': self.tools,
            'payloads': self.payloads,
            'cve_refs': self.cve_refs,
            'difficulty': self.difficulty,
            'detection_signals': self.detection_signals,
            'mitigation': self.mitigation,
            'references': self.references,
        }


@dataclass
class ThreatScenario:
    """Represents a threat scenario combining multiple attack vectors"""
    name: str
    scenario_id: str
    description: str
    target_type: str  # Web App, Network, Endpoint, Cloud
    severity: str  # Low, Medium, High, Critical
    attack_vectors: List[str]  # Vector IDs
    attack_chain: List[Tuple[str, str]]  # (phase, vector_id)
    difficulty: str
    estimated_time: int  # minutes
    learning_objectives: List[str]
    success_criteria: List[str]
    references: List[str]
    
    def to_dict(self):
        return {
            'name': self.name,
            'scenario_id': self.scenario_id,
            'description': self.description,
            'target_type': self.target_type,
            'severity': self.severity,
            'attack_vectors': self.attack_vectors,
            'attack_chain': self.attack_chain,
            'difficulty': self.difficulty,
            'estimated_time': self.estimated_time,
            'learning_objectives': self.learning_objectives,
            'success_criteria': self.success_criteria,
            'references': self.references,
        }


class AttackVectorsCatalog:
    """Comprehensive catalog of attack vectors"""
    
    VECTORS = {
        'sql_injection': AttackVector(
            name='SQL Injection',
            vector_id='sql_injection',
            description='Inject malicious SQL code into user input fields to manipulate database queries',
            vuln_type=VulnerabilityType.INJECTION,
            phase=AttackPhase.EXPLOITATION,
            tools=['sqlmap', 'burp_suite', 'curl'],
            payloads=[
                "' OR '1'='1",
                "'; DROP TABLE users--",
                "' UNION SELECT NULL, NULL--",
                "admin'--",
            ],
            cve_refs=['CVE-2019-9193', 'CVE-2019-2725'],
            difficulty='Easy',
            detection_signals=[
                'SQL syntax errors in responses',
                'Unusual query behavior',
                'Database error messages',
                'Time-based delays in responses',
                'Boolean-based results',
            ],
            mitigation=[
                'Use parameterized queries/prepared statements',
                'Input validation and sanitization',
                'Principle of least privilege for DB users',
                'Web Application Firewall (WAF)',
                'Regular security testing',
            ],
            references=[
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://portswigger.net/web-security/sql-injection',
            ]
        ),
        'xss_reflected': AttackVector(
            name='Reflected XSS',
            vector_id='xss_reflected',
            description='Inject JavaScript into search/input fields that execute in victim browser',
            vuln_type=VulnerabilityType.INJECTION,
            phase=AttackPhase.EXPLOITATION,
            tools=['burp_suite', 'curl', 'browser_dev_tools'],
            payloads=[
                '<script>alert(1)</script>',
                '<img src=x onerror="alert(1)">',
                'javascript:alert(1)',
                '<svg onload=alert(1)>',
            ],
            cve_refs=['CVE-2020-5902', 'CVE-2019-8943'],
            difficulty='Easy',
            detection_signals=[
                'User input reflected in response',
                'Lack of output encoding',
                'Browser console errors',
                'Cookie exfiltration attempts',
            ],
            mitigation=[
                'Output encoding (HTML, JavaScript, URL)',
                'Content Security Policy (CSP)',
                'Input validation',
                'HTTPOnly cookie flag',
                'Regular security audits',
            ],
            references=[
                'https://owasp.org/www-community/attacks/xss/',
                'https://portswigger.net/web-security/cross-site-scripting',
            ]
        ),
        'broken_authentication': AttackVector(
            name='Broken Authentication',
            vector_id='broken_authentication',
            description='Exploit weak authentication mechanisms to bypass login or forge tokens',
            vuln_type=VulnerabilityType.BROKEN_AUTH,
            phase=AttackPhase.EXPLOITATION,
            tools=['jwt_tool', 'hashcat', 'burp_suite'],
            payloads=[
                'admin:password',
                'jwt_alg_none_bypass',
                'jwt_signature_bypass',
                'session_fixation_attack',
            ],
            cve_refs=['CVE-2015-9235', 'CVE-2016-5696'],
            difficulty='Medium',
            detection_signals=[
                'Weak password policies',
                'Predictable session tokens',
                'JWT with "alg":"none"',
                'Lack of rate limiting',
                'No account lockout',
            ],
            mitigation=[
                'Implement strong password policies',
                'Multi-factor authentication',
                'Secure session management',
                'JWT signature validation',
                'Account lockout mechanisms',
            ],
            references=[
                'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication',
                'https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures',
            ]
        ),
        'ssrf': AttackVector(
            name='Server-Side Request Forgery',
            vector_id='ssrf',
            description='Make server issue requests to internal/external systems on your behalf',
            vuln_type=VulnerabilityType.SSRF,
            phase=AttackPhase.EXPLOITATION,
            tools=['curl', 'burp_suite', 'aws_cli'],
            payloads=[
                'http://localhost:8080',
                'http://169.254.169.254/latest/meta-data/',
                'file:///etc/passwd',
                'gopher://internal_service:9000',
            ],
            cve_refs=['CVE-2019-9193', 'CVE-2020-5902'],
            difficulty='Medium',
            detection_signals=[
                'Requests to internal IPs',
                'Unusual outbound connections',
                'AWS metadata access',
                'File:// protocol usage',
            ],
            mitigation=[
                'Input validation and URL parsing',
                'Deny-list internal IP ranges',
                'Disable unnecessary protocols',
                'Network segmentation',
                'Rate limiting',
            ],
            references=[
                'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                'https://portswigger.net/web-security/ssrf',
            ]
        ),
        'rce_file_upload': AttackVector(
            name='Remote Code Execution via File Upload',
            vector_id='rce_file_upload',
            description='Upload executable files to trigger remote code execution',
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            phase=AttackPhase.EXPLOITATION,
            tools=['burp_suite', 'curl', 'php_shell_generators'],
            payloads=[
                '<?php system($_GET["cmd"]); ?>',
                'shell.php.jpg (double extension)',
                'shell.php%00.jpg (null byte)',
                '.htaccess override',
            ],
            cve_refs=['CVE-2018-9995', 'CVE-2019-0604'],
            difficulty='Medium',
            detection_signals=[
                'Executable file uploads',
                'Missing file type validation',
                'Uploaded files accessible',
                'Web shell execution',
            ],
            mitigation=[
                'File type validation (magic bytes)',
                'Store uploads outside webroot',
                'Disable script execution in upload dir',
                'Randomize filenames',
                'Antivirus scanning',
            ],
            references=[
                'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
                'https://portswigger.net/web-security/file-upload',
            ]
        ),
        'privilege_escalation': AttackVector(
            name='Linux Privilege Escalation',
            vector_id='privilege_escalation',
            description='Exploit SUID binaries, sudo misconfig, or kernel vulnerabilities',
            vuln_type=VulnerabilityType.BROKEN_ACCESS,
            phase=AttackPhase.EXPLOITATION,
            tools=['LinPEAS', 'GTFObins', 'kernel_exploits'],
            payloads=[
                'sudo -l /usr/bin/find',
                'find . -exec /bin/bash \; -quit',
                'capability cap_setuid+ep /usr/bin/python',
                'LD_PRELOAD exploit',
            ],
            cve_refs=['CVE-2021-4034', 'CVE-2021-22555'],
            difficulty='Hard',
            detection_signals=[
                'SUID binaries with exploitable functions',
                'Weak sudo configuration',
                'Outdated kernel',
                'World-writable system files',
            ],
            mitigation=[
                'Remove unnecessary SUID binaries',
                'Minimize sudo usage',
                'Keep system updated',
                'Remove world-writable files',
                'Use AppArmor/SELinux',
            ],
            references=[
                'https://gtfobins.github.io/',
                'https://github.com/carlospolop/PEASS-ng',
            ]
        ),
        'lateral_movement': AttackVector(
            name='Lateral Movement',
            vector_id='lateral_movement',
            description='Use compromised account to pivot through network',
            vuln_type=VulnerabilityType.BROKEN_ACCESS,
            phase=AttackPhase.COMMAND_CONTROL,
            tools=['nmap', 'mimikatz', 'psexec', 'wmic'],
            payloads=[
                'pass_the_hash',
                'kerberoasting',
                'golden_ticket',
                'dcsync',
            ],
            cve_refs=['CVE-2014-6324', 'CVE-2019-1040'],
            difficulty='Hard',
            detection_signals=[
                'Lateral RDP/SSH connections',
                'Credential reuse across systems',
                'Admin share access',
                'Kerberos ticket abuse',
            ],
            mitigation=[
                'Network segmentation',
                'Least privilege principle',
                'Monitor lateral movement',
                'Disable admin shares',
                'Use MFA',
            ],
            references=[
                'https://attack.mitre.org/tactics/TA0008/',
                'https://posts.specterops.io/hiding-in-plain-sight-f6e46c4c2c09',
            ]
        ),
    }


class ThreatScenariosCatalog:
    """Comprehensive catalog of threat scenarios"""
    
    SCENARIOS = {
        'ecommerce_breach': ThreatScenario(
            name='E-Commerce Platform Breach',
            scenario_id='ecommerce_breach',
            description='Complete compromise of an e-commerce platform to exfiltrate customer data',
            target_type='Web Application',
            severity='Critical',
            attack_vectors=['sql_injection', 'xss_reflected', 'rce_file_upload'],
            attack_chain=[
                (AttackPhase.RECONNAISSANCE.value, 'sql_injection'),
                (AttackPhase.EXPLOITATION.value, 'sql_injection'),
                (AttackPhase.EXPLOITATION.value, 'xss_reflected'),
                (AttackPhase.EXPLOITATION.value, 'rce_file_upload'),
                (AttackPhase.ACTIONS.value, 'lateral_movement'),
            ],
            difficulty='Hard',
            estimated_time=60,
            learning_objectives=[
                'Understand SQL injection exploitation chains',
                'Learn XSS-based credential stealing',
                'Master file upload RCE',
                'Recognize data exfiltration methods',
            ],
            success_criteria=[
                'Extract customer database',
                'Achieve remote code execution',
                'Access sensitive files',
                'Exfiltrate payment information',
            ],
            references=[
                'https://attack.mitre.org/groups/G0079/',
                'https://www.mandiant.com/resources/insights',
            ]
        ),
        'internal_network_takeover': ThreatScenario(
            name='Internal Network Takeover',
            scenario_id='internal_network_takeover',
            description='Lateral movement through corporate network to domain controller',
            target_type='Network',
            severity='Critical',
            attack_vectors=['broken_authentication', 'privilege_escalation', 'lateral_movement'],
            attack_chain=[
                (AttackPhase.EXPLOITATION.value, 'broken_authentication'),
                (AttackPhase.EXPLOITATION.value, 'privilege_escalation'),
                (AttackPhase.COMMAND_CONTROL.value, 'lateral_movement'),
                (AttackPhase.ACTIONS.value, 'lateral_movement'),
            ],
            difficulty='Expert',
            estimated_time=90,
            learning_objectives=[
                'Compromise initial account',
                'Escalate privileges on workstation',
                'Pivot to domain resources',
                'Achieve domain admin access',
            ],
            success_criteria=[
                'Extract domain admin credentials',
                'Create golden ticket',
                'Compromise domain controller',
                'Maintain persistent access',
            ],
            references=[
                'https://attack.mitre.org/tactics/TA0008/',
                'https://harmj0y.medium.com/',
            ]
        ),
        'cloud_metadata_breach': ThreatScenario(
            name='Cloud Metadata & Credentials Theft',
            scenario_id='cloud_metadata_breach',
            description='SSRF attack to extract AWS credentials from metadata service',
            target_type='Cloud Application',
            severity='Critical',
            attack_vectors=['ssrf', 'broken_authentication'],
            attack_chain=[
                (AttackPhase.RECONNAISSANCE.value, 'ssrf'),
                (AttackPhase.EXPLOITATION.value, 'ssrf'),
                (AttackPhase.ACTIONS.value, 'lateral_movement'),
            ],
            difficulty='Medium',
            estimated_time=30,
            learning_objectives=[
                'Identify SSRF vulnerabilities',
                'Access metadata endpoints',
                'Extract AWS credentials',
                'Use stolen credentials',
            ],
            success_criteria=[
                'Access metadata endpoint',
                'Extract temporary credentials',
                'List S3 buckets',
                'Access sensitive data',
            ],
            references=[
                'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
                'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
            ]
        ),
    }


class AttackVectorEngine:
    """Unified engine for attack vectors and threat scenarios"""
    
    def __init__(self):
        self.vectors = AttackVectorsCatalog.VECTORS
        self.scenarios = ThreatScenariosCatalog.SCENARIOS
        self.execution_log = []
    
    def get_vector(self, vector_id: str) -> Optional[AttackVector]:
        """Get attack vector by ID"""
        return self.vectors.get(vector_id)
    
    def get_scenario(self, scenario_id: str) -> Optional[ThreatScenario]:
        """Get threat scenario by ID"""
        return self.scenarios.get(scenario_id)
    
    def get_scenario_vectors(self, scenario_id: str) -> List[AttackVector]:
        """Get all attack vectors for a scenario"""
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            return []
        
        return [self.get_vector(vid) for vid in scenario.attack_vectors 
                if self.get_vector(vid)]
    
    def get_scenario_chain(self, scenario_id: str) -> List[Dict]:
        """Get attack chain for a scenario with details"""
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            return []
        
        chain = []
        for phase, vector_id in scenario.attack_chain:
            vector = self.get_vector(vector_id)
            if vector:
                chain.append({
                    'phase': phase,
                    'vector': vector.to_dict(),
                    'sequence_step': len(chain) + 1,
                })
        
        return chain
    
    def find_vectors_by_vuln_type(self, vuln_type: VulnerabilityType) -> List[AttackVector]:
        """Find all vectors for a vulnerability type"""
        return [v for v in self.vectors.values() if v.vuln_type == vuln_type]
    
    def find_vectors_by_phase(self, phase: AttackPhase) -> List[AttackVector]:
        """Find all vectors for an attack phase"""
        return [v for v in self.vectors.values() if v.phase == phase]
    
    def find_vectors_by_difficulty(self, difficulty: str) -> List[AttackVector]:
        """Find vectors by difficulty level"""
        return [v for v in self.vectors.values() if v.difficulty == difficulty]
    
    def find_scenarios_by_severity(self, severity: str) -> List[ThreatScenario]:
        """Find scenarios by severity"""
        return [s for s in self.scenarios.values() if s.severity == severity]
    
    def log_execution(self, scenario_id: str, vector_id: str, success: bool, 
                     payload: str, result: str):
        """Log attack execution for training"""
        self.execution_log.append({
            'timestamp': datetime.now().isoformat(),
            'scenario': scenario_id,
            'vector': vector_id,
            'success': success,
            'payload': payload,
            'result': result,
        })
    
    def get_related_scenarios(self, vector_id: str) -> List[ThreatScenario]:
        """Find scenarios that use a specific attack vector"""
        return [s for s in self.scenarios.values() if vector_id in s.attack_vectors]
    
    def export_catalog(self) -> Dict:
        """Export complete catalog as JSON"""
        return {
            'vectors': {vid: v.to_dict() for vid, v in self.vectors.items()},
            'scenarios': {sid: s.to_dict() for sid, s in self.scenarios.items()},
            'exported_at': datetime.now().isoformat(),
        }
    
    def get_learning_path(self, target_difficulty: str) -> List[Dict]:
        """Generate progressive learning path"""
        scenarios = [s for s in self.scenarios.values() 
                    if s.difficulty == target_difficulty]
        
        path = []
        for scenario in sorted(scenarios, key=lambda x: x.estimated_time):
            vectors = self.get_scenario_vectors(scenario.scenario_id)
            path.append({
                'scenario': scenario.to_dict(),
                'vectors': [v.to_dict() for v in vectors],
                'progression': len(path) + 1,
            })
        
        return path
