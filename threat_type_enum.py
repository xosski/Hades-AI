"""
Threat Type Enumeration
Standardized threat type classification for consistency across all modules
"""

from enum import Enum
from typing import Dict, Set


class ThreatType(Enum):
    """Standard threat types used throughout the system"""
    
    # Code Injection & Execution
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RCE = "rce"
    CODE_INJECTION = "code_injection"
    COMMAND_INJECTION = "command_injection"
    
    # Authentication & Access
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    
    # Server-Side Issues
    SSRF = "ssrf"
    XXE = "xxe"
    INSECURE_DIRECT_OBJECT_REFERENCE = "idor"
    PATH_TRAVERSAL = "path_traversal"
    
    # Cryptography & Encoding
    WEAK_CRYPTO = "weak_crypto"
    INSECURE_RANDOMNESS = "insecure_randomness"
    PLAIN_TEXT_PASSWORD = "plain_text_password"
    
    # Configuration & Deployment
    MISCONFIGURATION = "misconfiguration"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    INSECURE_DEPENDENCIES = "insecure_dependencies"
    MISSING_SECURITY_HEADERS = "missing_security_headers"
    
    # Network & Protocol
    UNENCRYPTED_COMMUNICATION = "unencrypted_communication"
    INSECURE_DESERIALIZATION_NET = "insecure_deserialization_net"
    
    # Client-Side
    CLIENT_XSS = "client_xss"
    CSRF = "csrf"
    INSECURE_STORAGE = "insecure_storage"
    
    # Advanced
    JWT_BYPASS = "jwt_bypass"
    RACE_CONDITION = "race_condition"
    CACHING_ISSUE = "caching_issue"
    
    # Network & Infrastructure
    OPEN_PORTS = "open_ports"
    BLOCKED_IP = "blocked_ip"
    KNOWN_THREAT = "known_threat"
    SUSPICIOUS_PORT = "suspicious_port"
    OPEN_SENSITIVE_PORT = "open_sensitive_port"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    
    # Behavioral & Anomalies
    HONEYPOT_TRIGGER = "honeypot_trigger"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    RECONNAISSANCE = "reconnaissance"
    
    # Data & Privacy
    DATA_EXFILTRATION = "data_exfiltration"
    DATA_EXPOSURE = "data_exposure"
    PRIVACY_VIOLATION = "privacy_violation"
    
    # Unknown & General
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    COMPOSITE = "composite"
    
    @classmethod
    def from_string(cls, value: str) -> 'ThreatType':
        """Convert string to ThreatType enum"""
        if not value:
            return cls.UNKNOWN
        
        # Normalize input
        normalized = value.lower().strip()
        
        # Try direct match
        for threat_type in cls:
            if threat_type.value == normalized:
                return threat_type
        
        # Try mapping common variations
        variations = {
            'sql': cls.SQL_INJECTION,
            'injection': cls.SQL_INJECTION,
            'cross-site': cls.XSS,
            'xss': cls.XSS,
            'remote code': cls.RCE,
            'code execution': cls.RCE,
            'ssrf': cls.SSRF,
            'server request': cls.SSRF,
            'xxe': cls.XXE,
            'xml': cls.XXE,
            'idor': cls.INSECURE_DIRECT_OBJECT_REFERENCE,
            'object reference': cls.INSECURE_DIRECT_OBJECT_REFERENCE,
            'path': cls.PATH_TRAVERSAL,
            'traversal': cls.PATH_TRAVERSAL,
            'directory traversal': cls.PATH_TRAVERSAL,
            'auth': cls.AUTH_BYPASS,
            'bypass': cls.AUTH_BYPASS,
            'privilege': cls.PRIVILEGE_ESCALATION,
            'escalation': cls.PRIVILEGE_ESCALATION,
            'crypto': cls.WEAK_CRYPTO,
            'cryptography': cls.WEAK_CRYPTO,
            'configuration': cls.MISCONFIGURATION,
            'config': cls.MISCONFIGURATION,
            'hardcoded': cls.HARDCODED_CREDENTIALS,
            'credentials': cls.HARDCODED_CREDENTIALS,
            'jwt': cls.JWT_BYPASS,
            'token': cls.JWT_BYPASS,
            'csrf': cls.CSRF,
            'csrf': cls.CSRF,
            'cross-site request': cls.CSRF,
            'race': cls.RACE_CONDITION,
            'port': cls.OPEN_PORTS,
            'network': cls.SUSPICIOUS_PORT,
            'scan': cls.PORT_SCAN,
            'brute': cls.BRUTE_FORCE,
            'honeypot': cls.HONEYPOT_TRIGGER,
            'anomaly': cls.BEHAVIORAL_ANOMALY,
            'recon': cls.RECONNAISSANCE,
            'reconnaissance': cls.RECONNAISSANCE,
            'data': cls.DATA_EXPOSURE,
            'exfil': cls.DATA_EXFILTRATION,
        }
        
        # Check if value contains any variation keyword
        for key, threat_type in variations.items():
            if key in normalized:
                return threat_type
        
        # Default to unknown
        return cls.UNKNOWN
    
    @classmethod
    def get_severity(cls, threat_type: 'ThreatType') -> str:
        """Get default severity level for threat type"""
        severity_map = {
            # Critical
            cls.SQL_INJECTION: "Critical",
            cls.RCE: "Critical",
            cls.XXE: "Critical",
            cls.DATA_EXFILTRATION: "Critical",
            cls.PRIVILEGE_ESCALATION: "Critical",
            cls.JWT_BYPASS: "Critical",
            cls.BLOCKED_IP: "Critical",
            
            # High
            cls.XSS: "High",
            cls.SSRF: "High",
            cls.BRUTE_FORCE: "High",
            cls.AUTH_BYPASS: "High",
            cls.PATH_TRAVERSAL: "High",
            cls.CODE_INJECTION: "High",
            cls.COMMAND_INJECTION: "High",
            cls.CSRF: "High",
            cls.DATA_EXPOSURE: "High",
            cls.INSECURE_DESERIALIZATION: "High",
            cls.KNOWN_THREAT: "High",
            
            # Medium
            cls.WEAK_CRYPTO: "Medium",
            cls.MISCONFIGURATION: "Medium",
            cls.HARDCODED_CREDENTIALS: "Medium",
            cls.MISSING_SECURITY_HEADERS: "Medium",
            cls.INSECURE_STORAGE: "Medium",
            cls.CACHING_ISSUE: "Medium",
            cls.RACE_CONDITION: "Medium",
            cls.PORT_SCAN: "Medium",
            cls.SUSPICIOUS_PORT: "Medium",
            cls.BEHAVIORAL_ANOMALY: "Medium",
            cls.HONEYPOT_TRIGGER: "Medium",
            
            # Low
            cls.INSECURE_RANDOMNESS: "Low",
            cls.UNENCRYPTED_COMMUNICATION: "Low",
            cls.PLAIN_TEXT_PASSWORD: "Low",
            cls.INSECURE_DEPENDENCIES: "Low",
            cls.CLIENT_XSS: "Low",
            cls.OPEN_PORTS: "Low",
            cls.RECONNAISSANCE: "Low",
            
            # Unknown
            cls.UNKNOWN: "Medium",
            cls.SUSPICIOUS: "Medium",
            cls.COMPOSITE: "Medium",
        }
        return severity_map.get(threat_type, "Medium")
    
    @classmethod
    def get_category(cls, threat_type: 'ThreatType') -> str:
        """Get category for threat type"""
        category_map = {
            # Code Execution
            cls.SQL_INJECTION: "Code Execution",
            cls.XSS: "Code Execution",
            cls.RCE: "Code Execution",
            cls.CODE_INJECTION: "Code Execution",
            cls.COMMAND_INJECTION: "Code Execution",
            cls.XXE: "Code Execution",
            cls.CLIENT_XSS: "Code Execution",
            
            # Access Control
            cls.AUTH_BYPASS: "Access Control",
            cls.PRIVILEGE_ESCALATION: "Access Control",
            cls.BROKEN_ACCESS_CONTROL: "Access Control",
            cls.INSECURE_DIRECT_OBJECT_REFERENCE: "Access Control",
            
            # Data Security
            cls.DATA_EXFILTRATION: "Data Security",
            cls.DATA_EXPOSURE: "Data Security",
            cls.PRIVACY_VIOLATION: "Data Security",
            cls.INSECURE_STORAGE: "Data Security",
            
            # Cryptography
            cls.WEAK_CRYPTO: "Cryptography",
            cls.PLAIN_TEXT_PASSWORD: "Cryptography",
            cls.INSECURE_RANDOMNESS: "Cryptography",
            
            # Configuration
            cls.MISCONFIGURATION: "Configuration",
            cls.HARDCODED_CREDENTIALS: "Configuration",
            cls.MISSING_SECURITY_HEADERS: "Configuration",
            
            # Network
            cls.SSRF: "Network",
            cls.UNENCRYPTED_COMMUNICATION: "Network",
            cls.PORT_SCAN: "Network",
            cls.BRUTE_FORCE: "Network",
            cls.OPEN_PORTS: "Network",
            cls.SUSPICIOUS_PORT: "Network",
            
            # Protocol
            cls.INSECURE_DESERIALIZATION: "Protocol",
            cls.CSRF: "Protocol",
            cls.JWT_BYPASS: "Protocol",
            
            # Behavioral
            cls.BEHAVIORAL_ANOMALY: "Behavioral",
            cls.RECONNAISSANCE: "Behavioral",
            cls.HONEYPOT_TRIGGER: "Behavioral",
            
            # Operational
            cls.RACE_CONDITION: "Operational",
            cls.CACHING_ISSUE: "Operational",
            cls.INSECURE_DEPENDENCIES: "Operational",
            cls.PATH_TRAVERSAL: "Operational",
            
            # Infrastructure
            cls.BLOCKED_IP: "Infrastructure",
            cls.KNOWN_THREAT: "Infrastructure",
            
            # Unknown
            cls.UNKNOWN: "Unknown",
            cls.SUSPICIOUS: "Unknown",
            cls.COMPOSITE: "Composite",
        }
        return category_map.get(threat_type, "Unknown")
    
    @classmethod
    def get_remediation(cls, threat_type: 'ThreatType') -> str:
        """Get remediation guidance for threat type"""
        remediation_map = {
            cls.SQL_INJECTION: "Use parameterized queries and prepared statements",
            cls.XSS: "Input validation, output encoding, Content Security Policy",
            cls.RCE: "Strict input validation, run with minimal privileges",
            cls.SSRF: "URL whitelisting, network segmentation",
            cls.XXE: "Disable XML external entities, use schema validation",
            cls.AUTH_BYPASS: "Implement strong authentication mechanisms",
            cls.PRIVILEGE_ESCALATION: "Run with least privilege, secure configuration",
            cls.WEAK_CRYPTO: "Use strong cryptographic algorithms",
            cls.HARDCODED_CREDENTIALS: "Use secure credential management",
            cls.PATH_TRAVERSAL: "Input validation, use canonical paths",
            cls.CSRF: "CSRF tokens, SameSite cookies",
            cls.JWT_BYPASS: "Strong key management, validate all claims",
            cls.CACHING_ISSUE: "Proper cache headers, clear sensitive data",
            cls.MISSING_SECURITY_HEADERS: "Add security headers (CSP, HSTS, etc)",
            cls.INSECURE_DEPENDENCIES: "Update to latest secure versions",
            cls.UNENCRYPTED_COMMUNICATION: "Use TLS/SSL for all communication",
            cls.RACE_CONDITION: "Implement proper locking and synchronization",
            cls.BEHAVIORAL_ANOMALY: "Monitor and alert on suspicious behavior",
            cls.BRUTE_FORCE: "Rate limiting, account lockout, strong passwords",
            cls.PORT_SCAN: "Firewall rules, port filtering",
            cls.UNKNOWN: "Investigate and classify threat properly",
        }
        return remediation_map.get(threat_type, "Investigate and remediate appropriately")


# Standard threat type sets for filtering
CRITICAL_THREATS: Set[ThreatType] = {
    ThreatType.SQL_INJECTION,
    ThreatType.RCE,
    ThreatType.XXE,
    ThreatType.DATA_EXFILTRATION,
    ThreatType.PRIVILEGE_ESCALATION,
    ThreatType.JWT_BYPASS,
    ThreatType.BLOCKED_IP,
}

HIGH_THREATS: Set[ThreatType] = {
    ThreatType.XSS,
    ThreatType.SSRF,
    ThreatType.BRUTE_FORCE,
    ThreatType.AUTH_BYPASS,
    ThreatType.PATH_TRAVERSAL,
    ThreatType.CODE_INJECTION,
    ThreatType.CSRF,
    ThreatType.DATA_EXPOSURE,
}

MEDIUM_THREATS: Set[ThreatType] = {
    ThreatType.WEAK_CRYPTO,
    ThreatType.MISCONFIGURATION,
    ThreatType.MISSING_SECURITY_HEADERS,
    ThreatType.RACE_CONDITION,
    ThreatType.BEHAVIORAL_ANOMALY,
}

# Convenience functions
def get_threat_severity(threat_type_str: str) -> str:
    """Get severity for threat type string"""
    threat_enum = ThreatType.from_string(threat_type_str)
    return ThreatType.get_severity(threat_enum)


def get_threat_category(threat_type_str: str) -> str:
    """Get category for threat type string"""
    threat_enum = ThreatType.from_string(threat_type_str)
    return ThreatType.get_category(threat_enum)


def get_threat_remediation(threat_type_str: str) -> str:
    """Get remediation for threat type string"""
    threat_enum = ThreatType.from_string(threat_type_str)
    return ThreatType.get_remediation(threat_enum)
