"""
Enhanced Defense System for HadesAI
Advanced threat detection, response, and mitigation with ML-based analysis
Integrates with Unified LLM Router and Web Learning systems
"""

import json
import logging
import sqlite3
import threading
import time
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EnhancedDefenseSystem")


# ============================================================================
# ENUMS & DATA STRUCTURES
# ============================================================================

class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class DefenseAction(Enum):
    """Automated defense actions"""
    BLOCK_IP = "block_ip"
    TERMINATE_PROCESS = "terminate_process"
    ISOLATE_SYSTEM = "isolate_system"
    ALERT_ADMIN = "alert_admin"
    LOG_INCIDENT = "log_incident"
    ENABLE_WAF = "enable_waf"
    ENABLE_HONEYPOT = "enable_honeypot"
    ENFORCE_MFA = "enforce_mfa"
    REVOKE_SESSION = "revoke_session"
    INITIATE_CONTAINMENT = "initiate_containment"


@dataclass
class ThreatIndicator:
    """Threat indicator or signature"""
    indicator_id: str
    indicator_type: str  # ip, domain, hash, pattern, signature
    value: str
    severity: ThreatLevel
    source: str
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionEvent:
    """Detected threat event"""
    event_id: str
    timestamp: datetime
    threat_level: ThreatLevel
    threat_type: str
    description: str
    source_ip: Optional[str] = None
    target_resource: Optional[str] = None
    indicators_matched: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    response_actions: List[DefenseAction] = field(default_factory=list)


@dataclass
class DefenseRule:
    """Defense/response rule"""
    rule_id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    response_actions: List[DefenseAction]
    enabled: bool = True
    priority: int = 10
    threshold: int = 1
    time_window_seconds: int = 300


# ============================================================================
# THREAT DETECTION ENGINE
# ============================================================================

class ThreatDetectionEngine:
    """Advanced threat detection with signature and anomaly detection"""
    
    def __init__(self, db_path: str = "defense_system.db"):
        self.db_path = db_path
        self.threat_signatures: Dict[str, ThreatIndicator] = {}
        self.detection_history: List[DetectionEvent] = []
        self.anomaly_detector = AnomalyDetector()
        self._init_db()
        self._load_threat_database()
    
    def _init_db(self):
        """Initialize defense database"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    indicator_type TEXT,
                    value TEXT UNIQUE,
                    severity TEXT,
                    source TEXT,
                    created_at TEXT,
                    metadata TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    threat_level TEXT,
                    threat_type TEXT,
                    description TEXT,
                    source_ip TEXT,
                    target_resource TEXT,
                    indicators_matched TEXT,
                    metadata TEXT,
                    response_actions TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS defense_rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    trigger_conditions TEXT,
                    response_actions TEXT,
                    enabled BOOLEAN,
                    priority INTEGER,
                    threshold INTEGER,
                    time_window_seconds INTEGER
                )
            """)
            
            self.conn.commit()
            self._populate_default_indicators()
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    def _populate_default_indicators(self):
        """Populate default threat indicators"""
        default_indicators = [
            # Known malicious IPs
            ("ip", "192.168.1.100", ThreatLevel.CRITICAL, "internal_threat_db"),
            ("ip", "10.0.0.50", ThreatLevel.HIGH, "internal_threat_db"),
            
            # Known C2 domains
            ("domain", "evil.com", ThreatLevel.CRITICAL, "threat_intel"),
            ("domain", "malware.net", ThreatLevel.CRITICAL, "threat_intel"),
            
            # SQL injection signatures
            ("pattern", "' OR '1'='1", ThreatLevel.HIGH, "signature_db"),
            ("pattern", "UNION SELECT", ThreatLevel.HIGH, "signature_db"),
            ("pattern", "'; DROP TABLE", ThreatLevel.CRITICAL, "signature_db"),
            
            # XSS signatures
            ("pattern", "<script>", ThreatLevel.HIGH, "signature_db"),
            ("pattern", "onerror=", ThreatLevel.HIGH, "signature_db"),
            
            # File operation suspicious patterns
            ("pattern", "cmd.exe /c", ThreatLevel.HIGH, "signature_db"),
            ("pattern", "powershell -nop", ThreatLevel.HIGH, "signature_db"),
        ]
        
        for ind_type, value, severity, source in default_indicators:
            self.add_indicator(
                indicator_type=ind_type,
                value=value,
                severity=severity,
                source=source
            )
    
    def _load_threat_database(self):
        """Load threat database from storage"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM threat_indicators")
            
            for row in cursor.fetchall():
                indicator_id, ind_type, value, severity, source, created_at, metadata = row
                self.threat_signatures[value] = ThreatIndicator(
                    indicator_id=indicator_id,
                    indicator_type=ind_type,
                    value=value,
                    severity=ThreatLevel[severity],
                    source=source,
                    created_at=datetime.fromisoformat(created_at),
                    metadata=json.loads(metadata) if metadata else {}
                )
        except Exception as e:
            logger.error(f"Failed to load threat database: {e}")
    
    def add_indicator(self, indicator_type: str, value: str, severity: ThreatLevel, source: str, metadata: Dict = None) -> bool:
        """Add threat indicator"""
        try:
            import uuid
            indicator_id = f"ind_{uuid.uuid4().hex[:8]}"
            
            indicator = ThreatIndicator(
                indicator_id=indicator_id,
                indicator_type=indicator_type,
                value=value,
                severity=severity,
                source=source,
                metadata=metadata or {}
            )
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_indicators
                (indicator_id, indicator_type, value, severity, source, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator_id,
                indicator_type,
                value,
                severity.name,
                source,
                indicator.created_at.isoformat(),
                json.dumps(metadata or {})
            ))
            
            self.conn.commit()
            self.threat_signatures[value] = indicator
            return True
        except Exception as e:
            logger.error(f"Failed to add indicator: {e}")
            return False
    
    def detect_threat(self, content: str, context: Dict[str, Any] = None) -> Optional[DetectionEvent]:
        """Detect threats in content using signatures and anomalies"""
        import uuid
        
        if not context:
            context = {}
        
        event_id = f"evt_{uuid.uuid4().hex[:8]}"
        matched_indicators = []
        max_severity = ThreatLevel.INFO
        threat_type = "UNKNOWN"
        
        # Signature matching
        for signature, indicator in self.threat_signatures.items():
            if indicator.indicator_type == "pattern":
                if signature.lower() in content.lower():
                    matched_indicators.append(indicator.indicator_id)
                    if indicator.severity.value < max_severity.value:
                        max_severity = indicator.severity
                    threat_type = "SIGNATURE_MATCH"
            elif indicator.indicator_type == "ip":
                if signature in content:
                    matched_indicators.append(indicator.indicator_id)
                    if indicator.severity.value < max_severity.value:
                        max_severity = indicator.severity
                    threat_type = "IP_THREAT"
        
        # Anomaly detection
        anomaly_score = self.anomaly_detector.analyze(content)
        if anomaly_score > 0.7:
            if ThreatLevel.MEDIUM.value < max_severity.value:
                max_severity = ThreatLevel.MEDIUM
            threat_type = "ANOMALY_DETECTED"
        
        if max_severity == ThreatLevel.INFO and anomaly_score < 0.5:
            return None
        
        # Create detection event
        event = DetectionEvent(
            event_id=event_id,
            timestamp=datetime.now(),
            threat_level=max_severity,
            threat_type=threat_type,
            description=f"Threat detected: {threat_type} (Anomaly: {anomaly_score:.2f})",
            source_ip=context.get("source_ip"),
            target_resource=context.get("target_resource"),
            indicators_matched=matched_indicators,
            metadata={
                "anomaly_score": anomaly_score,
                "content_length": len(content),
                **context
            }
        )
        
        self.detection_history.append(event)
        self._store_event(event)
        
        return event
    
    def _store_event(self, event: DetectionEvent):
        """Store detection event"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO detection_events
                (event_id, timestamp, threat_level, threat_type, description,
                 source_ip, target_resource, indicators_matched, metadata, response_actions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp.isoformat(),
                event.threat_level.name,
                event.threat_type,
                event.description,
                event.source_ip,
                event.target_resource,
                json.dumps(event.indicators_matched),
                json.dumps(event.metadata),
                json.dumps([a.value for a in event.response_actions])
            ))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to store event: {e}")
    
    def get_recent_events(self, hours: int = 24) -> List[DetectionEvent]:
        """Get recent detection events"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [e for e in self.detection_history if e.timestamp > cutoff_time]


# ============================================================================
# ANOMALY DETECTION ENGINE
# ============================================================================

class AnomalyDetector:
    """Detect anomalous behavior using statistical analysis"""
    
    def __init__(self):
        self.baseline_stats = defaultdict(lambda: {"count": 0, "sum": 0})
        self.request_patterns = defaultdict(lambda: [])
    
    def analyze(self, content: str) -> float:
        """Analyze content for anomalies, return score 0-1"""
        
        score = 0.0
        
        # Check for suspicious character patterns
        suspicious_chars = set(['<', '>', '{', '}', '[', ']', '"', "'", '`'])
        char_ratio = sum(1 for c in content if c in suspicious_chars) / max(len(content), 1)
        score += min(char_ratio * 0.3, 0.3)
        
        # Check for entropy (randomness = suspicious)
        entropy = self._calculate_entropy(content)
        if entropy > 4.0:
            score += 0.3
        
        # Check for known dangerous patterns
        dangerous_keywords = [
            'eval', 'exec', 'system', 'passthru', 'shell_exec',
            'drop table', 'delete from', 'truncate', 'union select'
        ]
        for keyword in dangerous_keywords:
            if keyword.lower() in content.lower():
                score += 0.2
        
        # Check for encoding/obfuscation indicators
        encoding_patterns = ['base64', 'hex', 'unicode', 'htmlentities']
        for pattern in encoding_patterns:
            if pattern.lower() in content.lower():
                score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        from collections import Counter
        entropy = 0.0
        char_counts = Counter(text)
        text_len = len(text)
        
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * (probability ** 0.5)
        
        return entropy


# ============================================================================
# DEFENSE RESPONSE ENGINE
# ============================================================================

class DefenseResponseEngine:
    """Execute defense actions and manage response lifecycle"""
    
    def __init__(self):
        self.rules: Dict[str, DefenseRule] = {}
        self.active_blocks: Dict[str, datetime] = {}
        self.response_history: List[Dict] = []
        self._init_default_rules()
    
    def _init_default_rules(self):
        """Initialize default defense rules"""
        rules = [
            {
                "name": "Critical Threat Response",
                "trigger": {"threat_level": ThreatLevel.CRITICAL},
                "actions": [DefenseAction.ALERT_ADMIN, DefenseAction.LOG_INCIDENT, DefenseAction.BLOCK_IP]
            },
            {
                "name": "High Threat Detection",
                "trigger": {"threat_level": ThreatLevel.HIGH},
                "actions": [DefenseAction.LOG_INCIDENT, DefenseAction.ALERT_ADMIN]
            },
            {
                "name": "SQL Injection Prevention",
                "trigger": {"threat_type": "SIGNATURE_MATCH", "pattern": "SQL_INJECTION"},
                "actions": [DefenseAction.BLOCK_IP, DefenseAction.LOG_INCIDENT]
            },
            {
                "name": "XSS Prevention",
                "trigger": {"threat_type": "SIGNATURE_MATCH", "pattern": "XSS"},
                "actions": [DefenseAction.LOG_INCIDENT, DefenseAction.ALERT_ADMIN]
            }
        ]
        
        for rule_data in rules:
            self.add_rule(rule_data)
    
    def add_rule(self, rule_data: Dict):
        """Add defense rule"""
        import uuid
        rule_id = f"rule_{uuid.uuid4().hex[:8]}"
        
        rule = DefenseRule(
            rule_id=rule_id,
            name=rule_data.get("name", "Custom Rule"),
            description=rule_data.get("description", ""),
            trigger_conditions=rule_data.get("trigger", {}),
            response_actions=rule_data.get("actions", [])
        )
        
        self.rules[rule_id] = rule
        logger.info(f"Defense rule added: {rule.name}")
    
    def evaluate_and_respond(self, event: DetectionEvent) -> List[DefenseAction]:
        """Evaluate event against rules and execute responses"""
        triggered_actions = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            if self._matches_trigger(event, rule.trigger_conditions):
                triggered_actions.extend(rule.response_actions)
                logger.info(f"Defense rule triggered: {rule.name}")
        
        # Execute actions
        for action in set(triggered_actions):
            self._execute_action(action, event)
        
        # Record response
        self.response_history.append({
            "event_id": event.event_id,
            "timestamp": datetime.now().isoformat(),
            "triggered_actions": [a.value for a in triggered_actions]
        })
        
        return triggered_actions
    
    def _matches_trigger(self, event: DetectionEvent, conditions: Dict) -> bool:
        """Check if event matches rule trigger conditions"""
        for key, value in conditions.items():
            if key == "threat_level":
                if event.threat_level != value:
                    return False
            elif key == "threat_type":
                if value not in event.threat_type:
                    return False
        
        return bool(conditions)
    
    def _execute_action(self, action: DefenseAction, event: DetectionEvent):
        """Execute defense action"""
        logger.info(f"Executing defense action: {action.value}")
        
        if action == DefenseAction.ALERT_ADMIN:
            self._alert_admin(event)
        elif action == DefenseAction.LOG_INCIDENT:
            self._log_incident(event)
        elif action == DefenseAction.BLOCK_IP:
            if event.source_ip:
                self._block_ip(event.source_ip)
        elif action == DefenseAction.ISOLATE_SYSTEM:
            self._isolate_system(event)
    
    def _alert_admin(self, event: DetectionEvent):
        """Alert administrator"""
        alert_msg = f"""
        SECURITY ALERT
        ===============
        Time: {event.timestamp}
        Threat Level: {event.threat_level.name}
        Type: {event.threat_type}
        Description: {event.description}
        Source IP: {event.source_ip or 'Unknown'}
        """
        logger.warning(alert_msg)
    
    def _log_incident(self, event: DetectionEvent):
        """Log security incident"""
        logger.info(f"INCIDENT LOG: {event.event_id} - {event.threat_type}")
    
    def _block_ip(self, ip: str):
        """Block IP address"""
        self.active_blocks[ip] = datetime.now() + timedelta(hours=1)
        logger.warning(f"IP BLOCKED: {ip}")
    
    def _isolate_system(self, event: DetectionEvent):
        """Isolate affected system"""
        logger.critical(f"SYSTEM ISOLATION INITIATED for resource: {event.target_resource}")


# ============================================================================
# ENHANCED DEFENSE SYSTEM
# ============================================================================

class EnhancedDefenseSystem:
    """Main enhanced defense system orchestrator"""
    
    def __init__(self):
        self.detection_engine = ThreatDetectionEngine()
        self.response_engine = DefenseResponseEngine()
        self.monitoring_active = False
    
    def scan_content(self, content: str, context: Dict = None) -> Optional[DetectionEvent]:
        """Scan content for threats"""
        if not context:
            context = {}
        
        event = self.detection_engine.detect_threat(content, context)
        
        if event and event.threat_level.value <= ThreatLevel.MEDIUM.value:
            actions = self.response_engine.evaluate_and_respond(event)
            event.response_actions = actions
        
        return event
    
    def add_custom_indicator(self, indicator_type: str, value: str, severity: ThreatLevel):
        """Add custom threat indicator"""
        return self.detection_engine.add_indicator(
            indicator_type=indicator_type,
            value=value,
            severity=severity,
            source="custom"
        )
    
    def add_defense_rule(self, rule_data: Dict):
        """Add custom defense rule"""
        self.response_engine.add_rule(rule_data)
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        recent_events = self.detection_engine.get_recent_events(hours=24)
        
        threat_counts = defaultdict(int)
        for event in recent_events:
            threat_counts[event.threat_level.name] += 1
        
        return {
            "status": "ACTIVE",
            "recent_events_24h": len(recent_events),
            "threat_distribution": dict(threat_counts),
            "active_blocks": len(self.response_engine.active_blocks),
            "response_history_count": len(self.response_engine.response_history)
        }


if __name__ == "__main__":
    # Test defense system
    defense_system = EnhancedDefenseSystem()
    
    # Test detection
    test_content = "SELECT * FROM users WHERE id = ' OR '1'='1"
    event = defense_system.scan_content(test_content, {"source_ip": "192.168.1.10"})
    
    if event:
        print(f"Threat Detected: {event.threat_type}")
        print(f"Severity: {event.threat_level.name}")
        print(f"Actions Taken: {[a.value for a in event.response_actions]}")
    
    print("\nSecurity Status:")
    import pprint
    pprint.pprint(defense_system.get_security_status())
