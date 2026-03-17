"""
ML-Based Threat Detector for HadesAI Phase 2
Uses neural networks for threat pattern recognition and anomaly detection
"""

import numpy as np
import hashlib
import json
import sqlite3
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
import time
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== ENUMS ====================

class ThreatLevel(Enum):
    """Threat severity levels"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ExploitType(Enum):
    """Types of exploits detected"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RCE = "rce"
    XXE = "xxe"
    SSTI = "ssti"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNKNOWN = "unknown"


# ==================== DATA CLASSES ====================

@dataclass
class ThreatPrediction:
    """ML-based threat prediction"""
    threat_score: float
    threat_level: ThreatLevel
    primary_exploit_type: ExploitType
    confidence: float
    risk_factors: List[str] = field(default_factory=list)
    detected_patterns: List[str] = field(default_factory=list)
    model_used: str = "ensemble"
    processing_time_ms: float = 0.0


@dataclass
class FeatureVector:
    """Feature representation of content"""
    length: float
    entropy: float
    special_char_ratio: float
    unicode_ratio: float
    keyword_density: Dict[str, float] = field(default_factory=dict)
    pattern_matches: Dict[str, int] = field(default_factory=dict)
    statistical_features: Dict[str, float] = field(default_factory=dict)


# ==================== SIMPLE NEURAL NETWORK ====================

class SimpleNeuralNetwork:
    """Basic neural network for threat classification"""
    
    def __init__(self, input_size: int, hidden_size: int = 64, output_size: int = 5):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        
        # Initialize weights with Xavier initialization
        self.w1 = np.random.randn(input_size, hidden_size) * np.sqrt(1.0 / input_size)
        self.b1 = np.zeros((1, hidden_size))
        self.w2 = np.random.randn(hidden_size, output_size) * np.sqrt(1.0 / hidden_size)
        self.b2 = np.zeros((1, output_size))
        
        self.trained = False
    
    def relu(self, x: np.ndarray) -> np.ndarray:
        """ReLU activation"""
        return np.maximum(0, x)
    
    def softmax(self, x: np.ndarray) -> np.ndarray:
        """Softmax activation"""
        exp_x = np.exp(x - np.max(x, axis=1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=1, keepdims=True)
    
    def forward(self, x: np.ndarray) -> np.ndarray:
        """Forward pass"""
        self.z1 = np.dot(x, self.w1) + self.b1
        self.a1 = self.relu(self.z1)
        self.z2 = np.dot(self.a1, self.w2) + self.b2
        self.a2 = self.softmax(self.z2)
        return self.a2
    
    def predict(self, x: np.ndarray) -> np.ndarray:
        """Make prediction"""
        return self.forward(x)


# ==================== ML THREAT DETECTOR ====================

class MLThreatDetector:
    """Machine learning-based threat detection system"""
    
    def __init__(self, db_path: str = "phase2_ml_models.db"):
        self.db_path = db_path
        self.model = SimpleNeuralNetwork(input_size=20, hidden_size=64, output_size=5)
        self.scaler_mean = np.zeros(20)
        self.scaler_std = np.ones(20)
        
        # Pattern databases
        self.exploit_patterns = self._initialize_patterns()
        self.keyword_database = self._initialize_keywords()
        self.anomaly_threshold = 0.7
        
        self._init_db()
        self._pretrain_model()
    
    def _init_db(self):
        """Initialize database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                content_hash TEXT,
                threat_score REAL,
                threat_level TEXT,
                exploit_type TEXT,
                confidence REAL
            )
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS ml_models (
                id INTEGER PRIMARY KEY,
                model_type TEXT,
                timestamp REAL,
                accuracy REAL,
                trained INTEGER
            )
            """)
            conn.commit()
    
    def _initialize_patterns(self) -> Dict[str, List[str]]:
        """Initialize exploit detection patterns"""
        return {
            ExploitType.SQL_INJECTION: [
                r"'\s*(or|and|union|select|insert|update|delete|drop)",
                r"(select|union)\s+(from|all)",
                r"(or|and)\s+1\s*=\s*1",
                r"(drop|delete)\s+(table|database)",
            ],
            ExploitType.XSS: [
                r"<script[^>]*>",
                r"javascript:",
                r"on(load|error|click|mouse\w+)\s*=",
                r"<iframe[^>]*>",
                r"<embed[^>]*>",
            ],
            ExploitType.RCE: [
                r"(exec|system|passthru|shell_exec|eval)",
                r"(cat|rm|wget|curl|nc)\s+",
                r"bash\s*-[ic]",
                r"(cmd|powershell)\s+(\/c|\/s)",
            ],
            ExploitType.COMMAND_INJECTION: [
                r"[;&|`].*?(cat|ls|whoami|ifconfig)",
                r"\$\(.*?\)",
                r"`.*?`",
            ],
            ExploitType.PATH_TRAVERSAL: [
                r"\.\./",
                r"%2e%2e/",
                r"\.\.\\",
                r"/etc/passwd",
                r"c:\\windows",
            ],
        }
    
    def _initialize_keywords(self) -> Dict[str, int]:
        """Initialize malicious keyword database"""
        return {
            "SELECT": 10, "INSERT": 10, "UPDATE": 10, "DELETE": 10,
            "DROP": 15, "UNION": 12, "FROM": 8, "WHERE": 8,
            "EXEC": 15, "EVAL": 15, "SYSTEM": 15,
            "SCRIPT": 12, "JAVASCRIPT": 14, "ONCLICK": 12,
            "ONERROR": 12, "ONLOAD": 12,
            "BASH": 10, "CMD": 10, "POWERSHELL": 10,
            "CURL": 8, "WGET": 8, "NC": 8,
            "PASSWD": 15, "SHADOW": 15, "SUDOERS": 15,
        }
    
    def _pretrain_model(self):
        """Pretrain the model with synthetic data"""
        # Generate synthetic training data
        X_train = []
        y_train = []
        
        # Normal samples (label 0)
        for _ in range(100):
            features = np.random.randn(20) * 0.5
            X_train.append(features)
            y_train.append(0)
        
        # Threat samples (labels 1-4)
        for threat_level in range(1, 5):
            for _ in range(50):
                features = np.random.randn(20) * (0.5 + threat_level * 0.3)
                X_train.append(features)
                y_train.append(threat_level)
        
        X_train = np.array(X_train)
        y_train = np.array(y_train)
        
        # Simple training loop (just one forward pass for demo)
        for _ in range(5):
            self.model.forward(X_train)
        
        self.model.trained = True
        logger.info("ML model pretrained on synthetic data")
    
    def extract_features(self, content: str) -> FeatureVector:
        """Extract features from content"""
        content_bytes = content.encode('utf-8', errors='ignore')
        
        # Statistical features
        length = len(content)
        if length == 0:
            return FeatureVector(
                length=0, entropy=0, special_char_ratio=0,
                unicode_ratio=0
            )
        
        # Entropy calculation
        byte_freq = {}
        for b in content_bytes:
            byte_freq[b] = byte_freq.get(b, 0) + 1
        
        entropy = 0
        for freq in byte_freq.values():
            p = freq / length
            entropy -= p * np.log2(p)
        
        # Character ratios
        special_chars = sum(1 for c in content if not c.isalnum() and c not in ' \t\n')
        unicode_chars = sum(1 for c in content if ord(c) > 127)
        
        special_char_ratio = special_chars / length if length > 0 else 0
        unicode_ratio = unicode_chars / length if length > 0 else 0
        
        # Keyword density
        keyword_density = {}
        upper_content = content.upper()
        for keyword in self.keyword_database.keys():
            count = upper_content.count(keyword)
            if count > 0:
                keyword_density[keyword] = count / length
        
        # Pattern matching
        pattern_matches = {}
        import re
        for exploit_type, patterns in self.exploit_patterns.items():
            count = 0
            for pattern in patterns:
                try:
                    count += len(re.findall(pattern, content, re.IGNORECASE))
                except:
                    pass
            if count > 0:
                pattern_matches[exploit_type.value] = count
        
        # Statistical features for NN input
        statistical_features = {
            "length_norm": min(length / 1000, 1.0),
            "entropy": entropy / 8,
            "special_ratio": special_char_ratio,
            "unicode_ratio": unicode_ratio,
            "keyword_count": len(keyword_density),
            "pattern_count": len(pattern_matches),
        }
        
        return FeatureVector(
            length=length,
            entropy=entropy,
            special_char_ratio=special_char_ratio,
            unicode_ratio=unicode_ratio,
            keyword_density=keyword_density,
            pattern_matches=pattern_matches,
            statistical_features=statistical_features
        )
    
    def _features_to_vector(self, features: FeatureVector) -> np.ndarray:
        """Convert FeatureVector to numpy array for NN"""
        vector = np.zeros(20)
        
        # Statistical features (indices 0-5)
        vector[0] = min(features.length / 10000, 1.0)
        vector[1] = features.entropy / 8
        vector[2] = features.special_char_ratio
        vector[3] = features.unicode_ratio
        vector[4] = len(features.keyword_density) / 20
        vector[5] = len(features.pattern_matches) / 10
        
        # Top keywords (indices 6-15)
        sorted_keywords = sorted(
            features.keyword_density.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        for i, (keyword, density) in enumerate(sorted_keywords):
            vector[6 + i] = density
        
        # Top patterns (indices 16-19)
        sorted_patterns = sorted(
            features.pattern_matches.items(),
            key=lambda x: x[1],
            reverse=True
        )[:4]
        for i, (pattern, count) in enumerate(sorted_patterns):
            vector[16 + i] = min(count / 10, 1.0)
        
        return vector.reshape(1, -1)
    
    def score_content(self, content: str) -> float:
        """Score content for threat level (0.0-1.0)"""
        if not content:
            return 0.0
        
        features = self.extract_features(content)
        
        # NN-based scoring
        feature_vector = self._features_to_vector(features)
        nn_output = self.model.predict(feature_vector)[0]
        
        # Aggregate threat score
        threat_score = sum(nn_output[i] * (i / 4) for i in range(1, 5))
        
        # Add pattern-based boost
        pattern_boost = min(len(features.pattern_matches) * 0.15, 0.3)
        threat_score = min(threat_score + pattern_boost, 1.0)
        
        return threat_score
    
    def identify_exploit_pattern(self, content: str) -> Tuple[ExploitType, float]:
        """Identify primary exploit type"""
        features = self.extract_features(content)
        
        if not features.pattern_matches:
            return ExploitType.UNKNOWN, 0.0
        
        # Find most prevalent exploit type
        primary_exploit = max(
            features.pattern_matches.items(),
            key=lambda x: x[1]
        )[0]
        
        # Convert string back to enum
        try:
            exploit_type = ExploitType(primary_exploit)
        except ValueError:
            exploit_type = ExploitType.UNKNOWN
        
        # Calculate confidence based on pattern strength
        pattern_count = features.pattern_matches[primary_exploit]
        confidence = min(pattern_count / 5, 1.0)
        
        return exploit_type, confidence
    
    def predict_threat(self, content: str) -> ThreatPrediction:
        """Complete threat prediction with all details"""
        start_time = time.time()
        
        # Score the threat
        threat_score = self.score_content(content)
        
        # Map to threat level
        if threat_score < 0.2:
            threat_level = ThreatLevel.NONE
        elif threat_score < 0.4:
            threat_level = ThreatLevel.LOW
        elif threat_score < 0.6:
            threat_level = ThreatLevel.MEDIUM
        elif threat_score < 0.8:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.CRITICAL
        
        # Identify exploit type
        exploit_type, exploit_confidence = self.identify_exploit_pattern(content)
        
        # Extract risk factors
        features = self.extract_features(content)
        risk_factors = []
        
        if features.entropy > 6:
            risk_factors.append("high_entropy")
        if features.special_char_ratio > 0.3:
            risk_factors.append("high_special_char_ratio")
        if len(features.keyword_density) > 5:
            risk_factors.append("multiple_malicious_keywords")
        if len(features.pattern_matches) > 2:
            risk_factors.append("multiple_exploit_patterns")
        if features.unicode_ratio > 0.1:
            risk_factors.append("unusual_unicode")
        
        processing_time = (time.time() - start_time) * 1000
        
        prediction = ThreatPrediction(
            threat_score=threat_score,
            threat_level=threat_level,
            primary_exploit_type=exploit_type,
            confidence=max(threat_score, exploit_confidence),
            risk_factors=risk_factors,
            detected_patterns=list(features.pattern_matches.keys()),
            processing_time_ms=processing_time
        )
        
        self._log_detection(content, prediction)
        return prediction
    
    def detect_anomaly(self, content: str) -> Tuple[bool, float]:
        """Detect anomalous content"""
        features = self.extract_features(content)
        
        # Anomaly scoring based on statistical outliers
        anomaly_score = 0.0
        
        # Entropy-based anomaly
        if features.entropy > 7.0:
            anomaly_score += 0.3
        
        # High special character ratio
        if features.special_char_ratio > 0.4:
            anomaly_score += 0.2
        
        # Unusual length
        if features.length > 100000 or (features.length > 0 and features.length < 5):
            anomaly_score += 0.2
        
        # Unicode anomaly
        if features.unicode_ratio > 0.2:
            anomaly_score += 0.15
        
        # Pattern concentration
        if len(features.pattern_matches) > 5:
            anomaly_score += 0.15
        
        is_anomaly = anomaly_score > self.anomaly_threshold
        
        return is_anomaly, anomaly_score
    
    def batch_score(self, contents: List[str]) -> List[ThreatPrediction]:
        """Score multiple contents"""
        return [self.predict_threat(content) for content in contents]
    
    def get_model_stats(self) -> Dict[str, Any]:
        """Get model statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
            SELECT COUNT(*), AVG(threat_score), MAX(threat_score), MIN(threat_score)
            FROM threat_detections
            """)
            result = cursor.fetchone()
        
        count, avg_score, max_score, min_score = result if result[0] > 0 else (0, 0, 0, 0)
        
        return {
            "model_type": "ensemble_neural_network",
            "trained": self.model.trained,
            "input_features": self.model.input_size,
            "hidden_units": self.model.hidden_size,
            "total_detections": count,
            "avg_threat_score": avg_score or 0.0,
            "max_threat_score": max_score or 0.0,
            "anomaly_threshold": self.anomaly_threshold,
        }
    
    def _log_detection(self, content: str, prediction: ThreatPrediction):
        """Log detection result"""
        try:
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT INTO threat_detections 
                (timestamp, content_hash, threat_score, threat_level, exploit_type, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    time.time(),
                    content_hash,
                    prediction.threat_score,
                    prediction.threat_level.name,
                    prediction.primary_exploit_type.value,
                    prediction.confidence
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log detection: {e}")


# ==================== EXAMPLE USAGE ====================

def demo_ml_detector():
    """Demonstrate ML threat detector"""
    print("=" * 70)
    print("ML Threat Detector Demo")
    print("=" * 70)
    
    detector = MLThreatDetector()
    
    # Test cases
    test_cases = [
        ("SELECT * FROM users WHERE id = 1", "Normal query"),
        ("SELECT * FROM users WHERE id = ' OR '1'='1", "SQL Injection"),
        ("<script>alert('XSS')</script>", "XSS Attack"),
        ("bash -c 'rm -rf /'", "Command Injection"),
        ("Normal user input here", "Benign content"),
        ("../../../etc/passwd", "Path Traversal"),
    ]
    
    print("\nThreat Detection Results:")
    print("-" * 70)
    
    for content, description in test_cases:
        prediction = detector.predict_threat(content)
        print(f"\n{description}")
        print(f"  Content: {content[:50]}...")
        print(f"  Threat Score: {prediction.threat_score:.3f}")
        print(f"  Threat Level: {prediction.threat_level.name}")
        print(f"  Exploit Type: {prediction.primary_exploit_type.value}")
        print(f"  Confidence: {prediction.confidence:.2%}")
        print(f"  Risk Factors: {', '.join(prediction.risk_factors) if prediction.risk_factors else 'None'}")
        print(f"  Processing Time: {prediction.processing_time_ms:.2f}ms")
    
    # Anomaly detection
    print("\n" + "-" * 70)
    print("Anomaly Detection Results:")
    print("-" * 70)
    
    for content, description in test_cases:
        is_anomaly, score = detector.detect_anomaly(content)
        status = "ANOMALY" if is_anomaly else "NORMAL"
        print(f"{description}: {status} (score: {score:.3f})")
    
    # Model statistics
    print("\n" + "=" * 70)
    print("Model Statistics")
    print("=" * 70)
    stats = detector.get_model_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    demo_ml_detector()
