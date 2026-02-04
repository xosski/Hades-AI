"""
HadesAI - CONSOLIDATED GUI
All tabs integrated into one main application
Active Defense runs independently from Network Monitor
"""

import os
import sys
os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.text.font.*=false'

# Core imports
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import threading

# Qt imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QTabWidget, QGroupBox, QFormLayout,
    QCheckBox, QSpinBox, QDoubleSpinBox, QTableWidget, QTableWidgetItem,
    QLineEdit, QComboBox, QMessageBox, QProgressBar, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor

# Hades imports
from modules import personality_core_v2 as pcore
import pyfiglet

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HadesAI")

# Import optional modules
try:
    from autonomouscoding import AutonomousCodingAgent
    HAS_AUTONOMOUS_AGENT = True
except ImportError:
    HAS_AUTONOMOUS_AGENT = False

try:
    from fallback_llm import FallbackLLM
    HAS_FALLBACK_LLM = True
except ImportError:
    HAS_FALLBACK_LLM = False

# Autonomous Defense (independent of network monitor)
try:
    from modules.autonomous_defense import AutonomousDefenseEngine, DefenseLevel
    HAS_AUTONOMOUS_DEFENSE = True
except ImportError:
    HAS_AUTONOMOUS_DEFENSE = False

# Autonomous Operations (Threat Response, Learning, Decisions)
try:
    from modules.autonomous_operations import (
        ThreatResponseEngine, ContinuousLearningEngine, DecisionMakingAgent
    )
    HAS_AUTONOMOUS_OPS = True
except ImportError:
    HAS_AUTONOMOUS_OPS = False

# Advanced Autonomy (Self-Healing, Adaptive Strategies, Scheduling, Multi-Agent)
try:
    from modules.self_healing_system import SelfHealingSystem
    from modules.adaptive_strategy_engine import AdaptiveStrategyEngine
    from modules.autonomous_scheduler import AutonomousScheduler
    from modules.multi_agent_system import MultiAgentSystem
    HAS_ADVANCED_AUTONOMY = True
except ImportError:
    HAS_ADVANCED_AUTONOMY = False

# Payload Generator
try:
    from payload_generator_gui import PayloadGenerator, PayloadGeneratorTab
    HAS_PAYLOAD_GEN = True
except ImportError:
    HAS_PAYLOAD_GEN = False

# Network module
try:
    from modules.knowledge_network import KnowledgeNetworkNode
    HAS_NETWORK = True
except ImportError:
    HAS_NETWORK = False


# ============================================================================
# CONDENSED TABS
# ============================================================================

class ChatTab(QWidget):
    """Main chat interface"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        # Chat display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(QLabel("Chat"))
        layout.addWidget(self.chat_display)
        
        # Input
        input_layout = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Type message or command...")
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self._send_message)
        input_layout.addWidget(self.chat_input)
        input_layout.addWidget(send_btn)
        layout.addLayout(input_layout)
        
        self.setLayout(layout)
    
    def _send_message(self):
        msg = self.chat_input.text().strip()
        if msg:
            self.chat_display.append(f"You: {msg}")
            self.chat_input.clear()


class AnalysisTab(QWidget):
    """Code analysis interface"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Code Analysis"))
        
        input_layout = QHBoxLayout()
        self.code_input = QTextEdit()
        self.code_input.setPlaceholderText("Paste code to analyze...")
        analyze_btn = QPushButton("Analyze")
        input_layout.addWidget(self.code_input)
        input_layout.addWidget(analyze_btn)
        layout.addLayout(input_layout)
        
        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
        layout.addWidget(QLabel("Results"))
        layout.addWidget(self.analysis_output)
        
        self.setLayout(layout)


class WebTestingTab(QWidget):
    """Web penetration testing"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Web Testing"))
        
        # Target input
        target_layout = QFormLayout()
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("https://target.com")
        target_layout.addRow("Target:", self.target_url)
        layout.addLayout(target_layout)
        
        # Test options
        options_group = QGroupBox("Test Options")
        options_layout = QVBoxLayout()
        
        self.port_scan_cb = QCheckBox("Port Scan")
        self.vuln_scan_cb = QCheckBox("Vulnerability Scan")
        self.header_analysis_cb = QCheckBox("Header Analysis")
        
        options_layout.addWidget(self.port_scan_cb)
        options_layout.addWidget(self.vuln_scan_cb)
        options_layout.addWidget(self.header_analysis_cb)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Execute button
        exec_btn = QPushButton("Execute Tests")
        layout.addWidget(exec_btn)
        
        # Results
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        layout.addWidget(QLabel("Results"))
        layout.addWidget(self.results)
        
        self.setLayout(layout)


class ActiveDefenseTab(QWidget):
    """Active defense (independent of network monitor)"""
    def __init__(self):
        super().__init__()
        self.defense_engine = None
        if HAS_AUTONOMOUS_DEFENSE:
            self.defense_engine = AutonomousDefenseEngine()
        
        layout = QVBoxLayout()
        
        # Status
        status_group = QGroupBox("Defense Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Status: Disabled")
        self.status_label.setStyleSheet("color: #ff6b6b;")
        status_layout.addWidget(self.status_label)
        
        control_layout = QHBoxLayout()
        self.enable_btn = QPushButton("Enable Defense")
        self.enable_btn.clicked.connect(self._toggle_defense)
        self.block_ip_btn = QPushButton("Block IP")
        self.block_ip_btn.clicked.connect(self._block_ip)
        
        control_layout.addWidget(self.enable_btn)
        control_layout.addWidget(self.block_ip_btn)
        control_layout.addStretch()
        
        status_layout.addLayout(control_layout)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Configuration
        config_group = QGroupBox("Configuration")
        config_layout = QFormLayout()
        
        self.defense_level = QComboBox()
        self.defense_level.addItems(["PASSIVE", "REACTIVE", "PROACTIVE", "AGGRESSIVE"])
        self.defense_level.setCurrentText("REACTIVE")
        config_layout.addRow("Defense Level:", self.defense_level)
        
        self.auto_response_cb = QCheckBox("Auto-Response")
        self.auto_response_cb.setChecked(True)
        config_layout.addRow("Auto-Response:", self.auto_response_cb)
        
        self.block_threshold = QDoubleSpinBox()
        self.block_threshold.setRange(0.0, 1.0)
        self.block_threshold.setValue(0.7)
        config_layout.addRow("Block Threshold:", self.block_threshold)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Threat log
        layout.addWidget(QLabel("Threat Log (Recent)"))
        self.threat_log = QTextEdit()
        self.threat_log.setReadOnly(True)
        self.threat_log.setMaximumHeight(150)
        layout.addWidget(self.threat_log)
        
        # Blocked IPs
        layout.addWidget(QLabel("Blocked IPs"))
        self.blocked_ips_list = QTextEdit()
        self.blocked_ips_list.setReadOnly(True)
        self.blocked_ips_list.setMaximumHeight(100)
        layout.addWidget(self.blocked_ips_list)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def _toggle_defense(self):
        if not HAS_AUTONOMOUS_DEFENSE:
            QMessageBox.warning(self, "Error", "Defense module not available")
            return
        
        if self.defense_engine:
            level_name = self.defense_level.currentText()
            level = DefenseLevel[level_name]
            enabled = self.defense_engine.set_defense_level(level)
            
            if enabled:
                self.status_label.setText("Status: ACTIVE")
                self.status_label.setStyleSheet("color: #51cf66;")
            else:
                self.status_label.setText("Status: Disabled")
                self.status_label.setStyleSheet("color: #ff6b6b;")
    
    def _block_ip(self):
        ip = self.block_ip_btn.text()
        if self.defense_engine:
            self.defense_engine.block_ip(ip)
            self.threat_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Blocked IP: {ip}")


class OperationsTab(QWidget):
    """Autonomous Operations (Threat Response, Learning, Decisions)"""
    def __init__(self):
        super().__init__()
        
        self.threat_response = None
        self.learning_engine = None
        self.decision_agent = None
        
        if HAS_AUTONOMOUS_OPS:
            self.threat_response = ThreatResponseEngine()
            self.learning_engine = ContinuousLearningEngine()
            self.decision_agent = DecisionMakingAgent(self.learning_engine, self.threat_response)
        
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Autonomous Operations"))
        
        # Quick controls
        control_layout = QHBoxLayout()
        
        self.threat_response_cb = QCheckBox("Threat Response")
        self.threat_response_cb.stateChanged.connect(self._toggle_threat)
        
        self.learning_cb = QCheckBox("Continuous Learning")
        self.learning_cb.stateChanged.connect(self._toggle_learning)
        
        self.decision_cb = QCheckBox("Decision Agent")
        self.decision_cb.stateChanged.connect(self._toggle_decision)
        
        control_layout.addWidget(self.threat_response_cb)
        control_layout.addWidget(self.learning_cb)
        control_layout.addWidget(self.decision_cb)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(200)
        layout.addWidget(QLabel("Status"))
        layout.addWidget(self.status_text)
        
        # Exploits table
        layout.addWidget(QLabel("Top Exploits"))
        self.exploits_table = QTableWidget()
        self.exploits_table.setColumnCount(3)
        self.exploits_table.setHorizontalHeaderLabels(["Exploit", "Success Rate", "Confidence"])
        self.exploits_table.setMaximumHeight(150)
        layout.addWidget(self.exploits_table)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def _toggle_threat(self, state):
        if self.threat_response and state == 2:
            self.threat_response.enable_auto_response()
    
    def _toggle_learning(self, state):
        if self.learning_engine and state == 2:
            self.learning_engine.enable_continuous_learning()
    
    def _toggle_decision(self, state):
        if self.decision_agent and state == 2:
            self.decision_agent.enable_autonomous_decisions()


class AdvancedAutonomyTab(QWidget):
    """Advanced Autonomy (Self-Healing, Adaptive, Scheduling, Multi-Agent)"""
    def __init__(self):
        super().__init__()
        
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Advanced Autonomy Control"))
        
        # Sub-tabs
        self.autonomy_tabs = QTabWidget()
        
        if HAS_ADVANCED_AUTONOMY:
            # Self-Healing
            healing_group = QGroupBox("Self-Healing")
            healing_layout = QVBoxLayout()
            self.healing_cb = QCheckBox("Enable Self-Healing")
            self.auto_retry_cb = QCheckBox("Auto Retry")
            self.auto_retry_cb.setChecked(True)
            healing_layout.addWidget(self.healing_cb)
            healing_layout.addWidget(self.auto_retry_cb)
            healing_group.setLayout(healing_layout)
            self.autonomy_tabs.addTab(healing_group, "Healing")
            
            # Adaptive Strategies
            strategy_group = QGroupBox("Adaptive Strategies")
            strategy_layout = QVBoxLayout()
            self.strategy_cb = QCheckBox("Enable Strategies")
            self.ab_testing_cb = QCheckBox("A/B Testing")
            self.ab_testing_cb.setChecked(True)
            strategy_layout.addWidget(self.strategy_cb)
            strategy_layout.addWidget(self.ab_testing_cb)
            strategy_group.setLayout(strategy_layout)
            self.autonomy_tabs.addTab(strategy_group, "Strategies")
            
            # Scheduler
            sched_group = QGroupBox("Autonomous Scheduler")
            sched_layout = QVBoxLayout()
            self.sched_cb = QCheckBox("Enable Scheduler")
            layout.addWidget(QLabel("Check interval (s):"))
            self.sched_interval = QSpinBox()
            self.sched_interval.setRange(1, 3600)
            self.sched_interval.setValue(60)
            sched_layout.addWidget(self.sched_cb)
            sched_layout.addWidget(self.sched_interval)
            sched_group.setLayout(sched_layout)
            self.autonomy_tabs.addTab(sched_group, "Scheduler")
            
            # Multi-Agent
            agent_group = QGroupBox("Multi-Agent System")
            agent_layout = QVBoxLayout()
            self.agent_cb = QCheckBox("Enable Multi-Agent")
            agent_layout.addWidget(self.agent_cb)
            agent_group.setLayout(agent_layout)
            self.autonomy_tabs.addTab(agent_group, "Agents")
        
        layout.addWidget(self.autonomy_tabs)
        layout.addStretch()
        self.setLayout(layout)


class PayloadTab(QWidget):
    """Payload Generator"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Payload Generator"))
        
        if HAS_PAYLOAD_GEN:
            # File selection
            file_layout = QHBoxLayout()
            self.file_input = QLineEdit()
            self.file_input.setPlaceholderText("Select file...")
            browse_btn = QPushButton("Browse")
            file_layout.addWidget(self.file_input)
            file_layout.addWidget(browse_btn)
            layout.addLayout(file_layout)
            
            # Generate button
            gen_btn = QPushButton("Generate Payloads")
            layout.addWidget(gen_btn)
            
            # Payloads table
            self.payloads_table = QTableWidget()
            self.payloads_table.setColumnCount(2)
            self.payloads_table.setHorizontalHeaderLabels(["#", "Payload"])
            layout.addWidget(QLabel("Payloads"))
            layout.addWidget(self.payloads_table)
        else:
            layout.addWidget(QLabel("Payload Generator not available"))
        
        self.setLayout(layout)


class NetworkTab(QWidget):
    """Combined Network (Monitoring + P2P Sharing)"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Network Control"))
        
        # Network tabs
        self.net_tabs = QTabWidget()
        
        # Monitor tab
        monitor_group = QGroupBox("Network Monitoring")
        monitor_layout = QVBoxLayout()
        self.monitor_cb = QCheckBox("Enable Monitoring")
        monitor_layout.addWidget(self.monitor_cb)
        
        self.monitor_info = QTextEdit()
        self.monitor_info.setReadOnly(True)
        self.monitor_info.setMaximumHeight(150)
        monitor_layout.addWidget(QLabel("Activity"))
        monitor_layout.addWidget(self.monitor_info)
        
        monitor_group.setLayout(monitor_layout)
        self.net_tabs.addTab(monitor_group, "Monitor")
        
        # P2P Sharing tab
        if HAS_NETWORK:
            p2p_group = QGroupBox("P2P Knowledge Sharing")
            p2p_layout = QVBoxLayout()
            self.p2p_cb = QCheckBox("Enable P2P Network")
            p2p_layout.addWidget(self.p2p_cb)
            
            self.p2p_info = QTextEdit()
            self.p2p_info.setReadOnly(True)
            self.p2p_info.setMaximumHeight(150)
            p2p_layout.addWidget(QLabel("Network Status"))
            p2p_layout.addWidget(self.p2p_info)
            
            p2p_group.setLayout(p2p_layout)
            self.net_tabs.addTab(p2p_group, "P2P")
        
        layout.addWidget(self.net_tabs)
        layout.addStretch()
        self.setLayout(layout)


class KnowledgeBaseTab(QWidget):
    """Knowledge Base"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Knowledge Base"))
        
        # Search
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search knowledge base...")
        search_btn = QPushButton("Search")
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)
        
        # Results
        self.kb_results = QTextEdit()
        self.kb_results.setReadOnly(True)
        layout.addWidget(QLabel("Results"))
        layout.addWidget(self.kb_results)
        
        self.setLayout(layout)


# ============================================================================
# MAIN WINDOW
# ============================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HadesAI - Unified Pentesting Platform")
        self.setGeometry(0, 0, 1600, 1000)
        
        # Central widget
        self.central = QWidget()
        self.setCentralWidget(self.central)
        layout = QVBoxLayout(self.central)
        
        # Tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Add all tabs
        self.tabs.addTab(ChatTab(), "💬 Chat")
        self.tabs.addTab(AnalysisTab(), "🔍 Analysis")
        self.tabs.addTab(WebTestingTab(), "🌐 Web")
        self.tabs.addTab(ActiveDefenseTab(), "🛡️ Defense")
        self.tabs.addTab(OperationsTab(), "⚡ Ops")
        self.tabs.addTab(AdvancedAutonomyTab(), "🧠 Autonomy")
        if HAS_PAYLOAD_GEN:
            self.tabs.addTab(PayloadTab(), "💣 Payloads")
        self.tabs.addTab(NetworkTab(), "📡 Network")
        self.tabs.addTab(KnowledgeBaseTab(), "📚 Knowledge")
        
        # Status bar
        self.status = self.statusBar()
        self.status.showMessage("Ready")


# ============================================================================
# MAIN
# ============================================================================

def main():
    print(pyfiglet.figlet_format("HadesAI"))
    logger.info("HadesAI Consolidated starting...")
    
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
