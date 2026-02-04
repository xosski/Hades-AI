"""
Autonomous Operations GUI
Controls for threat response, learning, and decision-making
"""

import json
import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox,
    QSpinBox, QDoubleSpinBox, QTableWidget, QTableWidgetItem, QGroupBox,
    QFormLayout, QTextEdit, QProgressBar, QTabWidget, QComboBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor

logger = logging.getLogger("AutonomousOpsGUI")

try:
    from modules.autonomous_operations import (
        ThreatResponseEngine, ContinuousLearningEngine, 
        DecisionMakingAgent, ThreatEvent
    )
    HAS_AUTONOMOUS_OPS = True
except ImportError:
    HAS_AUTONOMOUS_OPS = False
    ThreatResponseEngine = None
    ContinuousLearningEngine = None
    DecisionMakingAgent = None


class AutonomousOpsTab(QWidget):
    """GUI for autonomous operations"""
    
    def __init__(self, parent=None, db_path: str = "hades_knowledge.db"):
        super().__init__(parent)
        self.db_path = db_path
        self.threat_response = None
        self.learning_engine = None
        self.decision_agent = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # ===== THREAT RESPONSE ENGINE =====
        threat_group = QGroupBox("Autonomous Threat Response")
        threat_layout = QVBoxLayout()
        
        # Enable/disable
        threat_control = QHBoxLayout()
        self.threat_checkbox = QCheckBox("Enable Auto-Response to Threats")
        self.threat_checkbox.stateChanged.connect(self._toggle_threat_response)
        threat_control.addWidget(self.threat_checkbox)
        
        self.threat_status = QLabel("Status: Disabled")
        self.threat_status.setStyleSheet("color: #ff6b6b;")
        threat_control.addWidget(self.threat_status)
        threat_control.addStretch()
        threat_layout.addLayout(threat_control)
        
        # Threat response options
        threat_opts = QFormLayout()
        
        self.auto_patch_check = QCheckBox("Auto-Patch Vulnerabilities")
        self.auto_patch_check.setChecked(True)
        threat_opts.addRow("Patching:", self.auto_patch_check)
        
        self.auto_exploit_check = QCheckBox("Auto-Exploit Known Vulnerabilities")
        self.auto_exploit_check.setChecked(False)
        threat_opts.addRow("Exploitation:", self.auto_exploit_check)
        
        self.threat_threshold = QDoubleSpinBox()
        self.threat_threshold.setRange(0.0, 1.0)
        self.threat_threshold.setValue(0.7)
        self.threat_threshold.setSingleStep(0.05)
        threat_opts.addRow("Response Threshold:", self.threat_threshold)
        
        threat_layout.addLayout(threat_opts)
        
        # Blocked IPs
        threat_layout.addWidget(QLabel("Auto-Blocked IPs:"))
        self.blocked_ips_list = QTextEdit()
        self.blocked_ips_list.setReadOnly(True)
        self.blocked_ips_list.setMaximumHeight(80)
        threat_layout.addWidget(self.blocked_ips_list)
        
        threat_group.setLayout(threat_layout)
        layout.addWidget(threat_group)
        
        # ===== CONTINUOUS LEARNING =====
        learning_group = QGroupBox("Continuous Learning Engine")
        learning_layout = QVBoxLayout()
        
        # Enable/disable
        learning_control = QHBoxLayout()
        self.learning_checkbox = QCheckBox("Enable Continuous Learning")
        self.learning_checkbox.stateChanged.connect(self._toggle_learning)
        learning_control.addWidget(self.learning_checkbox)
        
        self.learning_status = QLabel("Status: Disabled")
        self.learning_status.setStyleSheet("color: #ff6b6b;")
        learning_control.addWidget(self.learning_status)
        learning_control.addStretch()
        learning_layout.addLayout(learning_control)
        
        # Learning options
        learning_opts = QFormLayout()
        
        self.auto_update_check = QCheckBox("Auto-Update Exploit Rankings")
        self.auto_update_check.setChecked(True)
        learning_opts.addRow("Update Rankings:", self.auto_update_check)
        
        self.pattern_gen_check = QCheckBox("Generate New Attack Patterns")
        self.pattern_gen_check.setChecked(False)
        learning_opts.addRow("Pattern Generation:", self.pattern_gen_check)
        
        self.feedback_loop_check = QCheckBox("Enable Feedback Loop")
        self.feedback_loop_check.setChecked(True)
        learning_opts.addRow("Feedback Loop:", self.feedback_loop_check)
        
        learning_layout.addLayout(learning_opts)
        
        # Learning stats
        learning_layout.addWidget(QLabel("Learning Statistics:"))
        self.learning_stats = QTextEdit()
        self.learning_stats.setReadOnly(True)
        self.learning_stats.setMaximumHeight(100)
        self.learning_stats.setStyleSheet(
            "QTextEdit { background-color: #1e1e1e; color: #00ff00; font-family: Courier; }"
        )
        learning_layout.addWidget(self.learning_stats)
        
        # Top exploits
        learning_layout.addWidget(QLabel("Top Performing Exploits:"))
        self.exploits_table = QTableWidget()
        self.exploits_table.setColumnCount(4)
        self.exploits_table.setHorizontalHeaderLabels(
            ["Exploit", "Target Type", "Success Rate", "Confidence"]
        )
        self.exploits_table.setMaximumHeight(150)
        learning_layout.addWidget(self.exploits_table)
        
        refresh_learning_btn = QPushButton("Refresh Learning Stats")
        refresh_learning_btn.clicked.connect(self._refresh_learning_stats)
        learning_layout.addWidget(refresh_learning_btn)
        
        learning_group.setLayout(learning_layout)
        layout.addWidget(learning_group)
        
        # ===== DECISION AGENT =====
        decision_group = QGroupBox("Autonomous Decision-Making Agent")
        decision_layout = QVBoxLayout()
        
        # Enable/disable
        decision_control = QHBoxLayout()
        self.decision_checkbox = QCheckBox("Enable Decision Agent")
        self.decision_checkbox.stateChanged.connect(self._toggle_decision_agent)
        decision_control.addWidget(self.decision_checkbox)
        
        self.decision_status = QLabel("Status: Disabled")
        self.decision_status.setStyleSheet("color: #ff6b6b;")
        decision_control.addWidget(self.decision_status)
        decision_control.addStretch()
        decision_layout.addLayout(decision_control)
        
        # Decision options
        decision_opts = QFormLayout()
        
        self.cvss_threshold = QDoubleSpinBox()
        self.cvss_threshold.setRange(1.0, 10.0)
        self.cvss_threshold.setValue(7.0)
        self.cvss_threshold.setSingleStep(0.5)
        decision_opts.addRow("CVSS Threshold:", self.cvss_threshold)
        
        self.auto_prioritize_check = QCheckBox("Auto-Prioritize Targets")
        self.auto_prioritize_check.setChecked(True)
        decision_opts.addRow("Prioritization:", self.auto_prioritize_check)
        
        self.explain_reasoning_check = QCheckBox("Explain Reasoning")
        self.explain_reasoning_check.setChecked(True)
        decision_opts.addRow("Explanations:", self.explain_reasoning_check)
        
        decision_layout.addLayout(decision_opts)
        
        # Decision history
        decision_layout.addWidget(QLabel("Recent Decisions:"))
        self.decisions_table = QTableWidget()
        self.decisions_table.setColumnCount(4)
        self.decisions_table.setHorizontalHeaderLabels(
            ["Target", "Decision", "Risk Level", "Confidence"]
        )
        self.decisions_table.setMaximumHeight(150)
        decision_layout.addWidget(self.decisions_table)
        
        # Test decision
        test_decision_btn = QPushButton("Test Decision on Sample Target")
        test_decision_btn.clicked.connect(self._test_decision)
        decision_layout.addWidget(test_decision_btn)
        
        decision_group.setLayout(decision_layout)
        layout.addWidget(decision_group)
        
        # ===== STATUS DISPLAY =====
        status_group = QGroupBox("Autonomous Operations Status")
        status_layout = QVBoxLayout()
        
        self.ops_status = QTextEdit()
        self.ops_status.setReadOnly(True)
        self.ops_status.setMaximumHeight(120)
        self.ops_status.setStyleSheet(
            "QTextEdit { background-color: #1e1e1e; color: #00ff00; font-family: Courier; }"
        )
        status_layout.addWidget(self.ops_status)
        
        refresh_status_btn = QPushButton("Refresh Status")
        refresh_status_btn.clicked.connect(self._update_status)
        status_layout.addWidget(refresh_status_btn)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        layout.addStretch()
        self.setLayout(layout)
        
        # Initialize engines
        if HAS_AUTONOMOUS_OPS:
            self.threat_response = ThreatResponseEngine(self.db_path)
            self.learning_engine = ContinuousLearningEngine(self.db_path)
            self.decision_agent = DecisionMakingAgent(
                self.learning_engine, self.threat_response
            )
        
        self._update_status()
    
    def _toggle_threat_response(self, state):
        """Toggle threat response"""
        if not HAS_AUTONOMOUS_OPS:
            return
        
        if state == Qt.CheckState.Checked.value:
            if self.threat_response.enable_auto_response(
                block_ips=True,
                auto_patch=self.auto_patch_check.isChecked(),
                auto_exploit=self.auto_exploit_check.isChecked(),
                threshold=self.threat_threshold.value()
            ):
                self.threat_status.setText("Status: Active")
                self.threat_status.setStyleSheet("color: #51cf66;")
            else:
                self.threat_checkbox.setChecked(False)
        else:
            self.threat_response.enabled = False
            self.threat_status.setText("Status: Disabled")
            self.threat_status.setStyleSheet("color: #ff6b6b;")
    
    def _toggle_learning(self, state):
        """Toggle learning engine"""
        if not HAS_AUTONOMOUS_OPS:
            return
        
        if state == Qt.CheckState.Checked.value:
            if self.learning_engine.enable_continuous_learning(
                auto_update_exploits=self.auto_update_check.isChecked(),
                pattern_generation=self.pattern_gen_check.isChecked(),
                success_feedback_loop=self.feedback_loop_check.isChecked()
            ):
                self.learning_status.setText("Status: Active")
                self.learning_status.setStyleSheet("color: #51cf66;")
                self._refresh_learning_stats()
            else:
                self.learning_checkbox.setChecked(False)
        else:
            self.learning_engine.enabled = False
            self.learning_status.setText("Status: Disabled")
            self.learning_status.setStyleSheet("color: #ff6b6b;")
    
    def _toggle_decision_agent(self, state):
        """Toggle decision agent"""
        if not HAS_AUTONOMOUS_OPS:
            return
        
        if state == Qt.CheckState.Checked.value:
            if self.decision_agent.enable_autonomous_decisions(
                vulnerability_threshold=self.cvss_threshold.value(),
                auto_prioritize=self.auto_prioritize_check.isChecked(),
                explain_reasoning=self.explain_reasoning_check.isChecked()
            ):
                self.decision_status.setText("Status: Active")
                self.decision_status.setStyleSheet("color: #51cf66;")
            else:
                self.decision_checkbox.setChecked(False)
        else:
            self.decision_agent.enabled = False
            self.decision_status.setText("Status: Disabled")
            self.decision_status.setStyleSheet("color: #ff6b6b;")
    
    def _refresh_learning_stats(self):
        """Refresh learning statistics"""
        if not self.learning_engine:
            return
        
        stats = self.learning_engine.get_learning_stats()
        stats_text = json.dumps(stats, indent=2, default=str)
        self.learning_stats.setText(stats_text)
        
        # Update exploits table
        exploits = self.learning_engine.get_top_exploits(10)
        self.exploits_table.setRowCount(0)
        
        for idx, exploit in enumerate(exploits):
            self.exploits_table.insertRow(idx)
            self.exploits_table.setItem(idx, 0, QTableWidgetItem(exploit.exploit_name))
            self.exploits_table.setItem(idx, 1, QTableWidgetItem(exploit.target_type))
            self.exploits_table.setItem(
                idx, 2, 
                QTableWidgetItem(f"{exploit.success_rate:.1%}")
            )
            self.exploits_table.setItem(
                idx, 3,
                QTableWidgetItem(f"{exploit.confidence:.2f}")
            )
    
    def _test_decision(self):
        """Test decision agent on sample target"""
        if not self.decision_agent or not self.decision_agent.enabled:
            return
        
        # Sample target
        sample_target = {
            "name": "Test-Server",
            "type": "web_server",
            "cvss_score": 8.5,
            "vulnerabilities": ["SQL Injection", "RCE"]
        }
        
        decision = self.decision_agent.evaluate_target(sample_target)
        
        # Show decision
        history = self.decision_agent.get_decision_history()
        self.decisions_table.setRowCount(0)
        
        for idx, dec in enumerate(history[-10:]):
            self.decisions_table.insertRow(idx)
            self.decisions_table.setItem(idx, 0, QTableWidgetItem(dec.get("target", "")))
            self.decisions_table.setItem(idx, 1, QTableWidgetItem(dec.get("decision", "")))
            self.decisions_table.setItem(idx, 2, QTableWidgetItem(dec.get("risk_level", "")))
            self.decisions_table.setItem(
                idx, 3,
                QTableWidgetItem(f"{dec.get('confidence', 0):.2f}")
            )
    
    def _update_status(self):
        """Update operational status"""
        status_lines = [
            "=== Autonomous Operations Status ===",
            f"Threat Response: {'Active' if self.threat_response and self.threat_response.enabled else 'Inactive'}",
            f"Learning Engine: {'Active' if self.learning_engine and self.learning_engine.enabled else 'Inactive'}",
            f"Decision Agent: {'Active' if self.decision_agent and self.decision_agent.enabled else 'Inactive'}",
        ]
        
        if self.threat_response:
            blocked = len(self.threat_response.get_blocked_ips())
            status_lines.append(f"Blocked IPs: {blocked}")
            self.blocked_ips_list.setPlainText(
                "\n".join(self.threat_response.get_blocked_ips())
            )
        
        if self.learning_engine:
            stats = self.learning_engine.get_learning_stats()
            status_lines.append(
                f"Exploits Learned: {stats.get('total_exploits', 0)}"
            )
            status_lines.append(
                f"Avg Success Rate: {stats.get('average_success_rate', 0):.1%}"
            )
        
        self.ops_status.setText("\n".join(status_lines))


def main():
    """Module initialization"""
    logger.info("Autonomous Operations GUI module loaded successfully")
    return {
        "status": "ready",
        "module": "autonomous_ops_gui",
        "version": "1.0",
        "description": "GUI for Autonomous Operations"
    }


if __name__ == "__main__":
    result = main()
    print(json.dumps(result, indent=2))
