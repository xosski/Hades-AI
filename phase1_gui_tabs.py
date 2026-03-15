"""
Phase 1 GUI Tabs for HadesAI
Provides UI components for:
- ObsidianCore (AI Orchestration)
- EthicalControl (Authorization & Compliance)
- MalwareEngine (Payload Mutation)
"""

import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QPushButton, QTextEdit,
    QLabel, QLineEdit, QComboBox, QSpinBox, QCheckBox, QTableWidget,
    QTableWidgetItem, QListWidget, QListWidgetItem, QSplitter, QGroupBox,
    QFormLayout, QMessageBox, QProgressBar, QFileDialog, QPlainTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor

from modules.obsidian_core_integration import get_obsidian_core
from modules.ethical_control_integration import get_ethical_control
from modules.malware_engine_integration import get_malware_engine, MutationMethod

logger = logging.getLogger("Phase1GUI")

# ============================================================================
# OBSIDIAN CORE TAB
# ============================================================================

class ObsidianCoreTab(QWidget):
    """UI Tab for ObsidianCore AI Orchestration System"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.obsidian = get_obsidian_core()
        self.setup_ui()
        self.update_status()
    
    def setup_ui(self):
        """Setup the UI layout"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🤖 ObsidianCore - Advanced AI Orchestration")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Status section
        status_group = QGroupBox("System Status")
        status_layout = QFormLayout()
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        status_layout.addRow("Status:", self.status_text)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Control section
        control_group = QGroupBox("Engine Controls")
        control_layout = QVBoxLayout()
        
        # Attack Engine
        attack_box = QGroupBox("Attack Engine")
        attack_layout = QHBoxLayout()
        self.attack_type = QComboBox()
        self.attack_type.addItems(['exploitation', 'brute_force', 'privilege_escalation', 'lateral_movement'])
        self.attack_target = QLineEdit()
        self.attack_target.setPlaceholderText("Target URL/IP")
        self.attack_btn = QPushButton("⚔️ Execute Attack")
        self.attack_btn.clicked.connect(self.execute_attack)
        attack_layout.addWidget(QLabel("Attack Type:"))
        attack_layout.addWidget(self.attack_type)
        attack_layout.addWidget(QLabel("Target:"))
        attack_layout.addWidget(self.attack_target)
        attack_layout.addWidget(self.attack_btn)
        attack_box.setLayout(attack_layout)
        control_layout.addWidget(attack_box)
        
        # Defense Engine
        defense_box = QGroupBox("Defense Engine")
        defense_layout = QHBoxLayout()
        self.defense_type = QComboBox()
        self.defense_type.addItems(['firewall', 'behavioral', 'ids', 'adaptive'])
        self.defense_threshold = QSpinBox()
        self.defense_threshold.setRange(0, 100)
        self.defense_threshold.setValue(80)
        self.defense_btn = QPushButton("🛡️ Deploy Defense")
        self.defense_btn.clicked.connect(self.deploy_defense)
        defense_layout.addWidget(QLabel("Defense Type:"))
        defense_layout.addWidget(self.defense_type)
        defense_layout.addWidget(QLabel("Threshold:"))
        defense_layout.addWidget(self.defense_threshold)
        defense_layout.addWidget(self.defense_btn)
        defense_box.setLayout(defense_layout)
        control_layout.addWidget(defense_box)
        
        # Payload Engine
        payload_box = QGroupBox("Payload Engine")
        payload_layout = QHBoxLayout()
        self.payload_type = QComboBox()
        self.payload_type.addItems(['shellcode', 'reverse_shell', 'persistence_agent', 'data_exfiltration'])
        self.payload_btn = QPushButton("📦 Generate Payload")
        self.payload_btn.clicked.connect(self.generate_payload)
        payload_layout.addWidget(QLabel("Payload Type:"))
        payload_layout.addWidget(self.payload_type)
        payload_layout.addWidget(self.payload_btn)
        payload_box.setLayout(payload_layout)
        control_layout.addWidget(payload_box)
        
        # Movement Engine
        movement_box = QGroupBox("Movement Engine")
        movement_layout = QHBoxLayout()
        self.movement_from = QLineEdit()
        self.movement_from.setPlaceholderText("Current Position")
        self.movement_to = QLineEdit()
        self.movement_to.setPlaceholderText("Target Position")
        self.movement_btn = QPushButton("🎯 Plan Movement")
        self.movement_btn.clicked.connect(self.plan_movement)
        movement_layout.addWidget(QLabel("From:"))
        movement_layout.addWidget(self.movement_from)
        movement_layout.addWidget(QLabel("To:"))
        movement_layout.addWidget(self.movement_to)
        movement_layout.addWidget(self.movement_btn)
        movement_box.setLayout(movement_layout)
        control_layout.addWidget(movement_box)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Results section
        results_group = QGroupBox("Execution Results")
        results_layout = QVBoxLayout()
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Capabilities section
        caps_group = QGroupBox("Available Capabilities")
        caps_layout = QVBoxLayout()
        self.capabilities_list = QListWidget()
        caps_layout.addWidget(self.capabilities_list)
        caps_group.setLayout(caps_layout)
        layout.addWidget(caps_group)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Status")
        refresh_btn.clicked.connect(self.update_status)
        layout.addWidget(refresh_btn)
        
        self.setLayout(layout)
    
    def update_status(self):
        """Update system status display"""
        try:
            status = self.obsidian.get_system_status()
            self.status_text.setText(
                f"Core Available: {status['core_available']}\n"
                f"Integrated: {status['integrated']}\n"
                f"Engines: {len(status['engines'])} initialized"
            )
            
            # Update capabilities list
            caps = self.obsidian.get_capabilities()
            self.capabilities_list.clear()
            for category, items in caps.items():
                self.capabilities_list.addItem(f"[{category.upper()}]")
                for item in items:
                    self.capabilities_list.addItem(f"  • {item}")
            
        except Exception as e:
            self.status_text.setText(f"Error: {str(e)}")
            logger.error(f"Status update failed: {str(e)}")
    
    def execute_attack(self):
        """Execute attack"""
        try:
            attack_type = self.attack_type.currentText()
            target = self.attack_target.text()
            
            if not target:
                QMessageBox.warning(self, "Input Error", "Please enter a target")
                return
            
            result = self.obsidian.execute_attack(attack_type, target)
            self.results_text.append(
                f"[ATTACK EXECUTED]\n"
                f"Type: {attack_type}\n"
                f"Target: {target}\n"
                f"Success: {result.get('success')}\n"
                f"Details: {str(result.get('data', {}))}\n"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Attack failed: {str(e)}")
            logger.error(f"Attack execution failed: {str(e)}")
    
    def deploy_defense(self):
        """Deploy defense"""
        try:
            defense_type = self.defense_type.currentText()
            threshold = self.defense_threshold.value()
            
            result = self.obsidian.deploy_defense(defense_type, threshold=threshold/100)
            self.results_text.append(
                f"[DEFENSE DEPLOYED]\n"
                f"Type: {defense_type}\n"
                f"Threshold: {threshold}%\n"
                f"Deployed: {result.get('deployed')}\n"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Defense deployment failed: {str(e)}")
    
    def generate_payload(self):
        """Generate payload"""
        try:
            payload_type = self.payload_type.currentText()
            result = self.obsidian.generate_payload(payload_type)
            
            self.results_text.append(
                f"[PAYLOAD GENERATED]\n"
                f"Type: {payload_type}\n"
                f"Generated: {result.get('generated')}\n"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Payload generation failed: {str(e)}")
    
    def plan_movement(self):
        """Plan lateral movement"""
        try:
            from_pos = self.movement_from.text()
            to_pos = self.movement_to.text()
            
            if not from_pos or not to_pos:
                QMessageBox.warning(self, "Input Error", "Please enter both positions")
                return
            
            result = self.obsidian.plan_lateral_movement(from_pos, to_pos)
            self.results_text.append(
                f"[MOVEMENT PLANNED]\n"
                f"From: {from_pos}\n"
                f"To: {to_pos}\n"
                f"Path Found: {result.get('path_found')}\n"
                f"Path: {result.get('path', [])}\n"
                f"Techniques: {result.get('techniques', [])}\n"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Movement planning failed: {str(e)}")


# ============================================================================
# ETHICAL CONTROL TAB
# ============================================================================

class EthicalControlTab(QWidget):
    """UI Tab for EthicalControl Authorization & Compliance"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ec = get_ethical_control()
        self.setup_ui()
        self.update_status()
    
    def setup_ui(self):
        """Setup the UI layout"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🔒 EthicalControl - Authorization & Compliance")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Status section
        status_group = QGroupBox("System Status")
        status_layout = QFormLayout()
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        status_layout.addRow("Status:", self.status_text)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Authorization section
        auth_group = QGroupBox("Authorization Checks")
        auth_layout = QVBoxLayout()
        
        check_layout = QHBoxLayout()
        self.auth_operation = QLineEdit()
        self.auth_operation.setPlaceholderText("Operation type")
        self.auth_target = QLineEdit()
        self.auth_target.setPlaceholderText("Target")
        self.auth_exploit = QLineEdit()
        self.auth_exploit.setPlaceholderText("Exploit")
        self.auth_check_btn = QPushButton("✓ Check Authorization")
        self.auth_check_btn.clicked.connect(self.check_authorization)
        check_layout.addWidget(QLabel("Operation:"))
        check_layout.addWidget(self.auth_operation)
        check_layout.addWidget(QLabel("Target:"))
        check_layout.addWidget(self.auth_target)
        check_layout.addWidget(QLabel("Exploit:"))
        check_layout.addWidget(self.auth_exploit)
        check_layout.addWidget(self.auth_check_btn)
        auth_layout.addLayout(check_layout)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Whitelist section
        whitelist_group = QGroupBox("Whitelist Management")
        whitelist_layout = QVBoxLayout()
        
        # Targets
        target_layout = QHBoxLayout()
        self.new_target = QLineEdit()
        self.new_target.setPlaceholderText("New target to authorize")
        self.add_target_btn = QPushButton("➕ Add Target")
        self.add_target_btn.clicked.connect(self.add_target)
        target_layout.addWidget(QLabel("Target:"))
        target_layout.addWidget(self.new_target)
        target_layout.addWidget(self.add_target_btn)
        whitelist_layout.addLayout(target_layout)
        
        self.targets_list = QListWidget()
        self.targets_list.setMaximumHeight(100)
        whitelist_layout.addWidget(QLabel("Authorized Targets:"))
        whitelist_layout.addWidget(self.targets_list)
        
        # Exploits
        exploit_layout = QHBoxLayout()
        self.new_exploit = QLineEdit()
        self.new_exploit.setPlaceholderText("New exploit to authorize")
        self.add_exploit_btn = QPushButton("➕ Add Exploit")
        self.add_exploit_btn.clicked.connect(self.add_exploit)
        exploit_layout.addWidget(QLabel("Exploit:"))
        exploit_layout.addWidget(self.new_exploit)
        exploit_layout.addWidget(self.add_exploit_btn)
        whitelist_layout.addLayout(exploit_layout)
        
        self.exploits_list = QListWidget()
        self.exploits_list.setMaximumHeight(100)
        whitelist_layout.addWidget(QLabel("Authorized Exploits:"))
        whitelist_layout.addWidget(self.exploits_list)
        
        whitelist_group.setLayout(whitelist_layout)
        layout.addWidget(whitelist_group)
        
        # Results section
        results_group = QGroupBox("Results & Audit Log")
        results_layout = QVBoxLayout()
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Report buttons
        button_layout = QHBoxLayout()
        compliance_btn = QPushButton("📊 Compliance Report")
        compliance_btn.clicked.connect(self.show_compliance_report)
        audit_btn = QPushButton("📋 Audit Log")
        audit_btn.clicked.connect(self.show_audit_log)
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.update_status)
        button_layout.addWidget(compliance_btn)
        button_layout.addWidget(audit_btn)
        button_layout.addWidget(refresh_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def update_status(self):
        """Update status display"""
        try:
            status = self.ec.get_status()
            self.status_text.setText(
                f"Enabled: {status['enabled']}\n"
                f"Environment: {status['environment']}\n"
                f"Authorization Level: {status['authorization_level']}\n"
                f"Environment Authorized: {status['environment_authorized']}\n"
                f"Operations Logged: {status['operations_logged']}\n"
                f"Violations Detected: {status['violations_detected']}"
            )
            
            # Update whitelist displays
            self.targets_list.clear()
            for target in self.ec.get_authorized_targets():
                self.targets_list.addItem(target)
            
            self.exploits_list.clear()
            for exploit in self.ec.get_authorized_exploits():
                self.exploits_list.addItem(exploit)
                
        except Exception as e:
            self.status_text.setText(f"Error: {str(e)}")
            logger.error(f"Status update failed: {str(e)}")
    
    def check_authorization(self):
        """Check authorization"""
        try:
            operation = self.auth_operation.text() or "test"
            target = self.auth_target.text() or None
            exploit = self.auth_exploit.text() or None
            
            authorized = self.ec.is_authorized(operation, target, exploit)
            
            self.results_text.append(
                f"[AUTHORIZATION CHECK]\n"
                f"Operation: {operation}\n"
                f"Target: {target}\n"
                f"Exploit: {exploit}\n"
                f"Authorized: {authorized}\n"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Check failed: {str(e)}")
    
    def add_target(self):
        """Add authorized target"""
        target = self.new_target.text()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target")
            return
        
        try:
            self.ec.add_authorized_target(target)
            self.new_target.clear()
            self.targets_list.addItem(target)
            self.results_text.append(f"✓ Target authorized: {target}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed: {str(e)}")
    
    def add_exploit(self):
        """Add authorized exploit"""
        exploit = self.new_exploit.text()
        if not exploit:
            QMessageBox.warning(self, "Input Error", "Please enter an exploit")
            return
        
        try:
            self.ec.add_authorized_exploit(exploit)
            self.new_exploit.clear()
            self.exploits_list.addItem(exploit)
            self.results_text.append(f"✓ Exploit authorized: {exploit}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed: {str(e)}")
    
    def show_compliance_report(self):
        """Show compliance report"""
        try:
            report = self.ec.generate_compliance_report()
            self.results_text.setText(
                f"[COMPLIANCE REPORT]\n"
                f"Environment: {report['environment']}\n"
                f"Auth Level: {report['authorization_level']}\n\n"
                f"Operations:\n"
                f"  Total: {report['operations']['total']}\n"
                f"  Authorized: {report['operations']['authorized']}\n"
                f"  Denied: {report['operations']['denied']}\n"
                f"  Rate: {report['operations']['authorization_rate']}\n\n"
                f"Violations:\n"
                f"  Total: {report['violations']['total']}\n"
                f"  Critical: {report['violations']['critical']}\n"
                f"  High: {report['violations']['high']}\n"
                f"  Status: {report['violations']['compliance_status']}\n"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Report failed: {str(e)}")
    
    def show_audit_log(self):
        """Show audit log"""
        try:
            log = self.ec.get_audit_log(limit=10)
            self.results_text.setText("[AUDIT LOG - Last 10 Operations]\n\n")
            for entry in log:
                self.results_text.append(
                    f"{entry['timestamp']}\n"
                    f"  Operation: {entry['operation']}\n"
                    f"  Target: {entry['target']}\n"
                    f"  Authorized: {entry['authorized']}\n"
                )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Log retrieval failed: {str(e)}")


# ============================================================================
# MALWARE ENGINE TAB
# ============================================================================

class MalwareEngineTab(QWidget):
    """UI Tab for MalwareEngine Payload Mutation"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = get_malware_engine()
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the UI layout"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🔄 MalwareEngine - Payload Mutation & Evasion")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Input section
        input_group = QGroupBox("Payload Input")
        input_layout = QVBoxLayout()
        self.payload_input = QPlainTextEdit()
        self.payload_input.setPlaceholderText("Enter payload code to mutate...")
        self.payload_input.setMaximumHeight(150)
        input_layout.addWidget(self.payload_input)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Mutation options
        options_group = QGroupBox("Mutation Options")
        options_layout = QVBoxLayout()
        
        mutation_layout = QHBoxLayout()
        self.mutation_method = QComboBox()
        self.mutation_method.addItems([m.value for m in MutationMethod])
        self.iterations = QSpinBox()
        self.iterations.setRange(1, 10)
        self.iterations.setValue(1)
        
        self.mutate_btn = QPushButton("🔄 Mutate Payload")
        self.mutate_btn.clicked.connect(self.mutate_payload)
        
        mutation_layout.addWidget(QLabel("Method:"))
        mutation_layout.addWidget(self.mutation_method)
        mutation_layout.addWidget(QLabel("Iterations:"))
        mutation_layout.addWidget(self.iterations)
        mutation_layout.addWidget(self.mutate_btn)
        options_layout.addLayout(mutation_layout)
        
        # Advanced options
        advanced_layout = QHBoxLayout()
        self.polymorphic_btn = QPushButton("🎲 Polymorphic Variants")
        self.polymorphic_btn.clicked.connect(self.generate_polymorphic)
        self.variants_count = QSpinBox()
        self.variants_count.setRange(1, 10)
        self.variants_count.setValue(5)
        
        self.anti_analysis_btn = QPushButton("🛡️ Anti-Analysis")
        self.anti_analysis_btn.clicked.connect(self.add_anti_analysis)
        
        self.staged_btn = QPushButton("📦 Staged Payload")
        self.staged_btn.clicked.connect(self.generate_staged)
        self.stages_count = QSpinBox()
        self.stages_count.setRange(1, 5)
        self.stages_count.setValue(2)
        
        advanced_layout.addWidget(self.polymorphic_btn)
        advanced_layout.addWidget(QLabel("Variants:"))
        advanced_layout.addWidget(self.variants_count)
        advanced_layout.addWidget(self.anti_analysis_btn)
        advanced_layout.addWidget(self.staged_btn)
        advanced_layout.addWidget(QLabel("Stages:"))
        advanced_layout.addWidget(self.stages_count)
        options_layout.addLayout(advanced_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Output section
        output_group = QGroupBox("Generated Payload")
        output_layout = QVBoxLayout()
        self.payload_output = QPlainTextEdit()
        self.payload_output.setReadOnly(True)
        output_layout.addWidget(self.payload_output)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Analysis section
        analysis_group = QGroupBox("Detection Analysis")
        analysis_layout = QVBoxLayout()
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setMaximumHeight(150)
        analysis_layout.addWidget(self.analysis_text)
        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)
        
        # Statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(100)
        stats_layout.addWidget(self.stats_text)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Analyze button
        analyze_btn = QPushButton("🔍 Analyze Detection Risk")
        analyze_btn.clicked.connect(self.analyze_detection)
        layout.addWidget(analyze_btn)
        
        self.setLayout(layout)
    
    def mutate_payload(self):
        """Mutate payload"""
        try:
            payload = self.payload_input.toPlainText()
            if not payload:
                QMessageBox.warning(self, "Input Error", "Please enter a payload")
                return
            
            method = MutationMethod[self.mutation_method.currentText().upper()]
            iterations = self.iterations.value()
            
            result = self.engine.mutate_payload(payload, method, iterations)
            
            self.payload_output.setPlainText(result.get('final_payload', ''))
            
            # Show mutations info
            mutations_info = f"Mutations Applied: {len(result['mutations'])}\n"
            for i, m in enumerate(result['mutations'], 1):
                mutations_info += f"  {i}. {m['method']}: {m['size']} bytes (+{m['size_change_percent']:.1f}%)\n"
            
            self.analysis_text.setText(
                f"Original Size: {result['original_size']} bytes\n"
                f"Final Size: {result['final_size']} bytes\n"
                f"Total Size Increase: {result['size_increase_percent']:.1f}%\n\n"
                f"{mutations_info}"
            )
            
            # Update statistics
            self.update_statistics()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Mutation failed: {str(e)}")
    
    def generate_polymorphic(self):
        """Generate polymorphic variants"""
        try:
            payload = self.payload_input.toPlainText()
            if not payload:
                QMessageBox.warning(self, "Input Error", "Please enter a payload")
                return
            
            variants_count = self.variants_count.value()
            variants = self.engine.generate_polymorphic_payload(payload, variants_count)
            
            output = f"Generated {len(variants)} Polymorphic Variants:\n\n"
            for var in variants:
                output += f"Variant {var['variation_id']}:\n"
                output += f"  Size: {var['size']} bytes\n"
                output += f"  Methods: {', '.join(var['methods_used'])}\n"
                output += f"  Payload Preview: {var['payload'][:100]}...\n\n"
            
            self.payload_output.setPlainText(output)
            self.analysis_text.setText(f"✓ Generated {len(variants)} polymorphic variants")
            self.update_statistics()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Generation failed: {str(e)}")
    
    def add_anti_analysis(self):
        """Add anti-analysis to payload"""
        try:
            payload = self.payload_input.toPlainText()
            if not payload:
                QMessageBox.warning(self, "Input Error", "Please enter a payload")
                return
            
            result = self.engine.generate_anti_analysis_payload(payload)
            self.payload_output.setPlainText(result)
            self.analysis_text.setText("✓ Anti-analysis techniques added:\n  • Debugger detection\n  • VM detection\n  • Conditional execution")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed: {str(e)}")
    
    def generate_staged(self):
        """Generate staged payload"""
        try:
            payload = self.payload_input.toPlainText()
            if not payload:
                QMessageBox.warning(self, "Input Error", "Please enter a payload")
                return
            
            stages = self.stages_count.value()
            result = self.engine.generate_staged_payload(payload, stages)
            
            self.payload_output.setPlainText(result['first_stage'])
            
            stage_info = f"Generated {result['total_stages']}-Stage Payload:\n\n"
            for stage in result['stages']:
                stage_info += f"Stage {stage['stage_number']}: {stage['size']} bytes\n"
            
            self.analysis_text.setText(stage_info)
            self.update_statistics()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed: {str(e)}")
    
    def analyze_detection(self):
        """Analyze detection probability"""
        try:
            payload = self.payload_output.toPlainText()
            if not payload:
                QMessageBox.warning(self, "Input Error", "Generate a payload first")
                return
            
            analysis = self.engine.estimate_detection_probability(payload)
            
            output = f"Detection Analysis:\n\n"
            output += f"Detection Probability: {analysis['detection_probability']*100:.1f}%\n"
            output += f"Evasion Score: {analysis['evasion_score']*100:.1f}%\n\n"
            
            if analysis['suspicious_indicators']:
                output += "Suspicious Indicators:\n"
                for indicator in analysis['suspicious_indicators']:
                    output += f"  • {indicator}\n"
                output += "\n"
            
            if analysis['recommendations']:
                output += "Recommendations:\n"
                for rec in analysis['recommendations']:
                    output += f"  • {rec}\n"
            
            self.analysis_text.setText(output)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Analysis failed: {str(e)}")
    
    def update_statistics(self):
        """Update engine statistics"""
        try:
            stats = self.engine.get_statistics()
            self.stats_text.setText(
                f"Total Mutations: {stats['total_mutations']}\n"
                f"Payloads Generated: {stats['payloads_generated']}\n"
                f"Avg Size Increase: {stats['average_size_increase']:.1f}%\n"
                f"Success Rate: {stats['success_rate']:.1f}%\n"
                f"Methods Used: {len(stats['mutation_methods_used'])}"
            )
        except Exception as e:
            logger.error(f"Statistics update failed: {str(e)}")
