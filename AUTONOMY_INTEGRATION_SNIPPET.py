"""
Quick Integration Snippet for Predictive Autonomy

Add this to HadesAI.py to enable autonomous decision-making with
predictive execution and adaptive thresholds.
"""

# ============================================================================
# PREDICTIVE AUTONOMY INTEGRATION (Add to HadesAI class)
# ============================================================================

# In HadesAI.__init__():
def init_autonomous_intelligence(self):
    """Initialize autonomous intelligence system"""
    try:
        from modules.autonomous_intelligence import (
            AutonomousIntelligence, 
            AutonomyLevel,
            DecisionContext
        )
        
        self.autonomy = AutonomousIntelligence(
            cognitive_layer=self.cognitive_layer,
            action_executor=self.execute_autonomous_action,
            autonomy_level=AutonomyLevel.SEMI_AUTONOMOUS
        )
        
        self.autonomy_enabled = True
        logging.info("[OK] Autonomous Intelligence initialized")
        return True
    
    except ImportError as e:
        logging.warning(f"[!] Autonomous Intelligence not available: {e}")
        self.autonomy = None
        self.autonomy_enabled = False
        return False


# In HadesAI class, add this method:
def execute_autonomous_action(self, action_name: str, metadata: dict) -> dict:
    """
    Execute an autonomously-predicted action
    
    This is called by the autonomous intelligence system when it decides
    to execute a predicted action.
    """
    try:
        logging.info(f"[AUTO] Executing: {action_name}")
        
        # Route to appropriate handler
        if action_name == 'scan_port':
            return self._scan_target_ports(metadata)
        elif action_name == 'probe_service':
            return self._probe_service(metadata)
        elif action_name == 'exploit_vulnerability':
            return self._exploit_vulnerability(metadata)
        elif action_name == 'block_ip':
            return self._block_ip(metadata)
        elif action_name == 'escalate_privilege':
            return self._escalate_privilege(metadata)
        elif action_name == 'establish_persistence':
            return self._establish_persistence(metadata)
        else:
            return {'success': False, 'error': f'Unknown action: {action_name}'}
    
    except Exception as e:
        logging.error(f"[ERROR] Autonomous action failed: {e}")
        return {'success': False, 'error': str(e)}


# In HadesAI class, add this method:
def process_threat_autonomously(self, threat_data: dict, context: str = "THREAT_DETECTED"):
    """
    Process a detected threat using autonomous intelligence
    
    Called when threat_detected signal is emitted
    """
    if not self.autonomy_enabled or not self.autonomy:
        return
    
    try:
        from modules.autonomous_intelligence import DecisionContext
        
        # Map string context to enum
        context_map = {
            'THREAT_DETECTED': DecisionContext.THREAT_DETECTED,
            'ANOMALY_FOUND': DecisionContext.ANOMALY_FOUND,
            'PATTERN_MATCH': DecisionContext.PATTERN_MATCH,
            'RESOURCE_CONSTRAINED': DecisionContext.RESOURCE_CONSTRAINED,
        }
        
        ctx = context_map.get(context, DecisionContext.THREAT_DETECTED)
        
        # Let autonomous system handle it
        decision = self.autonomy.process_observation(threat_data, ctx)
        
        if decision:
            # Log in UI
            status = "EXECUTED" if decision.success else "SUGGESTED"
            msg = f"[AUTONOMY] {status}: {decision.predicted_action.action if decision.predicted_action else 'N/A'} - {decision.rationale}"
            self.log_message(msg)
            
            # Update autonomy status in UI
            self.update_autonomy_status()
    
    except Exception as e:
        logging.error(f"[ERROR] Autonomous threat processing failed: {e}")


# In HadesAI class, add this method:
def update_autonomy_status(self):
    """Update autonomy status display in UI"""
    if not self.autonomy:
        return
    
    try:
        status = self.autonomy.get_autonomy_status()
        
        # Update status bar or UI element
        status_text = (
            f"AUTONOMY: {status['autonomy_level']} | "
            f"Decisions: {status['total_decisions']} | "
            f"Success: {status['success_rate']:.0%} | "
            f"Accuracy: {status['prediction_accuracy']:.0%}"
        )
        
        # Update your status bar/label
        if hasattr(self, 'status_bar'):
            self.status_bar.showMessage(status_text)
    
    except Exception as e:
        logging.error(f"[ERROR] Failed to update autonomy status: {e}")


# In HadesAI class, add this method:
def show_autonomy_dashboard(self):
    """Show comprehensive autonomy intelligence dashboard"""
    if not self.autonomy:
        self.chat_display.append("[!] Autonomy system not available")
        return
    
    try:
        import json
        
        # Get comprehensive status
        full_status = self.autonomy.get_comprehensive_status()
        
        # Get decision log
        decisions = self.autonomy.get_decision_log(limit=10)
        
        # Get threshold adjustments if available
        adjustments = []
        if self.autonomy.thresholds:
            adjustments = self.autonomy.thresholds.get_adjustment_history(limit=5)
        
        # Format output
        output = "\n" + "=" * 70 + "\n"
        output += "AUTONOMOUS INTELLIGENCE DASHBOARD\n"
        output += "=" * 70 + "\n\n"
        
        # Autonomy status
        output += "[AUTONOMY STATUS]\n"
        autonomy = full_status['autonomy']
        for key, value in autonomy.items():
            if key.endswith('_rate') or key.endswith('_accuracy'):
                output += f"  {key}: {value:.1%}\n"
            else:
                output += f"  {key}: {value}\n"
        
        output += "\n[MODULES]\n"
        for module, available in full_status['modules'].items():
            status = "OK" if available else "UNAVAILABLE"
            output += f"  {module}: {status}\n"
        
        # Recent decisions
        output += "\n[RECENT AUTONOMOUS DECISIONS]\n"
        for d in decisions[-5:]:
            output += f"  [{d['timestamp']}] {d['context']}\n"
            output += f"    Action: {d['action']}\n"
            output += f"    Confidence: {d['confidence']:.1%}\n"
            output += f"    Result: {'SUCCESS' if d['success'] else 'FAILED'}\n"
        
        # Threshold adjustments
        if adjustments:
            output += "\n[RECENT THRESHOLD ADJUSTMENTS]\n"
            for adj in adjustments[-3:]:
                output += f"  {adj['threshold']}: {adj['old_value']:.3f} -> {adj['new_value']:.3f}\n"
                output += f"    Reason: {adj['reason']}\n"
        
        output += "\n" + "=" * 70 + "\n"
        
        self.chat_display.append(output)
    
    except Exception as e:
        self.chat_display.append(f"[ERROR] Failed to show autonomy dashboard: {e}")


# In HadesAI class, add these configuration methods:
def set_autonomy_level(self, level_name: str):
    """Set autonomy level (MANUAL, ASSISTED, SEMI_AUTONOMOUS, FULLY_AUTONOMOUS)"""
    if not self.autonomy:
        return
    
    try:
        from modules.autonomous_intelligence import AutonomyLevel
        
        level_map = {
            'MANUAL': AutonomyLevel.MANUAL,
            'ASSISTED': AutonomyLevel.ASSISTED,
            'SEMI_AUTONOMOUS': AutonomyLevel.SEMI_AUTONOMOUS,
            'FULLY_AUTONOMOUS': AutonomyLevel.FULLY_AUTONOMOUS,
        }
        
        level = level_map.get(level_name)
        if level:
            self.autonomy.set_autonomy_level(level)
            self.log_message(f"[OK] Autonomy level set to: {level_name}")
    
    except Exception as e:
        self.log_message(f"[ERROR] Failed to set autonomy level: {e}")


def set_predictor_confidence(self, threshold: float):
    """Set minimum confidence for autonomous action execution"""
    if not self.autonomy or not self.autonomy.predictor:
        return
    
    try:
        threshold = max(0.0, min(1.0, threshold))
        self.autonomy.set_predictor_confidence_threshold(threshold)
        self.log_message(f"[OK] Predictor confidence threshold: {threshold:.0%}")
    
    except Exception as e:
        self.log_message(f"[ERROR] Failed to set confidence threshold: {e}")


# ============================================================================
# UI TAB: Add "Autonomy Control" Tab (Example for QTabWidget)
# ============================================================================

def create_autonomy_control_tab(self):
    """Create autonomy control UI tab"""
    try:
        from PyQt6.QtWidgets import (
            QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, 
            QComboBox, QSlider, QPushButton, QTextEdit
        )
        from PyQt6.QtCore import Qt
        
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Autonomy Level Control
        level_group = QGroupBox("Autonomy Level")
        level_layout = QHBoxLayout()
        level_combo = QComboBox()
        level_combo.addItems(['MANUAL', 'ASSISTED', 'SEMI_AUTONOMOUS', 'FULLY_AUTONOMOUS'])
        level_combo.setCurrentText('SEMI_AUTONOMOUS')
        level_combo.currentTextChanged.connect(
            lambda x: self.set_autonomy_level(x)
        )
        level_layout.addWidget(QLabel("Level:"))
        level_layout.addWidget(level_combo)
        level_group.setLayout(level_layout)
        layout.addWidget(level_group)
        
        # Confidence Threshold Control
        conf_group = QGroupBox("Confidence Threshold")
        conf_layout = QHBoxLayout()
        conf_slider = QSlider(Qt.Orientation.Horizontal)
        conf_slider.setMinimum(0)
        conf_slider.setMaximum(100)
        conf_slider.setValue(65)
        conf_label = QLabel("65%")
        conf_slider.valueChanged.connect(
            lambda v: (self.set_predictor_confidence(v/100), conf_label.setText(f"{v}%"))
        )
        conf_layout.addWidget(QLabel("Threshold:"))
        conf_layout.addWidget(conf_slider)
        conf_layout.addWidget(conf_label)
        conf_group.setLayout(conf_layout)
        layout.addWidget(conf_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        dashboard_btn = QPushButton("Show Dashboard")
        dashboard_btn.clicked.connect(self.show_autonomy_dashboard)
        clear_btn = QPushButton("Clear History")
        clear_btn.clicked.connect(lambda: self.autonomy.clear_decision_history())
        btn_layout.addWidget(dashboard_btn)
        btn_layout.addWidget(clear_btn)
        layout.addLayout(btn_layout)
        
        # Status display
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        self.autonomy_status_display = QTextEdit()
        self.autonomy_status_display.setReadOnly(True)
        status_layout.addWidget(self.autonomy_status_display)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        
        return tab
    
    except Exception as e:
        logging.error(f"[ERROR] Failed to create autonomy control tab: {e}")
        return None


# ============================================================================
# SIGNAL CONNECTIONS (Add in HadesAI.setup_signals)
# ============================================================================

# Connect threat detection to autonomy
def connect_autonomy_signals(self):
    """Connect signals to autonomous intelligence"""
    if not self.autonomy:
        return
    
    try:
        # When threats are detected, process them autonomously
        if hasattr(self, 'network_monitor') and hasattr(self.network_monitor, 'threat_detected'):
            self.network_monitor.threat_detected.connect(
                lambda threat: self.process_threat_autonomously(threat)
            )
        
        # When defense engine detects issues
        if hasattr(self, 'defense_engine') and hasattr(self.defense_engine, 'threat_detected'):
            self.defense_engine.threat_detected.connect(
                lambda data: self.process_threat_autonomously(data, 'THREAT_DETECTED')
            )
    
    except Exception as e:
        logging.warning(f"[!] Failed to connect autonomy signals: {e}")


# ============================================================================
# USAGE IN HadesAI.run()
# ============================================================================

def example_autonomous_operation(self):
    """Example: Process a threat autonomously"""
    
    # Simulate threat detection
    threat = {
        'threat_count': 10,
        'anomaly_score': 0.75,
        'attack_detected': True,
        'threat_type': 'port_scan'
    }
    
    # Let autonomous system handle it
    self.process_threat_autonomously(threat, 'THREAT_DETECTED')
    
    # System will:
    # 1. Analyze threat level
    # 2. Update thresholds automatically
    # 3. Predict best response action
    # 4. Execute if confidence is high (e.g., >65%)
    # 5. Log decision with rationale


# ============================================================================
# INTEGRATION CHECKLIST
# ============================================================================

"""
[ ] 1. Add init_autonomous_intelligence() call in HadesAI.__init__()
[ ] 2. Add execute_autonomous_action() method to HadesAI
[ ] 3. Add process_threat_autonomously() method to HadesAI
[ ] 4. Add update_autonomy_status() method to HadesAI
[ ] 5. Add show_autonomy_dashboard() method to HadesAI
[ ] 6. Add autonomy control methods (set_autonomy_level, etc.)
[ ] 7. Create autonomy control UI tab with create_autonomy_control_tab()
[ ] 8. Connect threat signals via connect_autonomy_signals()
[ ] 9. Test with semi-autonomous mode first
[ ] 10. Monitor success rates and adjust thresholds
[ ] 11. Gradually increase autonomy as confidence improves
"""

# ============================================================================
# EXAMPLE: FULL INTEGRATION
# ============================================================================

def integrate_autonomy_into_hades(self):
    """
    Complete autonomy integration.
    Call this from HadesAI.__init__() after other systems are ready.
    """
    
    # Initialize system
    self.init_autonomous_intelligence()
    
    if self.autonomy:
        # Create UI tab
        autonomy_tab = self.create_autonomy_control_tab()
        if autonomy_tab and hasattr(self, 'tabs'):
            self.tabs.addTab(autonomy_tab, "Autonomy Control")
        
        # Connect signals
        self.connect_autonomy_signals()
        
        # Set default configuration (semi-autonomous)
        self.set_autonomy_level('SEMI_AUTONOMOUS')
        self.set_predictor_confidence(0.65)
        
        print("[OK] Autonomous Intelligence fully integrated")
