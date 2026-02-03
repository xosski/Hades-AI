"""
Advanced Autonomy GUI
Controls for Self-Healing, Adaptive Strategies, Autonomous Scheduling, and Multi-Agent Systems
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, QPushButton,
    QCheckBox, QSpinBox, QDoubleSpinBox, QComboBox, QTableWidget,
    QTableWidgetItem, QTextEdit, QGroupBox, QListWidget, QListWidgetItem,
    QProgressBar, QMessageBox, QStatusBar
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor
import logging
import time
from datetime import datetime
from typing import Optional

from modules.self_healing_system import SelfHealingSystem
from modules.adaptive_strategy_engine import AdaptiveStrategyEngine, StrategyType
from modules.autonomous_scheduler import AutonomousScheduler, TaskPriority
from modules.multi_agent_system import MultiAgentSystem, AgentRole

logger = logging.getLogger("AdvancedAutonomyGUI")


class SelfHealingTab(QWidget):
    """Self-Healing System Controls"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        super().__init__()
        self.healing = SelfHealingSystem(db_path)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Status Group
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Status: Disabled")
        status_layout.addWidget(self.status_label)
        
        button_layout = QHBoxLayout()
        self.enable_btn = QPushButton("Enable Self-Healing")
        self.enable_btn.clicked.connect(self.enable_healing)
        self.monitor_btn = QPushButton("Start Monitoring")
        self.monitor_btn.clicked.connect(self.start_monitoring)
        
        button_layout.addWidget(self.enable_btn)
        button_layout.addWidget(self.monitor_btn)
        status_layout.addLayout(button_layout)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Configuration Group
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout()
        
        self.auto_retry = QCheckBox("Auto Retry Failed Operations")
        self.auto_retry.setChecked(True)
        self.auto_rollback = QCheckBox("Auto Rollback on Error")
        self.auto_rollback.setChecked(True)
        self.auto_heal = QCheckBox("Auto Healing")
        self.auto_heal.setChecked(True)
        
        config_layout.addWidget(self.auto_retry)
        config_layout.addWidget(self.auto_rollback)
        config_layout.addWidget(self.auto_heal)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Health Status
        health_group = QGroupBox("Health Status")
        health_layout = QVBoxLayout()
        
        self.health_status = QLabel("No metrics available")
        health_layout.addWidget(self.health_status)
        
        self.health_table = QTableWidget()
        self.health_table.setColumnCount(4)
        self.health_table.setHorizontalHeaderLabels(
            ["Component", "Metric", "Value", "Status"]
        )
        health_layout.addWidget(self.health_table)
        
        health_group.setLayout(health_layout)
        layout.addWidget(health_group)
        
        # Error History
        error_group = QGroupBox("Error History")
        error_layout = QVBoxLayout()
        
        self.error_list = QTableWidget()
        self.error_list.setColumnCount(5)
        self.error_list.setHorizontalHeaderLabels(
            ["Component", "Error Type", "Severity", "Resolved", "Time"]
        )
        error_layout.addWidget(self.error_list)
        
        error_group.setLayout(error_layout)
        layout.addWidget(error_group)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self.refresh_status)
        layout.addWidget(refresh_btn)
        
        self.setLayout(layout)
        
        # Timer for updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.refresh_status)
    
    def enable_healing(self):
        try:
            success = self.healing.enable_self_healing(
                auto_retry=self.auto_retry.isChecked(),
                auto_rollback=self.auto_rollback.isChecked(),
                auto_heal=self.auto_heal.isChecked()
            )
            
            if success:
                self.status_label.setText("Status: Enabled")
                self.status_label.setStyleSheet("color: green;")
                self.update_timer.start(5000)
            else:
                QMessageBox.warning(self, "Error", "Failed to enable self-healing")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def start_monitoring(self):
        try:
            self.healing.start_monitoring()
            QMessageBox.information(self, "Success", "Monitoring started")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def refresh_status(self):
        try:
            health = self.healing.get_health_status()
            self.health_status.setText(f"Overall Status: {health['status']} ({health['healthy_metrics']}/{health['total_metrics']})")
            
            # Update metrics table
            self.health_table.setRowCount(len(health['metrics']))
            for i, metric in enumerate(health['metrics']):
                self.health_table.setItem(i, 0, QTableWidgetItem(metric['component']))
                self.health_table.setItem(i, 1, QTableWidgetItem(metric['metric']))
                self.health_table.setItem(i, 2, QTableWidgetItem(f"{metric['value']:.3f}"))
                status_item = QTableWidgetItem("✓" if metric['healthy'] else "✗")
                status_item.setBackground(
                    QColor("green") if metric['healthy'] else QColor("red")
                )
                self.health_table.setItem(i, 3, status_item)
            
            # Update error history
            errors = self.healing.get_error_history(limit=20)
            self.error_list.setRowCount(len(errors))
            for i, error in enumerate(errors):
                self.error_list.setItem(i, 0, QTableWidgetItem(error['component']))
                self.error_list.setItem(i, 1, QTableWidgetItem(error['error_type']))
                self.error_list.setItem(i, 2, QTableWidgetItem(f"{error['severity']:.2f}"))
                resolved = "Yes" if error['resolved'] else "No"
                self.error_list.setItem(i, 3, QTableWidgetItem(resolved))
                
                dt = datetime.fromtimestamp(error['timestamp'])
                self.error_list.setItem(i, 4, QTableWidgetItem(dt.strftime("%H:%M:%S")))
        except Exception as e:
            logger.error(f"Refresh failed: {e}")


class AdaptiveStrategyTab(QWidget):
    """Adaptive Strategy Engine Controls"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        super().__init__()
        self.engine = AdaptiveStrategyEngine(db_path)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Status
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Status: Disabled")
        status_layout.addWidget(self.status_label)
        
        self.enable_btn = QPushButton("Enable Adaptive Strategies")
        self.enable_btn.clicked.connect(self.enable_strategies)
        status_layout.addWidget(self.enable_btn)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Configuration
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout()
        
        self.ab_testing = QCheckBox("A/B Testing")
        self.ab_testing.setChecked(True)
        self.auto_switch = QCheckBox("Auto Strategy Switch")
        self.auto_switch.setChecked(True)
        
        config_layout.addWidget(self.ab_testing)
        config_layout.addWidget(self.auto_switch)
        
        config_layout.addWidget(QLabel("Performance Threshold:"))
        self.threshold = QDoubleSpinBox()
        self.threshold.setRange(0.0, 1.0)
        self.threshold.setSingleStep(0.05)
        self.threshold.setValue(0.3)
        config_layout.addWidget(self.threshold)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Strategies
        strategies_group = QGroupBox("Active Strategies")
        strategies_layout = QVBoxLayout()
        
        self.strategy_table = QTableWidget()
        self.strategy_table.setColumnCount(6)
        self.strategy_table.setHorizontalHeaderLabels(
            ["Strategy ID", "Type", "Success Rate", "Confidence", "Attempts", "Last Used"]
        )
        strategies_layout.addWidget(self.strategy_table)
        
        strategies_group.setLayout(strategies_layout)
        layout.addWidget(strategies_group)
        
        # Performance Summary
        summary_group = QGroupBox("Performance Summary")
        summary_layout = QVBoxLayout()
        
        self.summary_label = QLabel()
        summary_layout.addWidget(self.summary_label)
        
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_status)
        layout.addWidget(refresh_btn)
        
        self.setLayout(layout)
    
    def enable_strategies(self):
        try:
            success = self.engine.enable_adaptive_strategies(
                ab_testing=self.ab_testing.isChecked(),
                auto_switch=self.auto_switch.isChecked(),
                performance_threshold=self.threshold.value()
            )
            
            if success:
                self.status_label.setText("Status: Enabled")
                self.status_label.setStyleSheet("color: green;")
            else:
                QMessageBox.warning(self, "Error", "Failed to enable strategies")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def refresh_status(self):
        try:
            summary = self.engine.get_performance_summary()
            self.summary_label.setText(
                f"Strategies: {summary['total_strategies']} | "
                f"Active: {summary['active_strategies']} | "
                f"Avg Success: {summary['average_success_rate']:.1%} | "
                f"Adaptations: {summary['total_adaptations']}"
            )
            
            # Update strategies table
            all_strategies = self.engine.get_all_strategies()
            self.strategy_table.setRowCount(len(all_strategies))
            
            for i, strat in enumerate(all_strategies):
                self.strategy_table.setItem(i, 0, QTableWidgetItem(strat['strategy_id']))
                self.strategy_table.setItem(i, 1, QTableWidgetItem(strat['strategy_type']))
                self.strategy_table.setItem(i, 2, QTableWidgetItem(f"{strat['success_rate']:.1%}"))
                self.strategy_table.setItem(i, 3, QTableWidgetItem(f"{strat['confidence']:.2f}"))
                self.strategy_table.setItem(i, 4, QTableWidgetItem(str(strat['total_attempts'])))
                
                dt = datetime.fromtimestamp(strat['last_used'])
                self.strategy_table.setItem(i, 5, QTableWidgetItem(dt.strftime("%H:%M:%S")))
        except Exception as e:
            logger.error(f"Refresh failed: {e}")


class SchedulerTab(QWidget):
    """Autonomous Scheduler Controls"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        super().__init__()
        self.scheduler = AutonomousScheduler(db_path)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Status
        status_group = QGroupBox("Scheduler Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Status: Stopped")
        status_layout.addWidget(self.status_label)
        
        button_layout = QHBoxLayout()
        self.enable_btn = QPushButton("Enable Scheduler")
        self.enable_btn.clicked.connect(self.enable_scheduler)
        self.start_btn = QPushButton("Start Scheduler")
        self.start_btn.clicked.connect(self.start_scheduler)
        self.stop_btn = QPushButton("Stop Scheduler")
        self.stop_btn.clicked.connect(self.stop_scheduler)
        
        button_layout.addWidget(self.enable_btn)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        status_layout.addLayout(button_layout)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Tasks
        tasks_group = QGroupBox("Scheduled Tasks")
        tasks_layout = QVBoxLayout()
        
        self.task_table = QTableWidget()
        self.task_table.setColumnCount(6)
        self.task_table.setHorizontalHeaderLabels(
            ["Task ID", "Name", "Schedule", "Enabled", "Executions", "Last Run"]
        )
        tasks_layout.addWidget(self.task_table)
        
        tasks_group.setLayout(tasks_layout)
        layout.addWidget(tasks_group)
        
        # Execution History
        history_group = QGroupBox("Recent Executions")
        history_layout = QVBoxLayout()
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(
            ["Task ID", "Status", "Duration (s)", "Retries", "Time"]
        )
        history_layout.addWidget(self.history_table)
        
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self.refresh_status)
        layout.addWidget(refresh_btn)
        
        self.setLayout(layout)
    
    def enable_scheduler(self):
        try:
            success = self.scheduler.enable_scheduling()
            if success:
                self.status_label.setText("Status: Enabled")
                self.status_label.setStyleSheet("color: orange;")
            else:
                QMessageBox.warning(self, "Error", "Failed to enable scheduler")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def start_scheduler(self):
        try:
            self.scheduler.start_scheduler()
            self.status_label.setText("Status: Running")
            self.status_label.setStyleSheet("color: green;")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def stop_scheduler(self):
        try:
            self.scheduler.stop_scheduler()
            self.status_label.setText("Status: Stopped")
            self.status_label.setStyleSheet("color: red;")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def refresh_status(self):
        try:
            status = self.scheduler.get_scheduler_status()
            
            # Update tasks table
            all_tasks = self.scheduler.get_all_tasks()
            self.task_table.setRowCount(len(all_tasks))
            
            for i, task in enumerate(all_tasks):
                self.task_table.setItem(i, 0, QTableWidgetItem(task['task_id']))
                self.task_table.setItem(i, 1, QTableWidgetItem(task['name']))
                self.task_table.setItem(i, 2, QTableWidgetItem(task['schedule']))
                enabled = "✓" if task['enabled'] else "✗"
                self.task_table.setItem(i, 3, QTableWidgetItem(enabled))
                self.task_table.setItem(i, 4, QTableWidgetItem(str(task['execution_count'])))
                
                if task['last_execution']:
                    dt = datetime.fromtimestamp(task['last_execution'])
                    self.task_table.setItem(i, 5, QTableWidgetItem(dt.strftime("%H:%M:%S")))
            
            # Update execution history
            history = self.scheduler.get_execution_history(limit=20)
            self.history_table.setRowCount(len(history))
            
            for i, exec_rec in enumerate(history):
                self.history_table.setItem(i, 0, QTableWidgetItem(exec_rec['task_id']))
                self.history_table.setItem(i, 1, QTableWidgetItem(exec_rec['status']))
                self.history_table.setItem(i, 2, QTableWidgetItem(f"{exec_rec['duration']:.2f}"))
                self.history_table.setItem(i, 3, QTableWidgetItem(str(exec_rec['retry_count'])))
                
                dt = datetime.fromtimestamp(exec_rec['start_time'])
                self.history_table.setItem(i, 4, QTableWidgetItem(dt.strftime("%H:%M:%S")))
        except Exception as e:
            logger.error(f"Refresh failed: {e}")


class MultiAgentTab(QWidget):
    """Multi-Agent System Controls"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        super().__init__()
        self.system = MultiAgentSystem(db_path)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Status
        status_group = QGroupBox("Multi-Agent System Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Status: Disabled")
        status_layout.addWidget(self.status_label)
        
        button_layout = QHBoxLayout()
        self.enable_btn = QPushButton("Enable Multi-Agent System")
        self.enable_btn.clicked.connect(self.enable_system)
        self.start_btn = QPushButton("Start Coordination")
        self.start_btn.clicked.connect(self.start_coordination)
        
        button_layout.addWidget(self.enable_btn)
        button_layout.addWidget(self.start_btn)
        status_layout.addLayout(button_layout)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Agents
        agents_group = QGroupBox("Active Agents")
        agents_layout = QVBoxLayout()
        
        self.agent_table = QTableWidget()
        self.agent_table.setColumnCount(7)
        self.agent_table.setHorizontalHeaderLabels(
            ["Agent ID", "Name", "Role", "Status", "Current Task", "Performance", "Reliability"]
        )
        agents_layout.addWidget(self.agent_table)
        
        agents_group.setLayout(agents_layout)
        layout.addWidget(agents_group)
        
        # Collaborative Tasks
        tasks_group = QGroupBox("Collaborative Tasks")
        tasks_layout = QVBoxLayout()
        
        self.task_list = QTableWidget()
        self.task_list.setColumnCount(5)
        self.task_list.setHorizontalHeaderLabels(
            ["Task ID", "Name", "Status", "Required Roles", "Assigned Agents"]
        )
        tasks_layout.addWidget(self.task_list)
        
        tasks_group.setLayout(tasks_layout)
        layout.addWidget(tasks_group)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self.refresh_status)
        layout.addWidget(refresh_btn)
        
        self.setLayout(layout)
    
    def enable_system(self):
        try:
            success = self.system.enable_multi_agent_system()
            if success:
                self.status_label.setText("Status: Enabled")
                self.status_label.setStyleSheet("color: green;")
            else:
                QMessageBox.warning(self, "Error", "Failed to enable system")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def start_coordination(self):
        try:
            self.system.start_coordination()
            self.status_label.setText("Status: Running")
            self.status_label.setStyleSheet("color: green;")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
    
    def refresh_status(self):
        try:
            sys_status = self.system.get_system_status()
            
            # Update agents
            self.agent_table.setRowCount(len(self.system.agents))
            for i, (agent_id, agent) in enumerate(self.system.agents.items()):
                self.agent_table.setItem(i, 0, QTableWidgetItem(agent_id))
                self.agent_table.setItem(i, 1, QTableWidgetItem(agent.name))
                self.agent_table.setItem(i, 2, QTableWidgetItem(agent.role.value))
                self.agent_table.setItem(i, 3, QTableWidgetItem(agent.status.value))
                self.agent_table.setItem(i, 4, QTableWidgetItem(agent.current_task or ""))
                self.agent_table.setItem(i, 5, QTableWidgetItem(f"{agent.performance_score:.2f}"))
                self.agent_table.setItem(i, 6, QTableWidgetItem(f"{agent.reliability:.2f}"))
            
            # Update tasks
            self.task_list.setRowCount(len(self.system.collaborative_tasks))
            for i, (task_id, task) in enumerate(self.system.collaborative_tasks.items()):
                self.task_list.setItem(i, 0, QTableWidgetItem(task_id))
                self.task_list.setItem(i, 1, QTableWidgetItem(task.name))
                self.task_list.setItem(i, 2, QTableWidgetItem(task.status.value))
                roles = ", ".join([r.value for r in task.required_roles])
                self.task_list.setItem(i, 3, QTableWidgetItem(roles))
                self.task_list.setItem(i, 4, QTableWidgetItem(str(len(task.assigned_agents))))
        except Exception as e:
            logger.error(f"Refresh failed: {e}")


class AdvancedAutonomyTab(QWidget):
    """Main tab combining all four advanced autonomy systems"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        super().__init__()
        self.db_path = db_path
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # Add sub-tabs
        self.healing_tab = SelfHealingTab(self.db_path)
        self.strategy_tab = AdaptiveStrategyTab(self.db_path)
        self.scheduler_tab = SchedulerTab(self.db_path)
        self.agent_tab = MultiAgentTab(self.db_path)
        
        self.tabs.addTab(self.healing_tab, "🏥 Self-Healing")
        self.tabs.addTab(self.strategy_tab, "⚙️ Adaptive Strategies")
        self.tabs.addTab(self.scheduler_tab, "⏰ Autonomous Scheduler")
        self.tabs.addTab(self.agent_tab, "👥 Multi-Agent System")
        
        layout.addWidget(self.tabs)
        self.setLayout(layout)


if __name__ == "__main__":
    import sys
    from PyQt6.QtWidgets import QApplication, QMainWindow
    
    app = QApplication(sys.argv)
    window = QMainWindow()
    window.setWindowTitle("Advanced Autonomy Control Panel")
    window.setGeometry(100, 100, 1200, 800)
    
    tab = AdvancedAutonomyTab()
    window.setCentralWidget(tab)
    window.show()
    
    sys.exit(app.exec())
