"""
Tome AI Integration GUI - Fluid interface between AI and Exploit Tome
Allows users to see AI reasoning and craft new exploits together
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel,
    QTableWidget, QTableWidgetItem, QLineEdit, QComboBox, QSpinBox,
    QCheckBox, QGroupBox, QFormLayout, QTabWidget, QPlainTextEdit,
    QHeaderView, QMessageBox, QFileDialog, QProgressBar, QListWidget,
    QListWidgetItem, QSplitter, QTreeWidget, QTreeWidgetItem, QTextBrowser,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QEvent
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QIcon

from datetime import datetime
from typing import Optional, List, Dict
import json
import logging

from tome_ai_integration import TomeAIBridge, ExploitTemplate
from ai_exploit_crafter import AIExploitCrafter, ExploitIdea

logger = logging.getLogger(__name__)


class ExploitCraftingWorker(QThread):
    """Worker thread for exploit crafting"""
    finished = pyqtSignal()
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    result = pyqtSignal(object)
    
    def __init__(self, crafter: AIExploitCrafter, idea: ExploitIdea):
        super().__init__()
        self.crafter = crafter
        self.idea = idea
    
    def run(self):
        try:
            self.progress.emit("Analyzing tome knowledge...")
            template = self.crafter.craft_exploit_from_idea(self.idea)
            
            if template:
                self.progress.emit("Exploit crafting complete!")
                self.result.emit(template)
            else:
                self.error.emit("Failed to craft exploit")
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()


class TomeAITab(QWidget):
    """Main GUI tab for Tome-AI Integration"""
    
    def __init__(self, tome_db_path: str = "exploit_tome.db"):
        super().__init__()
        self.bridge = TomeAIBridge(tome_db_path)
        self.crafter = AIExploitCrafter(self.bridge)
        self.current_template = None
        self.crafting_worker = None
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Tab 1: Knowledge Browser
        tabs.addTab(self._create_knowledge_tab(), "📚 Knowledge Base")
        
        # Tab 2: Exploit Crafter
        tabs.addTab(self._create_crafter_tab(), "🔧 Craft Exploit")
        
        # Tab 3: AI Reasoning
        tabs.addTab(self._create_reasoning_tab(), "🧠 AI Reasoning")
        
        # Tab 4: Generated Exploits
        tabs.addTab(self._create_generated_tab(), "✨ Generated Exploits")
        
        # Tab 5: Patterns & Analysis
        tabs.addTab(self._create_analysis_tab(), "📊 Pattern Analysis")
        
        layout.addWidget(tabs)
    
    # ========== TAB: KNOWLEDGE BASE ==========
    
    def _create_knowledge_tab(self) -> QWidget:
        """Browse and explore exploit knowledge"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Header
        header = QLabel("📚 Exploit Knowledge Base")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Splitter for knowledge views
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel: Category browser
        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("Categories:"))
        
        self.category_list = QListWidget()
        self.category_list.itemClicked.connect(self._on_category_selected)
        left_layout.addWidget(self.category_list)
        
        left_widget = QWidget()
        left_widget.setLayout(left_layout)
        splitter.addWidget(left_widget)
        
        # Right panel: Exploits in category
        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Exploits in Category:"))
        
        self.knowledge_table = QTableWidget()
        self.knowledge_table.setColumnCount(5)
        self.knowledge_table.setHorizontalHeaderLabels([
            "Name", "Target", "Success Rate", "Status", "View"
        ])
        self.knowledge_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        right_layout.addWidget(self.knowledge_table)
        
        # Details panel
        details_layout = QVBoxLayout()
        details_layout.addWidget(QLabel("Payload Preview:"))
        
        self.knowledge_details = QPlainTextEdit()
        self.knowledge_details.setReadOnly(True)
        self.knowledge_details.setFont(QFont("Consolas", 9))
        self.knowledge_details.setMaximumHeight(150)
        details_layout.addWidget(self.knowledge_details)
        
        right_layout.addLayout(details_layout)
        
        right_widget = QWidget()
        right_widget.setLayout(right_layout)
        splitter.addWidget(right_widget)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        layout.addWidget(splitter)
        
        # Load button
        load_btn = QPushButton("🔄 Load Knowledge Base")
        load_btn.clicked.connect(self._load_knowledge_base)
        layout.addWidget(load_btn)
        
        # Auto-load on init
        QTimer.singleShot(100, self._load_knowledge_base)
        
        return widget
    
    def _load_knowledge_base(self):
        """Load knowledge base from tome"""
        try:
            kb = self.bridge.get_exploit_knowledge_base()
            
            self.category_list.clear()
            for category in sorted(kb.get('exploits_by_category', {}).keys()):
                self.category_list.addItem(category)
            
            # Show stats
            total = kb.get('total_exploits', 0)
            logger.info(f"Loaded {total} exploits from tome")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load knowledge: {e}")
    
    def _on_category_selected(self, item):
        """Handle category selection"""
        try:
            category = item.text()
            exploits = self.bridge.get_exploits_by_category(category)
            
            self.knowledge_table.setRowCount(len(exploits))
            
            for row, exploit in enumerate(exploits):
                name_item = QTableWidgetItem(exploit['name'])
                target_item = QTableWidgetItem(exploit['target'])
                
                success_rate = (exploit['success_count'] / max(1, exploit['success_count'] + exploit['fail_count'])) * 100
                success_item = QTableWidgetItem(f"{success_rate:.1f}%")
                
                status_item = QTableWidgetItem(exploit['status'])
                
                view_btn = QPushButton("View")
                view_btn.clicked.connect(lambda checked, e=exploit: self._view_exploit_details(e))
                
                self.knowledge_table.setItem(row, 0, name_item)
                self.knowledge_table.setItem(row, 1, target_item)
                self.knowledge_table.setItem(row, 2, success_item)
                self.knowledge_table.setItem(row, 3, status_item)
                self.knowledge_table.setCellWidget(row, 4, view_btn)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load category: {e}")
    
    def _view_exploit_details(self, exploit: Dict):
        """View exploit details"""
        payload = exploit.get('payload', 'No payload')
        self.knowledge_details.setPlainText(payload)
    
    # ========== TAB: EXPLOIT CRAFTER ==========
    
    def _create_crafter_tab(self) -> QWidget:
        """Create exploit crafting interface"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Header
        header = QLabel("🔧 AI Exploit Crafter")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Input form
        form_group = QGroupBox("Exploit Idea")
        form_layout = QFormLayout(form_group)
        
        self.craft_category = QComboBox()
        self.craft_category.addItems([
            "SQL Injection", "XSS", "RCE", "LFI", "CSRF",
            "Authentication Bypass", "Privilege Escalation",
            "Buffer Overflow", "XXE", "Insecure Deserialization"
        ])
        form_layout.addRow("Category:", self.craft_category)
        
        self.craft_target_type = QLineEdit()
        self.craft_target_type.setPlaceholderText("e.g., Web Application, Linux Server")
        form_layout.addRow("Target Type:", self.craft_target_type)
        
        self.craft_vulnerability = QPlainTextEdit()
        self.craft_vulnerability.setPlaceholderText("Describe the vulnerability...")
        self.craft_vulnerability.setMaximumHeight(100)
        form_layout.addRow("Vulnerability Description:", self.craft_vulnerability)
        
        self.craft_cves = QLineEdit()
        self.craft_cves.setPlaceholderText("CVE-XXXX-XXXXX (comma separated)")
        form_layout.addRow("CVE IDs:", self.craft_cves)
        
        self.craft_references = QPlainTextEdit()
        self.craft_references.setPlaceholderText("Reference URLs (one per line)")
        self.craft_references.setMaximumHeight(80)
        form_layout.addRow("References:", self.craft_references)
        
        layout.addWidget(form_group)
        
        # Crafting controls
        control_layout = QHBoxLayout()
        
        self.craft_button = QPushButton("✨ Craft Exploit")
        self.craft_button.clicked.connect(self._start_crafting)
        self.craft_button.setStyleSheet("background: #2196F3; color: white; padding: 10px; font-weight: bold;")
        control_layout.addWidget(self.craft_button)
        
        self.craft_clear_button = QPushButton("🔄 Clear")
        self.craft_clear_button.clicked.connect(self._clear_craft_form)
        control_layout.addWidget(self.craft_clear_button)
        
        layout.addLayout(control_layout)
        
        # Progress
        self.craft_progress = QProgressBar()
        self.craft_progress.setVisible(False)
        layout.addWidget(self.craft_progress)
        
        # Status
        self.craft_status = QLabel("")
        layout.addWidget(self.craft_status)
        
        # Result preview
        result_group = QGroupBox("Generated Exploit Preview")
        result_layout = QVBoxLayout(result_group)
        
        self.craft_result = QPlainTextEdit()
        self.craft_result.setReadOnly(True)
        self.craft_result.setFont(QFont("Consolas", 9))
        result_layout.addWidget(self.craft_result)
        
        layout.addWidget(result_group)
        
        # Save button
        save_layout = QHBoxLayout()
        
        self.save_crafted_button = QPushButton("💾 Save to Tome")
        self.save_crafted_button.clicked.connect(self._save_crafted_exploit)
        self.save_crafted_button.setEnabled(False)
        save_layout.addWidget(self.save_crafted_button)
        
        save_layout.addStretch()
        layout.addLayout(save_layout)
        
        return widget
    
    def _start_crafting(self):
        """Start exploit crafting"""
        try:
            # Validate inputs
            category = self.craft_category.currentText()
            target_type = self.craft_target_type.text().strip()
            vulnerability = self.craft_vulnerability.toPlainText().strip()
            cves_text = self.craft_cves.text().strip()
            refs_text = self.craft_references.toPlainText().strip()
            
            if not target_type or not vulnerability:
                QMessageBox.warning(self, "Warning", "Please fill in target type and vulnerability description")
                return
            
            # Parse CVEs and references
            cves = [c.strip() for c in cves_text.split(',') if c.strip()]
            refs = [r.strip() for r in refs_text.split('\n') if r.strip()]
            
            # Create idea
            idea = ExploitIdea(
                category=category,
                target_type=target_type,
                vulnerability_description=vulnerability,
                cve_ids=cves,
                references=refs,
                confidence_score=0.8
            )
            
            # Show progress
            self.craft_progress.setVisible(True)
            self.craft_progress.setValue(0)
            self.craft_button.setEnabled(False)
            self.craft_status.setText("🔄 Crafting exploit...")
            
            # Start crafting worker
            self.crafting_worker = ExploitCraftingWorker(self.crafter, idea)
            self.crafting_worker.progress.connect(self._on_craft_progress)
            self.crafting_worker.result.connect(self._on_craft_complete)
            self.crafting_worker.error.connect(self._on_craft_error)
            self.crafting_worker.finished.connect(self._on_craft_finished)
            self.crafting_worker.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start crafting: {e}")
    
    def _on_craft_progress(self, message: str):
        """Handle crafting progress"""
        self.craft_status.setText(f"⏳ {message}")
    
    def _on_craft_complete(self, template: ExploitTemplate):
        """Handle crafting complete"""
        self.current_template = template
        
        # Show result
        result_text = f"""
Name: {template.name}
Category: {template.category}
Target Type: {template.target_type}
Vulnerability: {template.vulnerability_type}
Difficulty: {template.difficulty}
CVE IDs: {', '.join(template.cve_ids)}
Tags: {', '.join(template.tags)}

PREREQUISITES:
{chr(10).join('- ' + p for p in template.prerequisites)}

PAYLOAD:
{template.payload_template}

SUCCESS INDICATORS:
{chr(10).join('- ' + s for s in template.success_indicators)}
"""
        
        self.craft_result.setPlainText(result_text)
        self.craft_status.setText("✅ Exploit crafted successfully!")
        self.save_crafted_button.setEnabled(True)
    
    def _on_craft_error(self, error: str):
        """Handle crafting error"""
        self.craft_status.setText(f"❌ Error: {error}")
        QMessageBox.critical(self, "Error", f"Crafting failed: {error}")
    
    def _on_craft_finished(self):
        """Handle crafting finished"""
        self.craft_progress.setVisible(False)
        self.craft_button.setEnabled(True)
    
    def _clear_craft_form(self):
        """Clear crafting form"""
        self.craft_category.setCurrentIndex(0)
        self.craft_target_type.clear()
        self.craft_vulnerability.clear()
        self.craft_cves.clear()
        self.craft_references.clear()
        self.craft_result.clear()
        self.save_crafted_button.setEnabled(False)
        self.current_template = None
    
    def _save_crafted_exploit(self):
        """Save crafted exploit to tome"""
        if not self.current_template:
            QMessageBox.warning(self, "Warning", "No exploit crafted yet")
            return
        
        result = self.bridge.create_exploit_from_ai(self.current_template)
        
        if result.get('success'):
            QMessageBox.information(self, "Success", f"Exploit saved to Tome!\nID: {result.get('exploit_id')}")
            self._clear_craft_form()
        else:
            QMessageBox.critical(self, "Error", f"Failed to save: {result.get('error')}")
    
    # ========== TAB: AI REASONING ==========
    
    def _create_reasoning_tab(self) -> QWidget:
        """Show AI reasoning process"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        header = QLabel("🧠 AI Reasoning & Decision Making")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Reasoning display
        self.reasoning_display = QTextBrowser()
        self.reasoning_display.setFont(QFont("Courier", 10))
        layout.addWidget(self.reasoning_display)
        
        # Actions
        action_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh Reasoning")
        refresh_btn.clicked.connect(self._refresh_reasoning)
        action_layout.addWidget(refresh_btn)
        
        export_btn = QPushButton("💾 Export Analysis")
        export_btn.clicked.connect(self._export_reasoning)
        action_layout.addWidget(export_btn)
        
        action_layout.addStretch()
        layout.addLayout(action_layout)
        
        return widget
    
    def _refresh_reasoning(self):
        """Refresh reasoning display"""
        try:
            analysis = self.bridge.analyze_exploit_patterns()
            
            reasoning = "<h3>Exploit Pattern Analysis</h3>"
            reasoning += "<h4>Top Performing Categories:</h4><ul>"
            
            for cat in analysis.get('category_performance', [])[:5]:
                reasoning += f"<li><b>{cat['category']}</b>: {cat['count']} exploits, Avg Success: {cat['avg_success_rate']:.1f}%</li>"
            
            reasoning += "</ul><h4>Most Used Techniques:</h4><ul>"
            
            tags = analysis.get('tag_frequency', {})
            for tag, count in sorted(tags.items(), key=lambda x: x[1], reverse=True)[:10]:
                reasoning += f"<li>{tag}: {count} exploits</li>"
            
            reasoning += "</ul>"
            
            self.reasoning_display.setHtml(reasoning)
        except Exception as e:
            self.reasoning_display.setHtml(f"<p style='color: red;'>Error: {e}</p>")
    
    def _export_reasoning(self):
        """Export reasoning analysis"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Analysis", "exploit_analysis.json", "JSON Files (*.json)"
            )
            
            if filename:
                self.bridge.export_knowledge_for_ai(filename)
                QMessageBox.information(self, "Success", f"Analysis exported to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {e}")
    
    # ========== TAB: GENERATED EXPLOITS ==========
    
    def _create_generated_tab(self) -> QWidget:
        """View generated exploits"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        header = QLabel("✨ AI-Generated Exploits")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # List of crafted exploits
        self.generated_list = QListWidget()
        self.generated_list.itemClicked.connect(self._on_generated_selected)
        layout.addWidget(self.generated_list)
        
        # Details
        details_group = QGroupBox("Exploit Details")
        details_layout = QVBoxLayout(details_group)
        
        self.generated_details = QPlainTextEdit()
        self.generated_details.setReadOnly(True)
        details_layout.addWidget(self.generated_details)
        
        layout.addWidget(details_group)
        
        return widget
    
    def _on_generated_selected(self, item: QListWidgetItem):
        """Handle generated exploit selection"""
        # Show details of crafted exploit
        pass
    
    # ========== TAB: PATTERN ANALYSIS ==========
    
    def _create_analysis_tab(self) -> QWidget:
        """Analyze exploit patterns"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        header = QLabel("📊 Pattern Analysis & Insights")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Analysis display
        self.analysis_display = QPlainTextEdit()
        self.analysis_display.setReadOnly(True)
        self.analysis_display.setFont(QFont("Consolas", 10))
        layout.addWidget(self.analysis_display)
        
        # Actions
        action_layout = QHBoxLayout()
        
        analyze_btn = QPushButton("📊 Analyze Patterns")
        analyze_btn.clicked.connect(self._analyze_patterns)
        action_layout.addWidget(analyze_btn)
        
        suggestions_btn = QPushButton("💡 Get Suggestions")
        suggestions_btn.clicked.connect(self._get_suggestions)
        action_layout.addWidget(suggestions_btn)
        
        action_layout.addStretch()
        layout.addLayout(action_layout)
        
        return widget
    
    def _analyze_patterns(self):
        """Analyze exploit patterns"""
        try:
            analysis = self.bridge.analyze_exploit_patterns()
            
            text = "EXPLOIT PATTERN ANALYSIS\n"
            text += "=" * 50 + "\n\n"
            
            text += "Category Performance:\n"
            for cat in analysis.get('category_performance', []):
                text += f"  {cat['category']}: {cat['count']} exploits\n"
            
            text += "\nMost Common Tags:\n"
            tags = analysis.get('tag_frequency', {})
            for tag, count in sorted(tags.items(), key=lambda x: x[1], reverse=True)[:15]:
                text += f"  {tag}: {count} uses\n"
            
            self.analysis_display.setPlainText(text)
        except Exception as e:
            self.analysis_display.setPlainText(f"Error: {e}")
    
    def _get_suggestions(self):
        """Get crafting suggestions"""
        try:
            suggestions = self.crafter.get_crafting_suggestions()
            
            text = "CRAFTING SUGGESTIONS\n"
            text += "=" * 50 + "\n\n"
            
            if suggestions:
                for i, suggestion in enumerate(suggestions, 1):
                    text += f"{i}. {suggestion}\n"
            else:
                text += "No gaps identified - knowledge base is comprehensive!"
            
            self.analysis_display.setPlainText(text)
        except Exception as e:
            self.analysis_display.setPlainText(f"Error: {e}")


def create_tome_ai_tab() -> QWidget:
    """Factory function to create the Tome-AI tab"""
    return TomeAITab()
