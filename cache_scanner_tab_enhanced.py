"""
Enhanced Cache Scanner Tab for HadesAI
Displays detailed code visibility with threat information
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QPushButton, QProgressBar, QTreeWidget, QTreeWidgetItem,
    QTextEdit, QSplitter, QComboBox, QSpinBox, QTabWidget
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QColor
from typing import Dict, List, Optional
import json


class EnhancedCacheScannerTab(QWidget):
    """Enhanced cache scanner tab with code details"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.current_findings = []
        self.selected_finding = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Control bar
        control_layout = self._create_control_bar()
        layout.addLayout(control_layout)
        
        # Main content with splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side: Results tree
        left_widget = self._create_results_panel()
        splitter.addWidget(left_widget)
        
        # Right side: Details panel
        right_widget = self._create_details_panel()
        splitter.addWidget(right_widget)
        
        splitter.setStretchFactor(0, 40)
        splitter.setStretchFactor(1, 60)
        layout.addWidget(splitter)
        
        # Stats at bottom
        stats_group = self._create_stats_panel()
        layout.addWidget(stats_group)
        
    def _create_control_bar(self) -> QHBoxLayout:
        """Create control bar with buttons"""
        control_layout = QHBoxLayout()
        
        # Scan button
        self.cache_scan_btn = QPushButton("Scan Browser Cache")
        self.cache_scan_btn.setMinimumHeight(35)
        control_layout.addWidget(self.cache_scan_btn)
        
        # Stop button
        self.cache_stop_btn = QPushButton("Stop Scan")
        self.cache_stop_btn.setEnabled(False)
        self.cache_stop_btn.setMinimumHeight(35)
        control_layout.addWidget(self.cache_stop_btn)
        
        # Export button
        self.cache_export_btn = QPushButton("Export Findings")
        self.cache_export_btn.setMinimumHeight(35)
        control_layout.addWidget(self.cache_export_btn)
        
        # Filter
        control_layout.addStretch()
        control_layout.addWidget(QLabel("Filter:"))
        self.cache_filter = QComboBox()
        self.cache_filter.addItems(["All", "HIGH", "MEDIUM", "LOW"])
        self.cache_filter.currentTextChanged.connect(self._apply_filter)
        control_layout.addWidget(self.cache_filter)
        
        # Limit
        control_layout.addWidget(QLabel("Limit:"))
        self.cache_limit = QSpinBox()
        self.cache_limit.setMinimum(10)
        self.cache_limit.setMaximum(1000)
        self.cache_limit.setValue(100)
        self.cache_limit.setMaximumWidth(70)
        control_layout.addWidget(self.cache_limit)
        
        # Progress
        self.cache_progress = QProgressBar()
        self.cache_progress.setMaximumWidth(250)
        self.cache_progress.setMaximumHeight(25)
        control_layout.addWidget(self.cache_progress)
        
        return control_layout
    
    def _create_results_panel(self) -> QWidget:
        """Create left panel with results tree"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Title
        title = QLabel("Detected Threats")
        title.setFont(QFont("Arial", 10, QFont.Bold))
        layout.addWidget(title)
        
        # Tree
        self.cache_tree = QTreeWidget()
        self.cache_tree.setHeaderLabels([
            "File",
            "Type",
            "Severity",
            "Browser",
            "Size"
        ])
        self.cache_tree.setColumnWidths([200, 120, 100, 100, 80])
        self.cache_tree.setAlternatingRowColors(True)
        self.cache_tree.itemClicked.connect(self._on_finding_selected)
        self.cache_tree.itemDoubleClicked.connect(self._on_finding_double_clicked)
        layout.addWidget(self.cache_tree)
        
        # Summary
        self.results_summary = QLabel("No threats detected")
        self.results_summary.setStyleSheet("color: #666; font-size: 9pt;")
        layout.addWidget(self.results_summary)
        
        return widget
    
    def _create_details_panel(self) -> QWidget:
        """Create right panel with threat details"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Title
        title = QLabel("Threat Details")
        title.setFont(QFont("Arial", 10, QFont.Bold))
        layout.addWidget(title)
        
        # Tabs for different views
        self.details_tabs = QTabWidget()
        
        # Summary tab
        summary_tab = self._create_summary_tab()
        self.details_tabs.addTab(summary_tab, "Summary")
        
        # Code tab
        code_tab = self._create_code_tab()
        self.details_tabs.addTab(code_tab, "Code")
        
        # Context tab
        context_tab = self._create_context_tab()
        self.details_tabs.addTab(context_tab, "Context")
        
        # Full Code tab
        fullcode_tab = self._create_fullcode_tab()
        self.details_tabs.addTab(fullcode_tab, "Full Code")
        
        layout.addWidget(self.details_tabs)
        
        return widget
    
    def _create_summary_tab(self) -> QWidget:
        """Create summary tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.summary_text)
        
        return widget
    
    def _create_code_tab(self) -> QWidget:
        """Create code tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.code_text = QTextEdit()
        self.code_text.setReadOnly(True)
        self.code_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.code_text)
        
        return widget
    
    def _create_context_tab(self) -> QWidget:
        """Create context tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.context_text = QTextEdit()
        self.context_text.setReadOnly(True)
        self.context_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.context_text)
        
        return widget
    
    def _create_fullcode_tab(self) -> QWidget:
        """Create full code tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        info = QLabel("Full file content discovered in cache")
        info.setStyleSheet("color: #666; font-size: 9pt; padding: 5px;")
        layout.addWidget(info)
        
        self.fullcode_text = QTextEdit()
        self.fullcode_text.setReadOnly(True)
        self.fullcode_text.setFont(QFont("Consolas", 8))
        layout.addWidget(self.fullcode_text)
        
        return widget
    
    def _create_stats_panel(self) -> QGroupBox:
        """Create stats panel"""
        group = QGroupBox("Scan Statistics")
        layout = QHBoxLayout(group)
        
        self.cache_stats = QLabel("No scan performed yet")
        self.cache_stats.setFont(QFont("Consolas", 10))
        layout.addWidget(self.cache_stats)
        
        return group
    
    def display_findings(self, findings: List[Dict], stats: Dict = None):
        """Display scan findings"""
        self.current_findings = findings
        self.cache_tree.clear()
        
        # Add items to tree
        for idx, finding in enumerate(findings[:self.cache_limit.value()]):
            threat_type = finding.get('threat_type', 'unknown')
            severity = finding.get('severity', 'LOW')
            browser = finding.get('browser', 'unknown')
            path = finding.get('path', 'unknown')
            size = finding.get('file_size', 0)
            
            item = QTreeWidgetItem([
                path.split('\\')[-1][:30],
                threat_type,
                severity,
                browser,
                f"{size / 1024:.1f} KB" if size > 0 else "0 KB"
            ])
            
            # Color by severity
            colors = {
                'HIGH': QColor('#ff6b6b'),
                'MEDIUM': QColor('#ffa94d'),
                'LOW': QColor('#69db7c')
            }
            
            for col in range(5):
                item.setForeground(col, colors.get(severity, QColor('#999')))
            
            # Store finding data
            item.finding_data = finding
            item.finding_index = idx
            
            self.cache_tree.addTopLevelItem(item)
        
        # Update summary
        self.results_summary.setText(
            f"Showing {len(findings[:self.cache_limit.value()])}/{len(findings)} threats"
        )
        
        # Update stats
        if stats:
            self.cache_stats.setText(
                f"Files Scanned: {stats.get('total_files', 0)} | "
                f"Total Size: {stats.get('total_size', 0) / 1024 / 1024:.1f} MB | "
                f"Threats Found: {len(findings)} | "
                f"High Risk: {sum(1 for f in findings if f.get('severity') == 'HIGH')} | "
                f"Medium Risk: {sum(1 for f in findings if f.get('severity') == 'MEDIUM')}"
            )
    
    def _on_finding_selected(self, item: QTreeWidgetItem, column: int):
        """Handle finding selection"""
        if not hasattr(item, 'finding_data'):
            return
        
        finding = item.finding_data
        self.selected_finding = finding
        
        self._update_details(finding)
    
    def _on_finding_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle finding double click"""
        if not hasattr(item, 'finding_data'):
            return
        
        finding = item.finding_data
        # Switch to code tab
        self.details_tabs.setCurrentIndex(1)
    
    def _update_details(self, finding: Dict):
        """Update details panels"""
        
        # Summary tab
        summary = f"""
THREAT DETAILS
==============

Type:        {finding.get('threat_type', 'unknown')}
Severity:    {finding.get('severity', 'unknown')}
Browser:     {finding.get('browser', 'unknown')}

PATH:        {finding.get('path', 'unknown')}
File Size:   {finding.get('file_size', 0):,} bytes
File Hash:   {finding.get('file_hash', 'N/A')}

MATCH POSITION
==============
Position:    {finding.get('position', 'unknown')}
Match Length: {finding.get('length', 0)}

DETECTION
=========
Detected At: {finding.get('detected_at', 'unknown')}
Pattern:     {finding.get('pattern', 'N/A')}

EXPLOIT LINK
============
Matched Exploit ID: {finding.get('matched_exploit_id', 'None')}
"""
        self.summary_text.setText(summary)
        
        # Code tab - matched code
        matched = finding.get('matched_code', '')
        self.code_text.setText(
            f"MATCHED CODE:\n\n{matched}\n\n"
            f"Length: {len(matched)} characters"
        )
        
        # Context tab
        context_before = finding.get('context_before', '')
        context_after = finding.get('context_after', '')
        matched_code = finding.get('matched_code', '')
        
        context_display = f"""BEFORE THREAT:
{context_before}

>>> THREAT DETECTED <<<
{matched_code}

AFTER THREAT:
{context_after}

---END OF CONTEXT---"""
        
        self.context_text.setText(context_display)
        
        # Full code tab
        full_code = finding.get('full_code', '')
        if full_code:
            self.fullcode_text.setText(
                f"FULL FILE CODE ({len(full_code)} bytes):\n\n{full_code[:50000]}"
                f"\n\n{'...[truncated]' if len(full_code) > 50000 else '[END OF FILE]'}"
            )
        else:
            self.fullcode_text.setText("Full code not available for this finding")
    
    def _apply_filter(self):
        """Apply severity filter"""
        severity_filter = self.cache_filter.currentText()
        
        for i in range(self.cache_tree.topLevelItemCount()):
            item = self.cache_tree.topLevelItem(i)
            
            if severity_filter == "All":
                item.setHidden(False)
            else:
                item_severity = item.text(2)  # Severity column
                item.setHidden(item_severity != severity_filter)
    
    def clear_details(self):
        """Clear all details"""
        self.summary_text.clear()
        self.code_text.clear()
        self.context_text.clear()
        self.fullcode_text.clear()
        self.selected_finding = None
    
    def set_progress(self, value: int):
        """Set progress bar"""
        self.cache_progress.setValue(value)
    
    def set_status(self, message: str):
        """Set status message"""
        self.results_summary.setText(message)
    
    def enable_controls(self, enabled: bool):
        """Enable/disable controls during scan"""
        self.cache_scan_btn.setEnabled(enabled)
        self.cache_stop_btn.setEnabled(not enabled)
        self.cache_filter.setEnabled(enabled)
        self.cache_limit.setEnabled(enabled)
        self.cache_export_btn.setEnabled(enabled)


# Integration function for HadesAI.py
def create_enhanced_cache_tab(parent=None) -> tuple:
    """
    Create enhanced cache scanner tab
    Returns: (widget, tab_instance)
    """
    tab = EnhancedCacheScannerTab(parent)
    return tab, tab
