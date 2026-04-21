"""
Data Mapping Tab - Visualize attack vectors from documented sites
Shows relationships between vulnerabilities, techniques, CVEs, and attack patterns
"""

import json
import html
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QGroupBox, QFormLayout, QComboBox,
    QLineEdit, QCheckBox, QSpinBox, QTreeWidget, QTreeWidgetItem,
    QSplitter, QProgressBar, QMessageBox, QFileDialog, QTabWidget,
    QListWidget, QListWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor, QBrush, QIcon


class AttackVectorAnalyzer:
    """Analyze and map attack vectors from documented threats"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.db_path = db_path
        
    def get_connection(self):
        """Get database connection"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            print(f"Database error: {e}")
            return None
    
    def get_documented_sites(self) -> List[Dict]:
        """Get all documented attack sites from web_learnings"""
        conn = self.get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT url, content_type, learned_at, 
                       exploits_found, patterns_found
                FROM web_learnings
                ORDER BY learned_at DESC
                LIMIT 100
            """)
            
            sites = []
            for row in cursor.fetchall():
                sites.append({
                    'url': row['url'],
                    'type': row['content_type'],
                    'learned': row['learned_at'],
                    'exploits': json.loads(row['exploits_found']) if row['exploits_found'] else [],
                    'patterns': json.loads(row['patterns_found']) if row['patterns_found'] else []
                })
            
            conn.close()
            return sites
        except Exception as e:
            print(f"Error fetching documented sites: {e}")
            return []
    
    def get_attack_vectors_for_site(self, site_url: str) -> Dict[str, List]:
        """Get all attack vectors identified for a specific site"""
        conn = self.get_connection()
        if not conn:
            return {}
        
        try:
            cursor = conn.cursor()
            vectors = {}
            
            # Get security patterns
            cursor.execute("""
                SELECT * FROM security_patterns
                ORDER BY confidence DESC
            """)
            vectors['patterns'] = [dict(row) for row in cursor.fetchall()]
            
            # Get threat findings
            cursor.execute("""
                SELECT * FROM threat_findings
                WHERE path LIKE ?
                ORDER BY detected_at DESC
            """, (f"%{site_url}%",))
            vectors['threats'] = [dict(row) for row in cursor.fetchall()]
            
            # Get learned exploits
            cursor.execute("""
                SELECT * FROM learned_exploits
                WHERE source_url = ?
                ORDER BY learned_at DESC
            """, (site_url,))
            vectors['exploits'] = [dict(row) for row in cursor.fetchall()]
            
            # Get CVEs and techniques
            cursor.execute("""
                SELECT * FROM cves
                ORDER BY cvss DESC
                LIMIT 50
            """)
            vectors['cves'] = [dict(row) for row in cursor.fetchall()]
            
            cursor.execute("""
                SELECT * FROM techniques
                ORDER BY confidence DESC
                LIMIT 50
            """)
            vectors['techniques'] = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            return vectors
        except Exception as e:
            print(f"Error fetching attack vectors: {e}")
            return {}
    
    def get_vector_summary(self) -> Dict[str, Any]:
        """Get summary statistics of all attack vectors"""
        conn = self.get_connection()
        if not conn:
            return {}
        
        try:
            cursor = conn.cursor()
            summary = {}
            
            # Count by type
            cursor.execute("SELECT COUNT(*) as count FROM security_patterns")
            summary['total_patterns'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as count FROM threat_findings")
            summary['total_threats'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as count FROM learned_exploits")
            summary['total_exploits'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as count FROM cves")
            summary['total_cves'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as count FROM web_learnings")
            summary['documented_sites'] = cursor.fetchone()[0]
            
            # Severity breakdown
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM threat_findings 
                GROUP BY severity
            """)
            summary['severity_breakdown'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # CVSS breakdown
            cursor.execute("""
                SELECT 
                    CASE 
                        WHEN cvss >= 9.0 THEN 'Critical'
                        WHEN cvss >= 7.0 THEN 'High'
                        WHEN cvss >= 4.0 THEN 'Medium'
                        ELSE 'Low'
                    END as severity,
                    COUNT(*) as count
                FROM cves
                GROUP BY severity
            """)
            summary['cve_severity'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            conn.close()
            return summary
        except Exception as e:
            print(f"Error getting summary: {e}")
            return {}
    
    def get_vector_relationships(self) -> List[Dict]:
        """Get relationships between attack vectors"""
        conn = self.get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            relationships = []
            
            # Get technique->CVE relationships
            cursor.execute("""
                SELECT DISTINCT
                    t.technique_id,
                    t.name as technique_name,
                    c.cve_id,
                    c.summary,
                    c.cvss
                FROM techniques t
                JOIN cves c ON c.summary LIKE '%' || t.name || '%'
                LIMIT 100
            """)
            
            for row in cursor.fetchall():
                relationships.append({
                    'from': row[0],
                    'from_name': row[1],
                    'from_type': 'technique',
                    'to': row[2],
                    'to_name': row[3],
                    'to_type': 'cve',
                    'severity': row[4]
                })
            
            conn.close()
            return relationships
        except Exception as e:
            print(f"Error getting relationships: {e}")
            return []


class DataMappingTab(QWidget):
    """Tab for visualizing attack vectors and threat mappings"""
    
    def __init__(self):
        super().__init__()
        self.analyzer = AttackVectorAnalyzer()
        self.current_site = None
        self.current_threat_rows = []
        self.threats_summary_html = ""
        self.init_ui()
        self.load_data()
    
    def init_ui(self):
        """Initialize UI"""
        main_layout = QVBoxLayout()
        
        # Top control panel
        control_layout = QHBoxLayout()
        
        # Site selector
        control_layout.addWidget(QLabel("Select Site:"))
        self.site_combo = QComboBox()
        self.site_combo.currentIndexChanged.connect(self.on_site_changed)
        control_layout.addWidget(self.site_combo)
        
        # View type selector
        control_layout.addWidget(QLabel("View:"))
        self.view_combo = QComboBox()
        self.view_combo.addItems([
            "Attack Vectors Overview",
            "Exploit Chain Map",
            "Threat Findings",
            "Security Patterns",
            "Learned Exploits",
            "CVE Mappings",
            "Technique Coverage",
            "Timeline Analysis",
            "Risk Matrix"
        ])
        self.view_combo.currentIndexChanged.connect(self.refresh_view)
        control_layout.addWidget(self.view_combo)
        
        # Buttons
        control_layout.addWidget(QPushButton("🔄 Refresh", clicked=self.load_data))
        control_layout.addWidget(QPushButton("📊 Export", clicked=self.export_mapping))
        control_layout.addWidget(QPushButton("📈 Generate Report", clicked=self.generate_report))
        control_layout.addStretch()
        
        main_layout.addLayout(control_layout)
        
        # Summary stats
        stats_layout = QHBoxLayout()
        
        self.stat_patterns = self.create_stat_box("Patterns", "0")
        self.stat_threats = self.create_stat_box("Threats", "0")
        self.stat_exploits = self.create_stat_box("Exploits", "0")
        self.stat_cves = self.create_stat_box("CVEs", "0")
        self.stat_sites = self.create_stat_box("Sites", "0")
        
        stats_layout.addWidget(self.stat_patterns)
        stats_layout.addWidget(self.stat_threats)
        stats_layout.addWidget(self.stat_exploits)
        stats_layout.addWidget(self.stat_cves)
        stats_layout.addWidget(self.stat_sites)
        
        main_layout.addLayout(stats_layout)
        
        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Site and attack vector tree
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        
        left_layout.addWidget(QLabel("Available Targets:"))
        self.vector_tree = QTreeWidget()
        self.vector_tree.setHeaderLabels(["Attack Vectors", "Count", "Severity"])
        self.vector_tree.itemClicked.connect(self.on_vector_selected)
        left_layout.addWidget(self.vector_tree)
        
        left_widget.setLayout(left_layout)
        splitter.addWidget(left_widget)
        
        # Right side - Detailed view
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        
        right_layout.addWidget(QLabel("Details:"))
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(3)
        self.details_table.setHorizontalHeaderLabels(["Property", "Value", "Status"])
        self.details_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.details_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.details_table.itemSelectionChanged.connect(self.on_details_table_selection_changed)
        right_layout.addWidget(self.details_table)
        
        # Details text area
        right_layout.addWidget(QLabel("Attack Vector Details:"))
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(300)
        right_layout.addWidget(self.details_text)
        
        right_widget.setLayout(right_layout)
        splitter.addWidget(right_widget)
        
        splitter.setSizes([400, 500])
        main_layout.addWidget(splitter)
        
        self.setLayout(main_layout)
    
    def create_stat_box(self, label: str, value: str) -> QGroupBox:
        """Create a statistic display box"""
        group = QGroupBox(label)
        layout = QVBoxLayout()
        
        value_label = QLabel(value)
        value_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff00;")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(value_label)
        group.setLayout(layout)
        group.setMinimumWidth(80)
        
        # Store reference for updating
        group.value_label = value_label
        
        return group
    
    def load_data(self):
        """Load all data from database"""
        # Get summary
        summary = self.analyzer.get_vector_summary()
        self.stat_patterns.value_label.setText(str(summary.get('total_patterns', 0)))
        self.stat_threats.value_label.setText(str(summary.get('total_threats', 0)))
        self.stat_exploits.value_label.setText(str(summary.get('total_exploits', 0)))
        self.stat_cves.value_label.setText(str(summary.get('total_cves', 0)))
        self.stat_sites.value_label.setText(str(summary.get('documented_sites', 0)))
        
        # Load documented sites
        sites = self.analyzer.get_documented_sites()
        
        self.site_combo.blockSignals(True)
        self.site_combo.clear()
        self.site_combo.addItem("All Sites")
        
        for site in sites:
            self.site_combo.addItem(site['url'], site)
        
        self.site_combo.blockSignals(False)
        
        # Populate vector tree
        self.populate_vector_tree(summary)
    
    def populate_vector_tree(self, summary: Dict):
        """Populate the attack vector tree"""
        self.vector_tree.clear()
        
        # Patterns
        patterns_item = QTreeWidgetItem(["Security Patterns", str(summary.get('total_patterns', 0))])
        patterns_item.setData(0, Qt.ItemDataRole.UserRole, 'patterns')
        self.vector_tree.addTopLevelItem(patterns_item)
        
        # Threats
        threats_item = QTreeWidgetItem(["Threat Findings", str(summary.get('total_threats', 0))])
        threats_item.setData(0, Qt.ItemDataRole.UserRole, 'threats')
        
        # Add severity breakdown
        severity_breakdown = summary.get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            color = self.get_severity_color(severity)
            child = QTreeWidgetItem([f"  {severity}", str(count)])
            child.setBackground(0, QBrush(color))
            threats_item.addChild(child)
        
        self.vector_tree.addTopLevelItem(threats_item)
        
        # Exploits
        exploits_item = QTreeWidgetItem(["Learned Exploits", str(summary.get('total_exploits', 0))])
        exploits_item.setData(0, Qt.ItemDataRole.UserRole, 'exploits')
        self.vector_tree.addTopLevelItem(exploits_item)
        
        # CVEs
        cves_item = QTreeWidgetItem(["CVEs", str(summary.get('total_cves', 0))])
        cves_item.setData(0, Qt.ItemDataRole.UserRole, 'cves')
        
        # Add CVSS breakdown
        cve_severity = summary.get('cve_severity', {})
        for severity, count in cve_severity.items():
            color = self.get_severity_color(severity)
            child = QTreeWidgetItem([f"  {severity}", str(count)])
            child.setBackground(0, QBrush(color))
            cves_item.addChild(child)
        
        self.vector_tree.addTopLevelItem(cves_item)
        
        # Techniques
        techniques_item = QTreeWidgetItem(["Techniques", "📋"])
        techniques_item.setData(0, Qt.ItemDataRole.UserRole, 'techniques')
        self.vector_tree.addTopLevelItem(techniques_item)
    
    def get_severity_color(self, severity: str) -> QColor:
        """Get color for severity level"""
        normalized = (severity or "").strip().lower()
        colors = {
            'critical': QColor("#ff0000"),
            'high': QColor("#ff7700"),
            'warning': QColor("#ffb347"),
            'medium': QColor("#ffff00"),
            'low': QColor("#00ff00"),
            'info': QColor("#00ccff"),
        }
        return colors.get(normalized, QColor("#cccccc"))

    def reset_default_table_headers(self):
        """Reset details table to the default 3-column layout"""
        self.details_table.setColumnCount(3)
        self.details_table.setHorizontalHeaderLabels(["Property", "Value", "Status"])
        self.details_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectItems)
        self.details_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

    def on_details_table_selection_changed(self):
        """Render full threat details when a threat row is selected"""
        if self.view_combo.currentText() != "Threat Findings":
            return

        selected_items = self.details_table.selectedItems()
        if not selected_items:
            if self.threats_summary_html:
                self.details_text.setHtml(self.threats_summary_html)
            return

        row = selected_items[0].row()
        if row < 0 or row >= len(self.current_threat_rows):
            return

        threat = self.current_threat_rows[row]
        severity = threat.get('severity', 'Unknown')
        severity_color = self.get_severity_color(severity).name()

        full_detail_html = (
            "<div style='margin-top:10px;padding:10px;border:1px solid #324760;"
            "border-left:4px solid " + severity_color + ";background:#0f141c;border-radius:8px;color:#d8dee9'>"
            "<div style='font-size:13px;font-weight:700;color:#8bd5ff;margin-bottom:6px'>"
            "Selected Threat (Full Detail)"
            "</div>"
            f"<div><b>Type:</b> {html.escape(str(threat.get('threat_type', 'N/A')))}</div>"
            f"<div><b>Severity:</b> <span style='color:{severity_color}'>{html.escape(str(severity))}</span></div>"
            f"<div><b>Path:</b> {html.escape(str(threat.get('path', 'N/A')))}</div>"
            f"<div><b>Sensor:</b> {html.escape(str(threat.get('browser', 'N/A')))}</div>"
            f"<div><b>Detected:</b> {html.escape(str(threat.get('detected_at', 'N/A')))}</div>"
            f"<div><b>Pattern:</b> {html.escape(str(threat.get('pattern', 'N/A')))}</div>"
            f"<div><b>Context:</b> {html.escape(str(threat.get('context', 'N/A')))}</div>"
            f"<div style='margin-top:6px'><b>Snippet:</b></div>"
            f"<pre style='white-space:pre-wrap;background:#0b0f14;border:1px solid #243041;padding:8px;border-radius:6px;'>"
            f"{html.escape(str(threat.get('code_snippet', '')))}"
            "</pre>"
            "</div>"
        )

        if self.threats_summary_html:
            self.details_text.setHtml(self.threats_summary_html + full_detail_html)
        else:
            self.details_text.setHtml(full_detail_html)
    
    def on_site_changed(self, index: int):
        """Handle site selection change"""
        if index < 0:
            return
        
        site_data = self.site_combo.itemData(index)
        if site_data:
            self.current_site = site_data['url']
        else:
            self.current_site = None
        
        self.refresh_view()
    
    def on_vector_selected(self, item: QTreeWidgetItem, column: int):
        """Handle vector selection"""
        vector_type = item.data(0, Qt.ItemDataRole.UserRole)
        if not vector_type:
            return
        
        self.display_vector_details(vector_type)
    
    def refresh_view(self):
        """Refresh the main view based on selected options"""
        view_type = self.view_combo.currentText()
        
        if view_type == "Attack Vectors Overview":
            self.show_overview()
        elif view_type == "Exploit Chain Map":
            self.show_exploit_chain_map()
        elif view_type == "Threat Findings":
            self.show_threats()
        elif view_type == "Security Patterns":
            self.show_patterns()
        elif view_type == "Learned Exploits":
            self.show_exploits()
        elif view_type == "CVE Mappings":
            self.show_cves()
        elif view_type == "Technique Coverage":
            self.show_techniques()
        elif view_type == "Timeline Analysis":
            self.show_timeline()
        elif view_type == "Risk Matrix":
            self.show_risk_matrix()
    
    def show_overview(self):
        """Show overview of all attack vectors"""
        self.reset_default_table_headers()
        self.details_table.setRowCount(0)
        
        vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
        
        overview_data = [
            ("Total Patterns", str(len(vectors.get('patterns', [])))),
            ("Total Threats", str(len(vectors.get('threats', [])))),
            ("Total Exploits", str(len(vectors.get('exploits', [])))),
            ("Total CVEs", str(len(vectors.get('cves', [])))),
            ("Total Techniques", str(len(vectors.get('techniques', [])))),
        ]
        
        for i, (prop, value) in enumerate(overview_data):
            self.details_table.insertRow(i)
            self.details_table.setItem(i, 0, QTableWidgetItem(prop))
            self.details_table.setItem(i, 1, QTableWidgetItem(value))
            self.details_table.setItem(i, 2, QTableWidgetItem("✓"))
        
        self.details_text.setHtml(self.build_exploit_chain_html(vectors))

    def show_exploit_chain_map(self):
        """Show exploit chains / attack vectors in a visual flow layout"""
        self.reset_default_table_headers()
        self.details_table.setRowCount(0)

        vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
        threats = vectors.get('threats', [])
        exploits = vectors.get('exploits', [])
        cves = vectors.get('cves', [])

        self.details_table.setColumnCount(3)
        self.details_table.setHorizontalHeaderLabels(["Chain Stage", "Mapped Vector", "Signal"])

        chain_rows = []
        for threat in threats[:5]:
            chain_rows.append((
                "Recon / Trigger",
                threat.get('threat_type', 'Unknown Threat'),
                threat.get('severity', 'Unknown')
            ))
        for exploit in exploits[:5]:
            attempts = exploit.get('success_count', 0) + exploit.get('fail_count', 0)
            chain_rows.append((
                "Exploit / Pivot",
                exploit.get('exploit_type', 'Unknown Exploit'),
                f"{exploit.get('success_count', 0)}/{attempts if attempts else 0}"
            ))
        for cve in cves[:5]:
            chain_rows.append((
                "Impact / Exposure",
                cve.get('cve_id', 'Unknown CVE'),
                f"CVSS {float(cve.get('cvss', 0) or 0):.1f}"
            ))

        for i, (stage, vector, signal) in enumerate(chain_rows):
            self.details_table.insertRow(i)
            self.details_table.setItem(i, 0, QTableWidgetItem(stage))
            self.details_table.setItem(i, 1, QTableWidgetItem(vector))
            self.details_table.setItem(i, 2, QTableWidgetItem(signal))

        self.details_text.setHtml(self.build_exploit_chain_html(vectors))

    def build_exploit_chain_html(self, vectors: Dict[str, List]) -> str:
        """Build a rich visual chain map for attack vectors"""
        threats = vectors.get('threats', [])
        exploits = vectors.get('exploits', [])
        cves = vectors.get('cves', [])
        techniques = vectors.get('techniques', [])

        top_threats = threats[:3]
        top_exploits = sorted(
            exploits,
            key=lambda e: (e.get('success_count', 0), -e.get('fail_count', 0)),
            reverse=True,
        )[:3]
        top_cves = sorted(cves, key=lambda c: float(c.get('cvss', 0) or 0), reverse=True)[:3]
        top_techniques = techniques[:3]

        if not (top_threats or top_exploits or top_cves or top_techniques):
            return (
                "<div style='padding:10px;color:#b0b8c4;'>"
                "No chain data available for this selection yet."
                "</div>"
            )

        def stage_card(title: str, accent: str, items: List[str]) -> str:
            rendered_items = "".join(
                f"<li style='margin:2px 0'>{html.escape(item)}</li>" for item in items
            ) or "<li style='margin:2px 0'>No vectors mapped</li>"
            return (
                "<div style='"
                "background:#121821;"
                "border:1px solid #243041;"
                "border-left:4px solid " + accent + ";"
                "border-radius:8px;"
                "padding:8px 10px;"
                "margin:6px 0;"
                "color:#d8dee9;"
                "'>"
                f"<div style='font-weight:700;color:{accent};margin-bottom:4px'>{html.escape(title)}</div>"
                f"<ul style='margin:0 0 0 16px;padding:0'>{rendered_items}</ul>"
                "</div>"
            )

        threat_items = [
            f"{t.get('threat_type', 'Unknown')} [{t.get('severity', 'Unknown')}]"
            for t in top_threats
        ]
        exploit_items = []
        for e in top_exploits:
            success = e.get('success_count', 0)
            fail = e.get('fail_count', 0)
            total = success + fail
            ratio = f"{success}/{total}" if total > 0 else "0/0"
            exploit_items.append(f"{e.get('exploit_type', 'Unknown')} (success {ratio})")

        cve_items = [
            f"{c.get('cve_id', 'Unknown')} (CVSS {float(c.get('cvss', 0) or 0):.1f})"
            for c in top_cves
        ]
        technique_items = [
            f"{t.get('name', 'Unknown')} / {t.get('category', 'N/A')}"
            for t in top_techniques
        ]

        return (
            "<div style='font-family:Segoe UI, Arial, sans-serif;'>"
            "<div style='font-size:14px;font-weight:700;color:#8bd5ff;margin-bottom:8px'>"
            "Exploit Chain / Attack Vector Mapping"
            "</div>"
            + stage_card("1. Entry & Trigger Signals", "#5ac8fa", threat_items)
            + "<div style='color:#88c0d0;font-weight:700;padding-left:8px'>↓</div>"
            + stage_card("2. Exploitation Paths", "#ff9f43", exploit_items)
            + "<div style='color:#88c0d0;font-weight:700;padding-left:8px'>↓</div>"
            + stage_card("3. Technique Alignment", "#b48ead", technique_items)
            + "<div style='color:#88c0d0;font-weight:700;padding-left:8px'>↓</div>"
            + stage_card("4. CVE / Impact Surface", "#ff6b6b", cve_items)
            + "</div>"
        )
    
    def show_threats(self):
        """Show threat findings"""
        self.details_table.setColumnCount(6)
        self.details_table.setHorizontalHeaderLabels([
            "Threat Type",
            "Severity",
            "Source Path",
            "Sensor",
            "Detected",
            "Pattern / Snippet",
        ])
        self.details_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.details_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.details_table.setRowCount(0)
        self.current_threat_rows = []
        self.threats_summary_html = ""
        
        vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
        threats = vectors.get('threats', [])

        for i, threat in enumerate(threats[:50]):
            self.details_table.insertRow(i)
            threat_item = QTableWidgetItem(threat.get('threat_type', 'N/A'))
            severity = threat.get('severity', 'N/A')
            severity_item = QTableWidgetItem(severity)

            severity_color = self.get_severity_color(severity)
            severity_item.setBackground(QBrush(severity_color))

            self.details_table.setItem(i, 0, threat_item)
            self.details_table.setItem(i, 1, severity_item)
            self.details_table.setItem(i, 2, QTableWidgetItem(threat.get('path', 'N/A')[:120]))
            self.details_table.setItem(i, 3, QTableWidgetItem(threat.get('browser', 'N/A')))
            self.details_table.setItem(i, 4, QTableWidgetItem((threat.get('detected_at', '') or '')[:19]))

            pattern = threat.get('pattern', '')
            snippet = threat.get('code_snippet', '')
            compact = f"{pattern} | {snippet}".strip(" |")
            self.details_table.setItem(i, 5, QTableWidgetItem(compact[:180]))

        self.current_threat_rows = threats[:50]

        if threats:
            severity_counts = {}
            for threat in threats:
                sev = (threat.get('severity') or 'Unknown').upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            severity_summary = " | ".join(
                f"{label}: {count}" for label, count in sorted(severity_counts.items())
            )

            cards = []
            for threat in threats[:8]:
                severity = threat.get('severity', 'Unknown')
                color = self.get_severity_color(severity).name()
                cards.append(
                    "<div style='background:#121821;border:1px solid #283548;border-left:4px solid " + color + ";"
                    "border-radius:8px;padding:8px 10px;margin:6px 0;color:#d8dee9'>"
                    f"<div style='font-weight:700'>{html.escape(str(threat.get('threat_type', 'Unknown Threat')))}"
                    f" <span style='color:{color}'>[{html.escape(str(severity))}]</span></div>"
                    f"<div><b>Path:</b> {html.escape(str(threat.get('path', 'N/A')))}</div>"
                    f"<div><b>Sensor:</b> {html.escape(str(threat.get('browser', 'N/A')))} | "
                    f"<b>Detected:</b> {html.escape(str(threat.get('detected_at', 'N/A')))}</div>"
                    f"<div><b>Pattern:</b> {html.escape(str(threat.get('pattern', 'N/A')))}</div>"
                    f"<div><b>Context:</b> {html.escape(str(threat.get('context', 'N/A')))}</div>"
                    f"<div><b>Snippet:</b> {html.escape(str(threat.get('code_snippet', ''))[:180])}</div>"
                    "</div>"
                )

            self.threats_summary_html = (
                "<div style='font-family:Segoe UI, Arial, sans-serif;'>"
                "<div style='font-size:14px;font-weight:700;color:#8bd5ff;margin-bottom:8px'>"
                f"Threat Findings Detail ({len(threats)} total)"
                "</div>"
                f"<div style='color:#b8c4d4;margin-bottom:8px'><b>Severity Mix:</b> {html.escape(severity_summary)}</div>"
                + "".join(cards)
                + "</div>"
            )
            self.details_text.setHtml(self.threats_summary_html)
        else:
            self.details_text.setText("No threat findings available for this selection.")

    def show_patterns(self):
        """Show security patterns"""
        self.reset_default_table_headers()
        self.details_table.setRowCount(0)
        
        vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
        patterns = vectors.get('patterns', [])
        
        for i, pattern in enumerate(patterns[:50]):
            self.details_table.insertRow(i)
            self.details_table.setItem(i, 0, QTableWidgetItem(pattern.get('pattern_type', 'N/A')))
            
            confidence = pattern.get('confidence', 0)
            self.details_table.setItem(i, 1, QTableWidgetItem(f"{confidence:.1%}"))
            
            occurrences = pattern.get('occurrences', 0)
            self.details_table.setItem(i, 2, QTableWidgetItem(str(occurrences)))
        
        if patterns:
            summary = f"Found {len(patterns)} security patterns\n\n"
            for pattern in patterns[:5]:
                summary += f"• {pattern.get('pattern_type')}\n"
                summary += f"  Confidence: {pattern.get('confidence', 0):.1%}\n"
                summary += f"  Occurrences: {pattern.get('occurrences', 0)}\n"
                summary += f"  Signature: {pattern.get('signature')[:50]}...\n\n"
            self.details_text.setText(summary)
    
    def show_exploits(self):
        """Show learned exploits"""
        self.reset_default_table_headers()
        self.details_table.setRowCount(0)
        
        vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
        exploits = vectors.get('exploits', [])
        
        for i, exploit in enumerate(exploits[:50]):
            self.details_table.insertRow(i)
            self.details_table.setItem(i, 0, QTableWidgetItem(exploit.get('exploit_type', 'N/A')))
            
            success_rate = exploit.get('success_count', 0)
            total = success_rate + exploit.get('fail_count', 0)
            rate = f"{success_rate}/{total}" if total > 0 else "0/0"
            self.details_table.setItem(i, 1, QTableWidgetItem(rate))
            
            self.details_table.setItem(i, 2, QTableWidgetItem(exploit.get('learned_at', '')[:10]))
        
        if exploits:
            summary = f"Found {len(exploits)} learned exploits\n\n"
            for exploit in exploits[:5]:
                summary += f"• {exploit.get('exploit_type')}\n"
                summary += f"  Source: {exploit.get('source_url')}\n"
                summary += f"  Success: {exploit.get('success_count', 0)} / Fail: {exploit.get('fail_count', 0)}\n"
                summary += f"  Code: {exploit.get('code', '')[:50]}...\n\n"
            self.details_text.setText(summary)
    
    def show_cves(self):
        """Show CVE mappings"""
        self.reset_default_table_headers()
        self.details_table.setRowCount(0)
        
        vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
        cves = vectors.get('cves', [])
        
        for i, cve in enumerate(cves[:50]):
            self.details_table.insertRow(i)
            self.details_table.setItem(i, 0, QTableWidgetItem(cve.get('cve_id', 'N/A')))
            
            cvss = cve.get('cvss', 0)
            self.details_table.setItem(i, 1, QTableWidgetItem(f"{cvss:.1f}"))
            
            self.details_table.setItem(i, 2, QTableWidgetItem(cve.get('summary', '')[:100]))
        
        if cves:
            summary = f"Found {len(cves)} related CVEs\n\n"
            for cve in cves[:5]:
                summary += f"• {cve.get('cve_id')} (CVSS: {cve.get('cvss', 0):.1f})\n"
                summary += f"  {cve.get('summary')}\n"
                summary += f"  Published: {cve.get('published', 'Unknown')}\n\n"
            self.details_text.setText(summary)
    
    def show_techniques(self):
        """Show attack techniques"""
        self.reset_default_table_headers()
        self.details_table.setRowCount(0)
        
        vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
        techniques = vectors.get('techniques', [])
        
        for i, tech in enumerate(techniques[:50]):
            self.details_table.insertRow(i)
            self.details_table.setItem(i, 0, QTableWidgetItem(tech.get('name', 'N/A')))
            self.details_table.setItem(i, 1, QTableWidgetItem(tech.get('category', 'N/A')))
            
            confidence = tech.get('confidence', 0)
            self.details_table.setItem(i, 2, QTableWidgetItem(f"{confidence:.1%}"))
        
        if techniques:
            summary = f"Found {len(techniques)} attack techniques\n\n"
            for tech in techniques[:5]:
                summary += f"• {tech.get('name')} ({tech.get('category')})\n"
                summary += f"  Confidence: {tech.get('confidence', 0):.1%}\n"
                summary += f"  {tech.get('description', '')[:100]}...\n\n"
            self.details_text.setText(summary)
    
    def show_timeline(self):
        """Show timeline analysis"""
        self.reset_default_table_headers()
        self.details_table.setRowCount(0)
        
        summary = "Attack Vector Timeline Analysis\n\n"
        summary += "Recent discoveries (last 30 days):\n"
        summary += "- Monitor database for timestamp-based analysis\n"
        summary += "- Track pattern emergence over time\n"
        summary += "- Correlate threat discovery with external events\n"
        summary += "- Identify attack campaign timing\n\n"
        
        summary += "Key metrics:\n"
        summary += "- Discovery frequency\n"
        summary += "- Exploitation lag time\n"
        summary += "- Pattern evolution\n"
        summary += "- Response timeline\n"
        
        self.details_text.setText(summary)
    
    def show_risk_matrix(self):
        """Show risk matrix visualization"""
        self.reset_default_table_headers()
        self.details_table.setRowCount(0)
        
        vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
        threats = vectors.get('threats', [])
        
        # Create risk matrix
        risk_matrix = {
            'Critical': {'High': 0, 'Medium': 0, 'Low': 0},
            'High': {'High': 0, 'Medium': 0, 'Low': 0},
            'Medium': {'High': 0, 'Medium': 0, 'Low': 0},
            'Low': {'High': 0, 'Medium': 0, 'Low': 0},
        }
        
        for threat in threats:
            severity = threat.get('severity', 'Low')
            threat_type = threat.get('threat_type', 'Medium')
            if severity in risk_matrix and threat_type in risk_matrix[severity]:
                risk_matrix[severity][threat_type] += 1
        
        # Display matrix
        row = 0
        summary = "Risk Matrix (Severity vs Threat Type)\n\n"
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            summary += f"{severity}:"
            for threat_type in ['High', 'Medium', 'Low']:
                count = risk_matrix[severity][threat_type]
                summary += f"  {threat_type}: {count}"
            summary += "\n"
        
        self.details_text.setText(summary)
    
    def display_vector_details(self, vector_type: str):
        """Display detailed information about a specific vector type"""
        self.details_table.setRowCount(0)
        
        if vector_type == 'patterns':
            self.show_patterns()
        elif vector_type == 'threats':
            self.show_threats()
        elif vector_type == 'exploits':
            self.show_exploits()
        elif vector_type == 'cves':
            self.show_cves()
        elif vector_type == 'techniques':
            self.show_techniques()
    
    def export_mapping(self):
        """Export the attack vector mapping"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Attack Vector Mapping", "", "JSON (*.json);;CSV (*.csv)"
        )
        
        if not file_path:
            return
        
        try:
            vectors = self.analyzer.get_attack_vectors_for_site(self.current_site or "")
            summary = self.analyzer.get_vector_summary()
            
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'site': self.current_site or 'All',
                'summary': summary,
                'vectors': {
                    'patterns': vectors.get('patterns', [])[:10],
                    'threats': vectors.get('threats', [])[:10],
                    'exploits': vectors.get('exploits', [])[:10],
                    'cves': vectors.get('cves', [])[:10],
                }
            }
            
            if file_path.endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            
            QMessageBox.information(self, "Success", f"Mapping exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {e}")
    
    def generate_report(self):
        """Generate detailed attack vector report"""
        try:
            report = "ATTACK VECTOR MAPPING REPORT\n"
            report += "=" * 50 + "\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += f"Site: {self.current_site or 'All Documented Sites'}\n\n"
            
            summary = self.analyzer.get_vector_summary()
            report += "SUMMARY\n"
            report += "-" * 50 + "\n"
            report += f"Total Security Patterns: {summary.get('total_patterns', 0)}\n"
            report += f"Total Threat Findings: {summary.get('total_threats', 0)}\n"
            report += f"Total Learned Exploits: {summary.get('total_exploits', 0)}\n"
            report += f"Total CVEs: {summary.get('total_cves', 0)}\n"
            report += f"Documented Sites: {summary.get('documented_sites', 0)}\n\n"
            
            report += "SEVERITY BREAKDOWN\n"
            report += "-" * 50 + "\n"
            for severity, count in summary.get('severity_breakdown', {}).items():
                report += f"{severity}: {count}\n"
            report += "\n"
            
            report += "CVE SEVERITY\n"
            report += "-" * 50 + "\n"
            for severity, count in summary.get('cve_severity', {}).items():
                report += f"{severity}: {count}\n"
            
            self.details_text.setText(report)
            QMessageBox.information(self, "Report Generated", "Attack Vector Report created successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Report generation failed: {e}")
