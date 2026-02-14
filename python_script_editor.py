"""
Python Script Editor & Manager for HadesAI
Allows creating, editing, and executing Python scripts with AI assistance
"""

import os
import sys
import json
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel,
    QComboBox, QFileDialog, QMessageBox, QSplitter, QListWidget,
    QListWidgetItem, QGroupBox, QFormLayout, QLineEdit, QCheckBox,
    QSpinBox, QTabWidget, QScrollArea, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter


class PythonHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for Python code"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#cc7832"))
        keyword_format.setFontWeight(True)
        keywords = ['and', 'as', 'assert', 'break', 'class', 'continue', 'def',
                   'del', 'elif', 'else', 'except', 'finally', 'for', 'from',
                   'global', 'if', 'import', 'in', 'is', 'lambda', 'not', 'or',
                   'pass', 'raise', 'return', 'try', 'while', 'with', 'yield']
        for word in keywords:
            pattern = f'\\b{word}\\b'
            self.highlighting_rules.append((pattern, keyword_format))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#6a8759"))
        self.highlighting_rules.append((r'"[^"\\]*(\\.[^"\\]*)*"', string_format))
        self.highlighting_rules.append((r"'[^'\\]*(\\.[^'\\]*)*'", string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#808080"))
        self.highlighting_rules.append((r'#[^\n]*', comment_format))
        
        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#6897bb"))
        self.highlighting_rules.append((r'\b\d+\b', number_format))
        
        # Functions
        function_format = QTextCharFormat()
        function_format.setForeground(QColor("#ffc66d"))
        self.highlighting_rules.append((r'\bdef\s+\w+', function_format))

    def highlightBlock(self, text):
        import re
        for pattern, fmt in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class ScriptExecutor(QThread):
    """Executes Python scripts in a separate thread"""
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, script_path: str):
        super().__init__()
        self.script_path = script_path
        self.process = None
    
    def run(self):
        try:
            self.output_signal.emit(f"[*] Executing: {self.script_path}\n")
            result = subprocess.run(
                [sys.executable, self.script_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.stdout:
                self.output_signal.emit(result.stdout)
            if result.stderr:
                self.error_signal.emit(result.stderr)
            
            self.output_signal.emit(f"\n[+] Exit code: {result.returncode}")
        except subprocess.TimeoutExpired:
            self.error_signal.emit("[!] Script execution timed out after 60 seconds")
        except Exception as e:
            self.error_signal.emit(f"[!] Execution error: {str(e)}")
        finally:
            self.finished_signal.emit()


class PythonScriptEditorTab(QWidget):
    """Main Python Script Editor Tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scripts_dir = Path("scripts")
        self.scripts_dir.mkdir(exist_ok=True)
        
        self.current_file = None
        self.executor = None
        self.init_ui()
        self.load_scripts_list()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QHBoxLayout(self)
        
        # Left panel - Script list and controls
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Script list
        left_layout.addWidget(QLabel("📄 Scripts"))
        self.scripts_list = QListWidget()
        self.scripts_list.itemClicked.connect(self._on_script_selected)
        left_layout.addWidget(self.scripts_list)
        
        # Controls
        btn_layout = QVBoxLayout()
        
        self.btn_new = QPushButton("➕ New Script")
        self.btn_new.clicked.connect(self._create_new_script)
        btn_layout.addWidget(self.btn_new)
        
        self.btn_delete = QPushButton("🗑️ Delete")
        self.btn_delete.clicked.connect(self._delete_script)
        btn_layout.addWidget(self.btn_delete)
        
        self.btn_save = QPushButton("💾 Save")
        self.btn_save.clicked.connect(self._save_script)
        btn_layout.addWidget(self.btn_save)
        
        self.btn_execute = QPushButton("▶️ Execute")
        self.btn_execute.clicked.connect(self._execute_script)
        self.btn_execute.setStyleSheet("QPushButton { background: #27ae60; }")
        btn_layout.addWidget(self.btn_execute)
        
        self.btn_open = QPushButton("📂 Open File")
        self.btn_open.clicked.connect(self._open_file)
        btn_layout.addWidget(self.btn_open)
        
        left_layout.addLayout(btn_layout)
        
        # Right panel - Editor and output
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Script info
        info_layout = QHBoxLayout()
        right_layout.addLayout(info_layout)
        
        self.label_current = QLabel("No script selected")
        self.label_current.setStyleSheet("color: #e94560;")
        right_layout.addWidget(self.label_current)
        
        # Editor tab
        editor_tabs = QTabWidget()
        
        # Code editor
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Consolas", 10))
        self.highlighter = PythonHighlighter(self.editor.document())
        editor_tabs.addTab(self.editor, "📝 Code")
        
        # Output panel
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 9))
        self.output.setMaximumHeight(150)
        editor_tabs.addTab(self.output, "📋 Output")
        
        right_layout.addWidget(editor_tabs)
        
        # Splitter between left and right
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        layout.addWidget(splitter)
    
    def load_scripts_list(self):
        """Load list of available scripts"""
        self.scripts_list.clear()
        for script_file in sorted(self.scripts_dir.glob("*.py")):
            item = QListWidgetItem(script_file.stem)
            item.setData(Qt.ItemDataRole.UserRole, str(script_file))
            self.scripts_list.addItem(item)
    
    def _on_script_selected(self, item: QListWidgetItem):
        """Load selected script"""
        script_path = item.data(Qt.ItemDataRole.UserRole)
        try:
            with open(script_path, 'r') as f:
                content = f.read()
            self.editor.setPlainText(content)
            self.current_file = script_path
            self.label_current.setText(f"File: {Path(script_path).name}")
            self.output.clear()
        except Exception as e:
            self._log_error(f"Failed to load script: {e}")
    
    def _create_new_script(self):
        """Create a new script"""
        dialog = QMessageBox(self)
        dialog.setWindowTitle("New Script")
        
        # Simple input dialog
        from PyQt6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "New Script", "Script name (without .py):")
        
        if ok and name:
            script_path = self.scripts_dir / f"{name}.py"
            if script_path.exists():
                QMessageBox.warning(self, "Error", "Script already exists")
                return
            
            # Create with template
            template = '''"""
Auto-generated Python script
"""

import sys
import os

def main():
    """Main function"""
    print("Hello from HadesAI!")
    print(f"Python version: {sys.version}")
    
    # Your code here
    pass

if __name__ == "__main__":
    main()
'''
            
            with open(script_path, 'w') as f:
                f.write(template)
            
            self.load_scripts_list()
            self._log_output(f"[+] Created new script: {name}.py")
    
    def _delete_script(self):
        """Delete selected script"""
        current = self.scripts_list.currentItem()
        if not current:
            QMessageBox.warning(self, "Error", "No script selected")
            return
        
        script_path = current.data(Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Delete {Path(script_path).name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            os.remove(script_path)
            self.load_scripts_list()
            self.editor.clear()
            self.current_file = None
            self._log_output("[+] Script deleted")
    
    def _save_script(self):
        """Save current script"""
        if not self.current_file:
            QMessageBox.warning(self, "Error", "No script selected")
            return
        
        try:
            with open(self.current_file, 'w') as f:
                f.write(self.editor.toPlainText())
            self._log_output(f"[+] Script saved: {Path(self.current_file).name}")
        except Exception as e:
            self._log_error(f"Failed to save: {e}")
    
    def _execute_script(self):
        """Execute the current script"""
        if not self.current_file:
            QMessageBox.warning(self, "Error", "No script selected")
            return
        
        # Save before executing
        self._save_script()
        
        self.output.clear()
        self._log_output("[*] Starting execution...")
        
        self.executor = ScriptExecutor(self.current_file)
        self.executor.output_signal.connect(self._log_output)
        self.executor.error_signal.connect(self._log_error)
        self.executor.finished_signal.connect(self._on_execution_finished)
        self.executor.start()
        
        self.btn_execute.setEnabled(False)
    
    def _open_file(self):
        """Open a Python file from disk"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Python Script", "", "Python Files (*.py)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Copy to scripts directory
                dest_path = self.scripts_dir / Path(file_path).name
                with open(dest_path, 'w') as f:
                    f.write(content)
                
                self.load_scripts_list()
                self._log_output(f"[+] Imported: {Path(file_path).name}")
            except Exception as e:
                self._log_error(f"Failed to open file: {e}")
    
    def _on_execution_finished(self):
        """Called when script execution finishes"""
        self.btn_execute.setEnabled(True)
        self._log_output("[+] Execution completed")
    
    def _log_output(self, message: str):
        """Log output to the output panel"""
        cursor = self.output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.output.setTextCursor(cursor)
        self.output.insertPlainText(message)
    
    def _log_error(self, message: str):
        """Log error message"""
        self._log_output(f"\n[!] ERROR: {message}\n")


# For standalone testing
if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication, QMainWindow
    
    app = QApplication(sys.argv)
    window = QMainWindow()
    window.setWindowTitle("Python Script Editor")
    window.setGeometry(100, 100, 1200, 700)
    
    editor = PythonScriptEditorTab()
    window.setCentralWidget(editor)
    
    window.show()
    sys.exit(app.exec())
