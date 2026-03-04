#!/usr/bin/env python3
"""
Hades AI - Clockworks Obfuscation GUI
Interactive UI for payload obfuscation using clock-direction RNG
"""

import sys
import json
import base64
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTextEdit, QLabel, QPushButton, QSpinBox, QComboBox,
    QMessageBox, QProgressBar, QStatusBar, QFileDialog, QGroupBox,
    QGridLayout, QCheckBox, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QTextCursor

from modules.obfuscation_engine import ClockworksObfuscator, keystream
from modules.hades_obfuscation_integration import (
    HadesObfuscationIntegration, ObfuscationType, get_obfuscation_service
)


class ObfuscationWorker(QThread):
    """Worker thread for obfuscation operations"""
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(dict)
    progress = pyqtSignal(int)

    def __init__(self, operation, payload, seed, rounds, payload_type):
        super().__init__()
        self.operation = operation
        self.payload = payload
        self.seed = seed
        self.rounds = rounds
        self.payload_type = payload_type

    def run(self):
        try:
            obfuscator = ClockworksObfuscator(seed=self.seed, rounds=self.rounds)
            self.progress.emit(25)

            if self.operation == "obfuscate":
                if self.payload_type == "lua":
                    result = obfuscator.obfuscate_lua(self.payload)
                else:
                    payload_bytes = self.payload.encode() if isinstance(self.payload, str) else self.payload
                    result = obfuscator.obfuscate_binary(payload_bytes, format="b64")
                self.progress.emit(75)
                self.result.emit({
                    "type": "obfuscation",
                    "result": result,
                    "original_size": len(self.payload.encode() if isinstance(self.payload, str) else self.payload),
                    "obfuscated_size": len(result)
                })
            elif self.operation == "deobfuscate":
                original = obfuscator.deobfuscate(self.payload, format="b64")
                self.progress.emit(75)
                self.result.emit({
                    "type": "deobfuscation",
                    "result": original.decode() if original else "",
                    "obfuscated_size": len(self.payload),
                    "original_size": len(original) if original else 0
                })

            self.progress.emit(100)
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit()


class ClockworksObfuscationGUI(QMainWindow):
    """Clockworks Obfuscation GUI for Hades AI"""

    def __init__(self):
        super().__init__()
        self.service = get_obfuscation_service()
        self.worker = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Hades AI - Clockworks Obfuscation Engine")
        self.setGeometry(100, 100, 1200, 800)

        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Obfuscation tab
        tabs.addTab(self.create_obfuscation_tab(), "Obfuscation")

        # Polymorphic tab
        tabs.addTab(self.create_polymorphic_tab(), "Polymorphic")

        # Batch tab
        tabs.addTab(self.create_batch_tab(), "Batch Operations")

        # Statistics tab
        tabs.addTab(self.create_stats_tab(), "Statistics")

        # Status bar
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

    def create_obfuscation_tab(self):
        """Create the main obfuscation tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Settings group
        settings_group = QGroupBox("Settings")
        settings_layout = QGridLayout()

        settings_layout.addWidget(QLabel("Seed (1-12):"), 0, 0)
        self.seed_spin = QSpinBox()
        self.seed_spin.setMinimum(1)
        self.seed_spin.setMaximum(12)
        self.seed_spin.setValue(7)
        settings_layout.addWidget(self.seed_spin, 0, 1)

        settings_layout.addWidget(QLabel("Rounds:"), 0, 2)
        self.rounds_spin = QSpinBox()
        self.rounds_spin.setMinimum(1)
        self.rounds_spin.setMaximum(20)
        self.rounds_spin.setValue(9)
        settings_layout.addWidget(self.rounds_spin, 0, 3)

        settings_layout.addWidget(QLabel("Payload Type:"), 1, 0)
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems(["lua", "payload", "shellcode", "command", "script", "binary"])
        settings_layout.addWidget(self.payload_type_combo, 1, 1)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # Input area
        layout.addWidget(QLabel("Input Payload:"))
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter payload to obfuscate or deobfuscate...")
        self.input_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.input_text)

        # Buttons
        button_layout = QHBoxLayout()
        
        obfuscate_btn = QPushButton("Obfuscate")
        obfuscate_btn.clicked.connect(self.obfuscate_payload)
        button_layout.addWidget(obfuscate_btn)

        deobfuscate_btn = QPushButton("Deobfuscate")
        deobfuscate_btn.clicked.connect(self.deobfuscate_payload)
        button_layout.addWidget(deobfuscate_btn)

        load_btn = QPushButton("Load File")
        load_btn.clicked.connect(self.load_input_file)
        button_layout.addWidget(load_btn)

        layout.addLayout(button_layout)

        # Output area
        layout.addWidget(QLabel("Output:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.output_text)

        # Copy and save buttons
        output_button_layout = QHBoxLayout()
        
        copy_btn = QPushButton("Copy Output")
        copy_btn.clicked.connect(self.copy_output)
        output_button_layout.addWidget(copy_btn)

        save_btn = QPushButton("Save Output")
        save_btn.clicked.connect(self.save_output)
        output_button_layout.addWidget(save_btn)

        layout.addLayout(output_button_layout)

        widget.setLayout(layout)
        return widget

    def create_polymorphic_tab(self):
        """Create the polymorphic generation tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Generate polymorphic variations with different seeds/rounds:"))

        # Settings
        settings_layout = QHBoxLayout()
        settings_layout.addWidget(QLabel("Variations:"))
        self.poly_variations_spin = QSpinBox()
        self.poly_variations_spin.setMinimum(1)
        self.poly_variations_spin.setMaximum(50)
        self.poly_variations_spin.setValue(5)
        settings_layout.addWidget(self.poly_variations_spin)

        settings_layout.addWidget(QLabel("Payload Type:"))
        self.poly_type_combo = QComboBox()
        self.poly_type_combo.addItems(["lua", "payload", "shellcode", "command", "script", "binary"])
        settings_layout.addWidget(self.poly_type_combo)

        layout.addLayout(settings_layout)

        # Input
        layout.addWidget(QLabel("Payload:"))
        self.poly_input = QTextEdit()
        self.poly_input.setPlaceholderText("Enter payload for polymorphic generation...")
        layout.addWidget(self.poly_input)

        # Generate button
        gen_btn = QPushButton("Generate Polymorphic Variations")
        gen_btn.clicked.connect(self.generate_polymorphic)
        layout.addWidget(gen_btn)

        # Results
        layout.addWidget(QLabel("Variations:"))
        self.poly_table = QTableWidget()
        self.poly_table.setColumnCount(5)
        self.poly_table.setHorizontalHeaderLabels(["#", "Seed", "Rounds", "Size", "Format"])
        layout.addWidget(self.poly_table)

        # Output
        layout.addWidget(QLabel("Selected Variation Output:"))
        self.poly_output = QTextEdit()
        self.poly_output.setReadOnly(True)
        self.poly_output.setFont(QFont("Courier", 9))
        layout.addWidget(self.poly_output)

        widget.setLayout(layout)
        return widget

    def create_batch_tab(self):
        """Create the batch operations tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Batch process multiple payloads (JSON format):"))

        self.batch_input = QTextEdit()
        self.batch_input.setPlaceholderText('{"payloads": ["payload1", "payload2", ...]}')
        self.batch_input.setFont(QFont("Courier", 10))
        layout.addWidget(self.batch_input)

        button_layout = QHBoxLayout()
        batch_btn = QPushButton("Process Batch")
        batch_btn.clicked.connect(self.process_batch)
        button_layout.addWidget(batch_btn)

        load_batch_btn = QPushButton("Load JSON File")
        load_batch_btn.clicked.connect(self.load_batch_file)
        button_layout.addWidget(load_batch_btn)

        layout.addLayout(button_layout)

        layout.addWidget(QLabel("Results:"))
        self.batch_output = QTextEdit()
        self.batch_output.setReadOnly(True)
        self.batch_output.setFont(QFont("Courier", 10))
        layout.addWidget(self.batch_output)

        widget.setLayout(layout)
        return widget

    def create_stats_tab(self):
        """Create the statistics tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Obfuscation Statistics:"))

        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.stats_text)

        refresh_btn = QPushButton("Refresh Statistics")
        refresh_btn.clicked.connect(self.update_stats)
        layout.addWidget(refresh_btn)

        clear_cache_btn = QPushButton("Clear Cache")
        clear_cache_btn.clicked.connect(self.clear_cache)
        layout.addWidget(clear_cache_btn)

        self.update_stats()

        widget.setLayout(layout)
        return widget

    def obfuscate_payload(self):
        """Obfuscate the input payload"""
        payload = self.input_text.toPlainText()
        if not payload:
            QMessageBox.warning(self, "Warning", "Please enter a payload to obfuscate")
            return

        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.statusbar.showMessage("Obfuscating...")

        self.worker = ObfuscationWorker(
            "obfuscate",
            payload,
            self.seed_spin.value(),
            self.rounds_spin.value(),
            self.payload_type_combo.currentText()
        )
        self.worker.result.connect(self.display_result)
        self.worker.error.connect(self.handle_error)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.start()

    def deobfuscate_payload(self):
        """Deobfuscate the input payload"""
        payload = self.input_text.toPlainText()
        if not payload:
            QMessageBox.warning(self, "Warning", "Please enter obfuscated data")
            return

        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.statusbar.showMessage("Deobfuscating...")

        self.worker = ObfuscationWorker(
            "deobfuscate",
            payload,
            self.seed_spin.value(),
            self.rounds_spin.value(),
            self.payload_type_combo.currentText()
        )
        self.worker.result.connect(self.display_result)
        self.worker.error.connect(self.handle_error)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.start()

    def display_result(self, result):
        """Display the obfuscation result"""
        output = result.get("result", "")
        self.output_text.setPlainText(str(output))
        self.statusbar.showMessage(
            f"Complete: {result.get('original_size', 0)} -> {result.get('obfuscated_size', 0)} bytes"
        )

    def generate_polymorphic(self):
        """Generate polymorphic variations"""
        payload = self.poly_input.toPlainText()
        if not payload:
            QMessageBox.warning(self, "Warning", "Please enter a payload")
            return

        self.statusbar.showMessage("Generating polymorphic variations...")
        variations = self.service.generate_polymorph_payload(
            payload,
            variations=self.poly_variations_spin.value(),
            payload_type=ObfuscationType[self.poly_type_combo.currentText().upper()]
        )

        self.poly_table.setRowCount(len(variations))
        self.poly_variations = variations

        for i, var in enumerate(variations):
            self.poly_table.setItem(i, 0, QTableWidgetItem(str(var.get("variation", i))))
            self.poly_table.setItem(i, 1, QTableWidgetItem(str(var.get("seed", "N/A"))))
            self.poly_table.setItem(i, 2, QTableWidgetItem(str(var.get("rounds", "N/A"))))
            self.poly_table.setItem(i, 3, QTableWidgetItem(str(var.get("obfuscated_size", 0))))
            self.poly_table.setItem(i, 4, QTableWidgetItem(var.get("format", "N/A")))

        self.statusbar.showMessage(f"Generated {len(variations)} variations")

    def process_batch(self):
        """Process batch obfuscation"""
        try:
            data = json.loads(self.batch_input.toPlainText())
            payloads = data.get("payloads", [])
            if not payloads:
                QMessageBox.warning(self, "Warning", "No payloads found in JSON")
                return

            self.statusbar.showMessage("Processing batch...")
            results = self.service.obfuscate_batch(payloads, ObfuscationType.PAYLOAD)

            output = json.dumps(results, indent=2)
            self.batch_output.setPlainText(output)
            self.statusbar.showMessage(f"Processed {len(results)} payloads")
        except json.JSONDecodeError:
            QMessageBox.critical(self, "Error", "Invalid JSON format")

    def update_stats(self):
        """Update statistics display"""
        stats = self.service.get_obfuscation_stats()
        text = f"""
Obfuscation Statistics
{'=' * 40}

Cached Payloads: {stats['cached_payloads']}
Total Original Size: {stats['total_original_size']} bytes
Total Obfuscated Size: {stats['total_obfuscated_size']} bytes
Compression Ratio: {stats['compression_ratio']:.2f}x

Current Defaults:
  Seed: {stats['default_seed']}
  Rounds: {stats['default_rounds']}
        """
        self.stats_text.setPlainText(text)

    def clear_cache(self):
        """Clear the obfuscation cache"""
        self.service.clear_cache()
        self.update_stats()
        self.statusbar.showMessage("Cache cleared")

    def load_input_file(self):
        """Load input from file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.input_text.setPlainText(f.read())
                self.statusbar.showMessage(f"Loaded: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {e}")

    def load_batch_file(self):
        """Load batch JSON from file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Open JSON File", "", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.batch_input.setPlainText(f.read())
                self.statusbar.showMessage(f"Loaded: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {e}")

    def save_output(self):
        """Save output to file"""
        text = self.output_text.toPlainText()
        if not text:
            QMessageBox.warning(self, "Warning", "No output to save")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(text)
                self.statusbar.showMessage(f"Saved: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {e}")

    def copy_output(self):
        """Copy output to clipboard"""
        text = self.output_text.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.statusbar.showMessage("Output copied to clipboard")

    def handle_error(self, error_msg):
        """Handle errors from worker thread"""
        self.progress.setVisible(False)
        self.statusbar.showMessage("Error occurred")
        QMessageBox.critical(self, "Error", f"Operation failed:\n{error_msg}")


def main():
    app = QApplication(sys.argv)
    window = ClockworksObfuscationGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
