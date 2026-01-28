"""
GUI components for Encrypted P2P Knowledge Network
Integrate into HadesAI.py main window
"""

import sys
import subprocess
import logging
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox,
    QSpinBox, QLineEdit, QTableWidget, QTableWidgetItem, QGroupBox,
    QFormLayout, QTextEdit, QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor

logger = logging.getLogger("NetworkShareGUI")


# Try to import cryptography, install if missing
def ensure_cryptography():
    """Ensure cryptography module is installed"""
    try:
        import cryptography
        return True
    except ImportError:
        logger.warning("cryptography module not found, attempting auto-install...")
        return False


def install_cryptography():
    """Automatically install cryptography module"""
    try:
        logger.info("Installing cryptography module...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
        logger.info("✓ cryptography installed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to install cryptography: {e}")
        return False


# Ensure cryptography is available
if not ensure_cryptography():
    if not install_cryptography():
        logger.error("Could not install cryptography. Manual install required.")

# Now import the network module
try:
    from modules.knowledge_network import KnowledgeNetworkNode
    HAS_NETWORK = True
except ImportError as e:
    logger.warning(f"Could not import KnowledgeNetworkNode: {e}")
    HAS_NETWORK = False
    KnowledgeNetworkNode = None

import json


class SyncWorker(QThread):
    """Background sync worker"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, network_node: KnowledgeNetworkNode, peer_id: str = None):
        super().__init__()
        self.network_node = network_node
        self.peer_id = peer_id
    
    def run(self):
        try:
            if self.peer_id:
                result = self.network_node.sync_from_peer(self.peer_id)
            else:
                result = self.network_node.sync_all_peers()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class NetworkShareTab(QWidget):
    """Network sharing configuration and monitoring tab"""
    
    def __init__(self, parent=None, db_path: str = "hades_knowledge.db"):
        super().__init__(parent)
        self.db_path = db_path
        self.network_node = None
        self.sync_worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # ===== ENABLE/DISABLE SECTION =====
        enable_group = QGroupBox("Network Control")
        enable_layout = QHBoxLayout()
        
        self.enable_checkbox = QCheckBox("Enable Encrypted P2P Knowledge Sharing")
        self.enable_checkbox.setEnabled(HAS_NETWORK)
        self.enable_checkbox.stateChanged.connect(self._toggle_network)
        enable_layout.addWidget(self.enable_checkbox)
        
        self.status_label = QLabel(
            "Status: Disabled" if HAS_NETWORK else "Status: Module Loading (Installing cryptography...)"
        )
        self.status_label.setFont(QFont("Courier", 10))
        status_color = "#ff6b6b" if HAS_NETWORK else "#ffb84d"
        self.status_label.setStyleSheet(f"color: {status_color}; font-weight: bold;")
        enable_layout.addWidget(self.status_label)
        
        enable_layout.addStretch()
        enable_group.setLayout(enable_layout)
        layout.addWidget(enable_group)
        
        # ===== SERVER CONFIGURATION =====
        config_group = QGroupBox("Server Configuration")
        config_layout = QFormLayout()
        
        self.port_spinbox = QSpinBox()
        self.port_spinbox.setRange(10000, 65535)
        self.port_spinbox.setValue(19999)
        self.port_spinbox.setToolTip("TLS file sync port")
        config_layout.addRow("TLS Sync Port:", self.port_spinbox)
        
        self.discovery_port_spinbox = QSpinBox()
        self.discovery_port_spinbox.setRange(8000, 65535)
        self.discovery_port_spinbox.setValue(8888)
        self.discovery_port_spinbox.setToolTip("Discovery server port")
        config_layout.addRow("Discovery Port:", self.discovery_port_spinbox)
        
        self.instance_id_input = QLineEdit()
        self.instance_id_input.setText("HadesAI-Instance-001")
        self.instance_id_input.setToolTip("Unique identifier for this instance")
        config_layout.addRow("Instance ID:", self.instance_id_input)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # ===== PEER DISCOVERY & MANAGEMENT =====
        discovery_group = QGroupBox("Local Network Discovery")
        discovery_layout = QVBoxLayout()
        
        # Auto-discovery status
        self.discovery_status = QLabel("Discovery: Scanning network...")
        self.discovery_status.setStyleSheet("color: #ffb84d; font-size: 10px;")
        discovery_layout.addWidget(self.discovery_status)
        
        # Discovered peers table
        discovery_layout.addWidget(QLabel("Discovered Peers (click to whitelist):"))
        self.discovered_table = QTableWidget()
        self.discovered_table.setColumnCount(4)
        self.discovered_table.setHorizontalHeaderLabels(
            ["Instance ID", "Hostname", "IP", "Port"]
        )
        self.discovered_table.horizontalHeader().setStretchLastSection(True)
        self.discovered_table.setMaximumHeight(150)
        self.discovered_table.cellDoubleClicked.connect(self._whitelist_discovered_peer)
        discovery_layout.addWidget(self.discovered_table)
        
        refresh_discovery_btn = QPushButton("Refresh Discovery")
        refresh_discovery_btn.clicked.connect(self._refresh_discovered_peers)
        discovery_layout.addWidget(refresh_discovery_btn)
        
        discovery_group.setLayout(discovery_layout)
        layout.addWidget(discovery_group)
        
        # ===== PEER MANAGEMENT =====
        peers_group = QGroupBox("Trusted Peers (Manual)")
        peers_layout = QVBoxLayout()
        
        # Peer list table
        self.peers_table = QTableWidget()
        self.peers_table.setColumnCount(4)
        self.peers_table.setHorizontalHeaderLabels(
            ["Instance ID", "Hostname", "Port", "Last Seen"]
        )
        self.peers_table.horizontalHeader().setStretchLastSection(True)
        self.peers_table.setMaximumHeight(200)
        peers_layout.addWidget(self.peers_table)
        
        # Add peer controls
        peer_control_layout = QHBoxLayout()
        
        QLabel("Add Peer:").setMaximumWidth(80)
        self.peer_hostname = QLineEdit()
        self.peer_hostname.setPlaceholderText("hostname or IP")
        self.peer_port = QSpinBox()
        self.peer_port.setRange(10000, 65535)
        self.peer_port.setValue(19999)
        self.peer_instance_id = QLineEdit()
        self.peer_instance_id.setPlaceholderText("Peer Instance ID")
        
        add_peer_btn = QPushButton("Add Trusted Peer")
        add_peer_btn.clicked.connect(self._add_trusted_peer)
        
        peer_control_layout.addWidget(QLabel("Hostname:"))
        peer_control_layout.addWidget(self.peer_hostname)
        peer_control_layout.addWidget(QLabel("Port:"))
        peer_control_layout.addWidget(self.peer_port)
        peer_control_layout.addWidget(QLabel("Instance ID:"))
        peer_control_layout.addWidget(self.peer_instance_id)
        peer_control_layout.addWidget(add_peer_btn)
        peer_control_layout.addStretch()
        
        peers_layout.addLayout(peer_control_layout)
        peers_group.setLayout(peers_layout)
        layout.addWidget(peers_group)
        
        # ===== SYNCHRONIZATION CONTROLS =====
        sync_group = QGroupBox("Database Synchronization")
        sync_layout = QVBoxLayout()
        
        sync_btn_layout = QHBoxLayout()
        
        self.sync_all_btn = QPushButton("Sync From All Peers")
        self.sync_all_btn.clicked.connect(self._sync_all_peers)
        self.sync_all_btn.setEnabled(False)
        
        self.sync_selected_btn = QPushButton("Sync From Selected")
        self.sync_selected_btn.clicked.connect(self._sync_selected_peer)
        self.sync_selected_btn.setEnabled(False)
        
        sync_btn_layout.addWidget(self.sync_all_btn)
        sync_btn_layout.addWidget(self.sync_selected_btn)
        sync_btn_layout.addStretch()
        
        sync_layout.addLayout(sync_btn_layout)
        
        # Sync progress
        self.sync_progress = QProgressBar()
        self.sync_progress.setVisible(False)
        sync_layout.addWidget(self.sync_progress)
        
        # Sync status log
        self.sync_log = QTextEdit()
        self.sync_log.setReadOnly(True)
        self.sync_log.setMaximumHeight(200)
        self.sync_log.setStyleSheet(
            "QTextEdit { background-color: #1e1e1e; color: #d4d4d4; font-family: Courier; }"
        )
        sync_layout.addWidget(QLabel("Sync Log:"))
        sync_layout.addWidget(self.sync_log)
        
        sync_group.setLayout(sync_layout)
        layout.addWidget(sync_group)
        
        # ===== STATUS SECTION =====
        status_group = QGroupBox("Network Status")
        status_layout = QVBoxLayout()
        
        self.network_status = QTextEdit()
        self.network_status.setReadOnly(True)
        self.network_status.setMaximumHeight(150)
        self.network_status.setStyleSheet(
            "QTextEdit { background-color: #1e1e1e; color: #00ff00; font-family: Courier; }"
        )
        status_layout.addWidget(self.network_status)
        
        refresh_status_btn = QPushButton("Refresh Status")
        refresh_status_btn.clicked.connect(self._update_status)
        status_layout.addWidget(refresh_status_btn)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def _toggle_network(self, state):
        """Enable/disable network sharing"""
        if not HAS_NETWORK:
            QMessageBox.warning(
                self, "Module Not Available",
                "Network sharing module not available.\n"
                "Required 'cryptography' module was installed.\n"
                "Please restart HadesAI to load the module."
            )
            self.enable_checkbox.setChecked(False)
            return
        
        if state == Qt.CheckState.Checked.value:
            self._start_network()
        else:
            self._stop_network()
    
    def _start_network(self):
        """Initialize and start network node"""
        if not HAS_NETWORK or KnowledgeNetworkNode is None:
            QMessageBox.critical(
                self, "Error",
                "Network node not available. Please ensure 'cryptography' module is installed:\n"
                "pip install cryptography"
            )
            self.enable_checkbox.setChecked(False)
            return
        
        try:
            instance_id = self.instance_id_input.text().strip()
            if not instance_id:
                QMessageBox.warning(self, "Error", "Instance ID cannot be empty")
                self.enable_checkbox.setChecked(False)
                return
            
            self.network_node = KnowledgeNetworkNode(
                instance_id=instance_id,
                db_path=self.db_path,
                port=self.port_spinbox.value(),
                discovery_port=self.discovery_port_spinbox.value()
            )
            
            if self.network_node.start():
                self.status_label.setText(
                    f"Status: Active ({instance_id})"
                )
                self.status_label.setStyleSheet("color: #51cf66; font-weight: bold;")
                
                self.sync_all_btn.setEnabled(True)
                self.sync_selected_btn.setEnabled(True)
                
                self._update_status()
                self._log_sync("Network node started successfully")
            else:
                raise Exception("Failed to start network node")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start network:\n{e}")
            self.enable_checkbox.setChecked(False)
    
    def _stop_network(self):
        """Stop network node"""
        try:
            if self.network_node:
                self.network_node.stop()
            
            self.status_label.setText("Status: Disabled")
            self.status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
            
            self.sync_all_btn.setEnabled(False)
            self.sync_selected_btn.setEnabled(False)
            
            self._log_sync("Network node stopped")
        except Exception as e:
            logger.error(f"Error stopping network: {e}")
    
    def _add_trusted_peer(self):
        """Add a trusted peer"""
        if not self.network_node:
            QMessageBox.warning(self, "Error", "Network not enabled")
            return
        
        hostname = self.peer_hostname.text().strip()
        port = self.peer_port.value()
        instance_id = self.peer_instance_id.text().strip()
        
        if not all([hostname, instance_id]):
            QMessageBox.warning(self, "Error", "Please fill in all peer fields")
            return
        
        if self.network_node.add_trusted_peer(instance_id, hostname, port):
            QMessageBox.information(self, "Success", f"Peer {instance_id} added and verified")
            self.peer_hostname.clear()
            self.peer_instance_id.clear()
            self._refresh_peers_table()
        else:
            QMessageBox.warning(
                self, "Error", 
                f"Could not connect to peer {hostname}:{port}"
            )
    
    def _refresh_peers_table(self):
        """Refresh peers table"""
        if not self.network_node:
            return
        
        self.peers_table.setRowCount(0)
        peers = self.network_node.get_peers()
        
        for idx, peer in enumerate(peers):
            self.peers_table.insertRow(idx)
            self.peers_table.setItem(idx, 0, QTableWidgetItem(peer.instance_id))
            self.peers_table.setItem(idx, 1, QTableWidgetItem(peer.hostname))
            self.peers_table.setItem(idx, 2, QTableWidgetItem(str(peer.port)))
            
            from datetime import datetime
            last_seen = datetime.fromtimestamp(peer.last_seen).strftime("%H:%M:%S")
            self.peers_table.setItem(idx, 3, QTableWidgetItem(last_seen))
    
    def _sync_all_peers(self):
        """Sync from all peers"""
        if not self.network_node:
            return
        
        self.sync_progress.setVisible(True)
        self.sync_progress.setRange(0, 0)  # Indeterminate
        self.sync_all_btn.setEnabled(False)
        
        self.sync_worker = SyncWorker(self.network_node)
        self.sync_worker.finished.connect(self._on_sync_finished)
        self.sync_worker.error.connect(self._on_sync_error)
        self.sync_worker.start()
        
        self._log_sync("Starting sync from all peers...")
    
    def _sync_selected_peer(self):
        """Sync from selected peer"""
        if not self.network_node:
            return
        
        selected_rows = self.peers_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Please select a peer")
            return
        
        row = selected_rows[0].row()
        peer_id = self.peers_table.item(row, 0).text()
        
        self.sync_progress.setVisible(True)
        self.sync_progress.setRange(0, 0)
        self.sync_selected_btn.setEnabled(False)
        
        self.sync_worker = SyncWorker(self.network_node, peer_id)
        self.sync_worker.finished.connect(self._on_sync_finished)
        self.sync_worker.error.connect(self._on_sync_error)
        self.sync_worker.start()
        
        self._log_sync(f"Starting sync from {peer_id}...")
    
    def _on_sync_finished(self, result: dict):
        """Handle sync completion"""
        self.sync_progress.setVisible(False)
        self.sync_all_btn.setEnabled(True)
        self.sync_selected_btn.setEnabled(True)
        
        if isinstance(result, dict) and "error" not in result:
            self._log_sync(f"Sync complete: {json.dumps(result, indent=2)}")
            QMessageBox.information(
                self, "Sync Complete", 
                f"Successfully synced\n\n{json.dumps(result, indent=2)}"
            )
        else:
            self._log_sync(f"Sync error: {result}")
    
    def _on_sync_error(self, error: str):
        """Handle sync error"""
        self.sync_progress.setVisible(False)
        self.sync_all_btn.setEnabled(True)
        self.sync_selected_btn.setEnabled(True)
        self._log_sync(f"ERROR: {error}")
        QMessageBox.critical(self, "Sync Error", f"Sync failed:\n{error}")
    
    def _log_sync(self, message: str):
        """Add message to sync log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.sync_log.append(f"[{timestamp}] {message}")
    
    def _refresh_discovered_peers(self):
        """Refresh discovered peers list"""
        if not self.network_node:
            self.discovery_status.setText("Discovery: Not available")
            return
        
        discovered = self.network_node.get_discovered_peers()
        self.discovered_table.setRowCount(0)
        
        for idx, peer in enumerate(discovered):
            self.discovered_table.insertRow(idx)
            self.discovered_table.setItem(idx, 0, QTableWidgetItem(peer.get("instance_id", "")))
            self.discovered_table.setItem(idx, 1, QTableWidgetItem(peer.get("hostname", "")))
            self.discovered_table.setItem(idx, 2, QTableWidgetItem(peer.get("ip", "")))
            self.discovered_table.setItem(idx, 3, QTableWidgetItem(str(peer.get("port", ""))))
        
        count = len(discovered)
        self.discovery_status.setText(
            f"Discovery: Found {count} peer{'s' if count != 1 else ''} on network (double-click to whitelist)"
        )
        self.discovery_status.setStyleSheet("color: #51cf66; font-size: 10px;")
    
    def _whitelist_discovered_peer(self, row, column):
        """Whitelist a discovered peer"""
        if not self.network_node:
            return
        
        instance_id = self.discovered_table.item(row, 0).text()
        hostname = self.discovered_table.item(row, 2).text()  # Use IP
        port = int(self.discovered_table.item(row, 3).text())
        
        if self.network_node.add_trusted_peer(instance_id, hostname, port):
            self._log_sync(f"Whitelisted discovered peer: {instance_id}")
            self._refresh_peers_table()
            self._refresh_discovered_peers()
            QMessageBox.information(self, "Success", f"Peer {instance_id} whitelisted")
        else:
            QMessageBox.warning(self, "Error", f"Could not whitelist {instance_id}")
    
    def _update_status(self):
        """Update network status display"""
        if not self.network_node:
            self.network_status.setText("Network node not initialized")
            return
        
        status = self.network_node.get_status()
        status_text = json.dumps(status, indent=2, default=str)
        self.network_status.setText(status_text)
        self._refresh_peers_table()
        self._refresh_discovered_peers()


def main():
    """Module initialization handler"""
    logger.info("Network Share GUI module loaded successfully")
    return {
        "status": "ready",
        "module": "network_share_gui",
        "version": "1.0",
        "description": "PyQt6 GUI for Encrypted P2P Knowledge Sharing",
        "network_available": HAS_NETWORK
    }


if __name__ == "__main__":
    result = main()
    print(json.dumps(result, indent=2))
