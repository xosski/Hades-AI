"""
Unified Shim for Sermon Codebase
Provides abstract interfaces for networking, data processing, and monitoring components
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Union
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Data Processing Interfaces
# ============================================================================

class DataProcessor(ABC):
    """Abstract base for data processing operations"""
    
    @abstractmethod
    def process(self, data: str) -> str:
        """Process data and return result"""
        pass
    
    @abstractmethod
    def validate(self, data: str) -> bool:
        """Validate input data"""
        pass


class BitProcessor(DataProcessor):
    """Handles bit stuffing/destuffing operations"""
    
    def process(self, data: str) -> str:
        """Applies bit stuffing to binary string"""
        if not self.validate(data):
            raise ValueError("Invalid binary data")
        return self._stuff_bits(data)
    
    def _stuff_bits(self, data: str) -> str:
        """Internal bit stuffing logic"""
        count = 0
        stuffed = ""
        for bit in data:
            if bit == '1':
                count += 1
                stuffed += bit
                if count == 5:
                    stuffed += '0'
                    count = 0
            else:
                count = 0
                stuffed += bit
        return stuffed
    
    def validate(self, data: str) -> bool:
        """Validate binary string"""
        return all(c in '01' for c in data) and len(data) > 0


class ChecksumProcessor(DataProcessor):
    """Handles checksum calculations (normal, 1's, 2's complement)"""
    
    METHOD_NORMAL = 0
    METHOD_ONES_COMPLEMENT = 1
    METHOD_TWOS_COMPLEMENT = 2
    
    def __init__(self, block_size: int = 8, method: int = METHOD_NORMAL):
        self.block_size = block_size
        self.method = method
    
    def process(self, data: str) -> str:
        """Calculate checksum for binary data"""
        if not self.validate(data):
            raise ValueError("Invalid binary data")
        return self._calculate_checksum(data)
    
    def _calculate_checksum(self, data: str) -> str:
        """Internal checksum calculation"""
        blocks = [data[i:i+self.block_size] 
                  for i in range(0, len(data), self.block_size)]
        checksum = 0
        for block in blocks:
            checksum ^= int(block, 2)
        return bin(checksum)[2:].zfill(self.block_size)
    
    def validate(self, data: str) -> bool:
        """Validate binary string"""
        return all(c in '01' for c in data) and len(data) > 0


class HammingProcessor(DataProcessor):
    """Handles Hamming code generation and error detection/correction"""
    
    def process(self, data: str) -> str:
        """Generate Hamming code for data"""
        if not self.validate(data):
            raise ValueError("Invalid binary data")
        return self._generate_hamming_code(data)
    
    def _generate_hamming_code(self, data: str) -> str:
        """Internal Hamming code generation"""
        bits = [int(b) for b in data]
        parity_bits = self._calculate_parity_bits(len(bits))
        total_bits = len(bits) + parity_bits
        code = [0] * total_bits
        
        # Insert data bits
        data_idx = 0
        for i in range(total_bits):
            if (i + 1) & i == 0:
                continue
            code[i] = bits[data_idx] if data_idx < len(bits) else 0
            data_idx += 1
        
        # Calculate parity bits
        for i in range(parity_bits):
            pos = 2 ** i
            parity = 0
            for j in range(total_bits):
                if (j + 1) & pos:
                    parity ^= code[j]
            code[pos - 1] = parity
        
        return ''.join(str(b) for b in code)
    
    def _calculate_parity_bits(self, data_bits: int) -> int:
        """Calculate required parity bits"""
        r = 0
        while (1 << r) < (data_bits + r + 1):
            r += 1
        return r
    
    def validate(self, data: str) -> bool:
        """Validate binary string"""
        return all(c in '01' for c in data) and len(data) > 0


# ============================================================================
# Network Interfaces
# ============================================================================

class NetworkAdapter(ABC):
    """Abstract base for network operations"""
    
    @abstractmethod
    def connect(self, host: str, port: int) -> bool:
        """Establish connection"""
        pass
    
    @abstractmethod
    def send(self, data: Union[str, bytes]) -> bool:
        """Send data"""
        pass
    
    @abstractmethod
    def receive(self, buffer_size: int = 1024) -> Union[str, bytes, None]:
        """Receive data"""
        pass
    
    @abstractmethod
    def disconnect(self) -> bool:
        """Close connection"""
        pass


class TCPAdapter(NetworkAdapter):
    """TCP socket implementation"""
    
    def __init__(self):
        self.socket = None
        self.connected = False
    
    def connect(self, host: str, port: int) -> bool:
        """Establish TCP connection"""
        try:
            import socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            logger.info(f"Connected to {host}:{port}")
            return True
        except Exception as e:
            logger.error(f"TCP connection failed: {e}")
            return False
    
    def send(self, data: Union[str, bytes]) -> bool:
        """Send data over TCP"""
        if not self.connected:
            logger.error("Not connected")
            return False
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.socket.sendall(data)
            return True
        except Exception as e:
            logger.error(f"Send failed: {e}")
            return False
    
    def receive(self, buffer_size: int = 1024) -> Optional[bytes]:
        """Receive data over TCP"""
        if not self.connected:
            logger.error("Not connected")
            return None
        try:
            return self.socket.recv(buffer_size)
        except Exception as e:
            logger.error(f"Receive failed: {e}")
            return None
    
    def disconnect(self) -> bool:
        """Close TCP connection"""
        if self.socket:
            try:
                self.socket.close()
                self.connected = False
                logger.info("Disconnected")
                return True
            except Exception as e:
                logger.error(f"Disconnect failed: {e}")
                return False
        return True


class UDPAdapter(NetworkAdapter):
    """UDP socket implementation"""
    
    def __init__(self):
        self.socket = None
        self.remote_addr = None
        self.connected = False
    
    def connect(self, host: str, port: int) -> bool:
        """Setup UDP connection"""
        try:
            import socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.remote_addr = (host, port)
            self.connected = True
            logger.info(f"UDP ready for {host}:{port}")
            return True
        except Exception as e:
            logger.error(f"UDP setup failed: {e}")
            return False
    
    def send(self, data: Union[str, bytes]) -> bool:
        """Send data over UDP"""
        if not self.connected or not self.remote_addr:
            logger.error("Not connected")
            return False
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.socket.sendto(data, self.remote_addr)
            return True
        except Exception as e:
            logger.error(f"Send failed: {e}")
            return False
    
    def receive(self, buffer_size: int = 1024) -> Optional[bytes]:
        """Receive data over UDP"""
        if not self.connected:
            logger.error("Not connected")
            return None
        try:
            data, _ = self.socket.recvfrom(buffer_size)
            return data
        except Exception as e:
            logger.error(f"Receive failed: {e}")
            return None
    
    def disconnect(self) -> bool:
        """Close UDP socket"""
        if self.socket:
            try:
                self.socket.close()
                self.connected = False
                logger.info("Disconnected")
                return True
            except Exception as e:
                logger.error(f"Disconnect failed: {e}")
                return False
        return True


# ============================================================================
# Monitoring Interfaces
# ============================================================================

class Monitor(ABC):
    """Abstract base for monitoring"""
    
    @abstractmethod
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect metrics"""
        pass
    
    @abstractmethod
    def report(self) -> str:
        """Generate report"""
        pass


class StatusMonitor(Monitor):
    """Monitors server/component status"""
    
    def __init__(self):
        self.metrics: Dict[str, Any] = {}
        self.status = "unknown"
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect current metrics"""
        return {
            "status": self.status,
            "timestamp": self._get_timestamp(),
            "metrics": self.metrics
        }
    
    def report(self) -> str:
        """Generate status report"""
        metrics = self.collect_metrics()
        return f"Status: {metrics['status']} | Timestamp: {metrics['timestamp']}"
    
    def set_status(self, status: str):
        """Update status"""
        self.status = status
        logger.info(f"Status: {status}")
    
    def set_metric(self, key: str, value: Any):
        """Set metric value"""
        self.metrics[key] = value
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()


class IncidentMonitor(Monitor):
    """Monitors data quality incidents"""
    
    def __init__(self):
        self.incidents: List[Dict[str, Any]] = []
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect incident metrics"""
        return {
            "total_incidents": len(self.incidents),
            "open_incidents": len([i for i in self.incidents if i.get("state") == "open"]),
            "closed_incidents": len([i for i in self.incidents if i.get("state") == "closed"]),
        }
    
    def report(self) -> str:
        """Generate incident report"""
        metrics = self.collect_metrics()
        return (f"Incidents - Total: {metrics['total_incidents']}, "
                f"Open: {metrics['open_incidents']}, "
                f"Closed: {metrics['closed_incidents']}")
    
    def add_incident(self, incident: Dict[str, Any]):
        """Log an incident"""
        self.incidents.append(incident)
        logger.warning(f"Incident logged: {incident.get('subject', 'Unknown')}")


# ============================================================================
# Unified Shim Interface
# ============================================================================

class SermonShim:
    """Main shim providing access to all subsystems"""
    
    def __init__(self):
        # Data processors
        self.bit_processor = BitProcessor()
        self.checksum_processor = ChecksumProcessor()
        self.hamming_processor = HammingProcessor()
        
        # Network adapters
        self.tcp_adapter = TCPAdapter()
        self.udp_adapter = UDPAdapter()
        
        # Monitors
        self.status_monitor = StatusMonitor()
        self.incident_monitor = IncidentMonitor()
        
        logger.info("SermonShim initialized")
    
    def process_data(self, processor_type: str, data: str) -> Optional[str]:
        """Process data using specified processor"""
        processors = {
            'bit': self.bit_processor,
            'checksum': self.checksum_processor,
            'hamming': self.hamming_processor,
        }
        
        processor = processors.get(processor_type)
        if not processor:
            logger.error(f"Unknown processor: {processor_type}")
            return None
        
        try:
            return processor.process(data)
        except Exception as e:
            logger.error(f"Processing failed: {e}")
            return None
    
    def send_over_network(self, protocol: str, host: str, port: int, 
                         data: Union[str, bytes]) -> bool:
        """Send data over network using specified protocol"""
        adapter = self.tcp_adapter if protocol.upper() == 'TCP' else self.udp_adapter
        
        if not adapter.connected:
            if not adapter.connect(host, port):
                return False
        
        return adapter.send(data)
    
    def receive_from_network(self, protocol: str, buffer_size: int = 1024) -> Optional[Union[str, bytes]]:
        """Receive data from network"""
        adapter = self.tcp_adapter if protocol.upper() == 'TCP' else self.udp_adapter
        
        if not adapter.connected:
            logger.error("Not connected. Call send_over_network first or connect explicitly")
            return None
        
        return adapter.receive(buffer_size)
    
    def get_status_report(self) -> str:
        """Get current system status"""
        return f"{self.status_monitor.report()} | {self.incident_monitor.report()}"


# ============================================================================
# Convenience Functions
# ============================================================================

def create_shim() -> SermonShim:
    """Factory function to create a new shim instance"""
    return SermonShim()
