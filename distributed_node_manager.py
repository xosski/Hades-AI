"""
Distributed Node Manager for HadesAI Phase 2
Enables multi-system deployment and distributed task execution
"""

import socket
import sqlite3
import json
import uuid
import logging
import time
import hashlib
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== ENUMS ====================

class NodeStatus(Enum):
    """Node operational status"""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"


class TaskDistributionStrategy(Enum):
    """Task distribution strategies"""
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    CAPABILITY_BASED = "capability_based"
    GEOGRAPHIC = "geographic"
    PERFORMANCE_BASED = "performance_based"


# ==================== DATA CLASSES ====================

@dataclass
class NodeInfo:
    """Information about a network node"""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    status: NodeStatus = NodeStatus.ONLINE
    cpu_cores: int = 1
    memory_gb: float = 4.0
    disk_gb: float = 100.0
    os_type: str = "linux"
    version: str = "1.0"
    capabilities: List[str] = field(default_factory=list)
    current_load: float = 0.0
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    last_heartbeat: float = field(default_factory=time.time)
    uptime_seconds: float = 0.0
    location: str = ""  # Geographic location


@dataclass
class DistributedTask:
    """Task for distributed execution"""
    task_id: str
    source_node: str
    target_node: Optional[str] = None
    task_type: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    created_at: float = field(default_factory=time.time)
    deadline: Optional[float] = None
    status: str = "pending"
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class NodeMetrics:
    """Performance metrics for a node"""
    node_id: str
    timestamp: float = field(default_factory=time.time)
    cpu_usage_percent: float = 0.0
    memory_usage_percent: float = 0.0
    disk_usage_percent: float = 0.0
    network_latency_ms: float = 0.0
    throughput_tasks_per_sec: float = 0.0
    success_rate: float = 1.0
    availability_percent: float = 100.0


@dataclass
class ReplicationRecord:
    """Data replication record"""
    data_id: str
    source_node: str
    replica_nodes: List[str] = field(default_factory=list)
    data_hash: str = ""
    last_verified: float = field(default_factory=time.time)
    replication_factor: int = 3


# ==================== DISTRIBUTED NODE MANAGER ====================

class DistributedNodeManager:
    """Manages distributed HadesAI deployment"""
    
    def __init__(self, db_path: str = "phase2_distributed_nodes.db", node_id: Optional[str] = None):
        self.db_path = db_path
        self.node_id = node_id or f"node_{uuid.uuid4().hex[:8]}"
        self.nodes: Dict[str, NodeInfo] = {}
        self.task_queue: List[DistributedTask] = []
        self.metrics_history: Dict[str, List[NodeMetrics]] = {}
        self.replication_map: Dict[str, ReplicationRecord] = {}
        self.running = False
        self.heartbeat_thread = None
        self.distribution_strategy = TaskDistributionStrategy.LEAST_LOADED
        self.lock = threading.Lock()
        
        self._init_db()
        self._register_local_node()
    
    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                hostname TEXT,
                ip_address TEXT,
                port INTEGER,
                status TEXT,
                cpu_cores INTEGER,
                memory_gb REAL,
                disk_gb REAL,
                os_type TEXT,
                version TEXT,
                capabilities TEXT,
                current_load REAL,
                active_tasks INTEGER,
                completed_tasks INTEGER,
                failed_tasks INTEGER,
                last_heartbeat REAL,
                location TEXT
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS distributed_tasks (
                task_id TEXT PRIMARY KEY,
                source_node TEXT,
                target_node TEXT,
                task_type TEXT,
                payload TEXT,
                priority INTEGER,
                created_at REAL,
                status TEXT,
                result TEXT,
                execution_time_ms REAL,
                retry_count INTEGER
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS node_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT,
                timestamp REAL,
                cpu_usage_percent REAL,
                memory_usage_percent REAL,
                disk_usage_percent REAL,
                network_latency_ms REAL,
                throughput_tasks_per_sec REAL,
                success_rate REAL
            )
            """)
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS replication (
                data_id TEXT PRIMARY KEY,
                source_node TEXT,
                replica_nodes TEXT,
                data_hash TEXT,
                last_verified REAL,
                replication_factor INTEGER
            )
            """)
            
            conn.commit()
    
    def _register_local_node(self):
        """Register this node"""
        local_node = NodeInfo(
            node_id=self.node_id,
            hostname=socket.gethostname(),
            ip_address=socket.gethostbyname(socket.gethostname()),
            port=5000,
            os_type="windows",
            version="2.0"
        )
        self.register_node(local_node)
    
    def register_node(self, node_info: NodeInfo) -> bool:
        """Register a new node in the network"""
        try:
            with self.lock:
                self.nodes[node_info.node_id] = node_info
                self.metrics_history[node_info.node_id] = []
            
            # Store in database
            self._store_node(node_info)
            logger.info(f"Node registered: {node_info.node_id} ({node_info.hostname})")
            return True
        except Exception as e:
            logger.error(f"Failed to register node: {e}")
            return False
    
    def deregister_node(self, node_id: str) -> bool:
        """Remove node from network"""
        try:
            with self.lock:
                if node_id in self.nodes:
                    del self.nodes[node_id]
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM nodes WHERE node_id = ?", (node_id,))
                conn.commit()
            
            logger.info(f"Node deregistered: {node_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to deregister node: {e}")
            return False
    
    def start_heartbeat(self):
        """Start heartbeat monitoring"""
        if not self.running:
            self.running = True
            self.heartbeat_thread = threading.Thread(
                target=self._heartbeat_worker,
                daemon=True
            )
            self.heartbeat_thread.start()
            logger.info("Heartbeat monitoring started")
    
    def stop_heartbeat(self):
        """Stop heartbeat monitoring"""
        self.running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=5)
        logger.info("Heartbeat monitoring stopped")
    
    def _heartbeat_worker(self):
        """Background worker for heartbeat and health checks"""
        while self.running:
            current_time = time.time()
            
            with self.lock:
                for node_id, node in self.nodes.items():
                    time_since_heartbeat = current_time - node.last_heartbeat
                    
                    # Check health
                    if time_since_heartbeat > 60:
                        node.status = NodeStatus.OFFLINE
                    elif time_since_heartbeat > 30:
                        node.status = NodeStatus.DEGRADED
                    else:
                        node.status = NodeStatus.ONLINE
                    
                    # Update metrics
                    self._update_node_metrics(node_id)
            
            time.sleep(10)
    
    def heartbeat(self, node_id: str, metrics: Optional[NodeMetrics] = None) -> bool:
        """Receive heartbeat from a node"""
        if node_id not in self.nodes:
            return False
        
        node = self.nodes[node_id]
        node.last_heartbeat = time.time()
        
        if node.status == NodeStatus.OFFLINE:
            node.status = NodeStatus.ONLINE
        
        if metrics:
            self.metrics_history[node_id].append(metrics)
            # Keep only last 1000 metrics per node
            if len(self.metrics_history[node_id]) > 1000:
                self.metrics_history[node_id] = self.metrics_history[node_id][-1000:]
        
        return True
    
    def submit_task(self, task: DistributedTask) -> Optional[str]:
        """Submit a task for distributed execution"""
        try:
            task.task_id = f"task_{uuid.uuid4().hex[:12]}"
            
            with self.lock:
                self.task_queue.append(task)
            
            self._store_task(task)
            logger.info(f"Task submitted: {task.task_id}")
            return task.task_id
        except Exception as e:
            logger.error(f"Failed to submit task: {e}")
            return None
    
    def execute_distributed(self, task: DistributedTask,
                           node_filter: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """Execute task on suitable node"""
        # Select target node
        target_node = self._select_target_node(node_filter)
        
        if not target_node:
            logger.error("No suitable nodes available")
            task.status = "failed"
            task.error = "No suitable nodes available"
            return None
        
        task.target_node = target_node.node_id
        task.status = "executing"
        
        # Simulate task execution
        start_time = time.time()
        
        try:
            # Increment active tasks
            target_node.active_tasks += 1
            
            # Simulate execution time based on task type
            execution_time = self._simulate_task_execution(task)
            
            task.status = "completed"
            task.result = {
                "node_id": target_node.node_id,
                "execution_time_ms": int(execution_time * 1000),
                "status": "success"
            }
            
            target_node.completed_tasks += 1
            
        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            task.retry_count += 1
            target_node.failed_tasks += 1
            
            # Retry if possible
            if task.retry_count < task.max_retries:
                logger.warning(f"Task {task.task_id} failed, retrying... ({task.retry_count}/{task.max_retries})")
                return self.execute_distributed(task, node_filter)
        
        finally:
            target_node.active_tasks = max(0, target_node.active_tasks - 1)
            task.execution_time_ms = (time.time() - start_time) * 1000
            self._store_task(task)
        
        return task.result
    
    def _select_target_node(self, node_filter: Optional[Dict[str, Any]] = None) -> Optional[NodeInfo]:
        """Select best node for task execution"""
        available_nodes = [
            node for node in self.nodes.values()
            if node.status == NodeStatus.ONLINE
        ]
        
        if not available_nodes:
            return None
        
        # Apply filters
        if node_filter:
            if "os_type" in node_filter:
                available_nodes = [
                    n for n in available_nodes
                    if n.os_type == node_filter["os_type"]
                ]
            
            if "min_cpu_cores" in node_filter:
                available_nodes = [
                    n for n in available_nodes
                    if n.cpu_cores >= node_filter["min_cpu_cores"]
                ]
            
            if "capabilities" in node_filter:
                required_caps = node_filter["capabilities"]
                available_nodes = [
                    n for n in available_nodes
                    if all(cap in n.capabilities for cap in required_caps)
                ]
        
        if not available_nodes:
            return None
        
        # Select based on strategy
        if self.distribution_strategy == TaskDistributionStrategy.LEAST_LOADED:
            return min(available_nodes, key=lambda n: n.active_tasks)
        
        elif self.distribution_strategy == TaskDistributionStrategy.ROUND_ROBIN:
            return available_nodes[0]
        
        elif self.distribution_strategy == TaskDistributionStrategy.PERFORMANCE_BASED:
            return max(available_nodes, key=lambda n: n.cpu_cores * (1 - n.current_load))
        
        else:
            return available_nodes[0]
    
    def _simulate_task_execution(self, task: DistributedTask) -> float:
        """Simulate task execution time"""
        base_time = 0.1  # 100ms base
        
        if task.task_type == "exploit_generation":
            base_time = 0.5
        elif task.task_type == "threat_analysis":
            base_time = 0.3
        elif task.task_type == "vulnerability_scan":
            base_time = 1.0
        
        # Add some variance
        import random
        return base_time * (0.8 + random.random() * 0.4)
    
    def replicate_data(self, data_id: str, data: Any, replication_factor: int = 3) -> bool:
        """Replicate data across nodes"""
        try:
            data_hash = hashlib.sha256(json.dumps(data).encode()).hexdigest()
            
            # Select replica nodes
            online_nodes = [
                n for n in self.nodes.values()
                if n.status == NodeStatus.ONLINE
            ]
            
            replica_count = min(replication_factor, len(online_nodes))
            replica_nodes = [n.node_id for n in online_nodes[:replica_count]]
            
            record = ReplicationRecord(
                data_id=data_id,
                source_node=self.node_id,
                replica_nodes=replica_nodes,
                data_hash=data_hash,
                replication_factor=replica_count
            )
            
            self.replication_map[data_id] = record
            self._store_replication(record)
            
            logger.info(f"Data replicated: {data_id} ({replica_count} replicas)")
            return True
        except Exception as e:
            logger.error(f"Failed to replicate data: {e}")
            return False
    
    def verify_replication(self, data_id: str) -> Tuple[bool, Dict[str, bool]]:
        """Verify data replication integrity"""
        if data_id not in self.replication_map:
            return False, {}
        
        record = self.replication_map[data_id]
        verification_results = {}
        
        for replica_node in record.replica_nodes:
            # In production, would verify actual data on remote nodes
            verification_results[replica_node] = True
        
        record.last_verified = time.time()
        return True, verification_results
    
    def get_node_status(self, node_id: Optional[str] = None) -> Dict[str, Any]:
        """Get node status"""
        if node_id:
            node = self.nodes.get(node_id)
            return asdict(node) if node else {}
        
        return {
            node_id: asdict(node)
            for node_id, node in self.nodes.items()
        }
    
    def get_cluster_health(self) -> Dict[str, Any]:
        """Get overall cluster health"""
        online_count = sum(1 for n in self.nodes.values() if n.status == NodeStatus.ONLINE)
        degraded_count = sum(1 for n in self.nodes.values() if n.status == NodeStatus.DEGRADED)
        offline_count = sum(1 for n in self.nodes.values() if n.status == NodeStatus.OFFLINE)
        
        total_tasks = sum(1 for n in self.nodes.values())
        total_completed = sum(n.completed_tasks for n in self.nodes.values())
        total_failed = sum(n.failed_tasks for n in self.nodes.values())
        
        success_rate = (
            total_completed / (total_completed + total_failed) * 100
            if (total_completed + total_failed) > 0 else 100
        )
        
        return {
            "total_nodes": len(self.nodes),
            "online_nodes": online_count,
            "degraded_nodes": degraded_count,
            "offline_nodes": offline_count,
            "cluster_availability": (online_count / len(self.nodes) * 100) if self.nodes else 0,
            "total_tasks_completed": total_completed,
            "total_tasks_failed": total_failed,
            "success_rate": success_rate,
            "pending_tasks": len([t for t in self.task_queue if t.status == "pending"]),
            "executing_tasks": len([t for t in self.task_queue if t.status == "executing"])
        }
    
    def _update_node_metrics(self, node_id: str):
        """Update node performance metrics"""
        node = self.nodes.get(node_id)
        if not node:
            return
        
        # Simulate metric collection
        metrics = NodeMetrics(
            node_id=node_id,
            cpu_usage_percent=20 + node.active_tasks * 10,
            memory_usage_percent=40 + node.active_tasks * 5,
            disk_usage_percent=60,
            network_latency_ms=5 + (node.active_tasks * 2),
            throughput_tasks_per_sec=node.active_tasks,
            success_rate=node.completed_tasks / (node.completed_tasks + max(1, node.failed_tasks))
        )
        
        self._store_metrics(metrics)
    
    def _store_node(self, node: NodeInfo):
        """Store node info in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO nodes
                (node_id, hostname, ip_address, port, status, cpu_cores, memory_gb, disk_gb,
                 os_type, version, capabilities, current_load, active_tasks, completed_tasks,
                 failed_tasks, last_heartbeat, location)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    node.node_id, node.hostname, node.ip_address, node.port,
                    node.status.value, node.cpu_cores, node.memory_gb, node.disk_gb,
                    node.os_type, node.version, json.dumps(node.capabilities),
                    node.current_load, node.active_tasks, node.completed_tasks,
                    node.failed_tasks, node.last_heartbeat, node.location
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing node: {e}")
    
    def _store_task(self, task: DistributedTask):
        """Store task in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO distributed_tasks
                (task_id, source_node, target_node, task_type, payload, priority,
                 created_at, status, result, execution_time_ms, retry_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    task.task_id, task.source_node, task.target_node,
                    task.task_type, json.dumps(task.payload), task.priority,
                    task.created_at, task.status,
                    json.dumps(task.result) if task.result else None,
                    task.execution_time_ms, task.retry_count
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing task: {e}")
    
    def _store_metrics(self, metrics: NodeMetrics):
        """Store metrics in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT INTO node_metrics
                (node_id, timestamp, cpu_usage_percent, memory_usage_percent, disk_usage_percent,
                 network_latency_ms, throughput_tasks_per_sec, success_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    metrics.node_id, metrics.timestamp,
                    metrics.cpu_usage_percent, metrics.memory_usage_percent,
                    metrics.disk_usage_percent, metrics.network_latency_ms,
                    metrics.throughput_tasks_per_sec, metrics.success_rate
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing metrics: {e}")
    
    def _store_replication(self, record: ReplicationRecord):
        """Store replication record"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO replication
                (data_id, source_node, replica_nodes, data_hash, last_verified, replication_factor)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    record.data_id, record.source_node,
                    json.dumps(record.replica_nodes), record.data_hash,
                    record.last_verified, record.replication_factor
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error storing replication: {e}")


# ==================== EXAMPLE USAGE ====================

def demo_distributed():
    """Demonstrate distributed node manager"""
    print("=" * 80)
    print("Distributed Node Manager Demo")
    print("=" * 80)
    
    manager = DistributedNodeManager()
    manager.start_heartbeat()
    
    # Register additional nodes
    print("\nRegistering nodes...")
    for i in range(3):
        node = NodeInfo(
            node_id=f"worker_{i}",
            hostname=f"worker{i}.local",
            ip_address=f"192.168.1.{100+i}",
            port=5000 + i,
            cpu_cores=4 + i,
            memory_gb=8.0 + i,
            os_type="linux",
            capabilities=["threat_analysis", "exploit_generation", "network_mapping"]
        )
        manager.register_node(node)
    
    # Submit distributed tasks
    print("\nSubmitting distributed tasks...")
    for i in range(5):
        task = DistributedTask(
            task_id=f"task_{i}",
            source_node=manager.node_id,
            task_type="threat_analysis" if i % 2 == 0 else "exploit_generation",
            payload={"target": f"system_{i}", "data": "test_data"},
            priority=i % 3
        )
        manager.submit_task(task)
    
    # Execute tasks
    print("\nExecuting distributed tasks...")
    for task in manager.task_queue:
        result = manager.execute_distributed(task)
        if result:
            print(f"[OK] Task {task.task_id[:12]}... completed on {result['node_id']}")
    
    # Get cluster health
    print("\n" + "=" * 80)
    print("Cluster Health")
    print("=" * 80)
    health = manager.get_cluster_health()
    for key, value in health.items():
        print(f"{key}: {value}")
    
    # Data replication
    print("\n" + "=" * 80)
    print("Data Replication")
    print("=" * 80)
    manager.replicate_data("exploit_db_001", {"cves": ["CVE-2024-0001"]}, replication_factor=2)
    print("[OK] Data replicated across nodes")
    
    manager.stop_heartbeat()


if __name__ == "__main__":
    demo_distributed()
