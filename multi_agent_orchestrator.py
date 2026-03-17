"""
Multi-Agent Orchestrator for HadesAI Phase 2
Coordinates multiple specialized AI agents for complex task execution
"""

import asyncio
import uuid
import json
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from abc import ABC, abstractmethod
from datetime import datetime
import sqlite3
import threading
from queue import PriorityQueue, Queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== ENUMS ====================

class AgentType(Enum):
    """Specialized agent types"""
    THREAT_ANALYZER = "threat_analyzer"
    EXPLOIT_GENERATOR = "exploit_generator"
    DEFENSE_STRATEGIST = "defense_strategist"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    PAYLOAD_OPTIMIZER = "payload_optimizer"
    THREAT_INTELLIGENCE = "threat_intelligence"
    NETWORK_MAPPER = "network_mapper"


class TaskPriority(Enum):
    """Task execution priority"""
    LOW = 3
    MEDIUM = 2
    HIGH = 1
    CRITICAL = 0


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentStatus(Enum):
    """Agent status"""
    IDLE = "idle"
    EXECUTING = "executing"
    WAITING = "waiting"
    ERROR = "error"
    OFFLINE = "offline"


# ==================== DATA CLASSES ====================

@dataclass
class AgentCapability:
    """Defines what an agent can do"""
    name: str
    description: str
    min_confidence: float = 0.7
    max_concurrent: int = 5
    timeout_seconds: int = 60


@dataclass
class TaskRequest:
    """Represents a task to execute"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_type: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    deadline: Optional[float] = None
    required_agents: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    def __lt__(self, other):
        """For priority queue ordering"""
        return self.priority.value < other.priority.value


@dataclass
class AgentState:
    """Represents an agent's current state"""
    agent_id: str
    agent_type: AgentType
    status: AgentStatus = AgentStatus.IDLE
    current_task: Optional[str] = None
    completed_tasks: int = 0
    failed_tasks: int = 0
    total_execution_time: float = 0.0
    avg_task_time: float = 0.0
    last_activity: float = field(default_factory=time.time)
    capabilities: List[AgentCapability] = field(default_factory=list)
    performance_score: float = 1.0
    load_factor: float = 0.0


@dataclass
class ExecutionResult:
    """Result of task execution"""
    task_id: str
    agent_id: str
    status: TaskStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


# ==================== AGENT INTERFACE ====================

class Agent(ABC):
    """Abstract base class for all agents"""
    
    def __init__(self, agent_id: str, agent_type: AgentType):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.state = AgentState(agent_id=agent_id, agent_type=agent_type)
        self.capabilities: List[AgentCapability] = []
        
    @abstractmethod
    def can_execute(self, task: TaskRequest) -> bool:
        """Check if agent can execute task"""
        pass
    
    @abstractmethod
    async def execute(self, task: TaskRequest) -> ExecutionResult:
        """Execute task and return result"""
        pass
    
    def register_capability(self, capability: AgentCapability):
        """Register a capability"""
        self.capabilities.append(capability)
        self.state.capabilities = self.capabilities


class ThreatAnalyzerAgent(Agent):
    """Analyzes security threats"""
    
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.THREAT_ANALYZER)
        self.register_capability(AgentCapability(
            name="threat_scoring",
            description="Score and classify threats",
            min_confidence=0.75
        ))
        self.register_capability(AgentCapability(
            name="threat_correlation",
            description="Correlate multiple threats",
            min_confidence=0.8
        ))
    
    def can_execute(self, task: TaskRequest) -> bool:
        return task.task_type in ["analyze_threat", "score_threat", "correlate_threats"]
    
    async def execute(self, task: TaskRequest) -> ExecutionResult:
        start = time.time()
        try:
            # Simulate threat analysis
            await asyncio.sleep(0.1)
            
            content = task.payload.get("content", "")
            threat_score = len(content) % 100 / 100
            
            result = {
                "threat_score": threat_score,
                "threat_level": "CRITICAL" if threat_score > 0.8 else "HIGH" if threat_score > 0.6 else "MEDIUM",
                "indicators": ["sql_injection_pattern", "xss_vector"] if threat_score > 0.5 else [],
                "recommendations": ["block_ip", "alert_admin"] if threat_score > 0.7 else []
            }
            
            return ExecutionResult(
                task_id=task.id,
                agent_id=self.agent_id,
                status=TaskStatus.COMPLETED,
                result=result,
                execution_time=time.time() - start
            )
        except Exception as e:
            return ExecutionResult(
                task_id=task.id,
                agent_id=self.agent_id,
                status=TaskStatus.FAILED,
                error=str(e),
                execution_time=time.time() - start
            )


class ExploitGeneratorAgent(Agent):
    """Generates exploit code"""
    
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.EXPLOIT_GENERATOR)
        self.register_capability(AgentCapability(
            name="exploit_generation",
            description="Generate exploit code",
            min_confidence=0.7
        ))
    
    def can_execute(self, task: TaskRequest) -> bool:
        return task.task_type in ["generate_exploit", "craft_payload"]
    
    async def execute(self, task: TaskRequest) -> ExecutionResult:
        start = time.time()
        try:
            await asyncio.sleep(0.15)
            
            cve_id = task.payload.get("cve_id", "CVE-2024-0000")
            
            result = {
                "exploit_code": f"#!/usr/bin/python3\n# Exploit for {cve_id}\nimport socket\n...",
                "language": "python",
                "success_rate": 0.85,
                "detection_risk": 0.3,
                "execution_time_ms": 2500
            }
            
            return ExecutionResult(
                task_id=task.id,
                agent_id=self.agent_id,
                status=TaskStatus.COMPLETED,
                result=result,
                execution_time=time.time() - start
            )
        except Exception as e:
            return ExecutionResult(
                task_id=task.id,
                agent_id=self.agent_id,
                status=TaskStatus.FAILED,
                error=str(e),
                execution_time=time.time() - start
            )


class DefenseStrategistAgent(Agent):
    """Develops defense strategies"""
    
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.DEFENSE_STRATEGIST)
        self.register_capability(AgentCapability(
            name="defense_planning",
            description="Plan defense strategies"
        ))
    
    def can_execute(self, task: TaskRequest) -> bool:
        return task.task_type in ["defense_strategy", "mitigation_plan"]
    
    async def execute(self, task: TaskRequest) -> ExecutionResult:
        start = time.time()
        try:
            await asyncio.sleep(0.12)
            
            threat_level = task.payload.get("threat_level", "MEDIUM")
            
            strategies = {
                "CRITICAL": ["immediate_isolation", "incident_response_team", "forensics"],
                "HIGH": ["enhanced_monitoring", "access_control_review", "patch_deployment"],
                "MEDIUM": ["vulnerability_scan", "security_audit", "training"]
            }
            
            result = {
                "defense_strategy": strategies.get(threat_level, []),
                "priority_actions": ["action_1", "action_2"],
                "timeline_days": 1 if threat_level == "CRITICAL" else 3 if threat_level == "HIGH" else 7,
                "resource_requirement": "high" if threat_level == "CRITICAL" else "medium"
            }
            
            return ExecutionResult(
                task_id=task.id,
                agent_id=self.agent_id,
                status=TaskStatus.COMPLETED,
                result=result,
                execution_time=time.time() - start
            )
        except Exception as e:
            return ExecutionResult(
                task_id=task.id,
                agent_id=self.agent_id,
                status=TaskStatus.FAILED,
                error=str(e),
                execution_time=time.time() - start
            )


# ==================== ORCHESTRATOR ====================

class MultiAgentOrchestrator:
    """Coordinates multiple agents for complex task execution"""
    
    def __init__(self, db_path: str = "phase2_orchestrator.db"):
        self.db_path = db_path
        self.agents: Dict[str, Agent] = {}
        self.task_queue: PriorityQueue = PriorityQueue()
        self.completed_tasks: Dict[str, ExecutionResult] = {}
        self.pending_tasks: Dict[str, TaskRequest] = {}
        self.running = False
        self.executor_thread = None
        self.lock = threading.Lock()
        
        self._init_db()
        self._initialize_default_agents()
    
    def _init_db(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                task_type TEXT,
                priority INTEGER,
                status TEXT,
                created_at REAL,
                completed_at REAL,
                execution_time REAL,
                agent_id TEXT,
                result TEXT
            )
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                agent_type TEXT,
                status TEXT,
                completed_tasks INTEGER,
                failed_tasks INTEGER,
                performance_score REAL,
                last_activity REAL
            )
            """)
            conn.commit()
    
    def _initialize_default_agents(self):
        """Create default specialized agents"""
        agents = [
            ThreatAnalyzerAgent(f"threat_analyzer_{uuid.uuid4().hex[:8]}"),
            ExploitGeneratorAgent(f"exploit_gen_{uuid.uuid4().hex[:8]}"),
            DefenseStrategistAgent(f"defense_strat_{uuid.uuid4().hex[:8]}"),
        ]
        
        for agent in agents:
            self.register_agent(agent)
    
    def register_agent(self, agent: Agent):
        """Register a new agent"""
        self.agents[agent.agent_id] = agent
        self._log_agent_event(agent, "registered")
        logger.info(f"Agent registered: {agent.agent_id} ({agent.agent_type.value})")
    
    def submit_task(self, task: TaskRequest) -> str:
        """Submit a task for execution"""
        with self.lock:
            self.pending_tasks[task.id] = task
            self.task_queue.put(task)
            task.status = TaskStatus.PENDING
            self._log_task_event(task, "submitted")
        
        logger.info(f"Task submitted: {task.id} (priority: {task.priority.name})")
        return task.id
    
    async def _execute_task(self, task: TaskRequest) -> Optional[ExecutionResult]:
        """Execute a single task using appropriate agent"""
        task.status = TaskStatus.ASSIGNED
        
        # Find best agent for task
        suitable_agents = [a for a in self.agents.values() if a.can_execute(task)]
        
        if not suitable_agents:
            result = ExecutionResult(
                task_id=task.id,
                agent_id="none",
                status=TaskStatus.FAILED,
                error="No suitable agent found"
            )
            return result
        
        # Select least busy agent
        agent = min(suitable_agents, key=lambda a: a.state.load_factor)
        task.status = TaskStatus.EXECUTING
        task.start_time = time.time()
        agent.state.current_task = task.id
        agent.state.status = AgentStatus.EXECUTING
        
        try:
            result = await agent.execute(task)
            
            # Update agent state
            agent.state.completed_tasks += 1
            agent.state.total_execution_time += result.execution_time
            agent.state.avg_task_time = agent.state.total_execution_time / agent.state.completed_tasks
            agent.state.status = AgentStatus.IDLE
            
            task.status = TaskStatus.COMPLETED
            task.result = result.result
            task.end_time = time.time()
            
            self._log_task_event(task, "completed")
            return result
            
        except Exception as e:
            logger.error(f"Task execution failed: {e}")
            agent.state.failed_tasks += 1
            agent.state.status = AgentStatus.ERROR
            
            result = ExecutionResult(
                task_id=task.id,
                agent_id=agent.agent_id,
                status=TaskStatus.FAILED,
                error=str(e)
            )
            
            task.status = TaskStatus.FAILED
            task.error = str(e)
            self._log_task_event(task, "failed")
            return result
    
    def _process_tasks(self):
        """Background thread to process queued tasks"""
        async def _async_process():
            while self.running:
                if self.task_queue.empty():
                    await asyncio.sleep(0.1)
                    continue
                
                task = self.task_queue.get_nowait()
                result = await self._execute_task(task)
                
                if result:
                    self.completed_tasks[task.id] = result
                    with self.lock:
                        if task.id in self.pending_tasks:
                            del self.pending_tasks[task.id]
        
        asyncio.run(_async_process())
    
    def start(self):
        """Start the orchestrator"""
        if not self.running:
            self.running = True
            self.executor_thread = threading.Thread(target=self._process_tasks, daemon=True)
            self.executor_thread.start()
            logger.info("Orchestrator started")
    
    def stop(self):
        """Stop the orchestrator"""
        self.running = False
        if self.executor_thread:
            self.executor_thread.join(timeout=5)
        logger.info("Orchestrator stopped")
    
    def execute_task_sync(self, task: TaskRequest) -> ExecutionResult:
        """Execute task synchronously"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self._execute_task(task))
            if result:
                self.completed_tasks[task.id] = result
            return result
        finally:
            loop.close()
    
    def get_agent_status(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Get agent status"""
        if agent_id:
            agent = self.agents.get(agent_id)
            return asdict(agent.state) if agent else {}
        
        return {
            agent_id: asdict(agent.state)
            for agent_id, agent in self.agents.items()
        }
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status"""
        if task_id in self.completed_tasks:
            result = self.completed_tasks[task_id]
            return {
                "status": result.status.value,
                "result": result.result,
                "error": result.error,
                "execution_time": result.execution_time
            }
        
        if task_id in self.pending_tasks:
            task = self.pending_tasks[task_id]
            return {
                "status": task.status.value,
                "created_at": task.created_at,
                "result": None,
                "error": task.error
            }
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        total_tasks = len(self.completed_tasks) + len(self.pending_tasks)
        
        agent_stats = {}
        for agent_id, agent in self.agents.items():
            agent_stats[agent_id] = {
                "type": agent.agent_type.value,
                "status": agent.state.status.value,
                "completed": agent.state.completed_tasks,
                "failed": agent.state.failed_tasks,
                "avg_time_ms": int(agent.state.avg_task_time * 1000),
                "performance_score": agent.state.performance_score
            }
        
        return {
            "total_agents": len(self.agents),
            "total_tasks": total_tasks,
            "completed_tasks": len(self.completed_tasks),
            "pending_tasks": len(self.pending_tasks),
            "agents": agent_stats,
            "uptime_seconds": time.time()
        }
    
    def _log_task_event(self, task: TaskRequest, event: str):
        """Log task event to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT INTO tasks (id, task_type, priority, status, created_at, agent_id, result)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    task.id,
                    task.task_type,
                    task.priority.value,
                    task.status.value,
                    task.created_at,
                    "pending",
                    json.dumps(task.result) if task.result else None
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log task event: {e}")
    
    def _log_agent_event(self, agent: Agent, event: str):
        """Log agent event to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                INSERT OR REPLACE INTO agents 
                (agent_id, agent_type, status, completed_tasks, failed_tasks, performance_score, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    agent.agent_id,
                    agent.agent_type.value,
                    agent.state.status.value,
                    agent.state.completed_tasks,
                    agent.state.failed_tasks,
                    agent.state.performance_score,
                    time.time()
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log agent event: {e}")


# ==================== EXAMPLE USAGE ====================

def demo_orchestrator():
    """Demonstrate orchestrator functionality"""
    print("=" * 60)
    print("Multi-Agent Orchestrator Demo")
    print("=" * 60)
    
    orchestrator = MultiAgentOrchestrator()
    
    # Create sample tasks
    tasks = [
        TaskRequest(
            task_type="analyze_threat",
            priority=TaskPriority.HIGH,
            payload={"content": "SELECT * FROM users WHERE id = ' OR '1'='1"}
        ),
        TaskRequest(
            task_type="generate_exploit",
            priority=TaskPriority.CRITICAL,
            payload={"cve_id": "CVE-2024-1234"}
        ),
        TaskRequest(
            task_type="defense_strategy",
            priority=TaskPriority.MEDIUM,
            payload={"threat_level": "CRITICAL"}
        ),
    ]
    
    # Submit tasks
    task_ids = []
    for task in tasks:
        task_id = orchestrator.submit_task(task)
        task_ids.append(task_id)
        print(f"[OK] Submitted task: {task_id[:8]}... (type: {task.task_type})")
    
    # Execute tasks
    print("\nExecuting tasks...")
    for task in tasks:
        result = orchestrator.execute_task_sync(task)
        print(f"  {task.task_type}: {result.status.value} ({result.execution_time:.3f}s)")
        if result.result:
            print(f"    Result preview: {str(result.result)[:60]}...")
    
    # Show statistics
    print("\n" + "=" * 60)
    print("Statistics")
    print("=" * 60)
    stats = orchestrator.get_statistics()
    print(f"Total Agents: {stats['total_agents']}")
    print(f"Total Tasks: {stats['total_tasks']}")
    print(f"Completed: {stats['completed_tasks']}")
    print(f"Pending: {stats['pending_tasks']}")
    
    print("\nAgent Status:")
    for agent_id, agent_stat in stats['agents'].items():
        print(f"  {agent_id[:16]}... ({agent_stat['type']})")
        print(f"    Completed: {agent_stat['completed']} | Failed: {agent_stat['failed']}")
        print(f"    Avg Time: {agent_stat['avg_time_ms']}ms | Score: {agent_stat['performance_score']}")


if __name__ == "__main__":
    demo_orchestrator()
