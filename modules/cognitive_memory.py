"""
Cognitive Memory Mapping System with Feedback Loop
Enables embedding-based memory storage, retrieval, optimization,
and reinforcement learning through outcome evaluation.
"""

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
import sqlite3
import threading
import uuid
import copy
import queue
from contextlib import closing
from typing import List, Optional, Callable, Dict, Tuple
import numpy as np
import json
import re


def _utcnow() -> datetime:
    """Naive UTC for compatibility with existing persisted timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class Memory:
    """Represents a single memory entry with embedding and metadata."""
    id: str
    content: str
    embedding: list
    importance: float
    timestamp: datetime
    metadata: dict = field(default_factory=dict)
    access_count: int = 0  # Track how many times recalled
    reinforcement_score: float = 0.5  # Track feedback reinforcement
    revision: int = 1
    updated_at: Optional[datetime] = None
    source_thread: str = ""
    parent_revision: Optional[int] = None
    status: str = "active"
    links: Dict[str, List[str]] = field(default_factory=dict)

    def __post_init__(self):
        if self.updated_at is None:
            self.updated_at = self.timestamp


class MemoryOperation(Enum):
    ADD = "ADD"
    UPDATE = "UPDATE"
    REINFORCE = "REINFORCE"
    SUPERSEDE = "SUPERSEDE"
    LINK = "LINK"
    FORGET = "FORGET"
    ACCESS = "ACCESS"


@dataclass(frozen=True)
class MemoryMutation:
    """A proposed canonical memory change."""

    operation: MemoryOperation
    memory_id: Optional[str] = None
    expected_revision: Optional[int] = None
    content: Optional[str] = None
    embedding: Optional[list] = None
    importance: Optional[float] = None
    metadata: Optional[dict] = None
    success_score: Optional[float] = None
    relation: Optional[str] = None
    target_memory_id: Optional[str] = None
    source_channel: str = "cortex"
    source_thread: str = ""
    reason: str = ""
    mutation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass(frozen=True)
class MemoryConflict:
    memory_id: str
    expected_revision: Optional[int]
    actual_revision: Optional[int]
    current: Optional[Memory]
    proposed: MemoryMutation
    reason: str


@dataclass(frozen=True)
class MemoryEvent:
    event_id: str
    memory_id: str
    operation: str
    revision: int
    expected_revision: Optional[int]
    timestamp: datetime
    source_channel: str
    source_thread: str
    reason: str
    payload: dict
    sequence: Optional[int] = None


@dataclass(frozen=True)
class MutationResult:
    success: bool
    memory: Optional[Memory] = None
    event: Optional[MemoryEvent] = None
    conflict: Optional[MemoryConflict] = None


class RevisionConflictError(RuntimeError):
    def __init__(self, actual_revision: Optional[int], reason: str,
                 current: Optional[Memory] = None):
        super().__init__(reason)
        self.actual_revision = actual_revision
        self.current = current


@dataclass
class _MutationRequest:
    mutation: MemoryMutation
    completed: threading.Event = field(default_factory=threading.Event)
    result: Optional[MutationResult] = None
    error: Optional[BaseException] = None


@dataclass
class Reflection:
    """Represents an outcome evaluation and reflection."""
    id: str
    user_input: str
    ai_output: str
    success_score: float  # 0.0-1.0
    timestamp: datetime
    metadata: dict = field(default_factory=dict)
    reflected_content: str = ""  # Structured reflection text


class MemoryStore:
    """Thread-safe materialized snapshot used by readers and one writer."""
    
    def __init__(self):
        self._memories: Dict[str, Memory] = {}
        self._lock = threading.RLock()
        self._authority_token = None

    def seal(self, authority_token: object) -> None:
        """Prevent mutation outside the attached canonical writer."""
        with self._lock:
            if self._authority_token is not None:
                raise RuntimeError("memory store already has an authority")
            self._authority_token = authority_token

    def _require_authority(self, authority_token: object) -> None:
        if self._authority_token is not None and authority_token is not self._authority_token:
            raise RuntimeError("canonical memory mutations must use MemoryCoordinator")

    @property
    def memories(self) -> List[Memory]:
        """Return detached snapshots; callers cannot mutate canonical state."""
        with self._lock:
            return copy.deepcopy(list(self._memories.values()))

    def add(self, memory: Memory) -> None:
        """Compatibility loader; live writes should use MemoryCoordinator."""
        self._replace(memory)

    def _replace(self, memory: Memory, authority_token: object = None) -> None:
        with self._lock:
            self._require_authority(authority_token)
            self._memories[memory.id] = copy.deepcopy(memory)

    def _get_canonical(self, memory_id: str, authority_token: object = None) -> Optional[Memory]:
        """Return the writer-owned object. Only MemoryCoordinator may call this."""
        with self._lock:
            self._require_authority(authority_token)
            return self._memories.get(memory_id)

    def search(self, query_embedding: list, top_k: int = 5, use_reinforcement: bool = True) -> List[tuple]:
        """
        Search memories by embedding similarity with optional reinforcement bias.
        Returns list of (similarity_score, Memory) tuples.
        """
        def cosine_similarity(a, b):
            a_norm = np.linalg.norm(a)
            b_norm = np.linalg.norm(b)
            if a_norm == 0 or b_norm == 0:
                return 0.0
            return float(np.dot(a, b) / (a_norm * b_norm))
        
        scored = []
        for m in self.memories:
            sim = cosine_similarity(query_embedding, m.embedding)
            # Apply reinforcement bias: boost memories with higher reinforcement scores
            if use_reinforcement:
                sim = sim * (0.7 + 0.3 * m.reinforcement_score)
            scored.append((sim, m))
        
        return sorted(scored, key=lambda item: item[0], reverse=True)[:top_k]

    def get_memory(self, memory_id: str) -> Optional[Memory]:
        """Retrieve a specific memory by ID."""
        with self._lock:
            memory = self._memories.get(memory_id)
            return copy.deepcopy(memory) if memory else None

    def delete(self, memory_id: str) -> bool:
        """Compatibility helper; live writes should use MemoryCoordinator."""
        return self._delete(memory_id)

    def _delete(self, memory_id: str, authority_token: object = None) -> bool:
        with self._lock:
            self._require_authority(authority_token)
            return self._memories.pop(memory_id, None) is not None

    def _clear(self, authority_token: object = None) -> None:
        with self._lock:
            self._require_authority(authority_token)
            self._memories.clear()

    def size(self) -> int:
        """Return total number of stored memories."""
        with self._lock:
            return len(self._memories)


class MemoryCoordinator:
    """Hippocampus: the sole live writer for canonical memory state."""

    def __init__(self, store: MemoryStore, persist: Callable[[MemoryEvent, Optional[Memory]], int]):
        self.store = store
        self.persist = persist
        self._authority_token = object()
        self.store.seal(self._authority_token)
        self.write_queue: queue.Queue = queue.Queue()
        self._events: List[MemoryEvent] = []
        self._events_lock = threading.RLock()
        self._stop = object()
        self._closed = False
        self._thread = threading.Thread(
            target=self._run,
            name="Hades-Hippocampus",
            daemon=True,
        )
        self._thread.start()

    def submit(self, mutation: MemoryMutation, timeout: Optional[float] = None) -> MutationResult:
        if self._closed:
            raise RuntimeError("memory authority is closed")
        request = _MutationRequest(mutation)
        self.write_queue.put(request)
        if not request.completed.wait(timeout):
            raise TimeoutError("memory mutation did not complete before timeout")
        if request.error:
            raise request.error
        return request.result

    def close(self, timeout: float = 5.0) -> None:
        if self._closed:
            return
        if self._thread.is_alive():
            self.write_queue.put(self._stop)
            self._thread.join(timeout)
        self._closed = True

    def get_events(self, memory_id: Optional[str] = None) -> List[MemoryEvent]:
        with self._events_lock:
            events = copy.deepcopy(self._events)
        if memory_id is not None:
            events = [event for event in events if event.memory_id == memory_id]
        return events

    def _run(self) -> None:
        while True:
            request = self.write_queue.get()
            if request is self._stop:
                return
            try:
                request.result = self._commit(request.mutation)
            except BaseException as exc:
                request.error = exc
            finally:
                request.completed.set()

    def _conflict(self, mutation: MemoryMutation, current: Optional[Memory], reason: str,
                  actual_revision: Optional[int] = None) -> MutationResult:
        return MutationResult(
            success=False,
            conflict=MemoryConflict(
                memory_id=mutation.memory_id or "",
                expected_revision=mutation.expected_revision,
                actual_revision=(
                    actual_revision
                    if actual_revision is not None
                    else (current.revision if current else None)
                ),
                current=copy.deepcopy(current),
                proposed=mutation,
                reason=reason,
            ),
        )

    def _commit(self, mutation: MemoryMutation) -> MutationResult:
        current = self.store._get_canonical(
            mutation.memory_id or "",
            self._authority_token,
        )
        if mutation.operation == MemoryOperation.ADD:
            if current is not None:
                return self._conflict(mutation, current, "memory already exists")
            updated = Memory(
                id=mutation.memory_id or str(uuid.uuid4()),
                content=mutation.content or "",
                embedding=list(mutation.embedding or []),
                importance=max(0.0, min(
                    1.0,
                    float(mutation.importance if mutation.importance is not None else 0.5),
                )),
                timestamp=mutation.timestamp,
                updated_at=mutation.timestamp,
                metadata=copy.deepcopy(mutation.metadata or {}),
                source_thread=mutation.source_thread,
            )
        else:
            if current is None:
                return self._conflict(mutation, None, "memory does not exist")
            if (
                mutation.expected_revision is not None
                and current.revision != mutation.expected_revision
            ):
                return self._conflict(mutation, current, "revision changed")

            updated = copy.deepcopy(current)
            updated.parent_revision = current.revision
            updated.revision = current.revision + 1
            updated.updated_at = mutation.timestamp
            updated.source_thread = mutation.source_thread

            if mutation.operation in (MemoryOperation.UPDATE, MemoryOperation.SUPERSEDE):
                if mutation.content is not None:
                    updated.content = mutation.content
                if mutation.embedding is not None:
                    updated.embedding = list(mutation.embedding)
                if mutation.importance is not None:
                    updated.importance = max(0.0, min(1.0, float(mutation.importance)))
                if mutation.metadata is not None:
                    updated.metadata = copy.deepcopy(mutation.metadata)
            elif mutation.operation == MemoryOperation.REINFORCE:
                score = max(0.0, min(
                    1.0,
                    float(mutation.success_score if mutation.success_score is not None else 0.5),
                ))
                updated.reinforcement_score = 0.3 * score + 0.7 * updated.reinforcement_score
                updated.importance = max(updated.importance, 0.3 + updated.reinforcement_score * 0.7)
            elif mutation.operation == MemoryOperation.LINK:
                if not mutation.relation or not mutation.target_memory_id:
                    return self._conflict(mutation, current, "link requires relation and target")
                target = self.store._get_canonical(
                    mutation.target_memory_id,
                    self._authority_token,
                )
                if target is None:
                    return self._conflict(mutation, current, "link target does not exist")
                targets = updated.links.setdefault(mutation.relation, [])
                if mutation.target_memory_id not in targets:
                    targets.append(mutation.target_memory_id)
            elif mutation.operation == MemoryOperation.ACCESS:
                updated.access_count += 1
            elif mutation.operation == MemoryOperation.FORGET:
                updated.status = "forgotten"

        payload = {
            "mutation_id": mutation.mutation_id,
            "before": self._serialize_memory(current) if current else None,
            "after": self._serialize_memory(updated),
        }
        event = MemoryEvent(
            event_id=str(uuid.uuid4()),
            memory_id=updated.id,
            operation=mutation.operation.value,
            revision=updated.revision,
            expected_revision=(
                mutation.expected_revision
                if mutation.expected_revision is not None
                else (current.revision if current else None)
            ),
            timestamp=mutation.timestamp,
            source_channel=mutation.source_channel,
            source_thread=mutation.source_thread,
            reason=mutation.reason,
            payload=payload,
        )
        try:
            sequence = self.persist(
                event,
                None if mutation.operation == MemoryOperation.FORGET else updated,
            )
        except RevisionConflictError as exc:
            return self._conflict(
                mutation,
                exc.current or current,
                str(exc),
                actual_revision=exc.actual_revision,
            )
        event = MemoryEvent(**{**event.__dict__, "sequence": sequence})
        if mutation.operation == MemoryOperation.FORGET:
            self.store._delete(updated.id, self._authority_token)
        else:
            self.store._replace(updated, self._authority_token)
        with self._events_lock:
            self._events.append(event)
        return MutationResult(True, copy.deepcopy(updated), event)

    @staticmethod
    def _serialize_memory(memory: Optional[Memory]) -> Optional[dict]:
        if memory is None:
            return None
        return {
            "id": memory.id,
            "content": memory.content,
            "embedding": memory.embedding,
            "importance": memory.importance,
            "timestamp": memory.timestamp.isoformat(),
            "updated_at": memory.updated_at.isoformat(),
            "metadata": memory.metadata,
            "access_count": memory.access_count,
            "reinforcement_score": memory.reinforcement_score,
            "revision": memory.revision,
            "source_thread": memory.source_thread,
            "parent_revision": memory.parent_revision,
            "status": memory.status,
            "links": memory.links,
        }


class ReflectionEngine:
    """Handles outcome evaluation and memory reinforcement."""
    
    def __init__(self):
        self.reflections: List[Reflection] = []
        self._lock = threading.RLock()
    
    def create_reflection(self, user_input: str, ai_output: str, 
                         success_score: float, metadata: dict = None) -> Reflection:
        """
        Create a reflection from an interaction outcome.
        
        Args:
            user_input: Original user input
            ai_output: AI response
            success_score: Outcome evaluation (0.0-1.0)
            metadata: Optional metadata
            
        Returns:
            Reflection object
        """
        reflected_content = f"""
Input: {user_input}
Output: {ai_output}
Outcome Score: {success_score:.2f}
Timestamp: {_utcnow()}
"""
        reflection = Reflection(
            id=str(uuid.uuid4()),
            user_input=user_input,
            ai_output=ai_output,
            success_score=success_score,
            timestamp=_utcnow(),
            metadata=metadata or {},
            reflected_content=reflected_content.strip()
        )
        with self._lock:
            self.reflections.append(reflection)
        return reflection
    
    def calculate_reinforcement(self, success_score: float, base_importance: float = 0.3) -> float:
        """
        Calculate memory importance based on reinforcement feedback.
        
        Args:
            success_score: Outcome score (0.0-1.0)
            base_importance: Base importance level
            
        Returns:
            Adjusted importance (0.0-1.0)
        """
        return min(1.0, base_importance + success_score * 0.7)
    
    def get_reflection_stats(self) -> dict:
        """Get statistics about reflections."""
        with self._lock:
            reflections = copy.deepcopy(self.reflections)
        if not reflections:
            return {
                'total_reflections': 0,
                'avg_success': 0.0,
                'best_success': 0.0,
                'worst_success': 0.0
            }
        
        scores = [r.success_score for r in reflections]
        return {
            'total_reflections': len(reflections),
            'avg_success': float(np.mean(scores)),
            'best_success': float(np.max(scores)),
            'worst_success': float(np.min(scores)),
            'recent': [
                {
                    'input': r.user_input[:100],
                    'score': r.success_score,
                    'timestamp': r.timestamp.isoformat()
                }
                for r in reflections[-5:]
            ]
        }


class MemoryOptimizer:
    """Handles memory pruning and compression."""
    
    def prune(self, store: MemoryStore, threshold: float = 0.2) -> int:
        """
        Remove low-importance memories below threshold.
        Returns count of pruned memories.
        """
        initial_count = store.size()
        for memory in store.memories:
            if memory.importance < threshold:
                store._delete(memory.id)
        return initial_count - store.size()

    def compress(self, store: MemoryStore) -> None:
        """
        Compress similar memories by averaging embeddings.
        Placeholder for future implementation with clustering.
        """
        # TODO: Implement clustering-based compression
        # Group similar memories, summarize content, average embeddings
        pass

    def decay(self, store: MemoryStore, decay_rate: float = 0.95) -> None:
        """
        Apply time-based decay to memory importance.
        Older memories gradually lose importance.
        """
        now = _utcnow()
        for memory in store.memories:
            age_days = (now - memory.timestamp).days
            decay_factor = decay_rate ** (age_days / 7)  # Decay per week
            memory.importance *= decay_factor
            store._replace(memory)

    def get_statistics(self, store: MemoryStore) -> dict:
        """Get statistics about stored memories."""
        memories = store.memories
        if not memories:
            return {
                'total_memories': 0,
                'avg_importance': 0.0,
                'oldest': None,
                'newest': None
            }
        
        importances = [m.importance for m in memories]
        timestamps = [m.timestamp for m in memories]
        
        return {
            'total_memories': store.size(),
            'avg_importance': np.mean(importances),
            'max_importance': float(np.max(importances)),
            'min_importance': float(np.min(importances)),
            'oldest': min(timestamps),
            'newest': max(timestamps)
        }


@dataclass
class _CortexRequest:
    mutation: MemoryMutation
    completed: threading.Event = field(default_factory=threading.Event)
    result: Optional[MutationResult] = None
    error: Optional[BaseException] = None


class Cortex:
    """Read-heavy active cognition channel that emits memory proposals."""

    def __init__(self, authority: MemoryCoordinator):
        self.authority = authority
        self.active_queue: queue.Queue = queue.Queue()
        self._stop = object()
        self._closed = False
        self._thread = threading.Thread(
            target=self._run,
            name="Hades-Cortex",
            daemon=True,
        )
        self._thread.start()

    def propose(self, mutation: MemoryMutation) -> MutationResult:
        if self._closed:
            raise RuntimeError("Cortex channel is closed")
        if not mutation.source_thread:
            mutation = replace(mutation, source_thread=threading.current_thread().name)
        request = _CortexRequest(mutation)
        self.active_queue.put(request)
        request.completed.wait()
        if request.error:
            raise request.error
        return request.result

    def close(self, timeout: float = 5.0) -> None:
        if self._closed:
            return
        if self._thread.is_alive():
            self.active_queue.put(self._stop)
            self._thread.join(timeout)
        self._closed = True

    def _run(self) -> None:
        while True:
            request = self.active_queue.get()
            if request is self._stop:
                return
            try:
                request.result = self.authority.submit(request.mutation)
            except BaseException as exc:
                request.error = exc
            finally:
                request.completed.set()


@dataclass
class _ReflectionRequest:
    prune_threshold: float
    apply_decay: bool
    completed: threading.Event = field(default_factory=threading.Event)
    result: Optional[dict] = None
    error: Optional[BaseException] = None


@dataclass
class _DreamerMutationRequest:
    mutation: MemoryMutation
    completed: threading.Event = field(default_factory=threading.Event)
    result: Optional[MutationResult] = None
    error: Optional[BaseException] = None


class Dreamer:
    """Reflection channel: analyzes snapshots and proposes canonical changes."""

    def __init__(self, store: MemoryStore, authority: MemoryCoordinator, optimizer: MemoryOptimizer):
        self.store = store
        self.authority = authority
        self.optimizer = optimizer
        self.reflection_queue: queue.Queue = queue.Queue()
        self._stop = object()
        self._closed = False
        self._thread = threading.Thread(
            target=self._run,
            name="Hades-Dreamer",
            daemon=True,
        )
        self._thread.start()

    def optimize(self, prune_threshold: float, apply_decay: bool) -> dict:
        if self._closed:
            raise RuntimeError("Dreamer channel is closed")
        request = _ReflectionRequest(prune_threshold, apply_decay)
        self.reflection_queue.put(request)
        request.completed.wait()
        if request.error:
            raise request.error
        return request.result

    def propose(self, mutation: MemoryMutation) -> MutationResult:
        if self._closed:
            raise RuntimeError("Dreamer channel is closed")
        if not mutation.source_thread:
            mutation = replace(mutation, source_thread="Hades-Dreamer")
        request = _DreamerMutationRequest(mutation)
        self.reflection_queue.put(request)
        request.completed.wait()
        if request.error:
            raise request.error
        return request.result

    def close(self, timeout: float = 5.0) -> None:
        if self._closed:
            return
        if self._thread.is_alive():
            self.reflection_queue.put(self._stop)
            self._thread.join(timeout)
        self._closed = True

    def _run(self) -> None:
        while True:
            request = self.reflection_queue.get()
            if request is self._stop:
                return
            try:
                if isinstance(request, _DreamerMutationRequest):
                    request.result = self.authority.submit(request.mutation)
                else:
                    request.result = self._optimize_snapshot(request)
            except BaseException as exc:
                request.error = exc
            finally:
                request.completed.set()

    def _optimize_snapshot(self, request: _ReflectionRequest) -> dict:
        snapshot = self.store.memories
        stats_before = self.optimizer.get_statistics(self.store)
        now = _utcnow()
        pruned = 0
        conflicts = []

        for memory in snapshot:
            importance = memory.importance
            if request.apply_decay:
                age_days = max(0, (now - memory.timestamp).days)
                importance *= 0.95 ** (age_days / 7)

            operation = (
                MemoryOperation.FORGET
                if importance < request.prune_threshold
                else MemoryOperation.UPDATE
            )
            if (
                operation == MemoryOperation.UPDATE
                and abs(importance - memory.importance) < 1e-12
            ):
                continue
            mutation = MemoryMutation(
                operation=operation,
                memory_id=memory.id,
                expected_revision=memory.revision,
                content=memory.content,
                embedding=memory.embedding,
                importance=importance,
                metadata=memory.metadata,
                source_channel="dreamer",
                source_thread=threading.current_thread().name,
                reason="periodic decay and consolidation",
            )
            result = self.authority.submit(mutation)
            if result.conflict:
                conflicts.append(result.conflict.memory_id)
            elif operation == MemoryOperation.FORGET:
                pruned += 1

        return {
            'pruned_count': pruned,
            'conflicts': conflicts,
            'stats_before': stats_before,
            'stats_after': self.optimizer.get_statistics(self.store),
        }


class MemoryAnalyzer:
    """Compares recent conversation context against long-term memories."""

    STOPWORDS = {
        'about', 'after', 'again', 'also', 'and', 'are', 'because', 'been', 'but',
        'can', 'could', 'did', 'does', 'for', 'from', 'had', 'has', 'have', 'how',
        'into', 'just', 'like', 'more', 'not', 'now', 'our', 'out', 'that', 'the',
        'their', 'them', 'then', 'there', 'this', 'through', 'use', 'was', 'were',
        'what', 'when', 'where', 'which', 'who', 'why', 'with', 'would', 'you', 'your'
    }

    def _keywords(self, text: str) -> List[str]:
        words = re.findall(r"[a-zA-Z][a-zA-Z0-9_\-]{2,}", text.lower())
        return [w for w in words if w not in self.STOPWORDS]

    def analyze(self, query: str, short_term_messages: List[dict],
                long_term_matches: List[tuple], max_items: int = 5) -> dict:
        """
        Compare short-term chat history to recalled long-term memories.

        Returns compact response-planning guidance instead of raw transcripts so an LLM
        can stay responsive, preserve recent intent, and add durable context only when
        it is relevant.
        """
        recent_text = "\n".join(
            f"{m.get('role', 'unknown')}: {m.get('message', '')}"
            for m in short_term_messages[-max_items:]
        )
        query_terms = set(self._keywords(query))
        short_terms = set(self._keywords(recent_text))

        relevant_memories = []
        long_terms = set()
        for score, memory in long_term_matches[:max_items]:
            content = getattr(memory, 'content', '') or ''
            memory_terms = set(self._keywords(content))
            long_terms.update(memory_terms)
            overlap = sorted((query_terms | short_terms) & memory_terms)
            relevant_memories.append({
                'id': getattr(memory, 'id', ''),
                'score': float(score),
                'importance': float(getattr(memory, 'importance', 0.0)),
                'overlap': overlap[:8],
                'content': content[:360]
            })

        repeated_terms = sorted((query_terms & short_terms) | (short_terms & long_terms))[:12]
        new_terms = sorted(query_terms - long_terms - short_terms)[:12]
        durable_terms = sorted((query_terms | short_terms) & long_terms)[:12]

        guidance = []
        if repeated_terms:
            guidance.append(
                "Continue the current thread of thought; the user is repeating or refining: "
                + ", ".join(repeated_terms[:6])
            )
        if durable_terms:
            guidance.append(
                "Blend in long-term context for: " + ", ".join(durable_terms[:6])
            )
        if new_terms:
            guidance.append(
                "Treat these as new or under-specified details and answer directly: "
                + ", ".join(new_terms[:6])
            )
        if relevant_memories:
            guidance.append(
                "Use the recalled memories as background, not as a substitute for the user's latest request."
            )
        else:
            guidance.append("No strong long-term memory match; rely primarily on the latest user message.")

        return {
            'query_terms': sorted(query_terms)[:20],
            'short_term_focus': sorted(short_terms)[:20],
            'repeated_terms': repeated_terms,
            'new_terms': new_terms,
            'durable_terms': durable_terms,
            'relevant_memories': relevant_memories,
            'response_guidance': guidance
        }

    def format_for_prompt(self, analysis: dict, char_limit: int = 1800) -> str:
        """Render analysis as concise prompt context."""
        if not analysis:
            return ""

        lines = ["Memory analyzer guidance:"]
        for item in analysis.get('response_guidance', [])[:4]:
            lines.append(f"- {item}")

        memories = analysis.get('relevant_memories', [])[:3]
        if memories:
            lines.append("Relevant long-term memories:")
            for mem in memories:
                overlap = ", ".join(mem.get('overlap') or []) or "general relevance"
                content = " ".join((mem.get('content') or '').split())
                lines.append(f"- score={mem.get('score', 0):.2f}; overlap={overlap}; {content}")

        output = "\n".join(lines)
        if len(output) > char_limit:
            return output[:char_limit - 3] + "..."
        return output


class CognitiveLayer:
    """
    Main interface for memory operations with feedback loop.
    Integrates embedding generation, storage, retrieval, optimization,
    and reinforcement learning through outcome evaluation.
    """
    
    def __init__(self, embedder: Callable = None, db_path: str = None):
        """
        Initialize the cognitive layer.
        
        Args:
            embedder: Callable that converts text to embeddings.
                     If None, uses simple word-frequency embeddings.
            db_path: Optional SQLite database used to persist memories and reflections.
        """
        self.store = MemoryStore()
        self.optimizer = MemoryOptimizer()
        self.analyzer = MemoryAnalyzer()
        self.reflection = ReflectionEngine()
        self.embedder = embedder or self._default_embedder
        self.db_path = db_path
        self._db_lock = threading.RLock()
        self._event_sequence = 0
        self._closed = False
        self._reinforcement_map = {}  # Map reflection IDs to memory IDs
        if self.db_path:
            self._init_db()
            self._load_state()
        self.hippocampus = MemoryCoordinator(self.store, self._persist_event)
        self.memory_authority = self.hippocampus
        self.cortex = Cortex(self.hippocampus)
        self.dreamer = Dreamer(self.store, self.hippocampus, self.optimizer)
        self.active_queue = self.cortex.active_queue
        self.memory_write_queue = self.hippocampus.write_queue
        self.reflection_queue = self.dreamer.reflection_queue

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        """Create durable cognitive-memory tables without owning the parent database."""
        with self._db_lock, closing(self._connect()) as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cognitive_memories (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    embedding TEXT NOT NULL,
                    importance REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    access_count INTEGER NOT NULL DEFAULT 0,
                    reinforcement_score REAL NOT NULL DEFAULT 0.5
                )
            """)
            existing_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(cognitive_memories)")
            }
            migrations = {
                "revision": "INTEGER NOT NULL DEFAULT 1",
                "updated_at": "TEXT",
                "source_thread": "TEXT NOT NULL DEFAULT ''",
                "parent_revision": "INTEGER",
                "status": "TEXT NOT NULL DEFAULT 'active'",
                "links": "TEXT NOT NULL DEFAULT '{}'",
            }
            for column, definition in migrations.items():
                if column not in existing_columns:
                    conn.execute(
                        f"ALTER TABLE cognitive_memories ADD COLUMN {column} {definition}"
                    )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cognitive_reflections (
                    id TEXT PRIMARY KEY,
                    user_input TEXT NOT NULL,
                    ai_output TEXT NOT NULL,
                    success_score REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    reflected_content TEXT NOT NULL,
                    memory_id TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cognitive_memory_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    memory_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    expected_revision INTEGER,
                    timestamp TEXT NOT NULL,
                    source_channel TEXT NOT NULL,
                    source_thread TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cognitive_memory_events_memory
                ON cognitive_memory_events(memory_id, sequence)
            """)

    def _load_state(self) -> None:
        """Restore memories and feedback mappings from SQLite."""
        with self._db_lock, closing(self._connect()) as conn, conn:
            memory_rows = conn.execute("""
                SELECT id, content, embedding, importance, timestamp, metadata,
                       access_count, reinforcement_score, revision, updated_at,
                       source_thread, parent_revision, status, links
                FROM cognitive_memories
                WHERE status = 'active'
                ORDER BY timestamp
            """).fetchall()
            reflection_rows = conn.execute("""
                SELECT id, user_input, ai_output, success_score, timestamp, metadata,
                       reflected_content, memory_id
                FROM cognitive_reflections ORDER BY timestamp
            """).fetchall()

        for row in memory_rows:
            memory = self._memory_from_row(row)
            self.store.add(memory)

        for row in reflection_rows:
            reflection = Reflection(
                id=row[0], user_input=row[1], ai_output=row[2],
                success_score=float(row[3]), timestamp=datetime.fromisoformat(row[4]),
                metadata=json.loads(row[5] or '{}'), reflected_content=row[6]
            )
            with self.reflection._lock:
                self.reflection.reflections.append(reflection)
            if row[7]:
                self._reinforcement_map[reflection.id] = row[7]

    @staticmethod
    def _memory_from_row(row) -> Memory:
        return Memory(
            id=row[0], content=row[1], embedding=json.loads(row[2]),
            importance=float(row[3]), timestamp=datetime.fromisoformat(row[4]),
            metadata=json.loads(row[5] or '{}'), access_count=int(row[6]),
            reinforcement_score=float(row[7]), revision=int(row[8] or 1),
            updated_at=datetime.fromisoformat(row[9] or row[4]),
            source_thread=row[10] or "", parent_revision=row[11],
            status=row[12] or "active", links=json.loads(row[13] or '{}'),
        )

    def _persist_event(self, event: MemoryEvent, memory: Optional[Memory]) -> int:
        """Atomically append an event and update the materialized SQLite snapshot."""
        if not self.db_path:
            self._event_sequence += 1
            return self._event_sequence

        with self._db_lock, closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("""
                SELECT id, content, embedding, importance, timestamp, metadata,
                       access_count, reinforcement_score, revision, updated_at,
                       source_thread, parent_revision, status, links
                FROM cognitive_memories WHERE id = ?
            """,
                (event.memory_id,),
            ).fetchone()
            canonical = self._memory_from_row(row) if row else None
            actual_revision = canonical.revision if canonical else None
            if event.operation == MemoryOperation.ADD.value:
                if actual_revision is not None:
                    raise RevisionConflictError(
                        actual_revision,
                        "memory already exists in canonical storage",
                        canonical,
                    )
            elif actual_revision != event.expected_revision:
                raise RevisionConflictError(
                    actual_revision,
                    "canonical revision changed",
                    canonical,
                )

            cursor = conn.execute("""
                INSERT INTO cognitive_memory_events
                (event_id, memory_id, operation, revision, expected_revision,
                 timestamp, source_channel, source_thread, reason, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id, event.memory_id, event.operation, event.revision,
                event.expected_revision, event.timestamp.isoformat(),
                event.source_channel, event.source_thread, event.reason,
                json.dumps(event.payload, default=str),
            ))
            sequence = int(cursor.lastrowid)
            if memory is None:
                conn.execute(
                    "DELETE FROM cognitive_memories WHERE id = ?",
                    (event.memory_id,),
                )
            else:
                conn.execute("""
                    INSERT OR REPLACE INTO cognitive_memories
                    (id, content, embedding, importance, timestamp, metadata,
                     access_count, reinforcement_score, revision, updated_at,
                     source_thread, parent_revision, status, links)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    memory.id, memory.content, json.dumps(memory.embedding),
                    memory.importance, memory.timestamp.isoformat(),
                    json.dumps(memory.metadata, default=str), memory.access_count,
                    memory.reinforcement_score, memory.revision,
                    memory.updated_at.isoformat(), memory.source_thread,
                    memory.parent_revision, memory.status,
                    json.dumps(memory.links, default=str),
                ))
            return sequence

    def _default_embedder(self, text: str) -> list:
        """
        Simple default embedder using word frequencies.
        Replace with proper embedding model (e.g., BERT, sentence-transformers).
        """
        words = re.findall(r"[a-zA-Z0-9_\-]+", text.lower())
        # Create a simple 128-dimensional embedding from word frequencies
        embedding = [0.0] * 128
        for word in words:
            hash_val = int.from_bytes(
                hashlib.blake2b(word.encode('utf-8'), digest_size=8).digest(),
                byteorder='big'
            ) % 128
            embedding[hash_val] += 1.0 / (len(words) + 1)
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = [x / norm for x in embedding]
        return embedding

    def remember(self, text: str, importance: float = 0.5, metadata: dict = None) -> str:
        """
        Store a new memory.
        
        Args:
            text: Memory content
            importance: Importance score (0.0-1.0)
            metadata: Optional metadata dictionary
            
        Returns:
            Memory ID
        """
        memory_id = str(uuid.uuid4())
        result = self.cortex.propose(MemoryMutation(
            operation=MemoryOperation.ADD,
            memory_id=memory_id,
            content=text,
            embedding=self.embedder(text),
            importance=max(0.0, min(1.0, float(importance))),
            metadata=copy.deepcopy(metadata or {}),
            source_channel="cortex",
            source_thread=threading.current_thread().name,
            reason="active cognition proposed a durable memory",
        ))
        if not result.success:
            raise RuntimeError(result.conflict.reason)
        return memory_id

    def submit_memory_mutation(self, mutation: MemoryMutation) -> MutationResult:
        """Submit an explicit versioned mutation to the canonical writer."""
        if not mutation.source_thread:
            mutation = replace(mutation, source_thread=threading.current_thread().name)
        return self.cortex.propose(mutation)

    def update_memory(self, memory_id: str, expected_revision: int,
                      content: str, metadata: Optional[dict] = None,
                      importance: Optional[float] = None,
                      reason: str = "memory corrected") -> MutationResult:
        """Update a memory using optimistic revision checking."""
        current = self.store.get_memory(memory_id)
        embedding = self.embedder(content)
        return self.submit_memory_mutation(MemoryMutation(
            operation=MemoryOperation.UPDATE,
            memory_id=memory_id,
            expected_revision=expected_revision,
            content=content,
            embedding=embedding,
            importance=importance,
            metadata=metadata if metadata is not None else (current.metadata if current else {}),
            source_channel="cortex",
            reason=reason,
        ))

    def supersede_memory(self, memory_id: str, expected_revision: int,
                         content: str, reason: str,
                         metadata: Optional[dict] = None) -> MutationResult:
        """Append a new interpretation while retaining prior revisions in history."""
        current = self.store.get_memory(memory_id)
        return self.submit_memory_mutation(MemoryMutation(
            operation=MemoryOperation.SUPERSEDE,
            memory_id=memory_id,
            expected_revision=expected_revision,
            content=content,
            embedding=self.embedder(content),
            importance=current.importance if current else None,
            metadata=metadata if metadata is not None else (current.metadata if current else {}),
            source_channel="cortex",
            reason=reason,
        ))

    def link_memories(self, memory_id: str, expected_revision: int,
                      relation: str, target_memory_id: str,
                      reason: str = "memory graph relationship") -> MutationResult:
        """Add a supports/contradicts/supersedes/derived_from/related_to edge."""
        if self.store.get_memory(target_memory_id) is None:
            return MutationResult(
                success=False,
                conflict=MemoryConflict(
                    memory_id=memory_id,
                    expected_revision=expected_revision,
                    actual_revision=None,
                    current=self.store.get_memory(memory_id),
                    proposed=MemoryMutation(
                        MemoryOperation.LINK,
                        memory_id=memory_id,
                        expected_revision=expected_revision,
                        relation=relation,
                        target_memory_id=target_memory_id,
                    ),
                    reason="target memory does not exist",
                ),
            )
        return self.submit_memory_mutation(MemoryMutation(
            operation=MemoryOperation.LINK,
            memory_id=memory_id,
            expected_revision=expected_revision,
            relation=relation,
            target_memory_id=target_memory_id,
            source_channel="cortex",
            reason=reason,
        ))

    def recall(self, query: str, top_k: int = 5, use_reinforcement: bool = True) -> List[tuple]:
        """
        Retrieve similar memories with optional reinforcement bias.
        
        Args:
            query: Search query text
            top_k: Number of results to return
            use_reinforcement: Apply reinforcement bias to boost successful memories
            
        Returns:
            List of (similarity_score, Memory) tuples
        """
        query_embedding = self.embedder(query)
        results = self.store.search(query_embedding, top_k, use_reinforcement)
        
        # Access accounting is also a proposal; readers never mutate snapshots.
        accessed = []
        for score, memory in results:
            result = self.cortex.propose(MemoryMutation(
                operation=MemoryOperation.ACCESS,
                memory_id=memory.id,
                source_channel="cortex",
                source_thread=threading.current_thread().name,
                reason="memory recalled",
            ))
            accessed.append((score, result.memory if result.success else memory))
        return accessed

    def optimize(self, prune_threshold: float = 0.2, apply_decay: bool = True) -> dict:
        """
        Optimize memory storage.
        
        Args:
            prune_threshold: Remove memories below this importance
            apply_decay: Apply time-based decay
            
        Returns:
            Optimization statistics
        """
        return self.dreamer.optimize(prune_threshold, apply_decay)

    def forget(self, memory_id: str) -> bool:
        """Forget the live snapshot while retaining its append-only history."""
        result = self.submit_memory_mutation(MemoryMutation(
            operation=MemoryOperation.FORGET,
            memory_id=memory_id,
            source_channel="cortex",
            reason="explicit forget request",
        ))
        return result.success

    def get_memory_stats(self) -> dict:
        """Get current memory statistics."""
        return self.optimizer.get_statistics(self.store)

    def set_embedder(self, embedder: Callable) -> None:
        """Replace the embedder function."""
        self.embedder = embedder

    def clear(self) -> None:
        """Forget all live memories without deleting their event history."""
        for memory in self.store.memories:
            self.submit_memory_mutation(MemoryMutation(
                operation=MemoryOperation.FORGET,
                memory_id=memory.id,
                expected_revision=memory.revision,
                source_channel="cortex",
                reason="clear all memories",
            ))
    
    # ========== Feedback Loop Methods ==========
    
    def evaluate_response(self, user_input: str, ai_output: str, 
                         success_score: float, metadata: dict = None) -> str:
        """
        Evaluate an AI response and create a reflection.
        This is the "outcome evaluation" step in the feedback loop.
        
        Args:
            user_input: User's original query
            ai_output: AI's response
            success_score: Evaluation score (0.0-1.0)
            metadata: Optional metadata about the interaction
            
        Returns:
            Reflection ID
        """
        reflection = self.reflection.create_reflection(
            user_input, ai_output, success_score, metadata
        )
        
        # Optionally store the reflection itself as a memory
        importance = self.reflection.calculate_reinforcement(success_score)
        memory_id = self.remember(
            text=reflection.reflected_content,
            importance=importance,
            metadata={
                'type': 'reflection',
                'reinforcement': True,
                'success_score': success_score
            }
        )
        self._reinforcement_map[reflection.id] = memory_id
        if self.db_path:
            with self._db_lock, closing(self._connect()) as conn, conn:
                conn.execute("""
                    INSERT OR REPLACE INTO cognitive_reflections
                    (id, user_input, ai_output, success_score, timestamp, metadata,
                     reflected_content, memory_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    reflection.id, reflection.user_input, reflection.ai_output,
                    reflection.success_score, reflection.timestamp.isoformat(),
                    json.dumps(reflection.metadata), reflection.reflected_content,
                    memory_id
                ))
        
        return reflection.id
    
    def reinforce_memory(self, memory_id: str, success_score: float) -> bool:
        """
        Reinforce a specific memory based on feedback.
        Updates the memory's reinforcement score and importance.
        
        Args:
            memory_id: Memory to reinforce
            success_score: Feedback score (0.0-1.0)
            
        Returns:
            Success status
        """
        result = self.submit_memory_mutation(MemoryMutation(
            operation=MemoryOperation.REINFORCE,
            memory_id=memory_id,
            success_score=max(0.0, min(1.0, float(success_score))),
            source_channel="cortex",
            reason="outcome reinforcement",
        ))
        return result.success

    def get_memory_snapshot(self, memory_id: str) -> Optional[Memory]:
        """Read a detached canonical snapshot."""
        return self.store.get_memory(memory_id)

    def get_memory_history(self, memory_id: str) -> List[MemoryEvent]:
        """Return the append-only revision history for one memory."""
        if not self.db_path:
            return self.hippocampus.get_events(memory_id)

        with self._db_lock, closing(self._connect()) as conn:
            rows = conn.execute("""
                SELECT sequence, event_id, memory_id, operation, revision,
                       expected_revision, timestamp, source_channel,
                       source_thread, reason, payload
                FROM cognitive_memory_events
                WHERE memory_id = ?
                ORDER BY sequence
            """, (memory_id,)).fetchall()
        return [
            MemoryEvent(
                sequence=int(row[0]), event_id=row[1], memory_id=row[2],
                operation=row[3], revision=int(row[4]),
                expected_revision=row[5],
                timestamp=datetime.fromisoformat(row[6]),
                source_channel=row[7], source_thread=row[8], reason=row[9],
                payload=json.loads(row[10]),
            )
            for row in rows
        ]

    def rollback_memory(self, memory_id: str, revision: int,
                        reason: str = "rollback to prior revision") -> MutationResult:
        """Create a new revision whose content matches a historical revision."""
        history = self.get_memory_history(memory_id)
        event = next((item for item in history if item.revision == revision), None)
        current = self.store.get_memory(memory_id)
        if event is None or current is None:
            mutation = MemoryMutation(
                MemoryOperation.SUPERSEDE,
                memory_id=memory_id,
                expected_revision=current.revision if current else None,
                reason=reason,
            )
            return MutationResult(
                False,
                conflict=MemoryConflict(
                    memory_id, mutation.expected_revision,
                    current.revision if current else None,
                    current, mutation, "requested revision is unavailable",
                ),
            )
        snapshot = event.payload.get("after") or {}
        return self.submit_memory_mutation(MemoryMutation(
            operation=MemoryOperation.SUPERSEDE,
            memory_id=memory_id,
            expected_revision=current.revision,
            content=snapshot.get("content", current.content),
            embedding=snapshot.get("embedding", current.embedding),
            importance=snapshot.get("importance", current.importance),
            metadata=snapshot.get("metadata", current.metadata),
            source_channel="cortex",
            reason=f"{reason}; source revision={revision}",
        ))

    def get_memory_graph(self) -> Dict[str, Dict[str, List[str]]]:
        """Return graph edges from the current materialized snapshot."""
        return {memory.id: copy.deepcopy(memory.links) for memory in self.store.memories}

    def consolidate_memories(self, memory_ids: List[str], summary: str,
                             importance: float = 0.7,
                             reason: str = "reflection consolidation") -> MutationResult:
        """Let Dreamer promote a summary linked to all source memories."""
        sources = [self.store.get_memory(memory_id) for memory_id in memory_ids]
        if not memory_ids or any(memory is None for memory in sources):
            mutation = MemoryMutation(
                MemoryOperation.ADD,
                content=summary,
                source_channel="dreamer",
                reason=reason,
            )
            return MutationResult(
                False,
                conflict=MemoryConflict(
                    "", None, None, None, mutation,
                    "all source memories must exist",
                ),
            )

        result = self.dreamer.propose(MemoryMutation(
            operation=MemoryOperation.ADD,
            memory_id=str(uuid.uuid4()),
            content=summary,
            embedding=self.embedder(summary),
            importance=max(0.0, min(1.0, float(importance))),
            metadata={"type": "consolidated_memory", "source_ids": list(memory_ids)},
            source_channel="dreamer",
            reason=reason,
        ))
        if not result.success:
            return result

        consolidated = result.memory
        for source_id in memory_ids:
            link_result = self.dreamer.propose(MemoryMutation(
                operation=MemoryOperation.LINK,
                memory_id=consolidated.id,
                expected_revision=consolidated.revision,
                relation="derived_from",
                target_memory_id=source_id,
                source_channel="dreamer",
                reason=reason,
            ))
            if not link_result.success:
                return link_result
            consolidated = link_result.memory
        return MutationResult(True, consolidated, link_result.event)

    def close(self) -> None:
        """Stop logical channel workers after draining synchronous operations."""
        if self._closed:
            return
        self.cortex.close()
        self.dreamer.close()
        self.hippocampus.close()
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
    
    def generate_with_memory(self, query: str, context_provider: Callable) -> Tuple[str, List[tuple]]:
        """
        Generate a response using recalled memories as context.
        This implements memory-augmented generation.
        
        Args:
            query: User query
            context_provider: Callable that takes (query, memory_context) -> response
                             This is typically your LLM call
            
        Returns:
            Tuple of (response, recalled_memories)
        """
        # Recall relevant memories
        memories = self.recall(query, top_k=5)
        
        # Format memory context
        memory_context = "\n".join(
            f"- {m.content}" for _, m in memories
        )
        
        # Generate response with memory context
        response = context_provider(query, memory_context)
        
        return response, memories

    def analyze_memory_context(self, query: str, short_term_messages: List[dict],
                               top_k: int = 5) -> dict:
        """Compare recent chat history with long-term memory recall."""
        memories = self.recall(query, top_k=top_k)
        return self.analyzer.analyze(query, short_term_messages, memories)

    def format_memory_analysis_for_prompt(self, analysis: dict,
                                          char_limit: int = 1800) -> str:
        """Render a memory analysis into concise LLM prompt context."""
        return self.analyzer.format_for_prompt(analysis, char_limit=char_limit)
    
    def get_reflection_stats(self) -> dict:
        """Get statistics about reflections and reinforcement."""
        return self.reflection.get_reflection_stats()
    
    def get_full_stats(self) -> dict:
        """Get comprehensive statistics about memories and reflections."""
        memory_stats = self.get_memory_stats()
        reflection_stats = self.get_reflection_stats()
        
        # Calculate memory quality metrics
        if self.store.memories:
            access_counts = [m.access_count for m in self.store.memories]
            reinforcement_scores = [m.reinforcement_score for m in self.store.memories]
            
            memory_stats['avg_access_count'] = float(np.mean(access_counts))
            memory_stats['avg_reinforcement'] = float(np.mean(reinforcement_scores))
            memory_stats['max_reinforcement'] = float(np.max(reinforcement_scores))
        
        return {
            'memories': memory_stats,
            'reflections': reflection_stats,
            'integration_quality': {
                'reinforced_memories': sum(
                    1 for m in self.store.memories 
                    if m.reinforcement_score > 0.5
                ),
                'frequently_accessed': sum(
                    1 for m in self.store.memories 
                    if m.access_count > 2
                )
            }
        }
