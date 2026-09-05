"""Narrative analogy and episodic feedback for advisory decision support.

The weave ranks candidate actions. It never executes them or overrides the
caller's authorization, approval, safety, or policy checks.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
import json
import math
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

WORD_RE = re.compile(r"[A-Za-z0-9_'-]+")


def tokenize(text: str) -> List[str]:
    return [word.lower() for word in WORD_RE.findall(text)]


def cosine_text(a: str, b: str) -> float:
    """Return dependency-free cosine similarity for two text values."""
    vector_a, vector_b = Counter(tokenize(a)), Counter(tokenize(b))
    if not vector_a or not vector_b:
        return 0.0
    overlap = set(vector_a) & set(vector_b)
    dot = sum(vector_a[key] * vector_b[key] for key in overlap)
    norm_a = math.sqrt(sum(value * value for value in vector_a.values()))
    norm_b = math.sqrt(sum(value * value for value in vector_b.values()))
    return dot / (norm_a * norm_b) if norm_a and norm_b else 0.0


@dataclass
class WorldState:
    description: str
    features: Dict[str, Any] = field(default_factory=dict)
    goals: List[str] = field(default_factory=list)

    def as_text(self) -> str:
        features = " ".join(f"{key} {value}" for key, value in self.features.items())
        return f"{self.description} {features} {' '.join(self.goals)}"


@dataclass
class Action:
    name: str
    description: str
    tags: List[str] = field(default_factory=list)
    cost: float = 0.0
    risk: float = 0.0
    reward_hint: float = 0.0

    def as_text(self) -> str:
        return f"{self.name} {self.description} {' '.join(self.tags)}"


@dataclass
class Consequence:
    action_name: str
    next_state: str
    effects: Dict[str, float] = field(default_factory=dict)
    confidence: float = 0.5

    def utility(self, weights: Dict[str, float]) -> float:
        return sum(self.effects.get(key, 0.0) * weight for key, weight in weights.items())


@dataclass
class DecisionPattern:
    id: str
    source_label: str
    situation: str
    abstract_roles: Dict[str, str]
    actions: List[Action]
    consequences: List[Consequence]
    concepts: List[str] = field(default_factory=list)
    notes: str = ""

    def as_text(self) -> str:
        return " ".join([
            self.situation,
            " ".join(self.concepts),
            " ".join(action.as_text() for action in self.actions),
            self.notes,
        ])


@dataclass
class DecisionOperator:
    name: str
    trigger_tags: List[str]
    description: str
    mutate: Callable[[WorldState, List[Action]], List[Action]]


@dataclass
class MemoryEpisode:
    id: str
    state_before: WorldState
    available_actions: List[Action]
    selected_action: str
    predicted_utility: float
    actual_utility: Optional[float]
    retrieved_pattern_ids: List[str]
    explanation: str


class NarrativeDecisionWeave:
    """Retrieve narrative analogies, rank actions, and learn from outcomes."""

    def __init__(self, memory_path: str = "ndw_memory.json"):
        self.patterns: List[DecisionPattern] = []
        self.episodes: List[MemoryEpisode] = []
        self.operators: List[DecisionOperator] = []
        self.memory_path = Path(memory_path)
        self.utility_weights = {
            "goal_progress": 1.00, "safety": 0.85, "helpfulness": 0.55,
            "knowledge": 0.45, "resource_gain": 0.40, "time_saved": 0.30,
            "damage": -1.00, "risk": -0.75, "resource_loss": -0.45,
            "time_cost": -0.30,
        }
        self._install_default_operators()
        self.load_memory()

    def add_pattern(
        self, source_label: str, situation: str, actions: List[Action],
        consequences: List[Consequence],
        abstract_roles: Optional[Dict[str, str]] = None,
        concepts: Optional[List[str]] = None, notes: str = "",
    ) -> DecisionPattern:
        pattern = DecisionPattern(
            str(uuid.uuid4()), source_label, situation, abstract_roles or {},
            actions, consequences, concepts or [], notes,
        )
        self.patterns.append(pattern)
        self.save_memory()
        return pattern

    def ingest_choice_passage(
        self, source_label: str, passage: str, choice_a: str, choice_b: str,
        consequence_a: str, consequence_b: str,
        concepts: Optional[List[str]] = None,
    ) -> DecisionPattern:
        return self.add_pattern(
            source_label, passage,
            [Action("A", choice_a, self._infer_tags(choice_a)),
             Action("B", choice_b, self._infer_tags(choice_b))],
            [Consequence("A", consequence_a, self._infer_effects(consequence_a), 0.60),
             Consequence("B", consequence_b, self._infer_effects(consequence_b), 0.60)],
            concepts=concepts or self._infer_tags(passage),
            notes="Ingested from a narrative choice passage.",
        )

    def retrieve_patterns(
        self, state: WorldState, top_k: int = 3,
    ) -> List[Tuple[DecisionPattern, float]]:
        query = state.as_text()
        state_tokens = set(tokenize(query))
        scored = []
        for pattern in self.patterns:
            overlap = sum(1 for concept in pattern.concepts if concept.lower() in state_tokens)
            score = cosine_text(query, pattern.as_text()) + min(0.25, overlap * 0.05)
            scored.append((pattern, score))
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored[:max(0, top_k)]

    def weave_actions(
        self, state: WorldState,
        retrieved: List[Tuple[DecisionPattern, float]],
        supplied_actions: Optional[List[Action]] = None,
    ) -> List[Action]:
        candidates = {action.description.casefold(): action for action in supplied_actions or []}
        for pattern, similarity in retrieved:
            if similarity <= 0:
                continue
            for action in pattern.actions:
                clone = Action(
                    f"{pattern.source_label}:{action.name}", action.description,
                    list(action.tags), action.cost, action.risk,
                    action.reward_hint + similarity * 0.10,
                )
                candidates.setdefault(clone.description.casefold(), clone)
        result = list(candidates.values())
        for operator in self.operators:
            tags = {tag for action in result for tag in action.tags}
            if all(tag in tags for tag in operator.trigger_tags):
                result = operator.mutate(state, result)
        return list({action.description.casefold(): action for action in result}.values())

    def score_action(
        self, state: WorldState, action: Action,
        retrieved: List[Tuple[DecisionPattern, float]],
    ) -> Tuple[float, str]:
        score = action.reward_hint - action.cost * 0.35 - action.risk * 0.75
        reasons = []
        if action.reward_hint:
            reasons.append(f"reward_hint={action.reward_hint:+.2f}")
        if action.cost:
            reasons.append(f"cost={action.cost:.2f}")
        if action.risk:
            reasons.append(f"risk={action.risk:.2f}")
        for pattern, similarity in retrieved:
            for consequence in pattern.consequences:
                source_action = next(
                    (item for item in pattern.actions if item.name == consequence.action_name), None
                )
                if source_action is None:
                    continue
                transfer = similarity * cosine_text(action.as_text(), source_action.as_text())
                if transfer <= 0:
                    continue
                utility = consequence.utility(self.utility_weights)
                score += utility * transfer * consequence.confidence
                if abs(utility * transfer) > 0.01:
                    reasons.append(
                        f"{pattern.source_label}:{source_action.name} "
                        f"transfer={transfer:.2f} utility={utility:+.2f}"
                    )
        for episode in self.episodes:
            if (episode.selected_action.casefold() == action.description.casefold()
                    and episode.actual_utility is not None):
                similarity = cosine_text(state.as_text(), episode.state_before.as_text())
                bonus = episode.actual_utility * similarity * 0.50
                score += bonus
                reasons.append(f"memory={bonus:+.2f} similarity={similarity:.2f}")
        for goal in state.goals:
            affinity = cosine_text(goal, action.as_text())
            if affinity:
                score += affinity * 0.25
                reasons.append(f"goal_affinity={affinity:.2f}")
        return score, "; ".join(reasons) or "no strong evidence"

    def decide(
        self, state: WorldState, supplied_actions: Optional[List[Action]] = None,
        top_k: int = 3,
    ) -> Dict[str, Any]:
        retrieved = self.retrieve_patterns(state, top_k)
        candidates = self.weave_actions(state, retrieved, supplied_actions)
        if not candidates:
            raise RuntimeError("NDW has no candidate actions.")
        scored = [(action, *self.score_action(state, action, retrieved)) for action in candidates]
        scored.sort(key=lambda item: item[1], reverse=True)
        best_action, best_score, explanation = scored[0]
        episode = MemoryEpisode(
            str(uuid.uuid4()), state, candidates, best_action.description, best_score,
            None, [pattern.id for pattern, _ in retrieved], explanation,
        )
        self.episodes.append(episode)
        self.save_memory()
        return {
            "selected_action": asdict(best_action),
            "predicted_utility": best_score,
            "explanation": explanation,
            "retrieved_patterns": [
                {"source": pattern.source_label, "similarity": round(score, 4),
                 "situation": pattern.situation}
                for pattern, score in retrieved
            ],
            "ranked_actions": [
                {"action": asdict(action), "score": round(score, 4), "explanation": reason}
                for action, score, reason in scored
            ],
            "episode_id": episode.id,
        }

    def record_outcome(self, episode_id: str, actual_utility: float) -> None:
        for episode in self.episodes:
            if episode.id == episode_id:
                episode.actual_utility = actual_utility
                self.save_memory()
                return
        raise KeyError(f"No memory episode with id {episode_id}")

    def _install_default_operators(self) -> None:
        def negotiate(state: WorldState, actions: List[Action]) -> List[Action]:
            if any("negotiate" in action.tags for action in actions):
                return actions
            return actions + [Action(
                "WEAVE_NEGOTIATE", "attempt a negotiated or cooperative solution",
                ["negotiate", "cooperate", "deescalate"], 0.15, 0.15, 0.20,
            )]

        def observe(state: WorldState, actions: List[Action]) -> List[Action]:
            if any("observe" in action.tags for action in actions):
                return actions
            return actions + [Action(
                "WEAVE_OBSERVE", "delay commitment and gather more information",
                ["observe", "delay", "knowledge"], 0.10, 0.05, 0.15,
            )]

        self.operators.extend([
            DecisionOperator("Confrontation -> Negotiation", ["confront", "avoid"],
                             "Invent a cooperative branch.", negotiate),
            DecisionOperator("Uncertainty -> Observe", ["uncertain"],
                             "Permit information gathering.", observe),
        ])

    def _infer_tags(self, text: str) -> List[str]:
        lowered = text.lower()
        rules = {
            "help": ["help", "assist", "aid", "rescue", "support"],
            "avoid": ["avoid", "flee", "leave", "escape", "ignore"],
            "confront": ["fight", "attack", "confront", "challenge", "oppose"],
            "negotiate": ["talk", "negotiate", "bargain", "compromise"],
            "observe": ["observe", "inspect", "watch", "study", "investigate"],
            "uncertain": ["unknown", "uncertain", "unclear", "maybe", "mystery"],
            "move": ["move", "carry", "push", "pull", "relocate"],
            "protect": ["protect", "guard", "shield", "defend"],
            "sacrifice": ["sacrifice", "give up", "lose", "miss"],
            "knowledge": ["learn", "discover", "understand", "information"],
        }
        return [tag for tag, words in rules.items() if any(word in lowered for word in words)]

    def _infer_effects(self, text: str) -> Dict[str, float]:
        lowered = text.lower()
        effects: Dict[str, float] = {}
        mappings = [
            ("succeeds", "goal_progress"), ("success", "goal_progress"),
            ("helps", "helpfulness"), ("saved", "safety"), ("safe", "safety"),
            ("learns", "knowledge"), ("discovers", "knowledge"),
            ("gains", "resource_gain"), ("loses", "resource_loss"),
            ("misses", "time_cost"), ("late", "time_cost"),
            ("hurt", "damage"), ("damaged", "damage"),
            ("danger", "risk"), ("risk", "risk"),
        ]
        for needle, dimension in mappings:
            if needle in lowered:
                effects[dimension] = effects.get(dimension, 0.0) + 1.0
        return effects

    def save_memory(self) -> None:
        payload = {
            "patterns": [asdict(pattern) for pattern in self.patterns],
            "episodes": [asdict(episode) for episode in self.episodes],
        }
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.memory_path.with_suffix(self.memory_path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(self.memory_path)

    def load_memory(self) -> None:
        if not self.memory_path.exists():
            return
        try:
            data = json.loads(self.memory_path.read_text(encoding="utf-8"))
            self.patterns = [DecisionPattern(
                id=item["id"], source_label=item["source_label"], situation=item["situation"],
                abstract_roles=item.get("abstract_roles", {}),
                actions=[Action(**action) for action in item.get("actions", [])],
                consequences=[Consequence(**value) for value in item.get("consequences", [])],
                concepts=item.get("concepts", []), notes=item.get("notes", ""),
            ) for item in data.get("patterns", [])]
            self.episodes = [MemoryEpisode(
                id=item["id"], state_before=WorldState(**item["state_before"]),
                available_actions=[Action(**action) for action in item.get("available_actions", [])],
                selected_action=item["selected_action"],
                predicted_utility=item["predicted_utility"],
                actual_utility=item.get("actual_utility"),
                retrieved_pattern_ids=item.get("retrieved_pattern_ids", []),
                explanation=item.get("explanation", ""),
            ) for item in data.get("episodes", [])]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.patterns = []
            self.episodes = []
