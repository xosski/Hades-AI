"""SOCRATES cross-agent reasoning critique and operator transfer for NDW."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional
import uuid

WORD_RE = re.compile(r"[A-Za-z0-9_'-]+")


def tokenize(text: str) -> List[str]:
    return [word.lower() for word in WORD_RE.findall(text)]


def overlap(a: str, b: str) -> float:
    words_a, words_b = set(tokenize(a)), set(tokenize(b))
    return len(words_a & words_b) / len(words_a | words_b) if words_a and words_b else 0.0


@dataclass
class ReasoningAssumption:
    text: str
    confidence: float = 0.5
    necessary: Optional[bool] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class CriticAlternative:
    name: str
    description: str
    predicted_utility: float
    risk: float = 0.0
    cost: float = 0.0
    reversibility: float = 0.5
    information_gain: float = 0.0
    explanation: List[str] = field(default_factory=list)


@dataclass
class Critique:
    id: str
    learner_episode_id: str
    goal: str
    learner_choice: str
    learner_reasoning: str
    detected_assumptions: List[ReasoningAssumption]
    challenged_assumptions: List[str]
    alternatives: List[CriticAlternative]
    preferred_alternative: Optional[str]
    why_preferred: List[str]
    generalized_principle: Optional[str]
    confidence: float
    created_at: float = field(default_factory=time.time)


@dataclass
class TransferableOperator:
    id: str
    name: str
    trigger_conditions: Dict[str, Any]
    transformation: str
    principle: str
    source_agent: str
    source_episode_id: str
    confidence: float = 0.5
    support_count: int = 1
    success_count: int = 0
    failure_count: int = 0
    active: bool = True
    created_at: float = field(default_factory=time.time)


@dataclass
class TransferResult:
    operator_id: str
    learner_agent: str
    accepted: bool
    reason: str
    test_required: bool = True
    created_at: float = field(default_factory=time.time)


class SOCRATES:
    """Critique learner traces and transfer testable reasoning operators."""

    def __init__(
        self, critic_name: str = "Machine-1", learner_name: str = "Machine-2",
        critique_path: str = "socrates_critiques.json",
        operator_path: str = "socrates_operators.json",
        transfer_path: str = "socrates_transfers.json",
    ):
        self.critic_name = critic_name
        self.learner_name = learner_name
        self.critique_path = Path(critique_path)
        self.operator_path = Path(operator_path)
        self.transfer_path = Path(transfer_path)
        self.critiques: List[Critique] = []
        self.operators: List[TransferableOperator] = []
        self.transfers: List[TransferResult] = []
        self.load()

    def critique_decision(
        self, learner_result: Dict[str, Any], goal: str,
        learner_reasoning: str = "",
        explicit_assumptions: Optional[List[str]] = None,
        environment_facts: Optional[Dict[str, Any]] = None,
        critic_alternatives: Optional[List[CriticAlternative]] = None,
    ) -> Critique:
        facts = environment_facts or {}
        chosen = learner_result["selected_action"]["description"]
        assumptions = self._infer_assumptions(
            goal, chosen, explicit_assumptions or [], facts
        )
        challenged = [item.text for item in assumptions if item.necessary is False]
        alternatives = (
            critic_alternatives if critic_alternatives is not None
            else self._generate_structural_alternatives(
                goal, chosen, assumptions, learner_result
            )
        )
        preferred = self._select_preferred_alternative(alternatives)
        why = self._explain_preference(preferred, challenged)
        principle = self._generalize_principle(preferred, challenged)
        confidence = min(
            0.95, 0.40 + min(0.20, 0.05 * len(challenged))
            + min(0.20, 0.03 * len(alternatives)) + (0.10 if preferred else 0.0)
        )
        critique = Critique(
            id=str(uuid.uuid4()), learner_episode_id=learner_result["episode_id"],
            goal=goal, learner_choice=chosen, learner_reasoning=learner_reasoning,
            detected_assumptions=assumptions, challenged_assumptions=challenged,
            alternatives=alternatives,
            preferred_alternative=preferred.description if preferred else None,
            why_preferred=why, generalized_principle=principle,
            confidence=confidence,
        )
        self.critiques.append(critique)
        self.save()
        return critique

    def _infer_assumptions(
        self, goal: str, chosen: str, explicit: List[str], facts: Dict[str, Any],
    ) -> List[ReasoningAssumption]:
        assumptions = [ReasoningAssumption(
            text, 0.85, self._assumption_necessity(text, facts),
            ["Explicitly supplied by learner/operator."],
        ) for text in explicit]
        assumptions.append(ReasoningAssumption(
            f"The goal '{goal}' requires the specific method '{chosen}'.", 0.75,
            False, ["A method is not logically identical to its desired outcome."],
        ))
        lowered = chosen.lower()
        if any(word in lowered for word in ("carry", "walk", "drive", "move manually")):
            assumptions.append(ReasoningAssumption(
                "Physical transport must use the conventional manual route.", 0.70,
                False, ["Movement does not logically require one transport method."],
            ))
        if any(word in lowered for word in ("immediately", "now", "right away")):
            assumptions.append(ReasoningAssumption(
                "Immediate action is more valuable than gathering information first.",
                0.60, None, ["This depends on urgency, uncertainty, and verification cost."],
            ))
        if any(word in lowered for word in ("one at a time", "individually", "separately")):
            assumptions.append(ReasoningAssumption(
                "Items or subgoals must be processed serially.", 0.80, False,
                ["Parallel or batched execution may satisfy the same objective."],
            ))
        unique = {}
        for assumption in assumptions:
            unique.setdefault(assumption.text.casefold(), assumption)
        return list(unique.values())

    def _assumption_necessity(
        self, assumption: str, facts: Dict[str, Any],
    ) -> Optional[bool]:
        for key, value in facts.items():
            if overlap(assumption, str(key).replace("_", " ")) > 0.2:
                if value is True or value in ("required", "must"):
                    return True
                if value is False or value in ("not_required", "optional"):
                    return False
        return None

    def _generate_structural_alternatives(
        self, goal: str, chosen: str, assumptions: List[ReasoningAssumption],
        learner_result: Dict[str, Any],
    ) -> List[CriticAlternative]:
        alternatives = []
        for row in learner_result.get("ranked_actions", []):
            action = row["action"]
            if action["description"] == chosen:
                continue
            alternatives.append(CriticAlternative(
                name=action.get("name", action["description"]),
                description=action["description"],
                predicted_utility=float(row.get("score", 0.0)),
                risk=float(action.get("risk", 0.0)), cost=float(action.get("cost", 0.0)),
                explanation=["Alternative already considered by learner.",
                             row.get("explanation", "")],
            ))
        lowered = chosen.lower()
        if any(word in lowered for word in ("carry", "move", "transport")):
            alternatives.extend([
                CriticAlternative(
                    "METHOD_SUBSTITUTION",
                    "satisfy the movement goal using a different transport method that reduces repeated travel",
                    0.55, 0.25, 0.20, 0.60, explanation=[
                        "The goal specifies a destination state, not a transport method."
                    ],
                ),
                CriticAlternative(
                    "BATCH_OR_PARALLELIZE",
                    "move multiple items in one batch or in parallel instead of serial trips",
                    0.65, 0.20, 0.20, 0.70, explanation=[
                        "Serial execution may be an unnecessary constraint."
                    ],
                ),
            ])
        if any(item.necessary is None for item in assumptions):
            alternatives.append(CriticAlternative(
                "VERIFY_ASSUMPTION",
                "test the uncertain assumption before committing to the current method",
                0.50, 0.10, 0.15, 0.90, 0.90,
                ["Low-cost verification may improve later choice quality."],
            ))
        alternatives.append(CriticAlternative(
            "GOAL_METHOD_SEPARATION",
            "restate the goal without the current method, then generate at least three different methods that satisfy the same end state",
            0.60, 0.05, 0.10, 1.00, 0.80,
            ["Separating outcome from implementation expands the search space."],
        ))
        unique = {}
        for alternative in alternatives:
            unique.setdefault(alternative.description.casefold(), alternative)
        return list(unique.values())

    def _select_preferred_alternative(
        self, alternatives: List[CriticAlternative],
    ) -> Optional[CriticAlternative]:
        return max(alternatives, key=lambda item: (
            item.predicted_utility - 0.35 * item.risk - 0.20 * item.cost
            + 0.15 * item.reversibility + 0.20 * item.information_gain
        ), default=None)

    def _explain_preference(
        self, preferred: Optional[CriticAlternative], challenged: List[str],
    ) -> List[str]:
        if preferred is None:
            return ["No superior alternative was identified."]
        reasons = [reason for reason in preferred.explanation if reason]
        if challenged:
            reasons.append("The alternative avoids or tests an unnecessary assumption.")
        reasons.append("Critic score includes utility, risk, cost, reversibility, and information gain.")
        return reasons

    def _generalize_principle(
        self, preferred: Optional[CriticAlternative], challenged: List[str],
    ) -> Optional[str]:
        if preferred is None:
            return None
        principles = {
            "GOAL_METHOD_SEPARATION": "Do not confuse the desired end state with the conventional method used to reach it. Restate the goal independently, then generate multiple implementation strategies.",
            "BATCH_OR_PARALLELIZE": "When repeated setup or travel dominates cost, test whether serial subtasks can be batched or parallelized.",
            "VERIFY_ASSUMPTION": "When a decision depends on an unresolved assumption and verification is cheap, gather information before committing.",
            "METHOD_SUBSTITUTION": "If the objective constrains the result but not the mechanism, search for alternative mechanisms with lower time, energy, or repetition cost.",
        }
        if preferred.name.upper() in principles:
            return principles[preferred.name.upper()]
        if challenged:
            return "Before committing, separate true requirements from inherited assumptions."
        return "Generate structurally different alternatives before finalizing a choice."

    def create_transferable_operator(
        self, critique: Critique,
    ) -> Optional[TransferableOperator]:
        if not critique.generalized_principle:
            return None
        text = critique.generalized_principle.lower()
        transformation = "generate_alternative_methods"
        if "end state" in text or "conventional method" in text:
            transformation = "separate_goal_from_method"
        elif "batched" in text or "parallelized" in text:
            transformation = "test_batch_or_parallel_execution"
        elif "verification" in text or "gather information" in text:
            transformation = "add_verify_before_commit_branch"
        elif "assumptions" in text:
            transformation = "challenge_hidden_assumptions"
        operator = TransferableOperator(
            id=str(uuid.uuid4()), name=f"SOCRATES:{transformation}",
            trigger_conditions=self._operator_trigger_conditions(transformation),
            transformation=transformation, principle=critique.generalized_principle,
            source_agent=self.critic_name,
            source_episode_id=critique.learner_episode_id,
            confidence=critique.confidence,
        )
        return self._store_operator(operator)

    def _operator_trigger_conditions(self, transformation: str) -> Dict[str, Any]:
        return {
            "separate_goal_from_method": {
                "goal_present": True, "single_method_dominates_reasoning": True,
            },
            "test_batch_or_parallel_execution": {
                "repeated_subtasks": True, "serial_execution": True,
            },
            "add_verify_before_commit_branch": {
                "uncertainty": "high", "verification_cost": "low_or_moderate",
            },
            "challenge_hidden_assumptions": {"assumption_count": ">=1"},
        }.get(transformation, {"novel_problem": True})

    def transfer_operator(
        self, operator: TransferableOperator, learner_agent: Optional[str] = None,
        learner_acceptance_threshold: float = 0.55,
    ) -> TransferResult:
        accepted = operator.active and operator.confidence >= learner_acceptance_threshold
        relation = "meets" if accepted else "does not meet"
        result = TransferResult(
            operator.id, learner_agent or self.learner_name, accepted,
            f"Operator confidence {operator.confidence:.2f} {relation} learner acceptance threshold {learner_acceptance_threshold:.2f}.",
        )
        self.transfers.append(result)
        self.save()
        return result

    def apply_operator(
        self, operator: TransferableOperator, goal: str, proposed_action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        if not operator.active:
            return []
        prompts = {
            "separate_goal_from_method": [
                f"Restate the goal without naming the current method: {goal}",
                "Generate at least three different mechanisms that satisfy the same end state.",
                f"Ask whether '{proposed_action}' is required or merely familiar.",
            ],
            "test_batch_or_parallel_execution": [
                "Identify repeated serial subtasks.", "Test whether they can be batched.",
                "Test whether independent subtasks can run in parallel.",
                "Compare total setup/travel cost before and after batching.",
            ],
            "add_verify_before_commit_branch": [
                "Identify the assumption with the highest consequence if wrong.",
                "Estimate the cost of checking that assumption.",
                "If verification is cheap relative to failure cost, add VERIFY -> ACT.",
            ],
            "challenge_hidden_assumptions": [
                f"List every constraint implied by '{proposed_action}'.",
                "Mark each constraint as REQUIRED, ASSUMED, or UNKNOWN.",
                "Generate alternatives that remove at least one ASSUMED constraint.",
            ],
        }
        return prompts.get(operator.transformation, [
            "Generate at least one structurally different alternative before committing."
        ])

    def operator_to_ndw_actions(
        self, operator: TransferableOperator, goal: str, proposed_action: str,
    ) -> List[Any]:
        try:
            from modules.narrative_decision_weave import Action
        except ImportError:
            return []
        return [Action(
            name=f"SOCRATES_{index}", description=prompt,
            tags=["metacognition", "alternative", operator.transformation],
            cost=0.08, risk=0.05, reward_hint=0.12,
        ) for index, prompt in enumerate(
            self.apply_operator(operator, goal, proposed_action), start=1
        )]

    def record_operator_result(
        self, operator_id: str, improved_outcome: bool, outcome_delta: float = 0.0,
    ) -> None:
        operator = self.find_operator(operator_id)
        if operator is None:
            raise KeyError(f"No SOCRATES operator {operator_id}")
        operator.support_count += 1
        if improved_outcome:
            operator.success_count += 1
            operator.confidence = min(
                0.99, operator.confidence + 0.04
                + min(0.05, max(0.0, outcome_delta) * 0.02)
            )
        else:
            operator.failure_count += 1
            operator.confidence = max(0.05, operator.confidence - 0.05)
        if operator.failure_count >= 3 and operator.failure_count > operator.success_count * 2:
            operator.active = False
        self.save()

    def internalize_operator(
        self, operator_id: str, mirror: Optional[Any] = None,
    ) -> Dict[str, Any]:
        operator = self.find_operator(operator_id)
        if operator is None:
            raise KeyError(f"No SOCRATES operator {operator_id}")
        rule = {
            "id": str(uuid.uuid4()), "source_operator_id": operator.id,
            "source": "internalized_from_cross_agent_critique",
            "trigger": operator.trigger_conditions,
            "recommended_transformation": operator.transformation,
            "principle": operator.principle, "confidence": operator.confidence,
            "support_count": operator.support_count,
        }
        if mirror is not None and hasattr(mirror, "learned_rules"):
            if hasattr(mirror, "_store_learned_rule"):
                mirror._store_learned_rule(rule)
            else:
                mirror.learned_rules.append(rule)
            if hasattr(mirror, "save"):
                mirror.save()
        return rule

    def find_operator(self, operator_id: str) -> Optional[TransferableOperator]:
        return next((item for item in self.operators if item.id == operator_id), None)

    def is_operator_accepted(self, operator_id: str) -> bool:
        """Return the latest learner acceptance decision for an operator."""
        transfer = next((item for item in reversed(self.transfers)
                         if item.operator_id == operator_id), None)
        return bool(transfer and transfer.accepted)

    def summarize_social_learning(self) -> Dict[str, Any]:
        return {
            "critic": self.critic_name, "learner": self.learner_name,
            "critiques": len(self.critiques), "operators": len(self.operators),
            "transfers": len(self.transfers),
            "accepted_transfers": sum(item.accepted for item in self.transfers),
            "active_operators": sum(item.active for item in self.operators),
            "operators_by_confidence": sorted([{
                "id": item.id, "name": item.name,
                "confidence": round(item.confidence, 3),
                "successes": item.success_count, "failures": item.failure_count,
                "active": item.active,
            } for item in self.operators], key=lambda item: item["confidence"], reverse=True),
        }

    def _store_operator(self, operator: TransferableOperator) -> TransferableOperator:
        signature = (operator.transformation,
                     json.dumps(operator.trigger_conditions, sort_keys=True),
                     operator.principle.casefold())
        for existing in self.operators:
            other = (existing.transformation,
                     json.dumps(existing.trigger_conditions, sort_keys=True),
                     existing.principle.casefold())
            if signature == other:
                existing.support_count += 1
                existing.confidence = min(0.99, existing.confidence + 0.03)
                self.save()
                return existing
        self.operators.append(operator)
        self.save()
        return operator

    def save(self) -> None:
        self._write_json(self.critique_path, [asdict(item) for item in self.critiques])
        self._write_json(self.operator_path, [asdict(item) for item in self.operators])
        self._write_json(self.transfer_path, [asdict(item) for item in self.transfers])

    def load(self) -> None:
        raw_critiques = self._read_json(self.critique_path, [])
        try:
            self.critiques = [Critique(
                id=item["id"], learner_episode_id=item["learner_episode_id"],
                goal=item["goal"], learner_choice=item["learner_choice"],
                learner_reasoning=item.get("learner_reasoning", ""),
                detected_assumptions=[ReasoningAssumption(**value)
                                      for value in item.get("detected_assumptions", [])],
                challenged_assumptions=item.get("challenged_assumptions", []),
                alternatives=[CriticAlternative(**value)
                              for value in item.get("alternatives", [])],
                preferred_alternative=item.get("preferred_alternative"),
                why_preferred=item.get("why_preferred", []),
                generalized_principle=item.get("generalized_principle"),
                confidence=item.get("confidence", 0.5),
                created_at=item.get("created_at", time.time()),
            ) for item in raw_critiques]
        except (KeyError, TypeError, ValueError):
            self.critiques = []
        try:
            self.operators = [TransferableOperator(**item)
                              for item in self._read_json(self.operator_path, [])]
            self.transfers = [TransferResult(**item)
                              for item in self._read_json(self.transfer_path, [])]
        except (TypeError, ValueError):
            self.operators, self.transfers = [], []

    def _read_json(self, path: Path, default: Any) -> Any:
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return default

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(path)
