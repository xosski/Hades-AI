"""MIRROR metacognitive introspection and regret reconciliation for NDW."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid


@dataclass
class ChoiceReason:
    factor: str
    value: float
    weight: float
    contribution: float
    explanation: str


@dataclass
class AlternativeDecision:
    action_name: str
    action_description: str
    predicted_utility: float
    reasons_for: List[str] = field(default_factory=list)
    reasons_against: List[str] = field(default_factory=list)
    counterfactual_utility: Optional[float] = None
    counterfactual_confidence: float = 0.0
    counterfactual_reasoning: List[str] = field(default_factory=list)


@dataclass
class DecisionIntrospection:
    id: str
    episode_id: str
    chosen_action: str
    chosen_description: str
    chosen_predicted_utility: float
    chosen_reasons: List[ChoiceReason]
    alternatives: List[AlternativeDecision]
    selected_because: List[str]
    rejected_alternatives_because: Dict[str, List[str]]
    state_summary: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class RegretAnalysis:
    id: str
    episode_id: str
    chosen_action: str
    actual_utility: float
    best_counterfactual_action: Optional[str]
    best_counterfactual_utility: Optional[float]
    regret: float
    hindsight_advantage: float
    decision_was_reasonable_at_time: bool
    outcome_cause: str
    reasoning_error: Optional[str]
    weight_updates: Dict[str, float]
    learned_rule: Optional[Dict[str, Any]]
    explanation: str
    created_at: float = field(default_factory=time.time)


class MIRROR:
    """Explain NDW choices, review roads not taken, and learn bounded weights."""

    DEFAULT_WEIGHTS = {
        "goal_progress": 1.00, "safety": 0.85, "helpfulness": 0.55,
        "knowledge": 0.45, "resource_gain": 0.40, "time_saved": 0.30,
        "reversibility": 0.50, "information_gain": 0.60, "confidence": 0.40,
        "damage": -1.00, "risk": -0.75, "resource_loss": -0.45,
        "time_cost": -0.30, "uncertainty": -0.50, "irreversibility": -0.65,
    }

    def __init__(
        self, introspection_path: str = "mirror_introspection.json",
        regret_path: str = "mirror_regret.json",
        reasoning_weights_path: str = "mirror_reasoning_weights.json",
        learned_rules_path: str = "mirror_learned_rules.json",
    ):
        self.introspection_path = Path(introspection_path)
        self.regret_path = Path(regret_path)
        self.reasoning_weights_path = Path(reasoning_weights_path)
        self.learned_rules_path = Path(learned_rules_path)
        self.introspections: List[DecisionIntrospection] = []
        self.regret_history: List[RegretAnalysis] = []
        self.learned_rules: List[Dict[str, Any]] = []
        self.reasoning_weights = dict(self.DEFAULT_WEIGHTS)
        self.load()

    def introspect_decision(
        self, ndw_result: Dict[str, Any], state_summary: str = "",
        factor_map: Optional[Dict[str, Dict[str, float]]] = None,
    ) -> DecisionIntrospection:
        ranked = ndw_result.get("ranked_actions", [])
        selected = ndw_result["selected_action"]
        chosen_desc = selected["description"]
        chosen_predicted = float(ndw_result["predicted_utility"])
        factors = factor_map or {}
        chosen_reasons = self._build_choice_reasons(
            chosen_desc, factors, self._ranked_explanation(ranked, chosen_desc)
        )
        alternatives = []
        rejected = {}
        for row in ranked:
            action = row["action"]
            description = action["description"]
            if description == chosen_desc:
                continue
            predicted = float(row["score"])
            reasons_for, reasons_against = self._compare_actions(
                chosen_desc, description, chosen_predicted, predicted, factors
            )
            alternatives.append(AlternativeDecision(
                action_name=action.get("name", description),
                action_description=description, predicted_utility=predicted,
                reasons_for=reasons_for, reasons_against=reasons_against,
            ))
            rejected[description] = reasons_against or [
                f"Predicted utility {predicted:.3f} was below the chosen action's {chosen_predicted:.3f}."
            ]
        selected_because = [
            f"Highest predicted utility among evaluated actions: {chosen_predicted:.3f}."
        ]
        strongest = sorted(chosen_reasons, key=lambda reason: abs(reason.contribution),
                           reverse=True)[:3]
        selected_because.extend(
            f"{reason.factor}: {reason.explanation}" for reason in strongest
        )
        record = DecisionIntrospection(
            id=str(uuid.uuid4()), episode_id=ndw_result["episode_id"],
            chosen_action=selected.get("name", chosen_desc),
            chosen_description=chosen_desc,
            chosen_predicted_utility=chosen_predicted,
            chosen_reasons=chosen_reasons, alternatives=alternatives,
            selected_because=selected_because,
            rejected_alternatives_because=rejected, state_summary=state_summary,
        )
        self.introspections.append(record)
        self.save()
        return record

    def review_outcome(
        self, episode_id: str, actual_utility: float,
        outcome_reasoner_analysis: Optional[Any] = None,
        alternative_outcomes: Optional[Dict[str, float]] = None,
        alternative_evidence: Optional[Dict[str, List[str]]] = None,
    ) -> RegretAnalysis:
        decision = self._find_introspection(episode_id)
        if decision is None:
            raise KeyError(f"No MIRROR introspection found for episode {episode_id}")
        supplied = alternative_outcomes or {}
        evidence = alternative_evidence or {}
        for alternative in decision.alternatives:
            if alternative.action_description in supplied:
                alternative.counterfactual_utility = float(supplied[alternative.action_description])
                alternative.counterfactual_confidence = 0.85
                alternative.counterfactual_reasoning = evidence.get(
                    alternative.action_description, ["Explicit counterfactual estimate supplied."]
                )
            else:
                estimate = self._estimate_counterfactual(
                    alternative, outcome_reasoner_analysis
                )
                alternative.counterfactual_utility = estimate[0]
                alternative.counterfactual_confidence = estimate[1]
                alternative.counterfactual_reasoning = estimate[2]
        best = max(
            decision.alternatives,
            key=lambda item: item.counterfactual_utility
            if item.counterfactual_utility is not None else -float("inf"),
            default=None,
        )
        best_utility = best.counterfactual_utility if best else None
        regret = max(0.0, best_utility - actual_utility) if best_utility is not None else 0.0
        reasonable = self._was_reasonable_at_time(decision, outcome_reasoner_analysis)
        cause = self._infer_outcome_cause(outcome_reasoner_analysis)
        reasoning_error = self._infer_reasoning_error(
            actual_utility, best, outcome_reasoner_analysis
        )
        updates = self._compute_weight_updates(
            actual_utility, best, outcome_reasoner_analysis
        )
        self._apply_weight_updates(updates)
        rule = self._derive_metacognitive_rule(
            decision, actual_utility, best, outcome_reasoner_analysis, reasonable
        )
        if rule:
            self._store_learned_rule(rule)
        review = RegretAnalysis(
            id=str(uuid.uuid4()), episode_id=episode_id,
            chosen_action=decision.chosen_description, actual_utility=actual_utility,
            best_counterfactual_action=best.action_description if best else None,
            best_counterfactual_utility=best_utility, regret=regret,
            hindsight_advantage=regret, decision_was_reasonable_at_time=reasonable,
            outcome_cause=cause, reasoning_error=reasoning_error,
            weight_updates=updates, learned_rule=rule,
            explanation=self._build_regret_explanation(
                decision, actual_utility, best, regret, reasonable, cause, reasoning_error
            ),
        )
        self.regret_history.append(review)
        self.save()
        return review

    def sync_weights_to_ndw(self, ndw: Any) -> None:
        """Apply learned weights only to dimensions already owned by NDW."""
        for factor in ndw.utility_weights:
            if factor in self.reasoning_weights:
                ndw.utility_weights[factor] = self.reasoning_weights[factor]

    def _build_choice_reasons(
        self, description: str, factor_map: Dict[str, Dict[str, float]],
        fallback: str,
    ) -> List[ChoiceReason]:
        reasons = []
        for factor, value in factor_map.get(description, {}).items():
            weight = self.reasoning_weights.get(factor, 0.0)
            contribution = float(value) * weight
            reasons.append(ChoiceReason(
                factor, float(value), weight, contribution,
                f"value={value:+.2f}, weight={weight:+.2f}, contribution={contribution:+.2f}",
            ))
        if not reasons and fallback:
            reasons.append(ChoiceReason("ndw_explanation", 1.0, 1.0, 1.0, fallback))
        return reasons

    def _compare_actions(
        self, chosen: str, alternative: str, chosen_score: float, alt_score: float,
        factor_map: Dict[str, Dict[str, float]],
    ) -> Tuple[List[str], List[str]]:
        reasons_for, reasons_against = [], []
        chosen_factors = factor_map.get(chosen, {})
        alt_factors = factor_map.get(alternative, {})
        for factor in set(chosen_factors) | set(alt_factors):
            weight = self.reasoning_weights.get(factor, 0.0)
            delta = (alt_factors.get(factor, 0.0) - chosen_factors.get(factor, 0.0)) * weight
            if delta > 0.10:
                reasons_for.append(f"Better on {factor} by {delta:+.2f} weighted utility.")
            elif delta < -0.10:
                reasons_against.append(f"Worse on {factor} by {abs(delta):.2f} weighted utility.")
        if alt_score < chosen_score:
            reasons_against.append(f"Overall predicted score lower by {chosen_score - alt_score:.3f}.")
        return reasons_for, reasons_against

    def _estimate_counterfactual(
        self, alternative: AlternativeDecision, analysis: Optional[Any],
    ) -> Tuple[float, float, List[str]]:
        estimate, confidence = alternative.predicted_utility, 0.35
        reasons = ["Estimate begins from original predicted utility; the action was not taken."]
        outcome_class = getattr(analysis, "outcome_class", "") if analysis else ""
        text = (alternative.action_description + " " + " ".join(
            alternative.reasons_for + alternative.reasons_against
        )).lower()
        information = any(word in text for word in ("inspect", "observe", "verify", "wait", "information"))
        if outcome_class == "GOOD_DECISION_BAD_CIRCUMSTANCE" and information:
            estimate, confidence = estimate + 0.20, confidence + 0.10
            reasons.append("Hidden circumstances mattered; information gathering receives a modest boost.")
        elif outcome_class == "GOOD_INTENT_BAD_EXECUTION" and information:
            estimate += 0.10
            reasons.append("Execution reliability favored a preparation-oriented alternative.")
        elif outcome_class == "GOOD_INTENT_BAD_MODEL":
            confidence -= 0.10
            reasons.append("Model error reduces counterfactual confidence.")
        return max(-1.0, min(1.0, estimate)), max(0.05, min(0.90, confidence)), reasons

    def _was_reasonable_at_time(
        self, decision: DecisionIntrospection, analysis: Optional[Any],
    ) -> bool:
        quality = getattr(analysis, "decision_quality", None) if analysis else None
        if quality is not None:
            return float(quality) >= 0.55
        return not decision.alternatives or decision.chosen_predicted_utility >= max(
            alternative.predicted_utility for alternative in decision.alternatives
        )

    def _infer_outcome_cause(self, analysis: Optional[Any]) -> str:
        outcome_class = getattr(analysis, "outcome_class", "UNKNOWN") if analysis else "UNKNOWN"
        return {
            "GOOD_DECISION_BAD_CIRCUMSTANCE": "EXTERNAL_CIRCUMSTANCE",
            "GOOD_INTENT_BAD_EXECUTION": "EXECUTION_FAILURE",
            "GOOD_INTENT_BAD_MODEL": "PREDICTION_MODEL_ERROR",
            "GOOD_EXPECTATION_BAD_OUTCOME_UNRESOLVED": "UNRESOLVED",
            "GOOD_DECISION_GOOD_OUTCOME": "EXPECTED_SUCCESS",
            "GOOD_DECISION_WEAKER_THAN_EXPECTED": "PARTIAL_MODEL_ERROR",
            "BAD_EXPECTATION_GOOD_OUTCOME": "MODEL_TOO_PESSIMISTIC",
            "BAD_DECISION_BAD_OUTCOME": "DECISION_AND_OUTCOME_BAD",
        }.get(outcome_class, outcome_class)

    def _infer_reasoning_error(
        self, actual: float, best: Optional[AlternativeDecision], analysis: Optional[Any],
    ) -> Optional[str]:
        if not best or best.counterfactual_utility is None or best.counterfactual_utility <= actual:
            return None
        outcome_class = getattr(analysis, "outcome_class", "") if analysis else ""
        return {
            "GOOD_DECISION_BAD_CIRCUMSTANCE": "Insufficient contingency planning or value assigned to information gathering.",
            "GOOD_INTENT_BAD_EXECUTION": "Execution reliability was underweighted relative to expected benefit.",
            "GOOD_INTENT_BAD_MODEL": "The consequence model misestimated the action or its assumptions.",
        }.get(outcome_class, "An alternative now appears better, but the cause is uncertain.")

    def _compute_weight_updates(
        self, actual: float, best: Optional[AlternativeDecision], analysis: Optional[Any],
    ) -> Dict[str, float]:
        if not best or best.counterfactual_utility is None:
            return {}
        advantage = best.counterfactual_utility - actual
        if advantage <= 0.05:
            return {}
        learning_rate = min(0.10, advantage * 0.08)
        text = best.action_description.lower()
        updates = {}
        if any(word in text for word in ("inspect", "observe", "verify", "information", "learn")):
            updates.update(information_gain=learning_rate, uncertainty=-learning_rate * 0.5)
        if any(word in text for word in ("wait", "delay")):
            updates["time_cost"] = learning_rate * 0.35
        if any(word in text for word in ("safe", "protect", "avoid")):
            updates["safety"] = learning_rate
        outcome_class = getattr(analysis, "outcome_class", "") if analysis else ""
        if outcome_class == "GOOD_INTENT_BAD_EXECUTION":
            updates.update(confidence=-learning_rate * 0.5, risk=-learning_rate * 0.5)
        elif outcome_class == "GOOD_INTENT_BAD_MODEL":
            updates["confidence"] = -learning_rate
        return updates

    def _apply_weight_updates(self, updates: Dict[str, float]) -> None:
        for factor, delta in updates.items():
            self.reasoning_weights[factor] = max(
                -2.0, min(2.0, self.reasoning_weights.get(factor, 0.0) + delta)
            )

    def _derive_metacognitive_rule(
        self, decision: DecisionIntrospection, actual: float,
        best: Optional[AlternativeDecision], analysis: Optional[Any], reasonable: bool,
    ) -> Optional[Dict[str, Any]]:
        if not best or best.counterfactual_utility is None or best.counterfactual_utility <= actual + 0.05:
            return None
        text = best.action_description.lower()
        rule = {
            "id": str(uuid.uuid4()), "source_episode": decision.episode_id,
            "chosen_action": decision.chosen_description,
            "better_alternative": best.action_description,
            "decision_was_reasonable_at_time": reasonable,
            "outcome_class": getattr(analysis, "outcome_class", "") if analysis else "",
            "trigger": {"similar_state": decision.state_summary or "unknown"},
            "recommended_transformation": f"consider_alternative:{best.action_description}",
            "confidence": 0.55,
        }
        if any(word in text for word in ("inspect", "observe", "verify", "information")):
            rule.update(trigger={"uncertainty": "high", "verification_cost": "low_or_moderate"},
                        recommended_transformation="generate_observe_then_act_branch", confidence=0.70)
        elif any(word in text for word in ("wait", "delay")):
            rule.update(trigger={"decision_irreversible": True, "delay_cost": "acceptable"},
                        recommended_transformation="consider_delayed_commitment", confidence=0.65)
        return rule

    def _build_regret_explanation(
        self, decision: DecisionIntrospection, actual: float,
        best: Optional[AlternativeDecision], regret: float, reasonable: bool,
        cause: str, reasoning_error: Optional[str],
    ) -> str:
        lines = [
            f"Chosen action '{decision.chosen_description}' had predicted utility {decision.chosen_predicted_utility:.3f} and actual utility {actual:.3f}.",
            "The choice was " + ("reasonable" if reasonable else "not well justified") + " based on information available at decision time.",
        ]
        if best and best.counterfactual_utility is not None:
            lines.append(f"Best current counterfactual is '{best.action_description}' with estimated utility {best.counterfactual_utility:.3f}.")
            lines.append(f"Estimated regret={regret:.3f}. Counterfactual confidence={best.counterfactual_confidence:.2f}.")
        lines.append(f"Primary outcome cause: {cause}.")
        if reasoning_error:
            lines.append(f"Reasoning update: {reasoning_error}")
        return " ".join(lines)

    def summarize_metacognition(self) -> Dict[str, Any]:
        if not self.regret_history:
            return {"episodes_reviewed": 0, "message": "No MIRROR outcome reviews yet."}
        causes: Dict[str, int] = {}
        for review in self.regret_history:
            causes[review.outcome_cause] = causes.get(review.outcome_cause, 0) + 1
        return {
            "episodes_reviewed": len(self.regret_history),
            "mean_regret": round(sum(item.regret for item in self.regret_history) / len(self.regret_history), 4),
            "reasonable_decision_rate": round(sum(item.decision_was_reasonable_at_time for item in self.regret_history) / len(self.regret_history), 4),
            "outcome_causes": causes,
            "reasoning_weights": {key: round(value, 4) for key, value in self.reasoning_weights.items()},
            "learned_rule_count": len(self.learned_rules),
        }

    def _find_introspection(self, episode_id: str) -> Optional[DecisionIntrospection]:
        return next((item for item in reversed(self.introspections)
                     if item.episode_id == episode_id), None)

    def _ranked_explanation(self, ranked: List[Dict[str, Any]], description: str) -> str:
        return next((row.get("explanation", "") for row in ranked
                     if row["action"]["description"] == description), "")

    def _store_learned_rule(self, rule: Dict[str, Any]) -> None:
        signature = (json.dumps(rule.get("trigger", {}), sort_keys=True),
                     rule.get("recommended_transformation"))
        for existing in self.learned_rules:
            other = (json.dumps(existing.get("trigger", {}), sort_keys=True),
                     existing.get("recommended_transformation"))
            if signature == other:
                existing["confidence"] = min(0.99, float(existing.get("confidence", 0.5)) + 0.03)
                existing["support_count"] = int(existing.get("support_count", 1)) + 1
                return
        rule["support_count"] = 1
        self.learned_rules.append(rule)

    def save(self) -> None:
        self._write_json(self.introspection_path, [asdict(item) for item in self.introspections])
        self._write_json(self.regret_path, [asdict(item) for item in self.regret_history])
        self._write_json(self.reasoning_weights_path, self.reasoning_weights)
        self._write_json(self.learned_rules_path, self.learned_rules)

    def load(self) -> None:
        weights = self._read_json(self.reasoning_weights_path, {})
        if isinstance(weights, dict):
            self.reasoning_weights.update(weights)
        rules = self._read_json(self.learned_rules_path, [])
        self.learned_rules = rules if isinstance(rules, list) else []
        introspections = self._read_json(self.introspection_path, [])
        try:
            self.introspections = [DecisionIntrospection(
                id=item["id"], episode_id=item["episode_id"],
                chosen_action=item["chosen_action"],
                chosen_description=item["chosen_description"],
                chosen_predicted_utility=item["chosen_predicted_utility"],
                chosen_reasons=[ChoiceReason(**reason) for reason in item.get("chosen_reasons", [])],
                alternatives=[AlternativeDecision(**alternative) for alternative in item.get("alternatives", [])],
                selected_because=item.get("selected_because", []),
                rejected_alternatives_because=item.get("rejected_alternatives_because", {}),
                state_summary=item.get("state_summary", ""),
                created_at=item.get("created_at", time.time()),
            ) for item in introspections]
        except (KeyError, TypeError, ValueError):
            self.introspections = []
        regrets = self._read_json(self.regret_path, [])
        try:
            self.regret_history = [RegretAnalysis(**item) for item in regrets]
        except (TypeError, ValueError):
            self.regret_history = []

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


def run_mirror_cycle(
    mirror: MIRROR, ndw_result: Dict[str, Any], actual_utility: float,
    state_summary: str = "",
    factor_map: Optional[Dict[str, Dict[str, float]]] = None,
    outcome_reasoner_analysis: Optional[Any] = None,
    alternative_outcomes: Optional[Dict[str, float]] = None,
) -> Tuple[DecisionIntrospection, RegretAnalysis]:
    introspection = mirror.introspect_decision(ndw_result, state_summary, factor_map)
    regret = mirror.review_outcome(
        ndw_result["episode_id"], actual_utility, outcome_reasoner_analysis,
        alternative_outcomes,
    )
    return introspection, regret
