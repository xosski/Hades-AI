"""Post-decision causal analysis and learning for Narrative Decision Weave."""
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


def text_overlap(a: str, b: str) -> float:
    words_a, words_b = set(tokenize(a)), set(tokenize(b))
    return len(words_a & words_b) / len(words_a | words_b) if words_a and words_b else 0.0


def clamp(value: float, low: float = -1.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


@dataclass
class ExpectedOutcome:
    action: str
    predicted_utility: float
    predicted_effects: Dict[str, float] = field(default_factory=dict)
    expected_state: str = ""
    confidence: float = 0.5
    assumptions: List[str] = field(default_factory=list)
    retrieved_patterns: List[str] = field(default_factory=list)


@dataclass
class ObservedOutcome:
    result_summary: str
    utility: float
    effects: Dict[str, float] = field(default_factory=dict)
    circumstances: Dict[str, Any] = field(default_factory=dict)
    external_events: List[str] = field(default_factory=list)
    newly_revealed_information: List[str] = field(default_factory=list)
    execution_quality: float = 1.0
    notes: str = ""


@dataclass
class CausalFactor:
    name: str
    category: str
    direction: str
    magnitude: float
    controllability: float
    evidence: str


@dataclass
class OutcomeAnalysis:
    id: str
    episode_id: str
    expected: ExpectedOutcome
    observed: ObservedOutcome
    prediction_error: float
    outcome_class: str
    primary_reason: str
    causal_factors: List[CausalFactor]
    decision_quality: float
    execution_quality: float
    circumstance_score: float
    model_error_score: float
    counterfactuals: List[str]
    lessons: List[str]
    proposed_operator: Optional[Dict[str, Any]]
    created_at: float = field(default_factory=time.time)


class NDWOutcomeReasoner:
    """Separate decision, execution, circumstance, and model quality after acting."""

    def __init__(self, history_path: str = "ndw_outcome_history.json",
                 learned_operators_path: str = "ndw_learned_operators.json"):
        self.history_path = Path(history_path)
        self.learned_operators_path = Path(learned_operators_path)
        self.history: List[OutcomeAnalysis] = []
        self.learned_operators: List[Dict[str, Any]] = []
        self.load()

    def analyze(self, episode_id: str, expected: ExpectedOutcome,
                observed: ObservedOutcome) -> OutcomeAnalysis:
        prediction_error = observed.utility - expected.predicted_utility
        factors = self._identify_causal_factors(expected, observed)
        circumstance_score = self._circumstance_score(factors)
        model_error_score = self._model_error_score(expected, observed, factors)
        decision_quality = self._decision_quality(expected, factors)
        outcome_class = self._classify(
            expected, observed, decision_quality, circumstance_score, model_error_score
        )
        operator = self._propose_operator(outcome_class, factors)
        analysis = OutcomeAnalysis(
            id=str(uuid.uuid4()), episode_id=episode_id, expected=expected,
            observed=observed, prediction_error=prediction_error,
            outcome_class=outcome_class,
            primary_reason=self._primary_reason(outcome_class, factors),
            causal_factors=factors, decision_quality=decision_quality,
            execution_quality=observed.execution_quality,
            circumstance_score=circumstance_score,
            model_error_score=model_error_score,
            counterfactuals=self._counterfactuals(factors),
            lessons=self._lessons(outcome_class, factors),
            proposed_operator=operator,
        )
        self.history.append(analysis)
        if operator:
            self._store_operator(operator)
        self.save()
        return analysis

    def _identify_causal_factors(self, expected: ExpectedOutcome,
                                 observed: ObservedOutcome) -> List[CausalFactor]:
        factors: List[CausalFactor] = []
        if observed.execution_quality < 0.8:
            factors.append(CausalFactor(
                "execution_failure", "execution", "hurt",
                1.0 - observed.execution_quality, 0.9,
                f"Execution quality={observed.execution_quality:.2f}",
            ))
        for event in observed.external_events:
            factors.append(CausalFactor(
                self._slug(event), "external_event",
                "hurt" if observed.utility < expected.predicted_utility else "neutral",
                min(1.0, 0.55 + abs(expected.predicted_utility - observed.utility) * 0.15),
                0.1, event,
            ))
        for information in observed.newly_revealed_information:
            factors.append(CausalFactor(
                self._slug(information), "hidden_information",
                "hurt" if observed.utility < expected.predicted_utility else "helped",
                0.65, 0.25, information,
            ))
        for key, value in observed.circumstances.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                direction = "helped" if value > 0 else "hurt" if value < 0 else "neutral"
                factors.append(CausalFactor(
                    str(key), "circumstance", direction,
                    min(1.0, abs(float(value))), 0.3, f"{key}={value}",
                ))
            elif bool(value):
                factors.append(CausalFactor(
                    str(key), "circumstance",
                    "hurt" if observed.utility < expected.predicted_utility else "neutral",
                    0.5, 0.3, f"{key}={value}",
                ))
        for key in set(expected.predicted_effects) | set(observed.effects):
            predicted = float(expected.predicted_effects.get(key, 0.0))
            actual = float(observed.effects.get(key, 0.0))
            delta = actual - predicted
            if abs(delta) >= 0.25:
                factors.append(CausalFactor(
                    f"effect_mismatch_{key}", "prediction_error",
                    "hurt" if delta < 0 else "helped", min(1.0, abs(delta)), 0.5,
                    f"Expected {key}={predicted:+.2f}, observed {key}={actual:+.2f}",
                ))
        evidence = (observed.external_events + observed.newly_revealed_information
                    + [observed.result_summary])
        for assumption in expected.assumptions:
            if observed.utility < expected.predicted_utility and any(
                text_overlap(assumption, item) > 0.15 for item in evidence
            ):
                factors.append(CausalFactor(
                    f"assumption_failed_{self._slug(assumption)}", "assumption_failure",
                    "hurt", 0.7, 0.4, f"Assumption may have failed: {assumption}",
                ))
        if not factors:
            factors.append(CausalFactor(
                "unresolved_variance", "unknown",
                "hurt" if observed.utility < expected.predicted_utility else "helped",
                min(1.0, abs(observed.utility - expected.predicted_utility)), 0.0,
                "No explicit causal factor supplied",
            ))
        return factors

    def _circumstance_score(self, factors: List[CausalFactor]) -> float:
        values = [
            (-1.0 if f.direction == "hurt" else 1.0) * f.magnitude * (1.0 - f.controllability)
            for f in factors
            if f.category in {"external_event", "circumstance", "hidden_information"}
        ]
        return 0.0 if not values else clamp(sum(values) / len(values))

    def _model_error_score(self, expected: ExpectedOutcome, observed: ObservedOutcome,
                           factors: List[CausalFactor]) -> float:
        relevant = [f for f in factors if f.category in {"prediction_error", "assumption_failure"}]
        bonus = sum(f.magnitude for f in relevant) / max(1, len(relevant))
        return clamp(abs(observed.utility - expected.predicted_utility) * 0.6 + bonus * 0.4,
                     0.0, 1.0)

    def _decision_quality(self, expected: ExpectedOutcome,
                          factors: List[CausalFactor]) -> float:
        quality = (clamp(expected.predicted_utility) + 1.0) / 2.0
        quality += (expected.confidence - 0.5) * 0.15
        external_harm = sum(
            f.magnitude * (1.0 - f.controllability) for f in factors
            if f.direction == "hurt"
            and f.category in {"external_event", "hidden_information", "circumstance"}
        )
        quality += min(0.2, external_harm * 0.08)
        failures = sum(f.magnitude for f in factors if f.category == "assumption_failure")
        quality -= min(0.25, failures * 0.10)
        return clamp(quality, 0.0, 1.0)

    def _classify(self, expected: ExpectedOutcome, observed: ObservedOutcome,
                  decision_quality: float, circumstance_score: float,
                  model_error_score: float) -> str:
        predicted_good = expected.predicted_utility > 0
        actual_good = observed.utility > 0
        if predicted_good and actual_good:
            return ("GOOD_DECISION_GOOD_OUTCOME" if observed.utility >= expected.predicted_utility
                    else "GOOD_DECISION_WEAKER_THAN_EXPECTED")
        if predicted_good and not actual_good:
            if observed.execution_quality < 0.65:
                return "GOOD_INTENT_BAD_EXECUTION"
            if circumstance_score < -0.25 and decision_quality >= 0.55:
                return "GOOD_DECISION_BAD_CIRCUMSTANCE"
            if model_error_score >= 0.55:
                return "GOOD_INTENT_BAD_MODEL"
            return "GOOD_EXPECTATION_BAD_OUTCOME_UNRESOLVED"
        return "BAD_EXPECTATION_GOOD_OUTCOME" if actual_good else "BAD_DECISION_BAD_OUTCOME"

    def _primary_reason(self, outcome_class: str, factors: List[CausalFactor]) -> str:
        harmful = sorted((f for f in factors if f.direction == "hurt"),
                         key=lambda f: f.magnitude, reverse=True)
        strongest = harmful[0] if harmful else factors[0]
        descriptions = {
            "GOOD_DECISION_BAD_CIRCUMSTANCE": "The choice was reasonable given the available information, but outside or hidden circumstances changed the result.",
            "GOOD_INTENT_BAD_EXECUTION": "The choice may have been reasonable, but it was not executed reliably.",
            "GOOD_INTENT_BAD_MODEL": "The prediction model overestimated the action or relied on a failed assumption.",
            "GOOD_EXPECTATION_BAD_OUTCOME_UNRESOLVED": "The positive expectation failed, but no single cause is proven yet.",
            "GOOD_DECISION_GOOD_OUTCOME": "The choice and outcome were both positive.",
            "GOOD_DECISION_WEAKER_THAN_EXPECTED": "The choice remained positive but underperformed its prediction.",
            "BAD_EXPECTATION_GOOD_OUTCOME": "The model predicted poorly, but the actual outcome was positive.",
            "BAD_DECISION_BAD_OUTCOME": "The choice was predicted poorly and produced a negative outcome.",
        }
        base = descriptions.get(outcome_class, "Outcome needs further analysis.")
        return (f"{base} Strongest factor: {strongest.name} "
                f"[{strongest.category}, magnitude={strongest.magnitude:.2f}]. "
                f"Evidence: {strongest.evidence}")

    def _counterfactuals(self, factors: List[CausalFactor]) -> List[str]:
        answers = []
        for factor in sorted(factors, key=lambda f: f.magnitude, reverse=True):
            if factor.direction != "hurt":
                continue
            if factor.controllability < 0.3:
                answers.append(f"If '{factor.name}' had not occurred, the original choice may have remained favorable.")
            elif factor.category == "execution":
                answers.append("If the same choice had been executed closer to plan, the result might have differed materially.")
            elif factor.category in {"assumption_failure", "prediction_error"}:
                answers.append(f"If '{factor.name}' had been known before acting, confidence should have been reduced or another branch considered.")
            else:
                answers.append(f"Future decisions should explicitly test for '{factor.name}' before committing.")
        return answers[:5] or ["Insufficient evidence for a strong counterfactual."]

    def _lessons(self, outcome_class: str, factors: List[CausalFactor]) -> List[str]:
        by_class = {
            "GOOD_DECISION_BAD_CIRCUMSTANCE": ["Do not equate a bad result with a bad decision.", "Preserve fallback options when external uncertainty is high."],
            "GOOD_INTENT_BAD_EXECUTION": ["Score execution capability separately from action desirability.", "Down-weight choices that require execution reliability the system does not have."],
            "GOOD_INTENT_BAD_MODEL": ["Recalibrate the consequence model and explicitly verify assumptions."],
            "BAD_EXPECTATION_GOOD_OUTCOME": ["The prediction model may be too pessimistic for this class of situation."],
            "GOOD_DECISION_GOOD_OUTCOME": ["Increase confidence only modestly; one success is evidence, not universal proof."],
        }
        lessons = list(by_class.get(outcome_class, []))
        templates = {
            "hidden_information": "Seek information about '{}' before similar future decisions.",
            "external_event": "Add a contingency branch for '{}'.",
            "assumption_failure": "Require explicit verification of '{}'.",
            "prediction_error": "Recalibrate '{}' in future consequence estimates.",
        }
        for factor in sorted(factors, key=lambda f: f.magnitude, reverse=True)[:4]:
            if factor.category in templates:
                lessons.append(templates[factor.category].format(factor.name))
        deduplicated = []
        for lesson in lessons:
            if lesson.lower() not in {item.lower() for item in deduplicated}:
                deduplicated.append(lesson)
        return deduplicated

    def _propose_operator(self, outcome_class: str,
                          factors: List[CausalFactor]) -> Optional[Dict[str, Any]]:
        harmful = [f for f in factors if f.direction == "hurt" and f.magnitude >= 0.5]
        if not harmful:
            return None
        factor = max(harmful, key=lambda f: f.magnitude)
        transformation = {
            "hidden_information": "add_observe_or_verify_branch",
            "external_event": "add_fallback_branch",
            "execution": "downweight_action_or_add_preparation_step",
            "assumption_failure": "lower_confidence_until_verified",
            "prediction_error": "recalibrate_expected_effect",
        }.get(factor.category)
        if not transformation:
            return None
        return {
            "id": str(uuid.uuid4()), "name": f"Learned rule for {factor.name}",
            "trigger_factor": factor.name, "transformation": transformation,
            "reason": factor.evidence, "source_outcome_class": outcome_class,
            "weight": round(factor.magnitude, 3),
        }

    def analyze_ndw_result(self, ndw_result: Dict[str, Any], observed: ObservedOutcome,
                           predicted_effects: Optional[Dict[str, float]] = None,
                           assumptions: Optional[List[str]] = None) -> OutcomeAnalysis:
        retrieved = ndw_result.get("retrieved_patterns", [])
        similarities = [float(item.get("similarity", 0)) for item in retrieved]
        confidence = (0.4 if not similarities else
                      min(0.95, 0.4 + (sum(similarities) / len(similarities)) * 0.5))
        expected = ExpectedOutcome(
            action=ndw_result["selected_action"]["description"],
            predicted_utility=float(ndw_result["predicted_utility"]),
            predicted_effects=predicted_effects or {}, confidence=confidence,
            assumptions=assumptions or [],
            retrieved_patterns=[item.get("source", "") for item in retrieved],
        )
        return self.analyze(ndw_result["episode_id"], expected, observed)

    def feed_back_to_ndw(self, ndw: Any, analysis: OutcomeAnalysis) -> None:
        ndw.record_outcome(analysis.episode_id, actual_utility=analysis.observed.utility)

    def summarize_learning(self) -> Dict[str, Any]:
        if not self.history:
            return {"episodes": 0}
        classes: Dict[str, int] = {}
        factors: Dict[str, int] = {}
        damage: Dict[str, float] = {}
        for analysis in self.history:
            classes[analysis.outcome_class] = classes.get(analysis.outcome_class, 0) + 1
            for factor in analysis.causal_factors:
                factors[factor.name] = factors.get(factor.name, 0) + 1
                if factor.direction == "hurt":
                    damage[factor.name] = damage.get(factor.name, 0.0) + factor.magnitude
        return {
            "episodes": len(self.history),
            "mean_absolute_prediction_error": round(
                sum(abs(item.prediction_error) for item in self.history) / len(self.history), 4
            ),
            "outcome_classes": classes,
            "most_recurring_factors": sorted(factors.items(), key=lambda x: x[1], reverse=True)[:10],
            "most_damaging_factors": sorted(damage.items(), key=lambda x: x[1], reverse=True)[:10],
            "learned_operator_count": len(self.learned_operators),
        }

    def save(self) -> None:
        self._write_json(self.history_path, [asdict(item) for item in self.history])
        self._write_json(self.learned_operators_path, self.learned_operators)

    def load(self) -> None:
        if self.learned_operators_path.exists():
            try:
                self.learned_operators = json.loads(self.learned_operators_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                self.learned_operators = []
        if self.history_path.exists():
            try:
                raw = json.loads(self.history_path.read_text(encoding="utf-8"))
                self.history = [OutcomeAnalysis(
                    id=item["id"], episode_id=item["episode_id"],
                    expected=ExpectedOutcome(**item["expected"]),
                    observed=ObservedOutcome(**item["observed"]),
                    prediction_error=item["prediction_error"], outcome_class=item["outcome_class"],
                    primary_reason=item["primary_reason"],
                    causal_factors=[CausalFactor(**factor) for factor in item["causal_factors"]],
                    decision_quality=item["decision_quality"], execution_quality=item["execution_quality"],
                    circumstance_score=item["circumstance_score"], model_error_score=item["model_error_score"],
                    counterfactuals=item["counterfactuals"], lessons=item["lessons"],
                    proposed_operator=item.get("proposed_operator"),
                    created_at=item.get("created_at", time.time()),
                ) for item in raw]
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                self.history = []

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(path)

    def _store_operator(self, operator: Dict[str, Any]) -> None:
        signature = (operator["name"], operator["transformation"], operator["reason"])
        for existing in self.learned_operators:
            if signature == (existing["name"], existing["transformation"], existing["reason"]):
                existing["weight"] = round(min(1.0, existing.get("weight", 0.5) + 0.05), 3)
                return
        self.learned_operators.append(operator)

    def _slug(self, text: str) -> str:
        return "_".join(tokenize(text)[:8]) or "unnamed_factor"
