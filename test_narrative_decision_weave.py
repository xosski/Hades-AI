from HadesAI import HadesAI
from modules.mirror import MIRROR
from modules.narrative_decision_weave import Action, NarrativeDecisionWeave, WorldState
from modules.ndw_outcome_reasoner import (
    ExpectedOutcome, NDWOutcomeReasoner, ObservedOutcome,
)
from modules.socrates import SOCRATES


def _seed(weave):
    weave.ingest_choice_passage(
        source_label="GuardStory",
        passage="A guard confronts an unknown stranger or avoids conflict.",
        choice_a="confront the unknown stranger",
        choice_b="avoid the stranger",
        consequence_a="The confrontation creates danger.",
        consequence_b="The guard remains safe but learns nothing.",
        concepts=["confront", "avoid", "uncertain"],
    )


def test_weave_generates_alternatives_and_persists_feedback(tmp_path):
    memory_path = tmp_path / "ndw.json"
    weave = NarrativeDecisionWeave(str(memory_path))
    _seed(weave)

    state = WorldState(
        "An unknown service is blocking progress.",
        {"uncertain": True},
        ["learn about the service safely"],
    )
    supplied = [
        Action("PROBE", "confront the unknown service", ["confront", "uncertain"], risk=0.5),
        Action("SKIP", "avoid the service", ["avoid"], cost=0.2, risk=0.1),
    ]
    result = weave.decide(state, supplied)
    names = {row["action"]["name"] for row in result["ranked_actions"]}

    assert "WEAVE_NEGOTIATE" in names
    assert "WEAVE_OBSERVE" in names
    weave.record_outcome(result["episode_id"], 0.8)

    restored = NarrativeDecisionWeave(str(memory_path))
    assert len(restored.patterns) == 1
    assert len(restored.episodes) == 1
    assert restored.episodes[0].actual_utility == 0.8


def test_outcome_reasoner_separates_circumstance_and_persists_learning(tmp_path):
    history_path = tmp_path / "outcomes.json"
    operators_path = tmp_path / "operators.json"
    reasoner = NDWOutcomeReasoner(str(history_path), str(operators_path))
    analysis = reasoner.analyze(
        "episode-1",
        ExpectedOutcome(
            "attempt rescue", 0.7,
            predicted_effects={"safety": 0.5},
            assumptions=["the rescue route remains passable"],
        ),
        ObservedOutcome(
            "An unseen road collapse blocked the rescue route.", -0.6,
            effects={"safety": -0.8},
            circumstances={"road_collapse": -0.9},
            external_events=["An unseen road collapse blocked the rescue route."],
            newly_revealed_information=["The rescue route was not passable."],
            execution_quality=0.95,
        ),
    )

    assert analysis.outcome_class == "GOOD_DECISION_BAD_CIRCUMSTANCE"
    assert analysis.circumstance_score < 0
    assert analysis.proposed_operator["transformation"] == "recalibrate_expected_effect"
    restored = NDWOutcomeReasoner(str(history_path), str(operators_path))
    assert restored.history[0].episode_id == "episode-1"
    assert restored.summarize_learning()["learned_operator_count"] == 1


def test_mirror_explains_regret_persists_and_syncs_weights(tmp_path):
    paths = [str(tmp_path / name) for name in (
        "introspection.json", "regret.json", "weights.json", "rules.json",
    )]
    mirror = MIRROR(*paths)
    result = {
        "episode_id": "mirror-1",
        "selected_action": {"name": "ACT", "description": "act immediately"},
        "predicted_utility": 0.7,
        "ranked_actions": [
            {"action": {"name": "ACT", "description": "act immediately"},
             "score": 0.7, "explanation": "high goal progress"},
            {"action": {"name": "CHECK", "description": "inspect safely first"},
             "score": 0.5, "explanation": "higher information gain"},
        ],
    }
    introspection = mirror.introspect_decision(
        result, "route safety uncertain",
        {"act immediately": {"goal_progress": 0.9, "risk": 0.6}},
    )
    review = mirror.review_outcome(
        "mirror-1", -0.6,
        alternative_outcomes={"inspect safely first": 0.6},
    )

    assert introspection.selected_because
    assert review.regret == 1.2
    assert review.learned_rule["recommended_transformation"] == "generate_observe_then_act_branch"
    weave = NarrativeDecisionWeave(str(tmp_path / "weights-ndw.json"))
    mirror.sync_weights_to_ndw(weave)
    assert weave.utility_weights["safety"] > 0.85
    restored = MIRROR(*paths)
    assert restored.summarize_metacognition()["episodes_reviewed"] == 1


def test_socrates_transfers_tests_and_persists_reasoning_operator(tmp_path):
    paths = [str(tmp_path / name) for name in (
        "critiques.json", "operators.json", "transfers.json",
    )]
    socrates = SOCRATES("Critic", "Learner", *paths)
    result = {
        "episode_id": "social-1",
        "selected_action": {
            "name": "CARRY", "description": "carry boxes separately",
        },
        "predicted_utility": 0.5,
        "ranked_actions": [{
            "action": {
                "name": "CARRY", "description": "carry boxes separately",
                "risk": 0.05, "cost": 0.4,
            },
            "score": 0.5, "explanation": "known method",
        }],
    }
    critique = socrates.critique_decision(
        result, "move boxes to another room",
        explicit_assumptions=["boxes must be moved one at a time"],
        environment_facts={"one_at_a_time": False},
    )
    operator = socrates.create_transferable_operator(critique)
    transfer = socrates.transfer_operator(operator)

    assert critique.challenged_assumptions
    assert transfer.accepted is True
    assert socrates.is_operator_accepted(operator.id) is True
    assert socrates.apply_operator(operator, critique.goal, critique.learner_choice)
    assert socrates.operator_to_ndw_actions(operator, critique.goal, critique.learner_choice)
    socrates.record_operator_result(operator.id, True, 0.5)
    assert operator.success_count == 1
    restored = SOCRATES("Critic", "Learner", *paths)
    assert restored.summarize_social_learning()["accepted_transfers"] == 1
    assert restored.find_operator(operator.id).success_count == 1


def test_hades_facade_ingests_decides_analyzes_and_formats_context(tmp_path):
    ai = HadesAI.__new__(HadesAI)
    ai.narrative_weave = NarrativeDecisionWeave(str(tmp_path / "facade.json"))
    ai.narrative_outcome_reasoner = NDWOutcomeReasoner(
        str(tmp_path / "outcomes.json"), str(tmp_path / "operators.json")
    )
    ai.mirror = MIRROR(
        str(tmp_path / "introspection.json"), str(tmp_path / "regret.json"),
        str(tmp_path / "weights.json"), str(tmp_path / "rules.json"),
    )
    ai.socrates = SOCRATES(
        "Hades-Critic", "Hades-NDW",
        str(tmp_path / "critiques.json"),
        str(tmp_path / "social-operators.json"),
        str(tmp_path / "transfers.json"),
    )

    pattern = ai.ingest_narrative_choice(
        "MaintenanceStory",
        "A maintainer finds an unknown process and can inspect or ignore it.",
        "inspect the unknown process",
        "ignore the process",
        "The maintainer learns useful information.",
        "The maintainer remains safe but learns nothing.",
        ["observe", "avoid", "uncertain"],
    )
    assert pattern["source_label"] == "MaintenanceStory"

    result = ai.decide_with_narrative(
        "An unknown process needs investigation.",
        [
            {"name": "INSPECT", "description": "inspect the process", "tags": ["observe", "uncertain"], "risk": 0.1},
            {"name": "IGNORE", "description": "ignore the process", "tags": ["avoid"], "risk": 0.05},
        ],
        goals=["learn about the process safely"],
        factor_map={
            "inspect the process": {"knowledge": 0.9, "safety": 0.8},
            "ignore the process": {"knowledge": 0.0, "safety": 0.6},
        },
    )
    assert result["episode_id"]
    assert result["ranked_actions"]
    assert result["socrates_critique"]["generalized_principle"]
    assert result["socrates_transfer"]["accepted"] is True
    assert ai.apply_socrates_operator(
        result["socrates_operator"]["id"],
        "learn about the process", result["selected_action"]["description"],
    )
    assert "MaintenanceStory" in ai.get_narrative_context("inspect an unknown process")

    recorded = ai.record_narrative_outcome(
        result["episode_id"], -0.5,
        result_summary="A service outage interrupted the inspection.",
        external_events=["A service outage interrupted the inspection."],
        execution_quality=0.9,
        assumptions=["the service remains available"],
        alternative_outcomes={
            row["action"]["description"]: 0.8
            for row in result["ranked_actions"]
            if row["action"]["description"] != result["selected_action"]["description"]
        },
    )
    assert recorded["recorded"] is True
    assert recorded["analysis"]["causal_factors"]
    assert recorded["regret_analysis"]["regret"] > 0
    assert result["mirror_introspection"]["selected_because"]
    assert ai.narrative_weave.episodes[-1].actual_utility == -0.5
    summary = ai.get_narrative_learning_summary()
    assert summary["episodes"] == 1
    assert summary["metacognition"]["episodes_reviewed"] == 1
    assert summary["social_learning"]["accepted_transfers"] == 1
    updated_operator = ai.record_socrates_operator_result(
        result["socrates_operator"]["id"], True, 0.4,
    )
    assert updated_operator["success_count"] == 1
