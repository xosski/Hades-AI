from HadesAI import HadesAI
from modules.narrative_decision_weave import Action, NarrativeDecisionWeave, WorldState


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


def test_hades_facade_ingests_decides_and_formats_context(tmp_path):
    ai = HadesAI.__new__(HadesAI)
    ai.narrative_weave = NarrativeDecisionWeave(str(tmp_path / "facade.json"))

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
    )
    assert result["episode_id"]
    assert result["ranked_actions"]
    assert "MaintenanceStory" in ai.get_narrative_context("inspect an unknown process")
    assert ai.record_narrative_outcome(result["episode_id"], 0.5)["recorded"] is True
