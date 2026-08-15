"""Regression tests for Cortex/Hippocampus/Dreamer memory channels."""

import tempfile
import threading
import unittest
import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from modules.cognitive_memory import (
    CognitiveLayer, MemoryMutation, MemoryOperation, MemoryType, OriginType,
)


class MemoryChannelTests(unittest.TestCase):
    def make_layer(self, directory, name="memory.db"):
        return CognitiveLayer(db_path=str(Path(directory) / name))

    def test_snapshots_are_detached_and_updates_are_versioned(self):
        with tempfile.TemporaryDirectory() as directory, self.make_layer(directory) as layer:
            memory_id = layer.remember("Project uses PostgreSQL", 0.8)
            snapshot = layer.get_memory_snapshot(memory_id)
            snapshot.content = "silently corrupted"

            self.assertEqual("Project uses PostgreSQL", layer.get_memory_snapshot(memory_id).content)
            updated = layer.update_memory(
                memory_id,
                expected_revision=1,
                content="Project migrated from PostgreSQL to SQLite",
            )
            stale = layer.update_memory(
                memory_id,
                expected_revision=1,
                content="stale writer",
            )

            self.assertTrue(updated.success)
            self.assertEqual(2, updated.memory.revision)
            self.assertFalse(stale.success)
            self.assertEqual(2, stale.conflict.actual_revision)
            self.assertEqual("Project migrated from PostgreSQL to SQLite", stale.conflict.current.content)
            with self.assertRaises(RuntimeError):
                layer.store.delete(memory_id)

    def test_cortex_returns_each_concurrent_callers_own_result(self):
        with tempfile.TemporaryDirectory() as directory, self.make_layer(directory) as layer:
            memory_id = layer.remember("initial")
            results = {}

            def update(index):
                content = f"writer-{index}"
                result = layer.submit_memory_mutation(MemoryMutation(
                    MemoryOperation.UPDATE,
                    memory_id=memory_id,
                    content=content,
                    embedding=layer.embedder(content),
                ))
                results[index] = result.memory.content

            threads = [threading.Thread(target=update, args=(index,)) for index in range(10)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual({index: f"writer-{index}" for index in range(10)}, results)

    def test_event_history_graph_and_rollback_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            layer = self.make_layer(directory)
            first_id = layer.remember("SQLite stores cognitive memory", 0.8)
            second_id = layer.remember("The application has durable state", 0.7)
            linked = layer.link_memories(first_id, 1, "supports", second_id)
            superseded = layer.supersede_memory(
                first_id,
                linked.memory.revision,
                "SQLite only stores cognitive memory",
                "scope was clarified",
            )
            self.assertTrue(superseded.success)
            layer.close()

            with self.make_layer(directory) as reloaded:
                snapshot = reloaded.get_memory_snapshot(first_id)
                self.assertEqual("SQLite only stores cognitive memory", snapshot.content)
                self.assertEqual([second_id], snapshot.links["supports"])
                history = reloaded.get_memory_history(first_id)
                self.assertEqual(["ADD", "LINK", "SUPERSEDE"], [event.operation for event in history])

                rolled_back = reloaded.rollback_memory(first_id, revision=1)
                self.assertTrue(rolled_back.success)
                self.assertEqual("SQLite stores cognitive memory", rolled_back.memory.content)
                self.assertEqual(4, rolled_back.memory.revision)

    def test_dreamer_prunes_through_authority_without_deleting_history(self):
        with tempfile.TemporaryDirectory() as directory, self.make_layer(directory) as layer:
            memory_id = layer.remember("temporary observation", importance=0.1)

            result = layer.optimize(prune_threshold=0.2, apply_decay=False)

            self.assertEqual(1, result["pruned_count"])
            self.assertIsNone(layer.get_memory_snapshot(memory_id))
            history = layer.get_memory_history(memory_id)
            self.assertEqual(["ADD", "FORGET"], [event.operation for event in history])
            self.assertEqual("dreamer", history[-1].source_channel)

    def test_dreamer_can_consolidate_sources_into_graph(self):
        with tempfile.TemporaryDirectory() as directory, self.make_layer(directory) as layer:
            first = layer.remember("Observation one")
            second = layer.remember("Observation two")

            result = layer.consolidate_memories(
                [first, second],
                "Both observations describe the same project decision",
            )

            self.assertTrue(result.success)
            self.assertEqual([first, second], result.memory.links["derived_from"])
            self.assertTrue(all(
                event.source_channel == "dreamer"
                for event in layer.get_memory_history(result.memory.id)
            ))

    def test_concurrent_reinforcement_has_one_canonical_writer(self):
        with tempfile.TemporaryDirectory() as directory, self.make_layer(directory) as layer:
            memory_id = layer.remember("Concurrent memory", 0.5)
            outcomes = []

            def reinforce():
                outcomes.append(layer.reinforce_memory(memory_id, 1.0))

            threads = [threading.Thread(target=reinforce) for _ in range(20)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            snapshot = layer.get_memory_snapshot(memory_id)
            self.assertEqual([True] * 20, outcomes)
            self.assertEqual(21, snapshot.revision)
            self.assertEqual(21, len(layer.get_memory_history(memory_id)))

    def test_sqlite_compare_and_swap_rejects_stale_process(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.make_layer(directory)
            memory_id = first.remember("revision one")
            second = self.make_layer(directory)
            try:
                self.assertTrue(first.update_memory(memory_id, 1, "revision two").success)
                stale = second.update_memory(memory_id, 1, "stale revision two")

                self.assertFalse(stale.success)
                self.assertEqual(2, stale.conflict.actual_revision)
                self.assertEqual("revision two", stale.conflict.current.content)
            finally:
                second.close()
                first.close()

    def test_existing_snapshot_schema_is_migrated_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "legacy.db"
            memory_id = "legacy-memory"
            with closing(sqlite3.connect(db_path)) as conn, conn:
                conn.execute("""
                    CREATE TABLE cognitive_memories (
                        id TEXT PRIMARY KEY, content TEXT NOT NULL,
                        embedding TEXT NOT NULL, importance REAL NOT NULL,
                        timestamp TEXT NOT NULL, metadata TEXT NOT NULL,
                        access_count INTEGER NOT NULL DEFAULT 0,
                        reinforcement_score REAL NOT NULL DEFAULT 0.5
                    )
                """)
                conn.execute("""
                    CREATE TABLE cognitive_reflections (
                        id TEXT PRIMARY KEY, user_input TEXT NOT NULL,
                        ai_output TEXT NOT NULL, success_score REAL NOT NULL,
                        timestamp TEXT NOT NULL, metadata TEXT NOT NULL,
                        reflected_content TEXT NOT NULL, memory_id TEXT
                    )
                """)
                conn.execute(
                    "INSERT INTO cognitive_memories VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        memory_id, "legacy content", json.dumps([1.0, 0.0]), 0.6,
                        datetime.now().isoformat(), "{}", 0, 0.5,
                    ),
                )

            with CognitiveLayer(db_path=str(db_path)) as layer:
                snapshot = layer.get_memory_snapshot(memory_id)
                self.assertEqual(1, snapshot.revision)
                self.assertEqual({}, snapshot.links)
                self.assertTrue(layer.update_memory(memory_id, 1, "migrated content").success)

            with closing(sqlite3.connect(db_path)) as conn:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(cognitive_memories)")}
                self.assertTrue({"revision", "updated_at", "status", "links"} <= columns)
                self.assertEqual(1, conn.execute(
                    "SELECT COUNT(*) FROM cognitive_memory_events"
                ).fetchone()[0])

    def test_recall_contract_and_access_accounting_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory, self.make_layer(directory) as layer:
            memory_id = layer.remember("The project database is PostgreSQL", 0.8)

            recalled = layer.recall("project database PostgreSQL", top_k=1)

            self.assertEqual(memory_id, recalled[0][1].id)
            self.assertIsInstance(recalled[0][0], float)
            self.assertEqual(1, recalled[0][1].access_count)
            self.assertEqual(2, recalled[0][1].revision)


    def test_loaded_module_analysis_routes_only_relevant_response_hooks(self):
        with tempfile.TemporaryDirectory() as directory, self.make_layer(directory) as layer:
            layer.sync_loaded_modules([
                {
                    "name": "Coding Module",
                    "capabilities": ["python code editing", "syntax repair"],
                    "public_callables": ["edit_code"],
                    "hooks": ["main"],
                },
                {
                    "name": "Response Formatter",
                    "capabilities": ["format response output"],
                    "public_callables": ["enhance_output"],
                    "hooks": ["enhance_output"],
                    "always_on": True,
                },
                {
                    "name": "Network Defense",
                    "capabilities": ["network monitoring"],
                    "public_callables": ["monitor_network"],
                    "hooks": ["main"],
                },
            ])

            decision = layer.analyze_loaded_modules("Repair and format this Python code")
            recommended = [item["name"] for item in decision["recommended_modules"]]

            self.assertIn("Coding Module", recommended)
            self.assertIn("Response Formatter", recommended)
            self.assertNotIn("Network Defense", recommended)
            self.assertEqual(["Response Formatter"], decision["response_modules"])
            self.assertEqual(["Coding Module"], decision["explicit_execution_modules"])
            context = layer.format_module_context(decision)
            self.assertIn("never", decision["decision_policy"])
            self.assertIn("main() requires explicit execution", context)

            model = layer.get_self_model()
            layer.update_self_model({
                "preferences": {"module_routing": {"Network Defense": 1.5}}
            }, expected_revision=model.revision)
            preferred = layer.analyze_loaded_modules("Unrelated request")
            self.assertIn(
                "Network Defense",
                [item["name"] for item in preferred["recommended_modules"]],
            )

    def test_typed_provenance_and_self_model_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            layer = self.make_layer(directory)
            memory_id = layer.remember(
                "The user selected concise answers",
                memory_type=MemoryType.EPISODIC,
                origin_type=OriginType.USER_STATED,
                confidence=0.9,
                evidence=["conversation-1"],
            )
            model = layer.get_self_model()
            updated = layer.update_self_model({
                "preferences": {"answer_style": "concise"},
                "active_goals": ["complete the current implementation"],
            }, expected_revision=model.revision)
            self.assertEqual(2, updated.revision)
            layer.close()

            with self.make_layer(directory) as reloaded:
                memory = reloaded.get_memory_snapshot(memory_id)
                self.assertEqual(MemoryType.EPISODIC.value, memory.memory_type)
                self.assertEqual(OriginType.USER_STATED.value, memory.origin_type)
                self.assertEqual(0.9, memory.confidence)
                self.assertEqual(["conversation-1"], memory.evidence)
                self.assertEqual(
                    "concise", reloaded.get_self_model().preferences["answer_style"]
                )

    def test_structured_reflection_is_provisional_and_affects_context(self):
        with tempfile.TemporaryDirectory() as directory:
            layer = self.make_layer(directory)
            episode_id = layer.remember(
                "Observed question and response",
                memory_type=MemoryType.EPISODIC,
                origin_type=OriginType.OBSERVED,
                confidence=1.0,
            )
            reflection = layer.reflect_on_interaction(
                "How should evidence be handled?",
                "Evidence should be checked and uncertainty should be labeled clearly.",
                memory_ids=[episode_id],
            )
            candidate = layer.get_memory_snapshot(reflection.candidate_memory_id)

            self.assertEqual(MemoryType.CANDIDATE.value, candidate.memory_type)
            self.assertEqual(OriginType.SELF_REFLECTION.value, candidate.origin_type)
            self.assertFalse(reflection.structured_data["outcome_observed"])
            self.assertIn("actual_outcome", reflection.structured_data)
            self.assertNotIn(
                candidate.id,
                [memory.id for _, memory in layer.recall("provisional reflection lesson")],
            )
            self.assertIn("Provisional reflection hypotheses", layer.format_cognitive_context())
            layer.close()

            with self.make_layer(directory) as reloaded:
                restored = reloaded.reflection.reflections[-1]
                self.assertEqual(candidate.id, restored.candidate_memory_id)
                self.assertIn("change_next_time", restored.structured_data)

    def test_candidate_promotion_requires_evidence_and_no_conflicts(self):
        with tempfile.TemporaryDirectory() as directory, self.make_layer(directory) as layer:
            first = layer.remember(
                "Observed outcome one", memory_type=MemoryType.EPISODIC,
                origin_type=OriginType.OBSERVED, confidence=1.0,
            )
            second = layer.remember(
                "User confirmed outcome two", memory_type=MemoryType.EPISODIC,
                origin_type=OriginType.USER_STATED, confidence=0.9,
            )
            conflict = layer.remember(
                "Contradictory observation", memory_type=MemoryType.EPISODIC,
                origin_type=OriginType.OBSERVED, confidence=0.8,
            )
            unsupported = layer.remember(
                "Provisional reflection lesson: verify evidence",
                memory_type=MemoryType.CANDIDATE,
                origin_type=OriginType.SELF_REFLECTION,
                confidence=0.8,
            )
            rejected = layer.promote_candidate_memory(unsupported)
            self.assertFalse(rejected.success)
            self.assertIn("requires 2", rejected.conflict.reason)

            contradicted = layer.remember(
                "Provisional reflection lesson: verify evidence",
                metadata={"lesson": "Verify evidence before making a durable claim."},
                memory_type=MemoryType.CANDIDATE,
                origin_type=OriginType.SELF_REFLECTION,
                confidence=0.8,
                evidence=[first, second],
                contradictions=[conflict],
            )
            rejected = layer.promote_candidate_memory(contradicted)
            self.assertFalse(rejected.success)
            self.assertIn("unresolved contradictions", rejected.conflict.reason)

            candidate = layer.remember(
                "Provisional reflection lesson: verify evidence",
                metadata={"lesson": "Verify evidence before making a durable claim."},
                memory_type=MemoryType.CANDIDATE,
                origin_type=OriginType.SELF_REFLECTION,
                confidence=0.8,
                evidence=[first, second],
            )
            promoted = layer.promote_candidate_memory(candidate)
            self.assertTrue(promoted.success)
            self.assertEqual(MemoryType.PROCEDURAL.value, promoted.memory.memory_type)
            self.assertEqual([first, second], promoted.memory.evidence)
            self.assertEqual(
                [candidate, first, second], promoted.memory.links["derived_from"]
            )

    def test_repeated_reflection_updates_persistent_self_model(self):
        with tempfile.TemporaryDirectory() as directory:
            layer = self.make_layer(directory)
            for index in range(3):
                episode = layer.remember(
                    f"Observed interaction {index}",
                    memory_type=MemoryType.EPISODIC,
                    origin_type=OriginType.OBSERVED,
                    confidence=1.0,
                )
                layer.reflect_on_interaction(
                    "Explain database migration evidence",
                    "Database migration evidence should be checked carefully and the answer "
                    "should clearly label uncertainty before presenting the final recommendation.",
                    memory_ids=[episode],
                )
            model = layer.get_self_model()
            self.assertEqual(1, len(model.learned_strategies))
            strategy = next(iter(model.learned_strategies.values()))
            self.assertEqual(3, strategy["evidence_count"])
            self.assertIn(strategy["strategy"], layer.format_cognitive_context())
            layer.close()

            with self.make_layer(directory) as reloaded:
                self.assertEqual(1, len(reloaded.get_self_model().learned_strategies))


if __name__ == "__main__":
    unittest.main()
