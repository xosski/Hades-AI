"""Regression tests for Cortex/Hippocampus/Dreamer memory channels."""

import tempfile
import threading
import unittest
import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from modules.cognitive_memory import CognitiveLayer, MemoryMutation, MemoryOperation


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


if __name__ == "__main__":
    unittest.main()
