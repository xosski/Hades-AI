"""Integration test for the canonical HadesAI persistent cognitive loop."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from HadesAI import HadesAI, HadesGUI, loaded_modules, loaded_module_specs
from modules.cognitive_memory import CognitiveLayer, MemoryType, OriginType


class _FakeConversationManager:
    def __init__(self):
        self.conversation = None

    def get_available_providers(self):
        return ["fallback"]

    def create_conversation(self, title, provider, model, system_prompt):
        self.conversation = SimpleNamespace(
            id="test-conversation",
            provider=provider,
            model=model,
            system_prompt=system_prompt,
            messages=[],
        )
        return self.conversation

    def send_message(self, message, conv_id, use_streaming=False):
        return "A direct test response grounded in the current request and available evidence."

    def switch_provider(self, conv_id, provider, model):
        self.conversation.provider = provider
        self.conversation.model = model
        return True

    def _save_conversation(self, conversation):
        self.conversation = conversation


class CanonicalCognitiveLoopTests(unittest.TestCase):
    def test_llm_chat_records_episode_reflects_and_analyzes_modules(self):
        previous_modules = dict(loaded_modules)
        previous_specs = dict(loaded_module_specs)
        cognitive = None
        try:
            loaded_modules.clear()
            loaded_module_specs.clear()
            loaded_modules["Evidence Module"] = SimpleNamespace(
                __file__="modules/Evidence Module.py",
                __doc__="Analyzes evidence policy and provenance.",
                CAPABILITIES=["evidence policy", "provenance analysis"],
                enhance_output=lambda response: response + " [evidence]",
            )
            loaded_module_specs["Evidence Module"] = "modules.Evidence Module"
            loaded_modules["Network Defense"] = SimpleNamespace(
                __file__="modules/Network Defense.py",
                __doc__="Monitors network traffic and defensive controls.",
                CAPABILITIES=["network monitoring", "defense"],
                enhance_output=lambda response: response + " [network]",
            )
            loaded_module_specs["Network Defense"] = "modules.Network Defense"

            with tempfile.TemporaryDirectory() as directory:
                ai = HadesAI.__new__(HadesAI)
                ai.llm_manager = _FakeConversationManager()
                cognitive = CognitiveLayer(db_path=str(Path(directory) / "memory.db"))
                ai.cognitive = cognitive
                ai.get_amp_threads_context = lambda message: ""
                ai.analyze_memory_context = lambda message: {}

                response = ai.llm_chat("Explain the evidence policy", provider="fallback")

                self.assertIn("direct test response", response.lower())
                memories = ai.cognitive.store.memories
                episodes = [
                    memory for memory in memories
                    if memory.memory_type == MemoryType.EPISODIC.value
                ]
                candidates = [
                    memory for memory in memories
                    if memory.memory_type == MemoryType.CANDIDATE.value
                ]
                self.assertEqual(1, len(episodes))
                self.assertEqual(OriginType.OBSERVED.value, episodes[0].origin_type)
                self.assertEqual(1, len(candidates))
                self.assertEqual([episodes[0].id], candidates[0].evidence)
                self.assertEqual(1, len(ai.cognitive.reflection.reflections))
                decision = episodes[0].metadata["module_decision"]
                self.assertEqual(["Evidence Module"], decision["response_modules"])
                self.assertIn(
                    "Persistent cognitive guidance",
                    ai.llm_manager.conversation.system_prompt,
                )
                self.assertIn(
                    "Loaded module capability analysis",
                    ai.llm_manager.conversation.system_prompt,
                )
                self.assertIn(
                    "Evidence Module",
                    ai.llm_manager.conversation.system_prompt,
                )
                gui_stub = SimpleNamespace(
                    ai=ai,
                    brain={},
                    _add_chat_message=lambda role, message: None,
                )
                processed = HadesGUI._process_through_modules(
                    gui_stub, "Explain the evidence policy", "base response"
                )
                self.assertEqual("base response [evidence]", processed)
                outcome = ai.cognitive.get_last_module_decision()
                self.assertEqual(["Evidence Module"], outcome["applied_modules"])
                self.assertNotIn("Network Defense", outcome["response_modules"])
        finally:
            if cognitive:
                cognitive.close()
            loaded_modules.clear()
            loaded_modules.update(previous_modules)
            loaded_module_specs.clear()
            loaded_module_specs.update(previous_specs)


if __name__ == "__main__":
    unittest.main()
