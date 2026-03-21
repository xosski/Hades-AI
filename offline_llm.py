"""
Offline LLM Orchestrator

Builds sophisticated, API-key-free responses by composing existing local
components:
- LocalAIResponse (knowledge-aware response generation)
- SophisticatedResponseEngine (reasoning structure)
- AdvancedResponseFormatter (readable output formatting)
"""

from __future__ import annotations

import argparse
import random

from local_ai_response import LocalAIResponse
from modules.advanced_response_formatter import AdvancedResponseFormatter, ResponseStyle
from modules.sophisticated_responses import SophisticatedResponseEngine


class OfflineLLM:
    """Unified local response engine that requires no external API keys."""

    def __init__(self, use_knowledge_db: bool = True):
        self.local_ai = LocalAIResponse(use_knowledge_db=use_knowledge_db)
        self.engine = SophisticatedResponseEngine()
        self.formatter = AdvancedResponseFormatter()
        self.turn_count = 0

    def generate(self, user_input: str, mood: str = "analytical", system_prompt: str = "") -> str:
        """
        Generate a sophisticated local response.

        Uses domain-aware generation from LocalAIResponse, then applies
        style-aware formatting so output quality remains high for both
        security and general technical prompts.
        """
        self.turn_count += 1

        # Handle normal conversational prompts first.
        small_talk = self._small_talk_reply(user_input)
        if small_talk:
            return small_talk

        brain_state = {"mood": mood}
        _mood, _complexity, request_type = self.engine.analyze_context(brain_state, user_input)

        style = self._to_style(request_type)

        # Local knowledge-aware content generation.
        raw_content = self.local_ai.generate(user_input=user_input, system_prompt=system_prompt, mood=mood)
        content = self._upgrade_generic_content(user_input, raw_content, request_type)

        # Thinking traces are generated locally from the query.
        thinking = self.engine.generate_thinking_process(user_input=user_input, thinking_style=mood)

        return self.formatter.format_with_thinking(
            user_input=user_input,
            response_content=content,
            thinking_process=thinking,
            style=style,
        )

    def _small_talk_reply(self, user_input: str) -> str | None:
        """Handle conversational prompts so they do not get security-generic replies."""
        text = user_input.strip().lower()

        if not text:
            return "I’m here and ready. Ask me anything."

        if any(x in text for x in ["how are you", "hows it going", "how're you"]):
            return random.choice([
                "I’m running well and fully local right now. Want to test me with a casual question or a technical one?",
                "Doing good. Response pipeline is active with no API keys. What do you want to explore next?",
                "All systems steady. I can do normal chat, planning, or deep technical breakdowns.",
            ])

        if text in {"hi", "hello", "hey", "yo", "sup"} or text.startswith("hello "):
            return random.choice([
                "Hey. I’m your offline LLM console. What are we working on?",
                "Hello. Give me a prompt and I’ll respond locally with no external APIs.",
                "Hi there. Want quick chat mode or a detailed technical answer?",
            ])

        if "who are you" in text or "what are you" in text:
            return (
                "I’m an offline response engine running entirely in this workspace. "
                "I use local modules for reasoning, formatting, and knowledge lookup without API keys."
            )

        if any(x in text for x in ["thank you", "thanks", "thx"]):
            return "You’re welcome. Keep the prompts coming."

        return None

    def close(self) -> None:
        """Release resources."""
        self.local_ai.close()

    @staticmethod
    def _to_style(request_type: str) -> ResponseStyle:
        mapping = {
            "technical": ResponseStyle.TECHNICAL,
            "educational": ResponseStyle.EDUCATIONAL,
            "strategic": ResponseStyle.STRATEGIC,
            "analytical": ResponseStyle.ANALYTICAL,
        }
        return mapping.get(request_type, ResponseStyle.TECHNICAL)

    def _upgrade_generic_content(self, user_input: str, raw_content: str, request_type: str) -> str:
        """
        Replace low-value generic fallback text with a richer local synthesis.

        LocalAIResponse is strong for security-domain prompts. For broader prompts,
        this keeps the quality high by producing structured, actionable guidance.
        """
        generic_marker = "Unfortunately, I don't have specific knowledge about this topic"
        if generic_marker not in raw_content:
            return raw_content

        concepts = self.engine._extract_concepts(user_input)
        focus = ", ".join(concepts[:3]) if concepts else "your topic"

        if request_type == "strategic":
            return (
                f"A practical way to approach {focus} is to sequence work by risk reduction and dependency order.\n\n"
                "1. Baseline and Prioritize: inventory assets, rank by exposure and business impact, and pick a small high-value pilot.\n"
                "2. Controls First: deploy foundational controls early (identity, logging, segmentation, patching, backup validation).\n"
                "3. Iterative Rollout: expand in waves with measurable gates (coverage, false-positive rate, MTTR, and incident trends).\n"
                "4. Operational Hardening: add runbooks, ownership, and continuous verification via tests and periodic reviews.\n\n"
                "Recommended output: a 30/60/90-day roadmap with owners, target metrics, and rollback criteria."
            )

        if request_type == "educational":
            return (
                f"Here is a clear way to understand {focus}:\n\n"
                "- Core idea: define the problem and the risk it introduces.\n"
                "- Mechanism: explain how failures occur in real systems.\n"
                "- Detection: identify observable signals and test cases.\n"
                "- Mitigation: map controls to each failure mode.\n"
                "- Validation: verify fixes with repeatable checks.\n\n"
                "If you share your stack (language, framework, deployment model), this can be translated into concrete implementation steps."
            )

        return (
            f"Technical analysis for {focus}:\n\n"
            "- Threat model or failure model first, so effort aligns to likely and high-impact scenarios.\n"
            "- Design controls at multiple layers (application, data, runtime, and operations).\n"
            "- Add observability early (logs, metrics, alerts) to detect regressions quickly.\n"
            "- Validate with targeted tests, then enforce through CI checks and operational runbooks.\n\n"
            "This keeps improvements measurable and prevents one-off hardening that degrades over time."
        )


def launch_offline_llm_gui(use_knowledge_db: bool = True) -> None:
    """Launch a standalone visual chat console for OfflineLLM."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QApplication,
        QComboBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QPushButton,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    class OfflineLLMConsole(QMainWindow):
        def __init__(self):
            super().__init__()
            self.llm = OfflineLLM(use_knowledge_db=use_knowledge_db)
            self._build_ui()

        def _build_ui(self) -> None:
            self.setWindowTitle("Offline LLM Console")
            self.resize(980, 700)

            root = QWidget()
            layout = QVBoxLayout(root)
            layout.setContentsMargins(12, 12, 12, 12)
            layout.setSpacing(10)

            self.chat_view = QTextEdit()
            self.chat_view.setReadOnly(True)
            self.chat_view.setFont(QFont("Consolas", 
 10))
            layout.addWidget(self.chat_view, stretch=1)

            controls = QHBoxLayout()
            controls.addWidget(QLabel("Mood:"))

            self.mood_box = QComboBox()
            self.mood_box.addItems(["analytical", "neutral", "curious", "optimistic", "pragmatic"])
            self.mood_box.setCurrentText("analytical")
            controls.addWidget(self.mood_box)

            self.input_box = QLineEdit()
            self.input_box.setPlaceholderText("Type your prompt...")
            self.input_box.returnPressed.connect(self._send)
            controls.addWidget(self.input_box, stretch=1)

            send_btn = QPushButton("Send")
            send_btn.clicked.connect(self._send)
            controls.addWidget(send_btn)

            clear_btn = QPushButton("Clear")
            clear_btn.clicked.connect(self._clear)
            controls.addWidget(clear_btn)

            layout.addLayout(controls)

            self.status_label = QLabel("Ready")
            self.status_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
            layout.addWidget(self.status_label)

            self.setCentralWidget(root)
            self._append_system("Offline LLM console started. No API keys required.")

        def _append_system(self, text: str) -> None:
            self.chat_view.append(f"[SYSTEM]\n{text}\n")

        def _append_user(self, text: str) -> None:
            self.chat_view.append(f"[YOU]\n{text}\n")

        def _append_assistant(self, text: str) -> None:
            self.chat_view.append(f"[OFFLINE LLM]\n{text}\n")
            sb = self.chat_view.verticalScrollBar()
            sb.setValue(sb.maximum())

        def _send(self) -> None:
            user_text = self.input_box.text().strip()
            if not user_text:
                return

            mood = self.mood_box.currentText()
            self._append_user(user_text)
            self.input_box.clear()
            self.status_label.setText("Generating response...")

            try:
                response = self.llm.generate(user_input=user_text, mood=mood)
            except Exception as exc:
                response = f"Error while generating response: {exc}"

            self._append_assistant(response)
            self.status_label.setText("Ready")

        def _clear(self) -> None:
            self.chat_view.clear()
            self._append_system("Chat cleared.")

        def closeEvent(self, event):
            self.llm.close()
            return super().closeEvent(event)

    app = QApplication.instance() or QApplication([])
    window = OfflineLLMConsole()
    window.show()
    app.exec()


def _main() -> None:
    parser = argparse.ArgumentParser(description="OfflineLLM utility")
    parser.add_argument("--gui", action="store_true", help="Launch visual chat console")
    parser.add_argument("--prompt", type=str, default="", help="Run one prompt in CLI mode")
    parser.add_argument("--mood", type=str, default="analytical", help="Mood used for generation")
    parser.add_argument("--no-kb", action="store_true", help="Disable knowledge DB lookup")
    args = parser.parse_args()

    use_knowledge_db = not args.no_kb

    if args.gui:
        try:
            launch_offline_llm_gui(use_knowledge_db=use_knowledge_db)
        except Exception as exc:
            import traceback
            print(f"Failed to start Offline LLM GUI: {exc}")
            traceback.print_exc()
        return

    llm = OfflineLLM(use_knowledge_db=use_knowledge_db)
    try:
        prompt = args.prompt or "Explain how to secure an API gateway and what to prioritize first"
        print(llm.generate(prompt, mood=args.mood))
    finally:
        llm.close()


if __name__ == "__main__":
    _main()
