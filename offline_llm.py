"""
Offline LLM Orchestrator

Builds sophisticated, API-key-free responses by composing existing local
components:
- LocalAIResponse (knowledge-aware response generation)
- SophisticatedResponseEngine (reasoning structure)
- AdvancedResponseFormatter (readable output formatting)
"""

from __future__ import annotations

from local_ai_response import LocalAIResponse
from modules.advanced_response_formatter import AdvancedResponseFormatter, ResponseStyle
from modules.sophisticated_responses import SophisticatedResponseEngine


class OfflineLLM:
    """Unified local response engine that requires no external API keys."""

    def __init__(self, use_knowledge_db: bool = True):
        self.local_ai = LocalAIResponse(use_knowledge_db=use_knowledge_db)
        self.engine = SophisticatedResponseEngine()
        self.formatter = AdvancedResponseFormatter()

    def generate(self, user_input: str, mood: str = "analytical", system_prompt: str = "") -> str:
        """
        Generate a sophisticated local response.

        Uses domain-aware generation from LocalAIResponse, then applies
        style-aware formatting so output quality remains high for both
        security and general technical prompts.
        """
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


if __name__ == "__main__":
    llm = OfflineLLM(use_knowledge_db=True)
    try:
        prompt = "Explain how to secure an API gateway and what to prioritize first"
        print(llm.generate(prompt, mood="analytical"))
    finally:
        llm.close()
