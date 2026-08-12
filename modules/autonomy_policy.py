"""Policy boundary for actions selected by autonomous components.

Predictions are untrusted proposals.  This module keeps confidence scoring
separate from permission to act, so a frequently observed action cannot gain
authorization merely by becoming more likely.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Dict, Iterable, Optional


class ActionRisk(IntEnum):
    """Potential impact of an action if the prediction is wrong."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    risk: ActionRisk
    reason: str


class AutonomousActionPolicy:
    """Fail closed for high-impact actions and optionally enforce an allowlist."""

    _HIGH_RISK_TERMS = (
        "delete", "destroy", "disable", "exfiltrate", "steal", "persist",
        "escalate", "lateral_move", "exploit", "inject", "deploy",
        "execute", "shell", "command", "malware", "credential",
        "ransomware", "cover_tracks",
    )
    _MEDIUM_RISK_TERMS = (
        "scan", "probe", "test", "quarantine", "block", "isolate",
        "restart", "modify", "write",
    )

    def __init__(
        self,
        allowed_actions: Optional[Iterable[str]] = None,
        approval_checker: Optional[Callable[[str, Dict[str, Any]], bool]] = None,
    ):
        self.allowed_actions = set(allowed_actions) if allowed_actions is not None else None
        self.approval_checker = approval_checker

    def classify(self, action: str) -> ActionRisk:
        normalized = action.strip().lower()
        if any(term in normalized for term in self._HIGH_RISK_TERMS):
            return ActionRisk.HIGH
        if any(term in normalized for term in self._MEDIUM_RISK_TERMS):
            return ActionRisk.MEDIUM
        return ActionRisk.LOW

    def evaluate(
        self,
        action: str,
        metadata: Optional[Dict[str, Any]] = None,
        max_risk: ActionRisk = ActionRisk.MEDIUM,
    ) -> PolicyDecision:
        metadata = metadata or {}
        risk = self.classify(action)

        if not action.strip():
            return PolicyDecision(False, risk, "action name is empty")

        if self.allowed_actions is not None and action not in self.allowed_actions:
            return PolicyDecision(False, risk, "action is not in the configured allowlist")

        if risk <= max_risk:
            return PolicyDecision(True, risk, "action is within the autonomous risk budget")

        # Approval comes from trusted application code, never prediction metadata.
        if self.approval_checker:
            try:
                if self.approval_checker(action, metadata):
                    return PolicyDecision(True, risk, "action was explicitly approved")
            except Exception:
                return PolicyDecision(False, risk, "trusted approval check failed")

        return PolicyDecision(False, risk, "action exceeds the autonomous risk budget")
