"""Focused regression tests for autonomous execution control paths."""

import tempfile
import unittest
from pathlib import Path

from modules.autonomy_policy import ActionRisk, AutonomousActionPolicy
from modules.autonomous_intelligence import AutonomyLevel, AutonomousIntelligence
from modules.autonomous_scheduler import AutonomousScheduler, ScheduledTask, TaskStatus
from modules.multi_agent_system import AgentRole, MultiAgentSystem, TaskStatus as AgentTaskStatus
from modules.predictive_executor import PredictedAction, PredictiveExecutor


class AutonomyPolicyTests(unittest.TestCase):
    def test_high_risk_prediction_is_denied_even_with_threshold_override(self):
        calls = []
        executor = PredictiveExecutor(executor_fn=lambda *args: calls.append(args) or True)
        prediction = PredictedAction("steal_data", 1.0, "learned", 1.0)

        result = executor.execute_predicted_action(prediction, override_threshold=True)

        self.assertFalse(result["success"])
        self.assertTrue(result["denied"])
        self.assertEqual([], calls)

    def test_trusted_approval_can_allow_high_risk_action(self):
        policy = AutonomousActionPolicy(approval_checker=lambda action, metadata: True)
        decision = policy.evaluate("deploy_change", {}, max_risk=ActionRisk.MEDIUM)
        self.assertTrue(decision.allowed)

    def test_broken_approval_checker_fails_closed(self):
        def broken_checker(action, metadata):
            raise RuntimeError("approval service unavailable")

        policy = AutonomousActionPolicy(approval_checker=broken_checker)
        decision = policy.evaluate("execute_command", {}, max_risk=ActionRisk.MEDIUM)
        self.assertFalse(decision.allowed)

    def test_assisted_mode_never_executes(self):
        system = AutonomousIntelligence(autonomy_level=AutonomyLevel.ASSISTED)
        prediction = PredictedAction("analyze_code", 1.0, "learned", 1.0)
        self.assertFalse(system._should_execute_prediction(prediction, 1.0, None))


class SchedulerTests(unittest.TestCase):
    def test_retries_are_bounded_and_recorded_once(self):
        with tempfile.TemporaryDirectory() as directory:
            scheduler = AutonomousScheduler(str(Path(directory) / "scheduler.db"))
            attempts = []

            def fail():
                attempts.append(1)
                raise RuntimeError("nope")

            task = ScheduledTask("bounded", "Bounded", fail, "@hourly", max_retries=2)
            scheduler._execute_task(task)

            self.assertEqual(3, len(attempts))
            self.assertEqual(1, len(scheduler.execution_history))
            self.assertEqual(2, scheduler.execution_history[0].retry_count)
            self.assertEqual(TaskStatus.FAILED, scheduler.execution_history[0].status)
            self.assertEqual(1, task.execution_count)


class MultiAgentTests(unittest.TestCase):
    def test_collaborating_agents_are_not_treated_as_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            system = MultiAgentSystem(str(Path(directory) / "agents.db"))
            system.register_agent("scout", "Scout", AgentRole.SCOUT)
            system.register_agent("breacher", "Breacher", AgentRole.BREACHER)
            task_id = system.create_collaborative_task(
                "Assessment",
                "Authorized assessment",
                [AgentRole.SCOUT, AgentRole.BREACHER],
            )

            system._resolve_conflicts()

            task = system.collaborative_tasks[task_id]
            self.assertEqual({"scout", "breacher"}, set(task.assigned_agents.values()))
            self.assertEqual(task_id, system.agents["scout"].current_task)
            self.assertEqual(task_id, system.agents["breacher"].current_task)

    def test_assigned_agents_can_complete_task(self):
        with tempfile.TemporaryDirectory() as directory:
            system = MultiAgentSystem(str(Path(directory) / "agents.db"))
            system.register_agent("scout", "Scout", AgentRole.SCOUT)
            task_id = system.create_collaborative_task(
                "Assessment", "Authorized assessment", [AgentRole.SCOUT]
            )
            task = system.collaborative_tasks[task_id]
            system._manage_tasks()
            self.assertEqual(AgentTaskStatus.IN_PROGRESS, task.status)
            self.assertTrue(system.report_agent_result("scout", task_id, {"done": True}))
            system._manage_tasks()
            self.assertEqual(AgentTaskStatus.COMPLETED, task.status)

    def test_unassigned_agent_result_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            system = MultiAgentSystem(str(Path(directory) / "agents.db"))
            system.register_agent("scout", "Scout", AgentRole.SCOUT)
            task_id = system.create_collaborative_task(
                "Assessment", "Authorized assessment", [AgentRole.SCOUT]
            )
            self.assertFalse(system.report_agent_result("other", task_id, {}))


if __name__ == "__main__":
    unittest.main()
