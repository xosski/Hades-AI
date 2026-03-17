"""
Fallback LLM for Autonomous Agent
Provides intelligent code analysis without requiring external API
Uses context-aware pattern matching and adaptive strategies
"""
import json
import re
from typing import Dict, Any, List, Tuple


class FallbackLLM:
    """
    Intelligent fallback when no external LLM is configured.
    Uses context-aware rule-based analysis to generate agent actions.
    Adapts strategies based on prompt content and history.
    """
    
    def __init__(self):
        self.iteration = 0
        self.tool_history = []
        self.action_patterns = {
            "explore": ["list_files", "read_file", "search_code"],
            "test": ["run_tests", "read_file"],
            "fix": ["edit_file", "run_tests", "read_file"],
            "analyze": ["search_code", "read_file", "run_tests"]
        }
        
    def __call__(self, system_prompt: str, user_prompt: str) -> str:
        """Generate action based on system and user prompts"""
        self.iteration += 1
        
        # Decide next action based on prompt content
        if self._is_planning_request(system_prompt):
            return self._generate_initial_plan(user_prompt)
        
        elif self._is_action_request(system_prompt):
            return self._decide_next_action(system_prompt, user_prompt)
        
        elif self._is_reflection_request(system_prompt):
            return self._update_plan(user_prompt)
        
        else:
            return self._default_action()
    
    def _is_planning_request(self, prompt: str) -> bool:
        """Check if this is a planning request"""
        keywords = ["Initial Plan", "high-level plan", "plan", "strategy"]
        return any(kw in prompt for kw in keywords)
    
    def _is_action_request(self, prompt: str) -> bool:
        """Check if this is an action decision request"""
        keywords = ["Choose ONE", "next action", "What should", "Execute"]
        return any(kw in prompt for kw in keywords)
    
    def _is_reflection_request(self, prompt: str) -> bool:
        """Check if this is a reflection/update request"""
        keywords = ["reflector", "Update", "trim", "adjust", "refine"]
        return any(kw.lower() in prompt.lower() for kw in keywords)
    
    def _generate_initial_plan(self, prompt: str) -> str:
        """Generate initial plan for analyzing code"""
        goals = self._extract_goals(prompt)
        
        # Customize plan based on goals
        if any(x in goals.lower() for x in ["exploit", "vulnerability", "security"]):
            plan_steps = [
                "1) Analyze vulnerability types",
                "2) Search for vulnerable code patterns",
                "3) Generate proof-of-concept exploits",
                "4) Test exploit effectiveness",
                "5) Document findings and remediation"
            ]
        elif any(x in goals.lower() for x in ["fix", "improve", "refactor"]):
            plan_steps = [
                "1) Understand current implementation",
                "2) Identify areas for improvement",
                "3) Make targeted fixes",
                "4) Run tests to verify changes",
                "5) Document improvements made"
            ]
        else:
            plan_steps = [
                "1) Explore repository structure",
                "2) Understand key files and architecture",
                "3) Identify patterns and issues",
                "4) Implement improvements",
                "5) Verify with testing"
            ]
        
        return json.dumps({
            "plan": "\\n".join(plan_steps)
        })
    
    def _decide_next_action(self, system_prompt: str, user_prompt: str) -> str:
        """Decide next action based on context"""
        
        goals = self._extract_goals(user_prompt)
        recent_steps = self._extract_history(user_prompt)
        observations = self._extract_observations(user_prompt)
        
        # Determine primary goal type
        goal_type = self._classify_goal(goals)
        
        # Check for error patterns
        if self._contains_error_indicators(observations):
            return json.dumps({
                "tool": "search_code",
                "args": {"query": "error|exception|fail|bug"},
                "rationale": "Errors detected - searching for error handling and problematic code"
            })
        
        # Check for test failures
        if self._contains_test_failures(observations):
            return json.dumps({
                "tool": "read_file",
                "args": {"path": "test_output.log"},
                "rationale": "Test failures found - examining detailed test output"
            })
        
        # Goal-based action selection
        if goal_type == "exploit":
            return self._next_exploit_action(recent_steps, observations)
        elif goal_type == "fix":
            return self._next_fix_action(recent_steps, observations)
        elif goal_type == "analyze":
            return self._next_analysis_action(recent_steps, observations)
        else:
            return self._next_exploration_action(recent_steps, observations)
    
    def _next_exploit_action(self, history: List[str], obs: str) -> str:
        """Generate next action for exploit discovery"""
        actions = [
            ("list_files", {"pattern": "**/*.py"}, "Finding Python files"),
            ("search_code", {"query": "socket|buffer|overflow|injection"}, "Searching for vulnerable patterns"),
            ("read_file", {"path": ""}, "Analyzing vulnerable code"),
            ("run_tests", {}, "Testing exploit functionality"),
            ("search_code", {"query": "def |class "}, "Finding exploitable entry points")
        ]
        
        # Select action based on iteration
        idx = min(self.iteration - 1, len(actions) - 1)
        tool, args, rationale = actions[idx]
        
        return json.dumps({
            "tool": tool,
            "args": args,
            "rationale": rationale
        })
    
    def _next_fix_action(self, history: List[str], obs: str) -> str:
        """Generate next action for fixing issues"""
        # If we found issues, edit them
        if "error" in obs.lower() or "fail" in obs.lower():
            return json.dumps({
                "tool": "edit_file",
                "args": {"path": "", "content": ""},
                "rationale": "Fixing identified issues in source code"
            })
        
        # Otherwise search for issues
        return json.dumps({
            "tool": "search_code",
            "args": {"query": "TODO|FIXME|XXX|HACK"},
            "rationale": "Finding issues marked in code comments"
        })
    
    def _next_analysis_action(self, history: List[str], obs: str) -> str:
        """Generate next action for code analysis"""
        if len(history) < 2:
            return json.dumps({
                "tool": "list_files",
                "args": {"pattern": "**/*.py"},
                "rationale": "Discovering Python modules to analyze"
            })
        
        return json.dumps({
            "tool": "read_file",
            "args": {"path": "README.md"},
            "rationale": "Understanding project architecture from documentation"
        })
    
    def _next_exploration_action(self, history: List[str], obs: str) -> str:
        """Generate next action for general exploration"""
        exploration_sequence = [
            ("list_files", {"pattern": "**/*.py"}, "Exploring repository structure"),
            ("read_file", {"path": "README.md"}, "Understanding project purpose"),
            ("search_code", {"query": "def main|if __name__"}, "Finding entry points"),
            ("read_file", {"path": "requirements.txt"}, "Analyzing dependencies"),
            ("run_tests", {}, "Checking test suite")
        ]
        
        idx = min(self.iteration - 1, len(exploration_sequence) - 1)
        tool, args, rationale = exploration_sequence[idx]
        
        return json.dumps({
            "tool": tool,
            "args": args,
            "rationale": rationale
        })
    
    def _update_plan(self, prompt: str) -> str:
        """Update plan based on recent observations"""
        observations = self._extract_observations(prompt)
        goals = self._extract_goals(prompt)
        
        # Generate adaptive plan update
        if "error" in observations.lower():
            update = "Encountered errors - shifting focus to debugging and error resolution"
        elif "success" in observations.lower() or "pass" in observations.lower():
            update = "Progress made - continuing with next phase of analysis"
        else:
            update = "New information gathered - adapting strategy accordingly"
        
        return json.dumps({
            "updated_plan": update
        })
    
    def _default_action(self) -> str:
        """Default safe action"""
        return json.dumps({
            "tool": "list_files",
            "args": {"pattern": "**/*.py"},
            "rationale": "Default: exploring repository structure"
        })
    
    def _extract_goals(self, prompt: str) -> str:
        """Extract goals from prompt"""
        match = re.search(r'Goals?:\s*([^\n]+)', prompt, re.IGNORECASE)
        return match.group(1) if match else ""
    
    def _extract_history(self, prompt: str) -> List[str]:
        """Extract recent steps from prompt"""
        steps = []
        if "Recent steps" in prompt or "History" in prompt:
            matches = re.findall(r'\d+\.\s+(\w+)\(', prompt)
            steps = matches
        return steps
    
    def _extract_observations(self, prompt: str) -> str:
        """Extract observations/results from prompt"""
        match = re.search(r'Observations?:\s*([^\n]+)', prompt, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Also check for output sections
        match = re.search(r'Output:\s*(.+?)(?:\n\n|$)', prompt, re.IGNORECASE | re.DOTALL)
        return match.group(1) if match else ""
    
    def _classify_goal(self, goals: str) -> str:
        """Classify the primary goal type"""
        goals_lower = goals.lower()
        
        if any(x in goals_lower for x in ["exploit", "vulnerability", "security"]):
            return "exploit"
        elif any(x in goals_lower for x in ["fix", "improve", "refactor", "debug"]):
            return "fix"
        elif any(x in goals_lower for x in ["analyze", "understand", "review"]):
            return "analyze"
        else:
            return "explore"
    
    def _contains_error_indicators(self, text: str) -> bool:
        """Check if text contains error indicators"""
        error_patterns = ["error", "exception", "traceback", "failed", "invalid"]
        return any(pattern in text.lower() for pattern in error_patterns)
    
    def _contains_test_failures(self, text: str) -> bool:
        """Check if text indicates test failures"""
        failure_patterns = ["test failed", "assertion", "failed to", "0 passed"]
        return any(pattern in text.lower() for pattern in failure_patterns)
