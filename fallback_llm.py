"""
Fallback LLM for Autonomous Agent
Provides intelligent code analysis without requiring external API
"""
import json
import re
from typing import Dict, Any


class FallbackLLM:
    """
    Intelligent fallback when no external LLM is configured.
    Uses rule-based code analysis to generate agent actions.
    """
    
    def __init__(self):
        self.iteration = 0
        self.tool_history = []
        
    def __call__(self, system_prompt: str, user_prompt: str) -> str:
        """Generate action based on system and user prompts"""
        self.iteration += 1
        
        # Decide next action based on user prompt content
        if "Initial Plan" in system_prompt or "Provide a short high-level plan" in system_prompt:
            return self._generate_initial_plan(user_prompt)
        
        elif "Choose ONE next action" in system_prompt:
            return self._decide_next_action(user_prompt)
        
        elif "reflector" in system_prompt.lower() or "Update/trim the plan" in system_prompt:
            return self._update_plan(user_prompt)
        
        else:
            return self._default_action()
    
    def _generate_initial_plan(self, prompt: str) -> str:
        """Generate initial plan for analyzing code"""
        return """{
  "plan": "1) List Python files to understand structure\\n2) Read key files (main, config, tests)\\n3) Run tests to identify issues\\n4) Fix critical errors\\n5) Verify with passing tests"
}"""
    
    def _decide_next_action(self, prompt: str) -> str:
        """Decide next action based on goals and history"""
        
        # Extract goals from prompt
        goals = self._extract_goals(prompt)
        recent_steps = self._extract_history(prompt)
        
        # Iteration-based strategy
        if self.iteration == 1:
            return json.dumps({
                "tool": "list_files",
                "args": {"pattern": "**/*.py"},
                "rationale": "First, understand repository structure by listing Python files"
            })
        
        elif self.iteration == 2:
            return json.dumps({
                "tool": "read_file",
                "args": {"path": "README.md"},
                "rationale": "Check README for project overview and setup instructions"
            })
        
        elif self.iteration == 3:
            return json.dumps({
                "tool": "search_code",
                "args": {"query": "test_"},
                "rationale": "Find test files to understand test structure"
            })
        
        elif self.iteration == 4:
            return json.dumps({
                "tool": "run_tests",
                "args": {},
                "rationale": "Run tests to identify failures and understand issues"
            })
        
        elif self.iteration == 5:
            return json.dumps({
                "tool": "read_file",
                "args": {"path": "requirements.txt"},
                "rationale": "Check dependencies to understand project needs"
            })
        
        elif self.iteration == 6:
            return json.dumps({
                "tool": "search_code",
                "args": {"query": "def "},
                "rationale": "Search for function definitions to understand code structure"
            })
        
        elif self.iteration == 7:
            return json.dumps({
                "tool": "search_code",
                "args": {"query": "import "},
                "rationale": "Find imports to understand dependencies and modules"
            })
        
        else:
            # Later iterations: focus on code quality
            if "analyze" in goals.lower() or "look" in goals.lower():
                return json.dumps({
                    "tool": "search_code",
                    "args": {"query": "TODO|FIXME|BUG"},
                    "rationale": "Search for code comments indicating issues"
                })
            else:
                return json.dumps({
                    "tool": "run_tests",
                    "args": {},
                    "rationale": "Verify current state with test execution"
                })
    
    def _update_plan(self, prompt: str) -> str:
        """Update plan based on recent observations"""
        return """{
  "updated_plan": "Continue analyzing codebase structure. Look for patterns and understand architecture."
}"""
    
    def _default_action(self) -> str:
        """Default safe action"""
        return json.dumps({
            "tool": "list_files",
            "args": {"pattern": "**/*.py"},
            "rationale": "Default action: explore repository"
        })
    
    def _extract_goals(self, prompt: str) -> str:
        """Extract goals from prompt"""
        match = re.search(r'Goals:\s*([^\n]+)', prompt)
        return match.group(1) if match else ""
    
    def _extract_history(self, prompt: str) -> list:
        """Extract recent steps from prompt"""
        # Simple extraction - could be improved
        steps = []
        if "Recent steps" in prompt:
            # Extract numbered steps
            matches = re.findall(r'\d+\.\s+(\w+)\(', prompt)
            steps = matches
        return steps
