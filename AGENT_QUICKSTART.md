# Autonomous Coding Agent - Quick Start Guide

## What Is It?
The Autonomous Coding Agent is an AI-powered tool integrated into HadesAI that can automatically:
- Fix failing tests
- Refactor code
- Add documentation
- Fix bugs
- Implement features

All while respecting your specifications and approval workflows.

## Setup (1 minute)

### Requirements
```bash
pip install openai  # or mistral, ollama, etc.
```

### Configuration
1. Open **HadesAI**
2. Go to the **"🔧 Self-Improvement"** tab
3. Configure your LLM provider (OpenAI, Mistral, Ollama, etc.)
4. Set your API key if needed

## First Run (5 minutes)

1. **Navigate** to the **"🤖 Autonomous Coder"** tab
2. **Set Repository Path**: `/path/to/your/code`
3. **Write Goals**: 
   ```
   - Fix all failing tests
   - Add missing docstrings to functions
   - Improve code comments
   ```
4. **Configure** (optional):
   - Leave Test Command as `pytest -q` unless your tests use different framework
   - Dry-Run: Check this to preview changes without applying
   - Max Iterations: 15 is good for most tasks
5. **Click** "▶ Start Agent"
6. **Watch** the live log as the agent works
7. **Review** proposed changes in the "Proposed/Applied Diff" panel

## Example Use Cases

### Case 1: Fix Failing Tests
```
Repository: /Users/dev/myproject
Goals:
- Make all pytest tests pass
- Don't change API contracts

Max Iterations: 20
Dry-Run: OFF (to apply changes)
```

### Case 2: Document Code
```
Repository: /Users/dev/legacy_code
Goals:
- Add comprehensive docstrings to all functions
- Add type hints where missing
- Add inline comments for complex logic

Max Iterations: 30
Dry-Run: ON (preview first)
```

### Case 3: Refactor Module
```
Repository: /Users/dev/project
Goals:
- Refactor src/utils/helpers.py for readability
- Extract duplicate code into functions
- Improve variable naming

Max Iterations: 15
Allow shell: OFF (safer)
```

## Understanding the Agent Interface

### Configuration Section
- **Repository**: Full path to your code directory
- **Goals**: Plain English description of what to accomplish
- **Test Command**: How to verify the work is done
- **Max Iterations**: Maximum steps the agent will take

### Options
- **Dry-Run**: Preview changes without writing files
- **Allow shell commands**: Enable running shell commands (⚠️ risky)
- **Require manual approval**: Approve each file change (slower but safer)

### Log Panel
Real-time output from the agent showing:
- Current step
- Tool being used (read_file, write_file, run_tests, etc.)
- Status and observations

### Diff Panel
Shows:
- File name being modified
- Unified diff of changes
- Preview of new content

## Tips for Success

✅ **DO:**
- Start with Dry-Run mode to see what it will do
- Be specific in your goals
- Use reasonable iteration counts (10-20)
- Test with a copy of your code first
- Review diffs carefully before applying

❌ **DON'T:**
- Run on production code without backup
- Set unreasonable iteration limits (100+)
- Give vague goals like "make better"
- Enable "Allow shell" unless absolutely needed
- Ignore the diffs - review them carefully

## Common Patterns

### Pattern 1: Test-Driven Development
```
Goals:
- Ensure all tests pass in tests/ directory
- Don't modify test files
- Only modify src/ code

Test Command: pytest tests/ -v
```

### Pattern 2: Documentation Pass
```
Goals:
- Add docstrings to every function using Google style
- Add type hints to function signatures
- Add comments explaining complex sections

Test Command: python -m pylint --disable=all --enable=missing-docstring src/
```

### Pattern 3: Linting Fixes
```
Goals:
- Fix all flake8 violations
- Keep functional behavior identical
- Run: flake8 src/

Test Command: flake8 src/ --count
```

## Troubleshooting

### Agent loops indefinitely
- Reduce Max Iterations
- Check your test command is actually runnable
- Verify LLM is responding correctly

### Agent makes bad changes
- Use Dry-Run mode first
- Write more specific goals
- Use Manual Approval option

### Agent too slow
- Reduce repository size (agent will scan all files)
- Limit scope in goals (e.g., "only fix module X")
- Use fewer max iterations

### LLM errors
- Check API key in Self-Improvement tab
- Verify network connectivity
- Check model name is spelled correctly
- Look at logs for error details

## Architecture

```
User Input (Goals, Repo, Settings)
        ↓
HadesAI Chat Interface
        ↓
Autonomous Coding Agent (QThread)
        ├→ Plan (using LLM)
        ├→ Act (read/write/test)
        ├→ Reflect (update strategy)
        └→ Emit signals (log, diff, progress)
        ↓
Knowledge Base (learns patterns)
```

## Advanced: Direct Control

The agent exposes these methods:
```python
# Start agent
self._start_agent()

# Stop agent  
self._stop_agent()

# Access agent instance
self._agent  # QThread, can check isRunning()
```

## Safety First

The agent includes safeguards:
- ✅ Forbids: `rm -rf`, `reboot`, `shutdown`, etc.
- ✅ File boundary: Can't escape the repository
- ✅ Timeout: 60 second max per command
- ✅ Approval: Optional manual verification
- ✅ Dry-run: Test before applying

## Support & Feedback

For issues or feature requests:
1. Check AUTONOMOUS_AGENT_INTEGRATION.md for detailed docs
2. Review the autonomouscoding.py for implementation
3. Check HadesAI.py for integration code
4. Enable verbose logging (in logs)

---

**Happy autonomous coding!** 🤖
