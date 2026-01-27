# Autonomous Coding Agent - Complete Guide

## Overview
The autonomous coding agent helps you analyze, understand, and improve code automatically. It works **with or without** external LLM APIs.

## Quick Start (2 minutes)

1. **Open HadesAI** → Click "🤖 Autonomous Coder" tab
2. **Set repository path** → `/path/to/your/code`
3. **Write your goal** → e.g., "Can you analyze the source code"
4. **Click Start** → Watch it work in real-time
5. **Review results** → Check diffs and completion message

## Two Modes

### Mode 1: Without External API (Recommended for Learning)
- ✅ No setup required
- ✅ Works offline
- ✅ Systematic code analysis
- ✅ Zero API costs
- ✅ Uses intelligent FallbackLLM

**Start Without Setup**: Just click "Start Agent" - it works automatically!

### Mode 2: With External LLM (Better for Complex Tasks)
- ✅ Uses OpenAI, Mistral, Ollama, Azure
- ✅ Smarter decision making
- ✅ Handles complex reasoning
- ✅ Requires API key

**Setup**: Go to "🔧 Self-Improvement" tab → Configure your LLM

## How It Works

### Without External LLM
```
Agent Steps (Automatic):
1. List Python files to understand structure
2. Read README to understand project
3. Search for test files
4. Run tests to check current state
5. Read requirements to understand dependencies
6. Search for function definitions
7. Search for imports
8-15. Continue analyzing based on findings
```

### With External LLM
```
Agent Steps (AI-Driven):
1. Generate custom plan based on goals
2. Execute intelligent tools
3. Analyze results
4. Decide next action
5-15. Dynamic actions based on discoveries
```

## Configuration Options

| Option | Effect | Default |
|--------|--------|---------|
| **Repository** | Where to analyze/modify code | Required |
| **Goals** | What you want agent to do | Required |
| **Test Command** | How to verify changes | `pytest -q` |
| **Max Iterations** | Max agent steps | 15 |
| **Dry-Run** | Preview changes without applying | OFF |
| **Allow Shell** | Enable command execution | OFF |
| **Manual Approval** | Review each change | OFF |

## Example Goals

### Analyze Code
```
Goals:
- Analyze the source code structure
- Identify main modules and functions
- Check for obvious issues
- List dependencies
```

### Fix Issues
```
Goals:
- Make all tests pass
- Fix import errors
- Resolve type mismatches
```

### Improve Quality
```
Goals:
- Add missing docstrings
- Improve code style
- Remove duplicate code
- Optimize imports
```

### Document Code
```
Goals:
- Add comprehensive docstrings
- Add type hints to functions
- Add inline comments
- Create architecture documentation
```

## Real-Time Monitoring

While the agent runs, you see:
- 📝 **Live Log** - Current actions and progress
- 📊 **Progress Bar** - Iteration count (e.g., 3/15)
- 📋 **Diffs** - Changes proposed/applied
- 🎯 **Completion Message** - Final status

## Understanding Log Messages

### 🤖 Agent Starting
Agent initialized with your settings

### 🎯 Goals
Your specified objectives

### 🧪 Test Command
How agent verifies work

### 📝 Initial Plan
High-level strategy (AI-generated or default)

### 🧭 Iteration X - Tool: Y
Current step and tool being used

### ♻️ Updated Plan
Refined strategy based on findings

### 🏁 Finished
Final result with summary

## Safety Features

✅ **Safe by Default**
- Can't run `rm -rf`, `reboot`, `shutdown`
- Can't escape repository directory
- 60-second timeout per command
- All changes logged

✅ **Approval Workflow**
- Check "Manual Approval" for safety
- Review diffs before applying
- Can reject changes

✅ **Dry-Run Mode**
- Preview what agent will do
- No files modified
- Perfect for learning

## Troubleshooting

### Agent Loops Indefinitely
- ✅ **Fixed!** Now uses intelligent fallback
- If still occurs: reduce max iterations or check goal clarity

### Agent Makes Bad Changes
- Use **Dry-Run** mode first
- Use **Manual Approval** option
- Write more specific goals

### Can't Find Repository
- Verify path is absolute: `/path/to/repo`
- Check path exists and readable
- No spaces in goals field needed

### Agent Seems Slow
- Normal for large codebases
- Check timeout in log messages
- Increase max iterations if needed

## Tips & Tricks

### ✅ DO:
- Start with dry-run to see what it does
- Use specific, clear goals
- Test on a copy first
- Review diffs carefully
- Check live log for progress

### ❌ DON'T:
- Run on production code without backup
- Use vague goals ("make better")
- Ignore error messages
- Set max iterations to 100
- Enable shell unless needed

## System Requirements

- Python 3.7+
- PyQt6 (auto-installed with HadesAI)
- 100MB free disk space
- Optional: OpenAI/Mistral API key

## Performance

| Task | Time | Notes |
|------|------|-------|
| Initialize | <1s | Instant |
| Analyze 10 files | 2-5s | Depends on size |
| Run tests | Variable | Depends on test suite |
| Single iteration | 1-5s | Without LLM API |

## Advantages vs Manual Code Review

| Aspect | Agent | Manual |
|--------|-------|--------|
| **Speed** | ⚡ Fast | Slow |
| **Systematic** | Thorough | Can miss issues |
| **Learning** | Improves over time | Constant |
| **Cost** | Free (with fallback) | Your time |
| **Accuracy** | Good | Perfect |
| **24/7** | Yes | No |

## Common Use Cases

### 1. Code Exploration
Learn a new codebase by letting the agent explore it

### 2. Code Quality
Improve style, documentation, and structure

### 3. Bug Finding
Analyze code for potential issues

### 4. Test Analysis
Understand failing tests and fix them

### 5. Dependency Review
Check imports and external dependencies

### 6. Refactoring
Organize code and remove duplication

## Advanced: Using with External LLM

### OpenAI (GPT-4)
```
1. Get API key from https://openai.com/api/
2. Go to Self-Improvement tab
3. Select "OpenAI"
4. Paste API key
5. Start agent (now uses GPT-4!)
```

### Ollama (Local - Free)
```
1. Install Ollama from https://ollama.ai
2. Run: ollama pull llama2
3. Go to Self-Improvement tab
4. Select "Ollama"
5. Start agent (uses local LLM!)
```

### Mistral AI
```
1. Get API key from https://mistral.ai/
2. Go to Self-Improvement tab
3. Select "Mistral"
4. Paste API key
5. Start agent
```

## FAQ

**Q: Does it need internet?**
A: No! Works offline with fallback LLM. Optional for external APIs.

**Q: Can it modify my files?**
A: Yes, with dry-run off. Always backup first or use dry-run.

**Q: How many iterations do I need?**
A: Start with 15. Increase for complex tasks, decrease for quick checks.

**Q: Can I stop it mid-run?**
A: Yes! Click "⏹ Stop" button anytime.

**Q: What if it makes mistakes?**
A: Check `.bak` files for backups, or use dry-run first.

**Q: Can it handle my language?**
A: Yes for Python, JS, Java, C++. Others: requires fallback LLM.

**Q: Is my code safe?**
A: Yes. All files stay local. No upload to cloud (unless using external LLM).

## Support

- **Documentation**: See AUTONOMOUS_AGENT_INTEGRATION.md
- **Quick Reference**: See AGENT_QUICKSTART.md
- **Technical Details**: See FALLBACK_LLM_FIX.md
- **Verification**: See VERIFICATION_REPORT.md

## Summary

The autonomous agent is your AI-powered code analyzer that:
- ✅ Works without setup (uses fallback LLM)
- ✅ Works with any external LLM (optional)
- ✅ Never gets stuck in loops
- ✅ Provides real-time progress
- ✅ Helps you understand code
- ✅ Saves you time

**Start analyzing code now!** 🚀

---

**Version**: 1.0
**Status**: Production Ready ✅
**Last Updated**: 2026-01-26
