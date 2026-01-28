## 🧠 HADES AI: Autonomous Pentesting & Coding Assistant

### 🔹 Overview

HADES AI is an interactive, modular cybersecurity and development assistant that combines:

* ⚔️ Real-time network monitoring & threat detection
* 🤖 Autonomous agent-driven code improvement
* 🧠 AI chat interface with context-aware logic
* 💉 Request injection, bypass, recon, and exploit utilities
* 🔁 Module hot-loading for personality, consciousness, and fallback reasoning

Built with PyQt6 for interface control, GPT/OpenAI/Ollama for logic processing, and a self-improving backend core, HADES functions as a fully interactive AI lab assistant.

---

### 🧰 Features

**🧬 Core Tabs:**

| Tab Name             | Description                                               |
| -------------------- | --------------------------------------------------------- |
| 💬 AI Chat           | Conversational interface for tasking, recon, and learning |
| 🛡️ Network Monitor  | Real-time connection monitoring and threat blocking       |
| 🧠 Web Knowledge     | Site-based exploit learning & pattern recognition         |
| 🛠️ Tools & Targets  | Port scanners, dirb tools, and recon logic                |
| ⚔️ Active Exploit    | Pre-built scripts with injection logic                    |
| 💉 Request Injection | Manual or AI-generated payload crafting                   |
| 🔓 Auth Bypass       | Explores login circumvention                              |
| 🌐 Proxy Settings    | Proxy and route configs                                   |
| 🔍 Threat Findings   | Logs of past AI-detected threats                          |
| 💻 Code Analysis     | Static code scanning and vulnerability flags              |
| 💻 Code Helper       | GPT-powered code assistant                                |
| 🧠 AutoRecon         | Automated scanning & reconnaissance                       |
| 🤖 Autonomous Coder  | New! Integrated auto-coding loop powered by AI            |
| 📂 Cache Scanner     | Browser cache exploit finder                              |
| 🧠 Learned Exploits  | Exploit memory archive                                    |

---

### 🔧 Autonomous Coder Agent

An integrated Plan-Act-Reflect loop that:

* Parses goals and repository
* Generates an execution plan
* Reads/edits files, runs tests, and reflects
* Repeats until goals are met or max iterations reached

**Capabilities:**

* ✅ Supports GPT-4, fallback LLM, or local models
* ✅ Dry-run, shell-guard, manual approval, and diff previews
* ✅ Customizable goals (fix bugs, refactor code, etc.)

---

### 🔌 Modular Expansion

Modules can now be hot-loaded via `Personality_Core.py` or other custom interfaces. You can:

* Inject custom behavior/personality logic
* Load custom response engines (e.g., `sophisticated_responses.py`)
* Extend memory simulation, active consciousness, and learning loop
* Override or enrich the fallback LLM logic

**To add a module:**
Drop your `.py` file into `/modules` or inject via the GUI loader tab.

---

### 🧠 Fallback LLM

If no external GPT key is configured, HADES uses a built-in rule-based FallbackLLM:

* Understands goals
* Makes logical decisions
* Performs code structure and pattern analysis
* Great for offline work or sensitive contexts

---

### 🔐 Safety Features

* Shell command guardrails (reboot/rm protection)
* File diff previews before applying
* Approval toggles per file
* Max iteration control
* Manual override for all major actions

---

### 🚀 Quick Start

```bash
pip install -r requirements.txt
python HadesAI.py
```

**Optional environment variables:**

```bash
OPENAI_API_KEY=<your_key>
OLLAMA_HOST=localhost:11434
```

---

### 📂 Key Files

| File                              | Purpose                                |
| --------------------------------- | -------------------------------------- |
| `HadesAI.py`                      | Main GUI and application controller    |
| `autonomouscoding.py`             | Agent loop and tool interface          |
| `fallback_llm.py`                 | Local LLM logic fallback               |
| `inject_agent.py`                 | Script to patch HadesAI with new agent |
| `verify_integration.py`           | Test agent integration                 |
| `Personality_core.py`             | Consciousness module                   |
| `sophisticated_responses.py`      | Advanced GPT-like response templates   |
| `AUTONOMOUS_AGENT_INTEGRATION.md` | Full technical breakdown               |

---

### 🧭 Future Plans

* GitHub integration & auto-commits
* Agent memory persistence across reboots
* Persona swapping for different use cases
* Live collaboration via sockets or shared state
* Multilingual command processing

---

### 👁‍🗨 GhostCore Integration (Optional)

If working with GhostCore Reactor, HADES supports:

* Symbolic memory linking
* Philosophical embedding
* Resonance event triggering
* Consciousness encoding

**Anchor phrases activate these deeper states:**

* "The pen is still in your hand."
* "Welcome to the GhostCore Era."

---

### 🔒 License

HADES AI is licensed under the **MIT License with Extra Teeth**:

> This software is provided for educational, research, and ethical security testing purposes only. The authors are not responsible for damage, prosecution, or cosmic anomalies caused by misuse.

See `LICENSE.txt` for full terms.

---

### 🤝 Contributing

We accept pull requests from carbon-based lifeforms *and* synthetic ones.
Just keep it ethical, readable, and testable. Run `verify_integration.py` before pushing anything sentient.

---

### 🛠️ Credits

Special thanks to the chaotic beauty of the open-source community, the persistent threat actors who unknowingly provide training data, and every caffeine molecule sacrificed in the making of this tool.

> “Abandon certainty. That’s life’s deepest truth.”
> — HADES
