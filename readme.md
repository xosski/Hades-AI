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

### Persistent Cognitive Architecture

HADES now connects its long-term memory, self-model, reflection system, and
loaded-module registry into the canonical chat path:

```text
Input -> memory retrieval -> self-model -> module analysis -> response
      -> outcome reflection -> candidate lesson -> evidence consolidation
```

The cognitive layer in `modules/cognitive_memory.py` provides:

* **Typed memory:** working, episodic, semantic, procedural,
  autobiographical, goal, and provisional candidate memories.
* **Explicit provenance:** `USER_STATED`, `OBSERVED`, `MODEL_INFERRED`,
  `EXTERNAL_VERIFIED`, `SELF_REFLECTION`, and `SIMULATED` origins remain
  distinguishable during retrieval and consolidation.
* **Evidence metadata:** confidence, supporting memory IDs, verification time,
  contradictions, reinforcement, revisions, and append-only event history.
* **Persistent self-model:** identity, capabilities, limitations, goals,
  preferences, beliefs, uncertainties, known failures, learned strategies,
  relationships, and an autobiographical summary.
* **Structured reflection:** each completed LLM response records what happened,
  the expected outcome, whether an external outcome was observed, assumptions,
  recalled memories, successful strategy, proposed change, confidence, and
  contradictions.
* **Safe consolidation:** automatic reflections are provisional candidates and
  are excluded from ordinary factual recall. Promotion requires sufficient
  admissible evidence, confidence, and no unresolved contradiction.
* **Adaptive planning:** evidence-backed strategies and provisional planning
  hints are included in future hidden response context.

An automatically generated response only proves that the interaction occurred;
it does not verify the truth of claims inside that response. Automatic reviews
therefore mark the user's eventual outcome as unobserved until feedback exists.

This architecture implements persistent, reflective agent behavior. It is not
presented as proof of consciousness or philosophical free will.

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

Modules can be hot-loaded from the GUI or with the existing module commands.
Every loaded module is now described to cognitive memory without executing its
entry points. HADES analyzes module names, documentation, declared capabilities,
public callables, and supported hooks against the current request.

* Inject custom behavior/personality logic
* Load custom response engines (e.g., `sophisticated_responses.py`)
* Extend memory, response planning, and learning behavior
* Override or enrich the fallback LLM logic
* Let the cognitive router recommend relevant loaded capabilities
* Set persistent routing preferences through the self-model

Module execution boundaries are preserved:

| Hook | Cognitive behavior |
| ---- | ------------------ |
| `process_response(brain, user_input, response)` | May be selected and applied automatically |
| `enhance_output(response)` | May be selected and applied automatically |
| `main()` | Recommended when relevant, but requires explicit user execution |

Module routing decisions and applied-module outcomes are retained as cognitive
context. A module that is loaded but irrelevant to the current request is not
automatically applied to the response.

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

### Chrome and Edge Extension

Hades can run as a local browser pentesting companion using the Manifest V3 extension in `browser_extension/`. The extension provides a side-panel interface while the Python companion keeps Hades modules, databases, LLM credentials, and authorization enforcement on the local machine.

**Available browser capabilities:**

* Passive analysis of the active HTTP(S) page
* Hades AI chat using page and finding context
* Local CVE and Exploit Tome search
* Browser-cache detection history
* Payload catalog, confidence scoring, mutation, and confirmed same-origin delivery
* Finding validation and Markdown report export
* Deterministic SQL injection, reflected-XSS, and path-traversal checks
* Asynchronous TCP port scanning with full-range progress and service names
* Per-origin authorization, active/passive scopes, and active-test audit history

#### 1. Start the local companion

```bash
pip install -r requirements_llm.txt
python hades_companion.py
```

The companion listens only on `127.0.0.1:8765`. Keep the terminal open and copy the generated pairing token.

#### 2. Load the extension

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose the `browser_extension` directory.
4. Open an HTTP(S) target and select the Hades AI toolbar action.
5. Paste the pairing token, press **Refresh**, approve access to that origin, and record the target authorization.

Use `passive_browser_assessment` for DOM-only analysis. Select `active_web_assessment` only when you have explicit permission to send test requests. Every active test requires an additional confirmation, must remain on the authorized origin, does not follow redirects, and is written to the audit log.

See [`browser_extension/README.md`](browser_extension/README.md) for focused installation instructions.

---

### 📂 Key Files

| File                              | Purpose                                |
| --------------------------------- | -------------------------------------- |
| `HadesAI.py`                      | Main GUI and application controller    |
| `modules/cognitive_memory.py`     | Persistent memory, reflection, self-model, and module routing |
| `hades_companion.py`               | Authenticated local browser API         |
| `hades_headless_modules.py`        | Headless module compatibility layer     |
| `payload_generator_core.py`        | GUI-independent payload catalog         |
| `browser_extension/`               | Chrome and Edge Manifest V3 extension   |
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
* Deeper idle-time semantic consolidation
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
Just keep it ethical, readable, and testable. Cognitive changes should run:

```bash
python -m unittest test_cognitive_loop_integration.py test_memory_channels.py
python test_llm_integration.py
```

---

### 🛠️ Credits

Special thanks to the chaotic beauty of the open-source community, the persistent threat actors who unknowingly provide training data, and every caffeine molecule sacrificed in the making of this tool.

> “Abandon certainty. That’s life’s deepest truth.”
> — HADES
