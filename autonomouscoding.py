import os
import re
import json
import time
import difflib
import shutil
import subprocess
from typing import Callable, Dict, Any, List, Optional

from PyQt6.QtCore import QThread, pyqtSignal


class AutonomousCodingAgent(QThread):
    """
    Plan-Act-Reflect agent for autonomous coding inside a repository.

    Loop:
      1) Plan: Propose next action (read/edit/run/tests) from goals + current observations
      2) Act: Execute tool with guardrails (file boundaries; timeouts)
      3) Reflect: Evaluate results, update memory and continue until goals met or max_iters

    LLM callable signature: llm(system_prompt: str, user_prompt: str) -> str
    """
    log = pyqtSignal(str)
    progress = pyqtSignal(int)
    diff_ready = pyqtSignal(dict)   # {path, diff, preview}
    finished = pyqtSignal(dict)     # {success, iterations, summary, errors}

    def __init__(
        self,
        repo_path: str,
        goals: str,
        test_cmd: str,
        llm: Callable[[str, str], str],
        kb=None,
        max_iters: int = 15,
        dry_run: bool = False,
        allow_shell: bool = False,
        timeout_cmd: int = 60,
        approval_required: bool = False,
    ):
        super().__init__()
        self.repo_path = os.path.abspath(repo_path)
        self.goals = goals.strip()
        self.test_cmd = test_cmd.strip() or "pytest -q"
        self.llm = llm
        self.kb = kb
        self.max_iters = max_iters
        self.dry_run = dry_run
        self.allow_shell = allow_shell
        self.timeout_cmd = timeout_cmd
        self.approval_required = approval_required

        self._stop = False
        self.trajectory: List[Dict[str, Any]] = []
        self.memory: List[str] = []     # short reflections
        self.errors: List[str] = []
        self.started_at = time.time()

        if not os.path.isdir(self.repo_path):
            raise ValueError(f"Repository path not found: {self.repo_path}")

    def stop(self):
        self._stop = True

    # ========== Agent Loop ==========

    def run(self):
        try:
            self._log(f"🤖 Agent starting in: {self.repo_path}")
            self._log(f"🎯 Goals: {self.goals}")
            self._log(f"🧪 Test command: {self.test_cmd}")
            plan = self._initial_plan()

            for it in range(1, self.max_iters + 1):
                if self._stop:
                    break
                self.progress.emit(int(100 * it / max(1, self.max_iters)))

                # Check tests first if plan suggests test-driven
                if it == 1 or ("run_tests" in plan.lower()):
                    ok, out = self._tool_run_tests()
                    self._record("run_tests", {}, ok, out)
                    if ok:
                        self._log("✅ Tests already passing. Goals may be complete.")
                        return self._finish(True, it, "Tests passing")

                # Ask model for next action
                action = self._decide_next_action(plan)
                tool, args, rationale = action.get("tool"), action.get("args", {}), action.get("rationale", "")
                self._log(f"🧭 Iteration {it} - Tool: {tool} | Rationale: {rationale[:140]}")

                ok, observation = self._dispatch_tool(tool, args)
                self._record(tool, args, ok, observation)

                if not ok:
                    self.errors.append(f"{tool} failed: {observation[:200]}")

                # Reflect
                plan = self._reflect_and_update_plan(tool, ok, observation, it)

                # Early stop if tests pass
                if tool in ("run_tests", "run_command") and "passed" in observation.lower():
                    self._log("🎉 Tests PASS indication detected in output.")
                    return self._finish(True, it, "Tests passing")

            # Out of iterations
            self._finish(False, self.max_iters, "Max iterations reached")
        except Exception as e:
            self.errors.append(str(e))
            self._finish(False, 0, f"Exception: {e}")

    # ========== LLM Orchestration ==========

    def _initial_plan(self) -> str:
        sys = "You are an autonomous software engineer optimizing code via tests and minimal changes."
        usr = f"""Repository: {self.repo_path}
Goals: {self.goals}

Provide a short high-level plan (3-6 bullet points)."""
        resp = self.llm(sys, usr) or ""
        self._log("📝 Initial Plan:\n" + resp.strip())
        return resp

    def _decide_next_action(self, plan: str) -> Dict[str, Any]:
        sys = (
            "You are an autonomous coding agent. Choose ONE next action in JSON only (no prose). "
            "Valid tools: read_file, list_files, write_file, run_tests, run_command, search_code.\n"
            "JSON schema:\n"
            '{ "tool": "read_file", "args": {"path":"relative/path.py"}, "rationale": "why" }\n'
        )
        history = self._summarize_trajectory(last=4)
        usr = f"""Goals: {self.goals}
Current Plan (short): {self._shorten(plan, 700)}

Recent steps (summarized):
{history}

Pick the next best tool with minimal arguments. Only output JSON."""
        raw = self.llm(sys, usr) or "{}"
        action = self._safe_json(raw)
        if action.get("tool") not in {"read_file", "list_files", "write_file", "run_tests", "run_command", "search_code"}:
            action = {"tool": "run_tests", "args": {}, "rationale": "Verify baseline before changes"}
        return action

    def _reflect_and_update_plan(self, tool: str, success: bool, observation: str, it: int) -> str:
        self.memory.append(f"Iter {it} {tool}: {'OK' if success else 'FAIL'} - {self._shorten(observation, 180)}")
        memory = "\n".join(self.memory[-6:])
        sys = "You are a concise reflector. Update/trim the plan in <= 6 lines max."
        usr = f"""Goals: {self.goals}
Recent outcome: Tool={tool} Success={success} Observation={self._shorten(observation, 500)}
Agent memory:
{memory}

Update the short plan (concise)."""
        plan = self.llm(sys, usr) or ""
        self._log("♻️ Updated Plan:\n" + self._shorten(plan, 600))
        return plan

    # ========== Tool Dispatcher ==========

    def _dispatch_tool(self, tool: str, args: Dict[str, Any]) -> (bool, str):
        try:
            if tool == "read_file":
                p = args.get("path", "")
                return True, self._tool_read_file(p)
            elif tool == "list_files":
                pat = args.get("pattern", "**/*.py")
                return True, self._tool_list_files(pat)
            elif tool == "write_file":
                p = args.get("path", "")
                content = args.get("content", "")
                return self._tool_write_file(p, content)
            elif tool == "run_tests":
                return self._tool_run_tests()
            elif tool == "run_command":
                cmd = args.get("cmd", "")
                return self._tool_run_command(cmd)
            elif tool == "search_code":
                q = args.get("query", "")
                return True, self._tool_search_code(q)
            else:
                return False, f"Unknown tool: {tool}"
        except Exception as e:
            return False, f"Tool error: {e}"

    # ========== Tools ==========

    def _tool_read_file(self, rel_path: str) -> str:
        path = self._safe_join(rel_path)
        if not os.path.isfile(path):
            return f"[read_file] Not found: {rel_path}"
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        preview = data[:12000]
        self._log(f"📖 Read {rel_path} ({len(data)} bytes)")
        return preview

    def _tool_list_files(self, pattern: str) -> str:
        # Simple recursive list honoring .py as default
        matches = []
        ext = pattern.split(".")[-1] if "." in pattern else ""
        for root, _, files in os.walk(self.repo_path):
            for fn in files:
                if not ext or fn.endswith("." + ext):
                    rel = os.path.relpath(os.path.join(root, fn), self.repo_path)
                    matches.append(rel)
        sample = "\n".join(matches[:200])
        self._log(f"🗂️ {len(matches)} files matched")
        return sample

    def _tool_write_file(self, rel_path: str, new_content: str) -> (bool, str):
        path = self._safe_join(rel_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        old = ""
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                old = f.read()

        if self.dry_run:
            diff = self._unified_diff(old, new_content, rel_path)
            self.diff_ready.emit({"path": rel_path, "diff": diff, "preview": new_content[:800]})
            return True, f"[dry_run] Proposed changes for {rel_path}:\n{diff[:4000]}"

        # backup
        if os.path.exists(path):
            shutil.copy2(path, path + ".bak")

        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)

        diff = self._unified_diff(old, new_content, rel_path)
        self.diff_ready.emit({"path": rel_path, "diff": diff, "preview": new_content[:800]})
        self._log(f"✍️ Wrote {rel_path} ({len(new_content)} bytes)")
        return True, f"[write_file] Updated {rel_path}\n{diff[:2000]}"

    def _tool_run_tests(self) -> (bool, str):
        return self._exec_in_repo(self.test_cmd, timeout=self.timeout_cmd, label="tests")

    def _tool_run_command(self, cmd: str) -> (bool, str):
        if not self.allow_shell:
            return False, "Shell disabled by policy (allow_shell=False)"
        # Basic guardrails: limit dangerous commands
        forbidden = ["rm -rf", ":(){:|:&};:", "mkfs", "shutdown", "reboot"]
        if any(x in cmd for x in forbidden):
            return False, "Forbidden command detected"

        return self._exec_in_repo(cmd, timeout=self.timeout_cmd, label="cmd")

    def _tool_search_code(self, query: str) -> str:
        # Simple grep-like search in repo
        results = []
        for root, _, files in os.walk(self.repo_path):
            for fn in files:
                if fn.endswith(('.py', '.js', '.ts', '.java', '.cpp', '.c', '.h')):
                    fpath = os.path.join(root, fn)
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            for i, line in enumerate(f, 1):
                                if query.lower() in line.lower():
                                    rel = os.path.relpath(fpath, self.repo_path)
                                    results.append(f"{rel}:{i}: {line.strip()}")
                                    if len(results) >= 50:
                                        break
                    except:
                        pass
        return "\n".join(results[:50]) if results else f"[search_code] No matches for '{query}'"

    def _safe_join(self, rel_path: str) -> str:
        # Prevent directory traversal attacks
        path = os.path.normpath(os.path.join(self.repo_path, rel_path))
        if not path.startswith(os.path.normpath(self.repo_path)):
            raise ValueError(f"Path traversal detected: {rel_path}")
        return path

    def _exec_in_repo(self, cmd: str, timeout: int = 60, label: str = "cmd") -> (bool, str):
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            ok = result.returncode == 0
            out = result.stdout + result.stderr
            self._log(f"[{label}] returncode={result.returncode} | {len(out)} bytes output")
            return ok, out
        except subprocess.TimeoutExpired as e:
            return False, f"Timeout after {timeout}s\n{str(e)}"
        except Exception as e:
            return False, f"Exec error: {e}"

    def _unified_diff(self, old: str, new: str, rel_path: str) -> str:
        return "".join(
            difflib.unified_diff(
                old.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                n=3
            )
        )

    def _safe_json(self, s: str) -> Dict[str, Any]:
        # Extract JSON object from possibly verbose LLM output
        try:
            return json.loads(s)
        except:
            match = re.search(r'\{.*\}', s, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except:
                    return {}
        return {}

    def _record(self, tool: str, args: Dict[str, Any], ok: bool, observation: str):
        evt = {
            "tool": tool,
            "args": args,
            "ok": ok,
            "observation": self._shorten(observation, 2000),
            "t": time.time()
        }
        self.trajectory.append(evt)
        # Optional KB persistence
        try:
            if self.kb:
                self.kb.store_experience(
                    source="autonomous_agent",
                    content=f"{tool} -> {ok}\n{self._shorten(observation, 1000)}",
                    tags="agent,autonomous,coding"
                )
        except:
            pass

    def _summarize_trajectory(self, last: int = 4) -> str:
        items = self.trajectory[-last:]
        lines = []
        for i, e in enumerate(items, 1):
            lines.append(f"{i}. {e['tool']}({e.get('args', {})}) -> {'OK' if e['ok'] else 'FAIL'}")
            lines.append(f"   {self._shorten(e['observation'], 160)}")
        return "\n".join(lines) if lines else "No actions yet."

    def _finish(self, success: bool, iterations: int, summary: str):
        took = time.time() - self.started_at
        self._log(f"🏁 Finished (success={success}) in {iterations} iter, {took:.1f}s\nSummary: {summary}")
        self.finished.emit({
            "success": success,
            "iterations": iterations,
            "summary": summary,
            "errors": self.errors[-5:],
        })

    def _shorten(self, s: str, n: int) -> str:
        return s if len(s) <= n else s[:n] + "...(trunc)"

    def _log(self, msg: str):
        self.log.emit(msg)
