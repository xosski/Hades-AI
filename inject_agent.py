#!/usr/bin/env python3
"""
Script to inject autonomous agent methods into HadesAI.py
"""

# Read the HadesAI.py file
with open('HadesAI.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the location to insert (before "class AutoReconScanner")
insert_marker = "class AutoReconScanner(QThread):"
insert_pos = content.find(insert_marker)

if insert_pos == -1:
    print("ERROR: Could not find insertion marker")
    exit(1)

# Agent methods to insert
agent_methods = '''
    # ========== AUTONOMOUS CODING AGENT ==========

    def _create_agent_tab(self) -> QWidget:
        """Create the Autonomous Coding Agent configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        form = QGroupBox("Agent Configuration")
        form_layout = QFormLayout(form)

        self.agent_repo = QLineEdit()
        self.agent_repo.setPlaceholderText("Path to local repo (workspace)")
        form_layout.addRow("Repository:", self.agent_repo)

        self.agent_goals = QPlainTextEdit()
        self.agent_goals.setPlaceholderText("Describe goals, e.g.\\n- Fix failing tests\\n- Refactor module X\\n- Add missing docstrings")
        self.agent_goals.setMinimumHeight(80)
        form_layout.addRow("Goals:", self.agent_goals)

        self.agent_test_cmd = QLineEdit()
        self.agent_test_cmd.setText("pytest -q")
        form_layout.addRow("Test Command:", self.agent_test_cmd)

        self.agent_iters = QSpinBox()
        self.agent_iters.setRange(1, 100)
        self.agent_iters.setValue(15)
        form_layout.addRow("Max Iterations:", self.agent_iters)

        self.agent_dry = QCheckBox("Dry-Run (no file writes)")
        self.agent_shell = QCheckBox("Allow shell commands (guarded)")
        self.agent_approve = QCheckBox("Require manual approval for file writes")
        flags_row = QHBoxLayout()
        flags_row.addWidget(self.agent_dry)
        flags_row.addWidget(self.agent_shell)
        flags_row.addWidget(self.agent_approve)
        flags_wrap = QWidget()
        flags_wrap.setLayout(flags_row)
        form_layout.addRow("Options:", flags_wrap)

        layout.addWidget(form)

        # Controls
        ctrl = QHBoxLayout()
        self.agent_start = QPushButton("▶ Start Agent")
        self.agent_start.clicked.connect(self._start_agent)
        self.agent_stop = QPushButton("⏹ Stop")
        self.agent_stop.setEnabled(False)
        self.agent_stop.clicked.connect(self._stop_agent)
        ctrl.addWidget(self.agent_start)
        ctrl.addWidget(self.agent_stop)
        ctrl.addStretch()
        layout.addLayout(ctrl)

        # Live log
        self.agent_log = QPlainTextEdit()
        self.agent_log.setReadOnly(True)
        self.agent_log.setFont(QFont("Consolas", 10))
        self.agent_log.setMinimumHeight(220)
        layout.addWidget(self.agent_log)

        # Diff preview
        diff_group = QGroupBox("Proposed/Applied Diff")
        diff_layout = QVBoxLayout(diff_group)
        self.agent_diff_path = QLabel("-")
        self.agent_diff_view = QPlainTextEdit()
        self.agent_diff_view.setReadOnly(True)
        self.agent_diff_view.setFont(QFont("Consolas", 9))

        approve_row = QHBoxLayout()
        self.agent_approve_btn = QPushButton("✅ Approve Write")
        self.agent_approve_btn.setEnabled(False)
        self.agent_approve_btn.clicked.connect(self._approve_write)
        self.agent_reject_btn = QPushButton("❌ Reject")
        self.agent_reject_btn.setEnabled(False)
        self.agent_reject_btn.clicked.connect(self._reject_write)
        approve_row.addWidget(self.agent_approve_btn)
        approve_row.addWidget(self.agent_reject_btn)
        approve_row.addStretch()

        diff_layout.addWidget(QLabel("File:"))
        diff_layout.addWidget(self.agent_diff_path)
        diff_layout.addWidget(self.agent_diff_view)
        diff_layout.addLayout(approve_row)

        layout.addWidget(diff_group)
        return widget

    def _agent_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Autonomous agent LLM interface"""
        try:
            if hasattr(self, "ai") and self.ai and hasattr(self.ai, "openai_client"):
                if self.ai.openai_client:
                    response = self.ai.openai_client.chat.completions.create(
                        model="gpt-4",
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        temperature=0.2,
                        max_tokens=1800
                    )
                    return response.choices[0].message.content
        except Exception as e:
            logging.error(f"LLM Error: {e}")
        return '{"tool":"run_tests","args":{},"rationale":"No AI configured; running tests as default."}'

    def _start_agent(self):
        """Start the autonomous coding agent"""
        repo = self.agent_repo.text().strip()
        goals = self.agent_goals.toPlainText().strip()
        test_cmd = self.agent_test_cmd.text().strip() or "pytest -q"
        max_iters = self.agent_iters.value()
        dry_run = self.agent_dry.isChecked()
        allow_shell = self.agent_shell.isChecked()
        approval_req = self.agent_approve.isChecked()

        if not repo or not os.path.isdir(repo):
            QMessageBox.warning(self, "Agent", "Please provide a valid local repository path.")
            return
        if not goals:
            QMessageBox.warning(self, "Agent", "Please describe the agent goals.")
            return

        self.agent_log.clear()
        self.agent_diff_view.clear()
        self.agent_diff_path.setText("-")

        # Start background agent
        self._agent = AutonomousCodingAgent(
            repo_path=repo,
            goals=goals,
            test_cmd=test_cmd,
            llm=self._agent_llm,
            kb=self.ai.kb,
            max_iters=max_iters,
            dry_run=dry_run,
            allow_shell=allow_shell,
            approval_required=approval_req,
        )
        self._agent.log.connect(self._on_agent_log)
        self._agent.progress.connect(lambda v: self.status_bar.showMessage(f"Agent progress: {v}%"))
        self._agent.diff_ready.connect(self._on_agent_diff)
        self._agent.finished.connect(self._on_agent_finished)
        self._agent.start()

        self.agent_start.setEnabled(False)
        self.agent_stop.setEnabled(True)
        self._add_chat_message("system", "🤖 Autonomous Coding Agent started")

    def _stop_agent(self):
        """Stop the autonomous coding agent"""
        if hasattr(self, "_agent") and self._agent and self._agent.isRunning():
            self._agent.stop()
            self._agent.wait(2000)
        self.agent_start.setEnabled(True)
        self.agent_stop.setEnabled(False)
        self._add_chat_message("system", "🛑 Agent stopped by user")

    def _on_agent_log(self, text: str):
        """Handle agent log output"""
        self.agent_log.appendPlainText(text)
        self.agent_log.verticalScrollBar().setValue(self.agent_log.verticalScrollBar().maximum())

    def _on_agent_diff(self, data: Dict):
        """Handle agent diff output"""
        self.agent_diff_path.setText(data.get("path", "-"))
        self.agent_diff_view.setPlainText(data.get("diff", "") or data.get("preview", ""))
        needs_approval = self.agent_approve.isChecked() and not self.agent_dry.isChecked()
        self.agent_approve_btn.setEnabled(needs_approval)
        self.agent_reject_btn.setEnabled(needs_approval)

    def _approve_write(self):
        """Approve a file write"""
        self.agent_approve_btn.setEnabled(False)
        self.agent_reject_btn.setEnabled(False)
        self._on_agent_log("✅ Manual approval acknowledged (note: current agent applies immediately).")

    def _reject_write(self):
        """Reject a file write"""
        self.agent_approve_btn.setEnabled(False)
        self.agent_reject_btn.setEnabled(False)
        self._on_agent_log("❌ Manual rejection acknowledged (note: revert manually if needed).")

    def _on_agent_finished(self, result: Dict):
        """Handle agent completion"""
        success = result.get("success", False)
        summ = result.get("summary", "")
        errs = result.get("errors", [])
        self._add_chat_message("assistant", f"🤖 Agent finished. Success={success}. {summ}\\nErrors: {errs[-1] if errs else 'None'}")
        self.agent_start.setEnabled(True)
        self.agent_stop.setEnabled(False)

'''

# Insert the methods
new_content = content[:insert_pos] + agent_methods + "\n\n" + content[insert_pos:]

# Write back
with open('HadesAI.py', 'w', encoding='utf-8') as f:
    f.write(new_content)

print("[SUCCESS] Agent methods added successfully to HadesAI.py")
