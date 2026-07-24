---
id: 006
title: Close Claim Gap — Shell Hook & Trace Capture
stage: general
date: 2026-07-24
surface: agent
model: claude-opus-4-8
feature: agent-instrumentation
branch: master
user: dilawar.gopang@gmail.com
command: (freeform implementation request)
labels: ["capture", "shell-hook", "mcp", "agent-trace", "positioning", "sdd"]
links:
  spec: specs/agent-instrumentation/spec.md
  ticket: null
  adr: null
  pr: null
files:
 - README.md (repositioned + honest capture table + SDK/MCP usage)
 - unworldly/shell_hook.py (new — lossless shell-hook capture)
 - unworldly/agent_trace.py (new — AgentTraceRecorder, trace_tool, MCPCaptureProxy, assess_tool_risk)
 - unworldly/watcher.py (capture=poll|hook|both)
 - unworldly/cli.py (hook install/uninstall/status/print; watch --capture)
 - unworldly/types.py (Session.capture_source)
 - unworldly/__init__.py (exports)
 - specs/agent-instrumentation/spec.md (new — capture layers L1–L4)
 - tests/test_shell_hook.py (new — 26 tests)
 - tests/test_agent_trace.py (new — 18 tests)
tests:
 - pytest: 254 passed (44 new)
 - ruff: clean on new modules
 - mypy --strict: clean on new modules
---

## Prompt

does this records AI Agents work? We have agents development kits and custom agents and no code agents: is my project best for what it claims?
Why whatever we claim is not happening?
yes do both options and even more as well

## Response snapshot

**Diagnosis (empirical):** `git --version` lives ~57ms; command monitor polls every 500ms → ~89% of commands never seen. Root cause is architectural: recorder is an external OS observer (watchdog + ps/wmic polling), never connected to the agent, so it captures side-effects, not the agent's decision trail. SDK/in-process tool calls and no-code/cloud agents leave no local trace → invisible. "Zero Interference" (passive) is the *cause* of incompleteness; sealing an incomplete log gives false assurance.

**Delivered (3 commits on master):**
- Option A: README repositioned to "black box for coding agents"; added honest "What it captures / can't see" table; killed "any AI agent" overclaim.
- L1 lossless capture: `shell_hook.py` (bash/zsh/pwsh preexec → `.unworldly/commands.log`, tailed by `ShellHookMonitor`); `unworldly hook install|uninstall|status|print`; `watch --capture poll|hook|both`.
- L2/L3 decision-trail capture: `agent_trace.py` — `AgentTraceRecorder`, `@trace_tool` decorator, `MCPCaptureProxy`, `assess_tool_risk`; reuses existing hash-chain/seal; `Session.capture_source` provenance.
- SDD spec `specs/agent-instrumentation/spec.md` defining capture layers L1–L4; L4 (OTel GenAI) spec-only.
- 44 new tests; 254 total pass; ruff + mypy --strict clean on new code.

**Not done (surfaced to user):** L4 OTel implementation; version bump + CHANGELOG + PyPI release; ADR `agent-instrumentation-capture-model` (reuse COMMAND event vs dedicated TOOL type) pending consent.

## Outcome

- ✅ Impact: Made the product claim substantially true — decision-trail capture now exists for SDK/MCP agents, and command capture can be lossless.
- 🧪 Tests: 254 passed (44 new); ruff + mypy --strict clean on new modules.
- 📁 Files: 2 new core modules, 2 new test files, 1 spec, 5 edited.
- 🔁 Next prompts: implement L4 OTel ingestion; bump version + release; create ADR.
- 🧠 Reflection: Reused session/integrity primitives instead of a new event type to keep the diff small and non-destabilizing; flagged the dedicated-TOOL-type refactor as an ADR.

## Evaluation notes (flywheel)

- Failure modes observed: original 500ms polling structurally lossy; passive-only design cannot see in-process agent work.
- Graders run and results (PASS/FAIL): tests PASS, ruff PASS, mypy --strict PASS.
- Prompt variant (if applicable): N/A
- Next experiment (smallest change to try): implement OTel GenAI span → session-event mapping behind an optional extra.
