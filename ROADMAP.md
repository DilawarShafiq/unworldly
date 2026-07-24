# Unworldly — Development Roadmap

**Vision:** The flight recorder for AI agents — honestly capture *everything every
kind of agent does* (local coding agents, SDK/custom agents, MCP agents, and
cloud/no-code agents), tamper-proof and local-first, so any agent action is
observable, risk-scored, and auditable.

This file is the work queue for autonomous development. Work items top-to-bottom;
check off when **implemented + tested (pytest/ruff/mypy) + committed**. Keep each
change small (constitution: Ship Small). If an item needs a human decision, write
a spec + suggest an ADR and move on — don't guess.

## Guardrails (autonomous mode)
- Every increment MUST pass `pytest`, add no new `ruff` errors over baseline, and
  be `mypy --strict` clean on new/changed modules **before** commit.
- **No `git push`, no PyPI publish, no outward-facing/irreversible actions.**
  Commit locally, tag locally; the maintainer reviews and releases.
- Update this file's checkboxes and `PROGRESS.md` each increment.

## Shipped (v0.6.0)
- [x] L1 lossless shell-hook command capture (`shell_hook.py`)
- [x] L2 tool-call trace recorder + `@trace_tool` (`agent_trace.py`)
- [x] L3 MCP capture proxy (`MCPCaptureProxy`)
- [x] Capture provenance field (`Session.capture_source`)
- [x] Honest README positioning + coverage table
- [x] Single-source versioning + guard tests

## Queue (toward the vision)
- [x] **1. `unworldly doctor`** — diagnostics: which capture layers are active,
      is the shell hook installed, is `wmic`/`ps` available, poll-mode coverage
      warning. Honest self-assessment of what *this* machine will capture.
- [x] **2. Capture provenance in report/replay** — reports state the coverage
      scope of the session's capture layer (US4 / FR-007 acceptance #2).
- [x] **3. Sensitive-argument redaction** in `agent_trace` — redact tokens, keys,
      emails, and long blobs in tool-call params before they hit disk (privacy NFR).
- [~] **4. L4 OpenTelemetry GenAI ingestion** — `unworldly collect`: map OTel
      `gen_ai.*` spans (execute_tool / model calls) to session events, reaching SDK
      and no-code/cloud agents that export OTel.
      DONE: pure span→event mapping (`otel_ingest.py`), `spans_to_session`, file
      ingestion + `unworldly collect <spans.json>`, redaction + risk reuse, tests.
      REMAINING: live OTLP/gRPC receiver endpoint (separate, heavier; needs deps).
- [x] **5. Standalone MCP proxy CLI** — `unworldly mcp-proxy -- <server cmd>` proxies
      MCP stdio, recording every `tools/call` (risk + redaction), no agent code
      change. Interceptor core fully tested; stdio pump is thin plumbing
      (integration-untested live).
- [x] **6. Agent detection for SDK agents** — `detect_sdk_agent()` identifies the
      in-process framework via `sys.modules` (Claude Agent SDK, Google ADK,
      LangGraph, CrewAI, AutoGen, LlamaIndex, OpenAI Agents SDK). `AgentTraceRecorder`
      auto-labels identity when no name is given. Honest: only "in use", not "installed".
- [x] **7. Completeness banner** — md/terminal reports show a Capture Coverage
      section (done in item 2); SARIF export now carries `unworldly/captureSource`
      + `unworldly/captureCoverage` into GitHub Code Scanning.
- [x] **8. eBPF/auditd lossless command capture (Linux)** — SPEC done:
      `specs/lossless-command-capture/spec.md` (auditd-first + eBPF backend, session-scoped,
      opt-in `--capture kernel`, graceful fallback, honesty contract). ADR suggested:
      `kernel-command-capture-backend`. Implementation deferred (root-requiring, platform-heavy).
- [x] **9. Cost/usage tracking** — `extract_usage` reads `gen_ai.usage.*` tokens from
      OTel spans; `spans_to_session` aggregates input/output/total onto `Session.usage`;
      reports show a Token Usage section. Tokens are factual; dollar cost = tokens × your
      model's rate (not guessed).
- [ ] **10. Prompt/reasoning capture (opt-in)** — spec only first (privacy-sensitive);
      requires explicit opt-in and redaction.

## Deferred / needs maintainer decision
- Web dashboard (larger; separate effort)
- ADR: `agent-instrumentation-capture-model` (reuse COMMAND event vs dedicated
  `TOOL` EventType) — pending maintainer consent
