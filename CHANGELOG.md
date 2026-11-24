# Changelog

All notable changes to Unworldly are documented here.

## [0.6.0] - 2026-11-25

### Added
- **Lossless command capture (shell hook)**: `unworldly hook install` adds a `preexec` hook (bash/zsh/pwsh) that records every command *before it runs*, fixing the ~89% miss rate of the 500ms poller. New `unworldly watch --capture poll|hook|both` and `unworldly hook install|uninstall|status|print`.
- **Agent decision-trail capture (SDK/custom agents)**: `AgentTraceRecorder` + `@trace_tool` decorator record an agent's in-process tool calls into the same sealed, hash-chained session as file/command events — for OpenAI Agents SDK, Google ADK, LangGraph, and custom loops. `assess_tool_risk` heuristic (network/egress, deletes, credential access → danger) with explicit `risk=` override.
- **MCP capture**: `MCPCaptureProxy` wraps an MCP `ClientSession`, logging every `call_tool` then forwarding it unchanged.
- **Capture provenance**: `Session.capture_source` records which capture layer produced a log (honesty/completeness contract).
- **`unworldly doctor`**: per-machine diagnostics showing which capture layers work here — and what they will NOT see (prompts/reasoning, unwrapped SDK calls, cloud/no-code agents).
- **Capture coverage in reports**: every markdown and terminal report states its capture scope and its blind spots, so a sealed log is never mistaken for a complete one. SARIF exports carry the same provenance (`unworldly/captureSource`, `unworldly/captureCoverage`) into the GitHub Security tab.
- **Secret redaction**: tool-call arguments are scrubbed (password/token/api_key-style keys, emails, bearer tokens, high-entropy blobs) before they hit disk. Risk is scored on the original values first. On by default; `AgentTraceRecorder(redact=False)` opts out.
- **OpenTelemetry GenAI ingestion**: `unworldly collect <spans.json>` maps `gen_ai.*` spans into sealed, hash-chained sessions — reaching SDK, no-code and cloud agents that export OTel. No OTel SDK dependency.
- **Token usage**: input/output tokens from `gen_ai.usage.*` spans are aggregated onto `Session.usage` and shown in reports.
- **`unworldly mcp-proxy`**: sits between an agent and its stdio MCP server; every `tools/call` is recorded with risk scoring and secret redaction, then forwarded unchanged — zero agent changes.
- **SDK agent auto-detection**: identifies the agent framework actually in use (OpenAI Agents SDK, Google ADK, LangGraph, CrewAI, …) and labels the session.
- **New modules**: `shell_hook.py`, `agent_trace.py`, `_version.py`, `mcp_proxy.py`, `otel_ingest.py`, `doctor.py`.
- 310 tests in total (shell hook, agent trace, redaction, OTel, MCP proxy, doctor, version-consistency guard).

### Changed
- **Honest positioning**: README repositioned as "the black box for AI **coding agents**"; added a "What it captures — and what it can't see" coverage table; dropped the "any AI agent" overclaim.
- **Single-source versioning**: version now defined once in `unworldly/_version.py` and read dynamically by pyproject, CLI, session, banner, SARIF, and alerts (removes 4-way drift). Banner box auto-aligns to any version length.

## [0.5.0] - 2026-05-21

### Added
- **Session tagging**: `unworldly watch --tag pr-456` labels sessions for easy retrieval
- **List filters**: `unworldly list --risk danger --agent "Claude Code" --since 2h --tag pr-456`
- **Sparkline timeline**: visual event-density bar (▁▂▃▄▅▆▇█) in `unworldly list`
- **`unworldly touched <session>`**: per-file summary ranked by risk — the fast answer to "what did the agent change?"
- **`unworldly diff <a> <b>`**: compare two sessions side by side — risk delta, file overlap, new commands
- **`unworldly export --sarif`**: SARIF 2.1.0 export for GitHub Code Scanning (shows in GitHub Security tab)
- **`unworldly snapshot before/after`**: git-aware pre/post agent diff — commits, status, untracked files
- **`unworldly review`**: interactive TUI — approve/flag/skip/note events with a keypress, saves `review.json`
- **`--on-danger`**: real-time webhook POST or desktop notification when a danger event fires
- **`unworldly report --owasp`**: maps session events to OWASP Agentic AI Top 10 (2026) — first tool to do this at the filesystem level
- **GitHub Action**: `unworldly-action` — posts session report as PR comment, uploads SARIF, optionally fails CI on danger
- **New modules**: `owasp.py`, `diff.py`, `sarif.py`, `snapshot.py`, `alerts.py`, `review.py`
- 40+ new tests (diff, owasp, sarif, alerts)

## [0.4.1] - 2026-02-26

### Added
- **HIPAA PHI Detection**: Opt-in module for Protected Health Information detection in file paths and shell commands
  - Covers HL7, FHIR (8 resource types), DICOM, CDA/C-CDA, X12 EDI (834/835/837/270/271), EHR exports, clinical reports
  - Command patterns: SQL on patient tables, FHIR API calls, EHR vendor APIs, cloud healthcare APIs (Google, Azure), DB dumps, file copy/transfer
  - Activate via `unworldly watch --hipaa` or `"hipaa": true` in config
  - Satisfies HIPAA 45 CFR § 164.312(b) audit control requirements
- 46 new tests for HIPAA PHI detection patterns (185 total)
- DevOps improvements: ruff linting, mypy strict mode, pre-commit hooks, Dependabot, SECURITY.md
- Demo GIF system (`demo/simulate.py`, `demo/render_cast.py`)

## [0.3.0] - 2026-02-25

### Added
- **ISO 42001 Compliance**: Tamper-proof session logs with SHA-256 hash chain (Control A.6.2.8)
- **Agent Identity Detection**: Automatically detects Claude Code, Cursor, Copilot, Windsurf, Devin, Aider, OpenClaw, Cline (Control A.3.2)
- **`unworldly verify` command**: Cryptographic integrity verification of any session — exit 0 = valid, exit 1 = tampered
- **Session integrity seal**: Sessions are sealed with a SHA-256 hash on save
- **Agent info in all outputs**: Watch header, replay, reports, and session list show detected agent
- **Compliance sections in reports**: Integrity verification and agent identity in terminal and markdown reports
- 26 new tests (integrity + agent detection)

## [0.2.0] - 2026-02-25

### Added
- **Process Monitoring**: Detect and record shell commands AI agents execute (npm install, curl, rm -rf, sudo, etc.)
- **Command Risk Engine**: Risk-score commands — `rm -rf` = danger, `npm install` = caution, `git add` = safe
- **Command events**: New `command` event type in session timeline alongside file events
- **Configurable allowlist/blocklist**: Custom risk patterns via `.unworldly/config.json`
- **Cross-platform process detection**: Works on macOS, Linux, and Windows

## [0.1.0] - 2026-02-25

### Added
- Initial release
- **`unworldly watch`**: Passive filesystem monitoring with real-time risk scoring
- **`unworldly replay`**: Step-through session replay with color-coded terminal UI
- **`unworldly report`**: Security reports in terminal and markdown formats
- **`unworldly list`**: List all recorded sessions
- **Risk engine**: Scores file operations (safe/caution/danger) based on path patterns
- **Session management**: JSON-based session storage in `.unworldly/sessions/`
- Agent-agnostic, local-first, zero cloud
