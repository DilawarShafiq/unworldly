# Changelog

All notable changes to Unworldly are documented here.

## [0.8.3] - 2026-11-25

### Fixed
- **File recording could stop on Windows.** When a file vanished right after being created (a temp file renamed away, including Unworldly's own atomic session save added in 0.8.2), resolving its path returned Windows' `\?\C:\…` form and the path comparison crashed the file-watcher thread, silently ending file recording for the rest of the session. Paths are now normalised, and a single bad event can no longer stop the watcher.
- **Executables in folders with spaces** (`C:\Program Files\…`) were split at the space and recorded as `Program Files\…`. The original argument list is now kept.

## [0.8.2] - 2026-11-25

### Changed
- **Long sessions no longer slow down.** The whole session file used to be rewritten after every event, so the cost grew with the session (2,000 events took ~38 s of CPU). Signed sessions are now rewritten in full at most once a second; records in between go straight to a small append-only crash journal (`<id>.journal.jsonl`). 2,000 events now take ~2.3 s.
- The session file is written atomically (temp file + rename), so a reader never sees a half-written file.

### Added
- **Crash recovery.** If the recorder stops before its last full save, `load_session` replays the journal. Recovered records must still carry valid forward-secure signatures, so a forged journal line is reported as TAMPERED; `verify` notes how many records were recovered.

## [0.8.1] - 2026-11-25

### Fixed
- **Garbled paths behind symlinks (macOS).** When the project or home folder is reached through a symlink (on macOS, `/var` → `/private/var`), the file watcher reports the real path, and events came out as `~/../../private/var/…/.ssh/authorized_keys` or similar. `watch` now resolves real paths on both sides, so paths read `~/.ssh/authorized_keys` and `app.py` as intended.

## [0.8.0] - 2026-11-25

### Added
- **Who ran it.** Each captured command is marked `agent` or `other` by tracing its parent processes to the agent's own process (Claude Code's `CLAUDE_PID`, or the agent's known process names). With no agent identified, nothing is guessed. Reports gain a "Run by" column and a count of commands not run by the agent; `replay` flags them.
- **Outside the project.** `watch` also watches `~/.ssh`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.gnupg`, `~/.docker`, shell startup files, PowerShell profiles, `~/.gitconfig`, `~/.npmrc`, `~/.pypirc` and `~/.netrc` for writes, recorded as danger (`known_hosts` as caution). Paths only, never content. `--no-outside` turns it off.
- **What changed inside files.** File events record before/after SHA-256 and a unified diff (vs the previous version seen in the session, else the last commit), capped at 200 lines / 16 KB, with secrets redacted. Danger-level files (credentials, keys, `.env`, PHI), binaries and files over 256 KB are never diffed; files over 5 MB are hashed as `tooLarge`. All of it is signed with the event.
- **`unworldly show <n> [session]`** prints one event in full: who ran it, parent processes, hashes and the coloured diff. Markdown reports include a File Changes section.
- **Agent model and version**: detected from env vars (`ANTHROPIC_MODEL`, `CLAUDE_MODEL`, `OPENAI_MODEL`, `AIDER_MODEL`) or the agent's `--model` argument, or set with `watch --model / --agent-version`. Shown in `watch`, reports and the session.
- `redact_text()` for free text (used for diffs).

### Fixed
- **Agent detection on Windows** no longer calls `wmic` (removed from newer Windows) or `tasklist`; it uses `psutil`.
- **False identity:** having `ANTHROPIC_API_KEY` set no longer reports Claude Code. Claude Code is detected via `CLAUDECODE` / `CLAUDE_CODE_ENTRYPOINT`.
- Unworldly's own helper processes (e.g. its `git` calls) are no longer recorded as commands.
- Secret redaction now removes the token itself from `Authorization: Bearer …` lines.

### Changed
- Process polling fetches the parent-process table only when new processes appear (about 10 ms on Windows) and caches process names, keeping the CPU budget.
- Fields added in 0.8 are hashed only when present, so 0.6 and 0.7 sessions still verify.

## [0.7.0] - 2026-11-25

### Added
- **Signed, forward-secure sessions.** Every event is signed with a one-time Ed25519 key; the next key's public half is committed inside the signature and the private key is destroyed. Someone who later steals the recorder's key cannot alter, remove or reorder anything already recorded, and recomputing the SHA-256 hashes (which defeated unsigned sessions) no longer passes `verify`.
- **Identity key** in the OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service), falling back to an owner-only key file. It signs each session's start and its final seal; `verify` and `doctor` show the identity fingerprint and where the key lives.
- **Heartbeats and recording gaps.** `watch` writes a signed heartbeat every 30 s and a signed end on clean shutdown. `verify` reports gaps and abnormal ends (recorder killed or paused, or the tail of a session cut off).
- **`verify` results:** VERIFIED, VERIFIED WITH GAPS, TAMPERED, or LEGACY (unsigned, pre-0.7). New `--strict` flag: exit 2 for gaps / abnormal end, 3 for legacy. Default exit codes are unchanged (0 = not tampered, 1 = tampered).
- Sessions from `AgentTraceRecorder`, `mcp-proxy` and `collect` are signed the same way.
- 22 new tests, including a simulated attacker holding the recorder's live key.

### Changed
- README: integrity claim upgraded from tamper-evident to **tamper-resistant**, with a "Session Integrity" section stating exactly what is and isn't protected.
- New dependencies: `cryptography` (Ed25519) and `keyring` (OS keychain).
- Session format: events gain `seq`, `signature`, `nextPublicKey`; sessions gain `signing`, `checkpoints`, `endSeal`. Older sessions still load and verify as legacy.

## [0.6.1] - 2026-11-25

### Fixed
- **Command capture on Windows**: `watch` recorded no commands on newer Windows, where `wmic` has been removed, and failed silently. Process listing now uses `psutil` on every platform (no helper processes spawned; also fixes macOS, whose `ps` lacks `--no-headers`).
- **Dropped commands**: the internal-process filter matched name fragments, so real commands such as `psql` (contains "ps") and every `powershell` command were never recorded. It now matches whole executable names, and skips shells only when started bare.
- **Silent failure**: if process listing cannot work on a machine, `watch` now says so at start instead of silently recording no commands.
- **`doctor`**: probes the real process-listing backend; reports `unworldly collect` (OTel file import) and `unworldly mcp-proxy` as available.

### Changed
- **Honest wording**: removed the "ISO 42001 Compliant" badge and "tamper-proof" claims. Unworldly produces *tamper-evident* audit trails that serve as ISO 42001 / SOC 2 evidence; it does not make an organisation compliant. README now states the integrity limit (sessions are not yet signed).
- New dependency: `psutil`.

### Added
- End-to-end test that runs the real `unworldly watch` CLI and checks `verify`, `replay`, `report` (incl. `--owasp`, markdown), `touched`, `list`, SARIF export and tamper detection against the recorded session.

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
