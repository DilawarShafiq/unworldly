# Changelog

All notable changes to Unworldly are documented here.

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
