# Changelog

All notable changes to Unworldly are documented here.

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
