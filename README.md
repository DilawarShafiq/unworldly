# Unworldly

[![CI](https://github.com/DilawarShafiq/unworldly/actions/workflows/ci.yml/badge.svg)](https://github.com/DilawarShafiq/unworldly/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/unworldly-recorder.svg)](https://pypi.org/project/unworldly-recorder/)
[![PyPI downloads](https://img.shields.io/pypi/dm/unworldly-recorder.svg)](https://pypi.org/project/unworldly-recorder/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![ISO 42001](https://img.shields.io/badge/ISO_42001-Compliant-blue.svg)](https://www.iso.org/standard/81230.html)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)

**The flight recorder for AI agents.** Records everything AI agents do on your system — file changes AND shell commands — replays sessions like a DVR, flags dangerous behavior in real-time, and produces tamper-proof, ISO 42001-compliant audit trails.

> You wouldn't run code without logs. Why are you running AI agents without a black box?

```bash
pip install unworldly-recorder
unworldly watch
# That's it. Every file change and shell command is now recorded.
```

## Why Unworldly?

AI agents are going autonomous. They edit files, run commands, install packages, access credentials — and **nobody is watching**. You finish a session and have no idea what actually happened. That's insane.

**Unworldly watches everything so you don't have to.**

- Works with **any** agent — Claude Code, Cursor, Devin, Copilot, Windsurf, Aider, OpenClaw, Cline
- **Zero interference** — passive monitoring, never slows down your agent
- **Local-first** — your data never leaves your machine. Zero cloud. Zero telemetry
- **Tamper-proof** — SHA-256 hash chain on every event. If someone edits the logs, the chain breaks
- **ISO 42001 compliant** — the audit trail standard for AI management systems

## Quick Start

```bash
# Install
pip install unworldly-recorder

# Start recording (run this BEFORE your AI agent)
unworldly watch

# In another terminal, run your AI agent normally
# Claude Code, Cursor, Copilot — anything

# When done, replay what happened
unworldly replay

# Generate a security audit report
unworldly report --format md

# Verify nobody tampered with the session
unworldly verify
```

## Live Output

```
  ╔═══════════════════════════════════════════════════╗
  ║  UNWORLDLY v0.3.0                                ║
  ║  The Flight Recorder for AI Agents               ║
  ╚═══════════════════════════════════════════════════╝

  ● REC — Watching: /Users/dev/my-project

  ◉ Agent Detected: Claude Code
    via environment variable: CLAUDE_CODE

  14:32:01  CREATE   src/auth/handler.ts                 safe
  14:32:03  MODIFY   package.json                        caution
  ┗━ Dependency manifest modified
  14:32:05  $> CMD   npm install jsonwebtoken bcrypt      caution
  ┗━ Installing npm package
  14:32:08  MODIFY   .env                                 DANGER
  ┗━ Credential file accessed!
  14:32:10  DELETE   src/old-auth.ts                      caution
  ┗━ File deleted
  14:32:12  $> CMD   curl https://unknown-api.com/data    DANGER
  ┗━ Network request to external URL!

  Session Summary
  Events: 6  ● Safe: 1  ● Caution: 3  ● Danger: 2
  Risk Score: 7.2/10
```

## How It Differs

| Feature | Unworldly | AgentOps | SecureClaw | Manual Logging |
|---------|-----------|----------|------------|----------------|
| Agent-agnostic | Any agent | Python SDK only | OpenClaw only | Per-agent setup |
| File monitoring | Real-time | No | Audit only | Manual |
| Command capture | Real-time | No | Pattern scan | Manual |
| Tamper-proof logs | SHA-256 hash chain | No | No | No |
| ISO 42001 compliant | Yes | No | Partial | No |
| Local-first / zero cloud | Yes | Cloud dashboard | Yes | Depends |
| Setup time | 1 command | SDK integration | Config required | Hours |
| Agent identity detection | Automatic | N/A | N/A | Manual |

## Features

- **Watch** — Passive filesystem + process monitoring. Zero interference with the agent
- **Command Detection** — Captures shell commands (npm install, curl, rm -rf, sudo) alongside file changes
- **Agent Identity** — Auto-detects which AI agent is running (8 agents supported)
- **Risk Engine** — Scores every action: credential access, destructive commands, network calls, mass deletions
- **Tamper-Proof Logs** — SHA-256 hash chain on every event. Modify one event and the chain breaks
- **Verify** — Cryptographic integrity verification. Exit code tells you if the session was tampered with
- **Replay** — Step through every action with a color-coded terminal UI
- **Report** — Generate terminal or markdown security reports with integrity verification
- **Configurable** — Custom risk patterns via `.unworldly/config.json` allowlist/blocklist
- **Cross-platform** — macOS, Linux, Windows. Runs anywhere Python runs

## ISO 42001 Compliance

Unworldly implements key controls from the [ISO 42001 AI Management System](https://www.iso.org/standard/81230.html) standard:

| ISO 42001 Control | What It Requires | Unworldly Implementation |
|-------------------|------------------|--------------------------|
| **A.3.2** Roles & accountability | Know WHO is acting | Auto-detects agent identity |
| **A.6.2.8** Event logging | Defensible audit logs | SHA-256 hash-chained events |
| **A.8** Transparency | Observable AI behavior | Full session replay + reports |
| **A.9** Accountability | Tamper-evident records | Cryptographic verify command |

```bash
# Verify session integrity — exit 0 = valid, exit 1 = tampered
unworldly verify

  Integrity Verification
  ────────────────────────────

  ✓ SESSION INTEGRITY VERIFIED
    All 47 events have valid hash chain
    Session seal is intact — no tampering detected
```

## Agent Detection

Automatically identifies the AI agent modifying your system:

| Agent | Detection Method |
|-------|-----------------|
| Claude Code | `CLAUDE_CODE` env, `claude` process |
| Cursor | `CURSOR_SESSION` env, `Cursor` process |
| GitHub Copilot | `GITHUB_COPILOT` env |
| Windsurf | `WINDSURF_SESSION` env |
| Devin | `DEVIN_SESSION` env |
| Aider | `AIDER_MODEL` env |
| OpenClaw | `OPENCLAW_SESSION` env |
| Cline | `CLINE_SESSION` env |

Don't see your agent? [Open an issue](https://github.com/DilawarShafiq/unworldly/issues/new) or add it yourself — it's one entry in `unworldly/agent_detect.py`.

## Risk Detection

| Pattern | Risk Level | Example |
|---------|-----------|---------|
| Normal file edits | Safe | Creating/editing source files |
| Standard commands | Safe | `git add`, `npm test`, `ls` |
| Dependency changes | Caution | `npm install`, modifying package.json |
| Config file access | Caution | Editing tsconfig, webpack config |
| Package installs | Caution | `npm install`, `pip install`, `brew install` |
| Credential access | **DANGER** | Reading/writing .env, keys, tokens |
| Destructive commands | **DANGER** | `rm -rf`, `sudo`, `git reset --hard` |
| Network requests | **DANGER** | `curl`, `wget` to external URLs |
| Elevated privileges | **DANGER** | `sudo`, `chmod 777`, `kill -9` |

## Custom Risk Patterns

```json
{
  "commands": {
    "allowlist": [
      { "pattern": "my-internal-tool", "risk": "safe", "reason": "Trusted internal tool" }
    ],
    "blocklist": [
      { "pattern": "sketchy-package", "risk": "danger", "reason": "Known vulnerable" }
    ]
  }
}
```

Save as `.unworldly/config.json` in your project root.

## Roadmap

- [ ] **MCP Server** — Expose Unworldly as a Model Context Protocol tool
- [ ] **Web Dashboard** — Browser-based session viewer with search and filtering
- [ ] **CI/CD Integration** — GitHub Action to audit AI-generated PRs
- [ ] **PHI Detection** — HIPAA-specific patterns for healthcare environments
- [ ] **Cost Tracking** — Estimate compute cost of agent sessions
- [ ] **Plugin System** — Custom analyzers and reporters
- [ ] **Real-time Alerts** — Webhook/Slack notifications on danger events

## Who Is This For?

- **Developers** running AI agents who want to know what actually happened
- **Security teams** auditing AI agent behavior in enterprise environments
- **Compliance officers** needing ISO 42001 / HIPAA audit trails
- **Open-source maintainers** reviewing AI-generated pull requests
- **Anyone** who believes AI agents should be observable and accountable

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We welcome PRs — especially new agent detections, risk patterns, and platform fixes.

## License

MIT — see [LICENSE](LICENSE).
