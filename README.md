# Unworldly

[![npm version](https://img.shields.io/npm/v/unworldly-recorder.svg)](https://www.npmjs.com/package/unworldly-recorder)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![ISO 42001](https://img.shields.io/badge/ISO_42001-Compliant-blue.svg)](https://www.iso.org/standard/81230.html)

> You wouldn't run code without logs. Why are you running AI agents without a black box?

The flight recorder for AI agents. Records everything AI agents do on your system — **file changes AND shell commands** — replays sessions like a DVR, flags dangerous behavior in real-time, and produces **tamper-proof, ISO 42001-compliant audit trails**.

Works with **any** agent — Claude Code, Cursor, Devin, OpenClaw, Copilot, Windsurf, Aider, Cline, or your custom agents. Agent-agnostic. Local-first. Zero cloud.

## Install

```bash
npm install -g unworldly-recorder
```

Or run directly:

```bash
npx unworldly-recorder watch
```

## The Problem

AI agents are going autonomous. They edit your files, run commands, install packages, access credentials — and **nobody is watching**. You have no idea what they actually did. That's insane.

ISO 42001 (AI Management Systems) requires organizations to maintain defensible audit trails for AI activity. HIPAA requires WHO/WHAT/WHEN/WHERE/WHY for every system action. Unworldly gives you both — automatically.

## What Unworldly Does

```bash
# Start recording while any AI agent runs
unworldly watch

# Replay exactly what happened
unworldly replay

# Generate a security audit report
unworldly report

# Verify session integrity (tamper detection)
unworldly verify

# List all recorded sessions
unworldly list
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

## Features

- **Watch** — Passive filesystem + process monitoring. Zero interference with the agent.
- **Command Detection** — Captures shell commands (npm install, curl, rm -rf, sudo) alongside file changes.
- **Agent Identity** — Automatically detects which AI agent is running (Claude Code, Cursor, Copilot, Devin, Windsurf, Aider, OpenClaw, Cline).
- **Risk Engine** — Scores every action: credential access, destructive commands, unknown network calls, mass deletions.
- **Tamper-Proof Logs** — SHA-256 hash chain on every event. If anyone modifies a session log, the chain breaks.
- **Verify** — Cryptographic integrity verification of any session. Detects tampering instantly.
- **Replay** — Step through every action with a beautiful terminal UI, color-coded by risk.
- **Report** — Generate terminal or markdown security reports with integrity verification and agent identity.
- **Configurable** — Custom risk patterns via `.unworldly/config.json` allowlist/blocklist.
- **Agent-agnostic** — Doesn't care what agent is running. Just watches.
- **Local-only** — Your data never leaves your machine. Zero telemetry.

## ISO 42001 Compliance

Unworldly implements key controls from the ISO 42001 AI Management System standard:

| ISO 42001 Control | Unworldly Feature |
|-------------------|-------------------|
| **A.3.2** Roles & accountability | Agent identity detection — records WHO |
| **A.6.2.8** Event logging | Hash-chained event logs — records WHAT/WHEN/WHERE |
| **A.8** Transparency | Full session replay + markdown reports |
| **A.9** Accountability | Tamper-proof integrity verification |

### Verify Session Integrity

```bash
# Verify the latest session hasn't been tampered with
unworldly verify

# Verify a specific session
unworldly verify abc123

# Exit code 0 = valid, 1 = tampered
```

```
  Integrity Verification
  ────────────────────────────

  ✓ SESSION INTEGRITY VERIFIED
    All 47 events have valid hash chain
    Session seal is intact — no tampering detected
```

### Agent Detection

Unworldly automatically identifies the AI agent modifying your system:

| Agent | Detection Method |
|-------|-----------------|
| Claude Code | `CLAUDE_CODE` env var, `claude` process |
| Cursor | `CURSOR_SESSION` env var, `Cursor` process |
| GitHub Copilot | `GITHUB_COPILOT` env var |
| Windsurf | `WINDSURF_SESSION` env var |
| Devin | `DEVIN_SESSION` env var |
| Aider | `AIDER_MODEL` env var |
| OpenClaw | `OPENCLAW_SESSION` env var |
| Cline | `CLINE_SESSION` env var |

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

Create `.unworldly/config.json` to customize:

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

## Who Is This For?

- **Developers** running AI agents on their codebase who want to know what actually happened
- **Security teams** auditing AI agent behavior in enterprise environments
- **Compliance officers** needing ISO 42001 / HIPAA audit trails for AI-assisted development
- **Open-source maintainers** reviewing AI-generated pull requests
- **Anyone** who believes AI agents should be observable and accountable

## Tech

TypeScript, Node.js, zero cloud dependencies. SHA-256 cryptographic integrity. Runs anywhere Node runs.

## License

MIT
