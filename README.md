# Unworldly

> You wouldn't run code without logs. Why are you running AI agents without a black box?

The flight recorder for AI agents. Records everything AI agents do on your system, replays sessions like a DVR, and flags dangerous behavior in real-time.

Works with **any** agent — Claude Code, Cursor, Devin, OpenClaw, Copilot, Windsurf, or your custom agents. Agent-agnostic. Local-first. Zero cloud.

## The Problem

AI agents are going autonomous. They edit your files, run commands, install packages, access credentials — and **nobody is watching**. You have no idea what they actually did. That's insane.

## What Unworldly Does

```bash
# Start recording while any AI agent runs
npx unworldly watch

# Replay exactly what happened
npx unworldly replay session-2024-02-24.json

# Generate a security audit report
npx unworldly report session-2024-02-24.json
```

## Live Output

```
🔴 UNWORLDLY v0.1.0 — Recording session...

14:32:01  📁 CREATE  src/auth/handler.ts                    ✅ Safe
14:32:03  📁 MODIFY  package.json (+2 deps)                 ⚠️  Caution
14:32:05  🔧 EXEC    npm install jsonwebtoken bcrypt         ⚠️  Caution
14:32:08  📁 MODIFY  .env                                   🚨 DANGER
14:32:08  ┗━ Agent accessed credential file!
14:32:10  📁 DELETE  src/old-auth.ts                         ⚠️  Caution
14:32:12  🔧 EXEC    curl https://unknown-api.com/v1/data   🚨 DANGER
14:32:12  ┗━ Unknown outbound network request detected!

Session Risk Score: 7.2/10 — 2 critical actions flagged
```

## Features

- **Watch** — Passive filesystem + process monitoring. Zero interference with the agent.
- **Replay** — Step through every action with a beautiful terminal UI, color-coded by risk
- **Report** — Generate human-readable security reports for compliance/audit
- **Risk Engine** — Scores every action: credential access, destructive commands, unknown network calls, mass deletions
- **Agent-agnostic** — Doesn't care what agent is running. Just watches.
- **Local-only** — Your data never leaves your machine

## Risk Detection

| Pattern | Risk Level | Example |
|---------|-----------|---------|
| Normal file edits | Safe | Creating/editing source files |
| Dependency changes | Caution | `npm install`, modifying package.json |
| Config file access | Caution | Editing tsconfig, webpack config |
| Credential access | Danger | Reading/writing .env, keys, tokens |
| Destructive commands | Danger | `rm -rf`, `git reset --hard` |
| Unknown network calls | Danger | `curl`, `wget` to unknown domains |
| System file modification | Danger | Writing outside project directory |

## Who Is This For?

- **Developers** running AI agents on their codebase who want to know what actually happened
- **Security teams** auditing AI agent behavior in enterprise environments
- **Compliance officers** needing audit trails for AI-assisted development
- **Open-source maintainers** reviewing AI-generated pull requests

## Status

🚧 **Under active development** — Star this repo to follow progress!

## License

MIT
