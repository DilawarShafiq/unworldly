# Implementation Plan: Process Monitoring & Command Detection

**Branch**: `1-process-monitoring` | **Date**: 2026-02-24 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/1-process-monitoring/spec.md`

## Summary

Add process/command monitoring to Unworldly so it captures shell commands alongside file changes. The approach uses Node.js `child_process` event interception via a lightweight process monitor that polls `/proc` (Linux/macOS) or uses `wmic`/`Get-Process` (Windows) to detect new child processes spawned in the watched directory. Command events are unified into the existing event model, risk-scored with command-specific patterns, and rendered in the same color-coded terminal output.

## Technical Context

**Language/Version**: TypeScript 5.7+ (strict mode)
**Primary Dependencies**: chalk, chokidar, commander (existing); no new runtime dependencies
**Storage**: JSON files in `.unworldly/sessions/` (existing)
**Testing**: vitest
**Target Platform**: Node.js >= 18 on Windows, macOS, Linux
**Project Type**: Single CLI tool
**Performance Goals**: <100ms risk scoring per command, <2% CPU overhead
**Constraints**: Zero network requests, passive monitoring only, <50MB RAM

## Constitution Check

*GATE: All six principles verified.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Agent-Agnostic | PASS | Process monitoring detects any shell command regardless of which AI agent spawned it |
| II. Local-First Privacy | PASS | No network requests. All command data stored locally in `.unworldly/sessions/` |
| III. Zero Interference | PASS | Read-only process polling. Never injects, blocks, or wraps commands |
| IV. Risk-First Design | PASS | Every command gets risk-scored. Feature exists to surface command risks |
| V. CLI-First | PASS | Command events display with color-coded icons in terminal output |
| VI. Ship Small | PASS | Plan uses 5 incremental tasks, each independently testable |

## Project Structure

### Documentation (this feature)

```text
specs/1-process-monitoring/
├── spec.md
├── plan.md              # This file
├── checklists/
│   └── requirements.md
└── tasks.md             # Next step (/sp.tasks)
```

### Source Code (repository root)

```text
src/
├── types.ts             # MODIFY — Add CommandEvent type and 'command' EventType
├── risk.ts              # MODIFY — Add command risk patterns + assessCommandRisk()
├── command-monitor.ts   # CREATE — Process detection engine (cross-platform)
├── command-risk.ts      # CREATE — Command-specific risk scoring with patterns
├── config.ts            # CREATE — Config loader for .unworldly/config.json
├── display.ts           # MODIFY — Add command event formatting
├── session.ts           # MODIFY — Handle new event type in addEvent()
├── watcher.ts           # MODIFY — Integrate command monitor alongside chokidar
├── replay.ts            # MODIFY — Handle command events in replay
├── report.ts            # MODIFY — Include command events in reports
├── cli.ts               # NO CHANGE — Commands already work, events flow through
└── index.ts             # MODIFY — Export new modules

tests/
├── command-risk.test.ts  # CREATE — Command risk scoring tests
├── command-monitor.test.ts # CREATE — Process monitor tests
├── config.test.ts        # CREATE — Config loading tests
└── risk.test.ts          # CREATE — Updated risk engine tests
```

**Structure Decision**: Follows existing flat `src/` layout. Two new files (`command-monitor.ts`, `command-risk.ts`, `config.ts`) handle the new domain. No directory restructuring needed.

## Design Decisions

### D1: Event Type Extension

Extend the existing `WatchEvent` type to support command events rather than creating a separate type. This keeps the event timeline unified.

```typescript
// types.ts additions
export type EventType = 'create' | 'modify' | 'delete' | 'command';

export interface WatchEvent {
  timestamp: string;
  type: EventType;
  path: string;        // For commands: the command string (e.g., "npm install lodash")
  risk: RiskLevel;
  reason?: string;
  command?: CommandInfo; // Present only for 'command' events
}

export interface CommandInfo {
  executable: string;   // e.g., "npm"
  args: string[];       // e.g., ["install", "lodash"]
  cwd: string;          // Working directory
  pid: number;          // Process ID
  exitCode?: number;    // When available
}
```

**Rationale**: Single event stream means replay, report, and display work with minimal changes. The `command?` field is optional so existing file events are unaffected. Backward-compatible with existing session JSON files.

### D2: Process Detection Strategy

Use periodic polling of active processes to detect new child processes. Cross-platform approach:

- **Linux/macOS**: Read `/proc` filesystem or use `ps` command to list processes with their CWD
- **Windows**: Use `wmic process` or `powershell Get-Process` to detect new processes
- **Fallback**: If process monitoring is unavailable, emit a warning and continue with file-only monitoring

Poll interval: 500ms (configurable). Detect new PIDs since last poll, capture command line and working directory.

**Rationale**: Polling is simpler and more portable than ptrace/ETW/DTrace. 500ms polling is frequent enough to catch commands (most AI agent commands run >500ms) while keeping CPU overhead minimal. Zero dependencies — uses only Node.js `child_process.execSync` for platform queries.

### D3: Command Risk Scoring

Separate command risk scoring from file risk scoring. New `command-risk.ts` module with its own pattern lists:

- **DANGER patterns**: `rm -rf`, `rm -r`, `sudo`, `curl`, `wget`, `chmod 777`, `dd`, `mkfs`, `kill -9`, `format`, `del /f /s`
- **CAUTION patterns**: `npm install`, `pip install`, `brew install`, `apt install`, `git push`, `docker run`, `docker exec`
- **SAFE patterns**: `git add`, `git status`, `git diff`, `git log`, `ls`, `cat`, `echo`, `pwd`, `node`, `npm test`, `npm run`

Pattern matching is done on the full command string (executable + args) for context-aware scoring. For example, `npm install lodash` (known package) could be caution, while `npm install` (any install) is always at least caution.

### D4: Config File Format

`.unworldly/config.json` schema:

```json
{
  "commands": {
    "allowlist": [
      { "pattern": "my-tool", "risk": "safe", "reason": "Internal tool" }
    ],
    "blocklist": [
      { "pattern": "bad-pkg", "risk": "danger", "reason": "Known vulnerable" }
    ]
  }
}
```

Custom patterns are checked BEFORE defaults, allowing overrides. Config is loaded once at watch start and cached.

### D5: Display Format for Commands

Command events use a distinct icon `$>` (resembling a shell prompt) to differentiate from file events which use `CREATE`/`MODIFY`/`DELETE`:

```
  14:23:01  $> COMMAND  npm install lodash   caution
  ┗━ Installing package
  14:23:05  CREATE     package-lock.json     caution
  ┗━ Lock file modified
```

## Complexity Tracking

No constitution violations. No complexity justifications needed.
