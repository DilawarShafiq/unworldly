<!--
  Sync Impact Report
  ==================
  Version change: 0.0.0 (template) → 1.0.0
  Modified principles: All new (initial ratification)
  Added sections: Technology Stack, Development Workflow
  Removed sections: None
  Templates requiring updates:
    - .specify/templates/plan-template.md ✅ No update needed (Constitution Check is dynamic)
    - .specify/templates/spec-template.md ✅ No update needed (spec is principle-agnostic)
    - .specify/templates/tasks-template.md ✅ No update needed (Ship Small aligns with incremental delivery)
  Follow-up TODOs: None
-->

# Unworldly Constitution

## Core Principles

### I. Agent-Agnostic

Unworldly MUST work with any AI agent — Claude Code, Cursor, Devin,
OpenClaw, Copilot, Windsurf, or custom agents. The codebase MUST NOT
contain logic coupled to a specific agent's internals, protocols, or APIs.

- Detection and monitoring MUST rely on observable side effects
  (filesystem changes, process activity) rather than agent-specific hooks.
- No agent vendor names in runtime code paths; agent identification
  is informational only (e.g., session metadata).
- If an agent-specific integration is added, it MUST be optional and
  behind a plugin/adapter boundary.

### II. Local-First Privacy

All data MUST stay on the user's machine. Zero cloud, zero telemetry,
zero data collection.

- Session recordings MUST be stored locally in `.unworldly/sessions/`.
- The tool MUST NOT make outbound network requests for any reason.
- No analytics, crash reporting, or usage tracking of any kind.
- Reports MUST be generated locally; sharing is the user's choice.

### III. Zero Interference

Unworldly MUST be a passive observer. It MUST NOT modify, block, or
slow down the agent being watched.

- File watching MUST use non-blocking, event-driven mechanisms.
- The watcher MUST NOT lock files or compete for filesystem resources.
- CPU and memory overhead MUST remain negligible (<2% CPU, <50MB RAM)
  during normal operation.
- If monitoring degrades system performance, the tool MUST degrade
  gracefully (drop events) rather than interfere with the agent.

### IV. Risk-First Design

Every feature MUST tie back to helping users understand and manage
risk from AI agent activity.

- New features MUST be justified by a risk they help detect, assess,
  or communicate.
- The risk engine is the core of the product; changes to risk scoring
  patterns MUST be reviewed carefully and documented.
- Risk levels (safe, caution, danger) MUST have clear, documented
  criteria for classification.
- Features that do not serve risk visibility are out of scope.

### V. CLI-First

The terminal is the primary interface. Output MUST be beautiful,
informative, and screenshot-friendly.

- All commands MUST produce well-formatted terminal output with
  color-coded risk indicators.
- Output MUST be useful both in interactive terminals and when piped
  (detect TTY and adjust formatting).
- Structured output (JSON) MUST be available for machine consumption
  via flags (e.g., `--json`).
- The tool MUST work without any GUI, browser, or external dashboard.

### VI. Ship Small

Every change MUST be independently testable and deployable. No
big-bang releases.

- Each PR MUST address a single concern (one feature, one fix,
  one refactor).
- New features MUST be usable immediately after merge without
  requiring additional unreleased features.
- Prefer many small, safe iterations over large ambitious changes.
- YAGNI: do not build for hypothetical future requirements.

## Technology Stack

- **Language**: TypeScript (strict mode, no `any` types)
- **Runtime**: Node.js >= 18.0.0
- **Module system**: ESM (`"type": "module"`)
- **Distribution**: npm / npx
- **Core dependencies**:
  - `chalk` — terminal colors
  - `chokidar` — filesystem watching
  - `commander` — CLI framework
- **Testing**: vitest
- **Build**: tsc (TypeScript compiler)
- **Session storage**: JSON files in `.unworldly/sessions/`

New dependencies MUST be justified by a clear need that cannot be
met with Node.js built-in APIs. Prefer zero-dependency solutions
when the added complexity is minimal.

## Development Workflow

- **Code quality**: Strict TypeScript with `"strict": true`. No
  `any` types. All public APIs MUST have explicit return types.
- **Testing**: All risk patterns MUST have unit tests. New features
  MUST include tests. Vitest is the test runner.
- **Commits**: Small, atomic commits. Each commit MUST leave the
  project in a buildable, working state.
- **Branching**: Feature branches off `main`. PRs reviewed before
  merge.
- **Build verification**: `npm run build` MUST succeed with zero
  errors and zero warnings before any commit.

## Governance

This constitution is the authoritative source for all development
decisions in the Unworldly project.

- All PRs and code reviews MUST verify compliance with these
  principles.
- Amendments require: (1) documented rationale, (2) approval from
  maintainers, (3) version bump per semantic versioning below.
- Versioning: MAJOR for principle removals or redefinitions, MINOR
  for new principles or material expansions, PATCH for clarifications
  and wording fixes.
- Complexity violations (e.g., adding dependencies, expanding scope
  beyond risk monitoring) MUST be justified in writing.

**Version**: 1.0.0 | **Ratified**: 2026-02-24 | **Last Amended**: 2026-02-24
