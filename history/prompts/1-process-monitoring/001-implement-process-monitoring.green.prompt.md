---
id: 001
title: implement-process-monitoring
stage: green
date: 2026-02-24
surface: agent
model: claude-opus-4-6
feature: 1-process-monitoring
branch: 1-process-monitoring
user: DilawarShafiq
command: /sp.specify + /sp.plan + /sp.tasks + /sp.implement
labels: ["process-monitoring", "command-detection", "risk-scoring", "feature"]
links:
  spec: specs/1-process-monitoring/spec.md
  ticket: null
  adr: null
  pr: https://github.com/DilawarShafiq/unworldly/pull/1
files:
  - src/types.ts
  - src/command-risk.ts
  - src/command-monitor.ts
  - src/config.ts
  - src/display.ts
  - src/watcher.ts
  - src/report.ts
  - src/session.ts
  - src/index.ts
  - tests/command-risk.test.ts
  - tests/command-monitor.test.ts
  - tests/config.test.ts
  - specs/1-process-monitoring/spec.md
  - specs/1-process-monitoring/plan.md
  - specs/1-process-monitoring/tasks.md
  - specs/1-process-monitoring/checklists/requirements.md
tests:
  - tests/command-risk.test.ts (25 tests - PASS)
  - tests/command-monitor.test.ts (4 tests - PASS)
  - tests/config.test.ts (4 tests - PASS)
---

## Prompt

complete the current project

## Response snapshot

Executed full SDD workflow for process monitoring feature:
1. Created feature branch `1-process-monitoring`
2. Wrote spec with 5 user stories, 15 functional requirements, 7 success criteria
3. Wrote implementation plan with 5 design decisions (event type extension, poll-based process detection, command risk scoring, config file format, display format)
4. Wrote 16 tasks across 5 phases
5. Implemented all tasks:
   - Extended WatchEvent type with 'command' and CommandInfo
   - Created command risk scoring engine with danger/caution/safe patterns
   - Created cross-platform process monitor (Linux/macOS/Windows)
   - Created config loader for .unworldly/config.json
   - Updated display, report, replay for command events
   - Integrated command monitor into watcher
6. 33 tests passing, zero build errors
7. Created PR #1

## Outcome

- Impact: Major feature — Unworldly now captures both file changes AND shell commands from AI agents
- Tests: 33 tests passing across 3 test suites (command-risk, command-monitor, config)
- Files: 16 files created/modified (3 new source, 3 new tests, 6 modified source, 4 spec docs)
- Next prompts: Manual E2E testing, npm publish, merge PR
- Reflection: Poll-based process detection is the right trade-off for cross-platform support. Ordering of risk patterns matters — more specific patterns must be checked before general ones.

## Evaluation notes (flywheel)

- Failure modes observed: git push --force and git reset --hard initially classified as caution instead of danger due to pattern ordering (caution patterns checked before danger overrides). Fixed by moving specific danger patterns to the DANGER_PATTERNS array.
- Graders run and results (PASS/FAIL): TypeScript build PASS, vitest 33/33 PASS
- Prompt variant (if applicable): N/A
- Next experiment (smallest change to try): Add integration test that spawns a real child process and verifies the monitor captures it
