---
id: 001
title: Initial Constitution Ratification
stage: constitution
date: 2026-02-24
surface: agent
model: claude-opus-4-6
feature: none
branch: master
user: DilawarShafiq
command: /sp.constitution
labels: ["constitution", "governance", "principles", "initial-setup"]
links:
  spec: null
  ticket: null
  adr: null
  pr: null
files:
  - .specify/memory/constitution.md
tests:
  - null
---

## Prompt

Unworldly - The Flight Recorder for AI Agents. A CLI tool that records, replays, and audits everything AI agents do on your system. Core principles: (1) Agent-Agnostic: Works with any AI agent - Claude Code, Cursor, Devin, OpenClaw, Copilot. Never coupled to a specific agent. (2) Local-First Privacy: All data stays on the user's machine. Zero cloud, zero telemetry, zero data collection. (3) Zero Interference: Passive monitoring only. Never modify, block, or slow down the agent being watched. (4) Risk-First Design: Every feature must tie back to helping users understand and manage risk from AI agent activity. (5) CLI-First: Terminal is the primary interface. Beautiful, informative output that screenshots well for sharing. (6) Ship Small: Every change should be independently testable and deployable. No big-bang releases. Tech stack: TypeScript, Node.js, npm distribution. Dependencies: chalk (terminal colors), chokidar (filesystem watching), commander (CLI framework). Architecture: Modular source files (risk engine, session management, watcher, replay, report). Session data stored as JSON in .unworldly/sessions/. Testing: vitest. Code quality: strict TypeScript, ESM modules, no any types.

## Response snapshot

Created Unworldly Constitution v1.0.0 with 6 core principles (Agent-Agnostic, Local-First Privacy, Zero Interference, Risk-First Design, CLI-First, Ship Small), Technology Stack section (TypeScript/Node.js/ESM), Development Workflow section, and Governance rules. All template placeholders replaced. Sync Impact Report confirms no dependent templates require updates.

## Outcome

- Impact: Foundation document ratified — all future development governed by these 6 principles
- Tests: N/A (governance document)
- Files: .specify/memory/constitution.md (created v1.0.0)
- Next prompts: /sp.specify for core features, /sp.plan for architecture
- Reflection: Constitution captures the opinionated, privacy-first, risk-focused identity that differentiates Unworldly

## Evaluation notes (flywheel)

- Failure modes observed: None
- Graders run and results (PASS/FAIL): Manual validation PASS — no unresolved placeholders, dates ISO format, principles declarative and testable
- Prompt variant (if applicable): N/A
- Next experiment (smallest change to try): Run /sp.specify to create feature spec for next development phase
