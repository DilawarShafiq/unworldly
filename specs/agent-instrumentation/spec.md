# Feature Specification: Agent Instrumentation (Decision-Trail Capture)

**Feature Branch**: `agent-instrumentation`
**Created**: 2026-07-24
**Status**: Draft
**Input**: User question — "Does this record AI agents' work? We have agent dev kits, custom agents, and no-code agents; is my project best for what it claims?"

## Problem

Unworldly today captures **OS side-effects** of agents that run on the local machine: file changes (`watchdog`) and shell commands (500ms process polling, now also a lossless shell hook). This is a good fit for **local coding agents** (Claude Code, Cursor, Aider, Cline).

It captures **nothing** for agents whose work is *in-process tool/API calls* rather than files or shells:

- **Agent Dev Kits / SDKs** — OpenAI Agents SDK, Google ADK, Claude Agent SDK, LangGraph. Their actions (call an API, query a DB, send email, use an MCP tool) leave no file or process trace.
- **No-code / cloud agents** — n8n, Zapier, Make, Lindy. They run off the user's machine entirely.

The product tagline ("flight recorder for *any* AI agent") therefore over-claims. This spec defines the work to make the claim true: capture the agent's **decision trail** (which tool it called, with what arguments, and the outcome), not just the aftermath on disk.

## Guiding Contract: Completeness Honesty

A cryptographically sealed log that is silently incomplete is worse than no log — it looks authoritative. Every capture layer MUST be explicit about what it does and does not see, and the session metadata MUST record which capture layer(s) produced it. (See US4.)

## Capture Layers

| Layer | Captures | Status |
|-------|----------|--------|
| **L1 Filesystem + Shell** | Local file changes + shell commands | ✅ Shipped (`watcher`, `command_monitor`, `shell_hook`) |
| **L2 Tool-Call Trace** | In-process tool calls made by SDK/custom agents | 🚧 This spec — US1 |
| **L3 MCP Capture** | Tool calls routed through an MCP server/proxy | 🚧 This spec — US2 |
| **L4 OpenTelemetry GenAI** | Spans emitted by OTel-instrumented / no-code agents | 🚧 This spec — US3 |

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Tool-Call Trace Recorder (Priority: P1)

A developer building an agent with an SDK (OpenAI Agents SDK, Google ADK, LangGraph, or a hand-rolled loop) wraps their tool functions so that every tool the agent invokes is recorded into an Unworldly session — same risk scoring, same SHA-256 hash chain, same `verify`/`report`/`replay` commands as file and command events.

**Why this priority**: This is the smallest change that makes decision-trail capture real for the *entire* SDK/custom-agent category, framework-agnostic, with no live-service dependency. It is the foundation L3 (MCP) and L4 (OTel) both feed into.

**Independent Test**: Instantiate a recorder, record several tool calls (a safe read, a risky write, a network call), then load the produced session and assert the events, risk levels, hash chain, and seal are all valid.

**Acceptance Scenarios**:

1. **Given** an `AgentTraceRecorder` for a directory, **When** a tool call `db.read(table="users")` is recorded, **Then** a hash-chained event is written to a session with the tool name, compact arguments, timestamp, and a risk level.
2. **Given** a recorded trace session, **When** `unworldly verify` runs on it, **Then** the hash chain and seal validate (exit 0).
3. **Given** a recorded trace session, **When** `unworldly report`/`replay` runs, **Then** tool-call events render alongside any file/command events.
4. **Given** a tool call whose name/arguments suggest a destructive or exfiltration action (e.g. `shell.exec`, `http.post` to an external host, `fs.delete`), **When** it is recorded without an explicit risk, **Then** it is classified `danger`; benign reads default to `caution`/`safe`.
5. **Given** a `@trace_tool(recorder)`-decorated function, **When** the agent calls it, **Then** the call is recorded and the original return value is passed through unchanged.

### User Story 2 — MCP Capture (Priority: P2)

An agent that consumes tools via the Model Context Protocol has its tool calls captured by routing them through an Unworldly MCP layer (a proxy in front of downstream MCP servers, or a recording wrapper around an MCP `ClientSession`). Each `call_tool` is logged via the US1 recorder before being forwarded.

**Why this priority**: MCP is the emerging standard interface between agents and tools; capturing at this seam is agent-agnostic and requires no code changes inside the agent. Depends on US1 for the recording primitive.

**Acceptance Scenarios**:

1. **Given** the Unworldly MCP wrapper around a `ClientSession`, **When** the agent calls a downstream tool, **Then** the call (name + arguments) is recorded and the downstream result is returned unchanged.
2. **Given** a downstream tool errors, **When** it is called through the wrapper, **Then** the attempt is still recorded (with error outcome) and the error propagates.

### User Story 3 — OpenTelemetry GenAI Ingestion (Priority: P3)

An agent built on a stack that emits OpenTelemetry GenAI spans (OpenAI Agents SDK, Google ADK, LangGraph, or a no-code platform with OTel export) points its OTLP exporter at an Unworldly collector endpoint; Unworldly maps `gen_ai.*` spans (tool calls, model calls) into session events.

**Why this priority**: Reaches agents Unworldly cannot instrument directly, including cloud/no-code platforms, via an open standard. Spec-only in this iteration.

**Acceptance Scenarios**:

1. **Given** an OTLP endpoint exposed by Unworldly, **When** a `gen_ai.execute_tool` span is received, **Then** a corresponding tool-call event is recorded in a session.
2. **Given** a batch of spans for one trace, **When** ingested, **Then** they map to one session preserving order and timing.

### User Story 4 — Capture Provenance in Sessions (Priority: P2)

Every session records which capture layer(s) produced it, so a reader (or auditor) can tell what the log could and could not have seen.

**Acceptance Scenarios**:

1. **Given** a session produced by the trace recorder, **When** it is saved, **Then** its metadata identifies the capture source (e.g. `sdk-trace`).
2. **Given** a report is generated, **When** the session was captured by a non-exhaustive layer, **Then** the report states the coverage scope.

## Requirements *(mandatory)*

- **FR-001**: The system MUST provide a framework-agnostic recorder that writes tool-call events into a standard Unworldly session using the existing hash-chain and seal primitives.
- **FR-002**: Tool-call events MUST be risk-scored; an explicit caller-supplied risk MUST override the heuristic.
- **FR-003**: The recorder MUST NOT alter tool return values or raise into the agent's control flow on recording failure (Zero Interference).
- **FR-004**: Recorded trace sessions MUST validate under `unworldly verify` and render under `report`/`replay`.
- **FR-005**: The system MUST expose an MCP recording wrapper (US2) reusing FR-001.
- **FR-006 (spec-only)**: The system SHOULD define an OTLP ingestion mapping from `gen_ai.*` spans to session events (US3).
- **FR-007**: Sessions MUST carry capture-provenance metadata (US4).

## Non-Functional Requirements

- **Performance**: Recording one tool call MUST add < 5 ms overhead (excluding disk flush) so it is safe inside an agent loop.
- **Reliability**: Recording failures are swallowed and never propagate to the agent.
- **Security/Privacy**: Local-first — traces stay on disk under `.unworldly/`. Arguments MAY contain sensitive data; the recorder MUST support argument truncation and MUST NOT transmit anywhere.
- **Compatibility**: No mandatory new heavy dependency for L2; MCP (L3) and OTel (L4) deps are optional extras.

## Out of Scope

- Deterministic replay/re-execution of agent decisions (record only).
- Capturing model prompts/completions verbatim (privacy; may be a later opt-in).
- A hosted collector service (local OTLP receiver only, if built).

## Architectural Decision (ADR candidate)

Representing tool calls: this iteration reuses the existing `COMMAND` event type (executable = tool name) so the entire pipeline — risk, hash chain, seal, report, replay, verify — works unchanged. A dedicated `TOOL` `EventType` (with a tool-specific risk model and display) is the cleaner long-term model but touches `types`, `display`, `report`, `replay`, and `integrity`. That trade-off — reuse-now vs. dedicated-type-later — is architecturally significant and cross-cutting.

📋 Architectural decision detected: capture-layer model + tool-call event representation — Document reasoning and tradeoffs? Run `/sp.adr agent-instrumentation-capture-model`

## Definition of Done

- [ ] L2 recorder implemented with risk heuristic + explicit-risk override
- [ ] Trace sessions verify/report/replay correctly
- [ ] Recording never breaks the host agent (failure swallowed, return value untouched)
- [ ] Capture-provenance metadata on sessions
- [ ] Tests: recorder, risk heuristic, decorator pass-through, verify roundtrip
- [ ] L3 MCP wrapper (reuses L2)
- [ ] L4 OTel mapping documented
