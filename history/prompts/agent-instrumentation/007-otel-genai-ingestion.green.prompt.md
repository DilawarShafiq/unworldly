---
id: 007
title: OTel GenAI Ingestion (L4)
stage: green
date: 2026-07-24
surface: agent
model: claude-opus-4-8
feature: agent-instrumentation
branch: master
user: dilawar.gopang@gmail.com
command: (autonomous dev loop — ROADMAP item 4)
labels: ["otel", "genai", "ingestion", "capture-layer", "l4"]
links:
  spec: specs/agent-instrumentation/spec.md
  ticket: null
  adr: null
  pr: null
files:
 - unworldly/otel_ingest.py (new)
 - unworldly/cli.py (unworldly collect)
 - unworldly/__init__.py (exports)
 - tests/test_otel_ingest.py (new — 8 tests)
tests:
 - pytest: 291 passed (8 new)
 - ruff: baseline (20), no new
 - mypy --strict: clean on otel_ingest.py
---

## Prompt

Autonomous dev loop — implement ROADMAP item 4 (L4 OpenTelemetry GenAI ingestion), smallest dependency-light slice with tests.

## Response snapshot

Implemented `unworldly/otel_ingest.py`: pure, dependency-light mapping of OTel GenAI spans (plain dicts) to session events.
- `span_to_event(span, redact=True)` — maps `execute_tool` spans (via `gen_ai.tool.name` or `execute_tool <name>` span name) to risk-scored, redacted COMMAND events; maps `chat`/model spans to safe `llm:<model>` events; returns None for non-GenAI spans.
- `spans_to_session(...)` — builds a sealed, hash-chained session with `capture_source="otel"`.
- `ingest_file(path)` + `unworldly collect <spans.json>` CLI.
- Reuses L2/L3 `assess_tool_risk` + `redact_params` (risk on originals, redact for storage).

Left ROADMAP item 4 unchecked (partial): the live OTLP/gRPC receiver endpoint remains (heavier, needs deps).

## Outcome

- ✅ Impact: SDK/no-code/cloud agents that export OTel GenAI spans can now produce an Unworldly audit trail (offline/file-based path).
- 🧪 Tests: 291 passed (8 new); ruff baseline; mypy --strict clean.
- 📁 Files: 1 new module, 1 new test file, cli + init edits.
- 🔁 Next prompts: item 5 (standalone MCP proxy CLI); later a light OTLP receiver.
- 🧠 Reflection: keeping span input as plain dicts avoided pulling the OTel SDK into core while still being real and testable.

## Evaluation notes (flywheel)

- Failure modes observed: none; console cp1252 can't print ✓ (cosmetic only).
- Graders run and results (PASS/FAIL): tests PASS, ruff PASS, mypy PASS.
- Prompt variant (if applicable): N/A
- Next experiment (smallest change to try): optional light OTLP HTTP receiver behind an extra.
