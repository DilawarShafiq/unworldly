# Feature Specification: Opt-In Prompt & Reasoning Capture

**Feature Branch**: `prompt-capture`
**Created**: 2026-07-24
**Status**: Draft (spec-only — NOT to be implemented without explicit maintainer + user consent)
**Input**: ROADMAP item 10. The one thing every capture layer today deliberately does NOT record: the agent's prompts, model messages, and chain-of-thought.

## Problem & Tension

A true "flight recorder" would include the cockpit voice recorder — the agent's
prompts, tool rationales, and model completions. That is the highest-signal data
for debugging and audit. It is also the **most sensitive**: prompts routinely
contain secrets, PII, proprietary code, and customer data. Capturing it by
default would violate the Local-First Privacy principle and could create a
liability worse than the problem Unworldly solves.

**Therefore this capability must be strictly opt-in, redacted, consent-gated, and
never the default.** This spec exists to define those guardrails *before* any
code, so the feature can never ship as an accident.

## Non-Negotiable Guardrails

1. **Off by default.** Never captured unless the user sets an explicit flag
   (`--capture-prompts`) or config (`"capturePrompts": true`) AND acknowledges a
   one-time consent prompt.
2. **Local-only.** Prompt content never leaves the machine; no telemetry, no
   cloud, same as all other data. Stored under `.unworldly/` only.
3. **Redacted on write.** Reuse and extend `redact_params` — scrub secrets, keys,
   emails, and long blobs before persistence. Redaction runs before hashing.
4. **Separable & deletable.** Prompt bodies stored in a *separate* file from the
   event stream (e.g. `.unworldly/prompts/<session>.jsonl`), referenced by hash,
   so a session can be shared/audited **without** the prompt bodies, and prompts
   can be purged independently (`unworldly purge --prompts <session>`).
5. **Honest provenance.** `capture_source` / report coverage must state that
   prompt capture was on, and reports must never leak raw prompt text into the
   default output — only a redacted preview behind an explicit `--show-prompts`.
6. **Size-bounded.** Truncate to a configurable byte cap; never store unbounded
   model context.

## User Scenarios

### US1 — Opt-in debugging capture (Priority: P1, gated)
A developer debugging a misbehaving agent runs with `--capture-prompts`, sees a
consent notice, and gets a session where each tool call/model span is linked to a
redacted prompt/completion preview — enough to understand *why* the agent acted.

**Acceptance**:
1. Without the flag, no prompt text is stored anywhere (assert absence on disk).
2. With the flag, first run shows a consent prompt; declining stores nothing.
3. Stored prompt bodies are redacted and live in a separate file from events.
4. Default `report` shows no raw prompt text; `--show-prompts` shows redacted previews.

### US2 — Purge (Priority: P1)
`unworldly purge --prompts <session>` deletes prompt bodies while keeping the
sealed event trail intact and still verifiable.

**Acceptance**: after purge, event hash chain + seal still validate; prompt file gone.

## Requirements
- **FR-001**: Prompt capture MUST be opt-in (flag + config) and consent-gated; default off.
- **FR-002**: Prompt bodies MUST be redacted before write and stored separately from events.
- **FR-003**: The event seal MUST remain valid whether or not prompt bodies exist or are purged.
- **FR-004**: No prompt content in default report output; redacted preview only behind `--show-prompts`.
- **FR-005**: Configurable truncation cap; local-only storage; no network.
- **FR-006**: `unworldly purge --prompts` removes bodies without breaking integrity.

## Out of Scope
- Capturing raw model API traffic at the network layer.
- Any default-on behavior. Any cloud storage or sharing of prompt bodies.

## Architectural Decision (ADR candidate)
Storing prompt/reasoning content changes Unworldly's data-sensitivity class from
"metadata about actions" to "potentially secret payloads," with real privacy,
retention, and liability consequences. The storage model (separate redacted file,
hash-referenced, independently purgeable) and the consent/opt-in contract are
cross-cutting and long-lived.

📋 Architectural decision detected: opt-in prompt/reasoning capture — data
sensitivity, consent model, separable storage & purge — Document reasoning and
tradeoffs? Run `/sp.adr prompt-capture-privacy-model`

## Definition of Done (future implementation)
- [ ] Opt-in flag + config + one-time consent gate (default off)
- [ ] Redacted, size-capped, separate-file storage referenced by hash
- [ ] Event seal valid with/without prompt bodies; `purge --prompts` keeps integrity
- [ ] Default report hides prompt text; `--show-prompts` shows redacted preview
- [ ] Tests: default-off absence, consent decline, redaction, purge-keeps-seal
