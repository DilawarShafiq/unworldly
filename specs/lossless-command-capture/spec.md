# Feature Specification: Kernel-Level Lossless Command Capture (Linux)

**Feature Branch**: `lossless-command-capture`
**Created**: 2026-07-24
**Status**: Draft (spec-only; no implementation yet)
**Input**: ROADMAP item 8 — remove reliance on shell rc hooks for lossless command capture.

## Problem

Unworldly has two command-capture mechanisms today, both with gaps:

1. **Poll mode** (`command_monitor.py`) — samples the process list every 500ms.
   Misses ~89% of short-lived commands. Best-effort only.
2. **Shell hook** (`shell_hook.py`) — a `preexec` hook logs every command. Lossless,
   but only for commands run *through an instrumented interactive shell*. It misses:
   - commands an agent spawns directly via `execve`/`posix_spawn` (no shell),
   - subprocesses of subprocesses,
   - anything in a shell the user didn't install the hook into.

For an agent that calls `subprocess.run(["rm","-rf",...])` directly (no shell), **neither
mechanism reliably sees it**. A kernel-level probe closes this gap: it observes every
`execve` regardless of how it was launched.

## Goal

Capture **every process execution** under the watched session, losslessly, without
requiring a shell hook, on Linux — feeding the same risk/hash-chain pipeline.

## Candidate Mechanisms

### A. eBPF (tracepoint `sched_process_exec` / kprobe on `execve`)
- **How**: attach a BPF program to the exec tracepoint; stream `{pid, ppid, comm, argv, cwd}`
  to userspace via a ring buffer. Filter to descendants of the watched session / cwd.
- **Pros**: lossless, low overhead, no per-shell setup, sees no-shell `execve`.
- **Cons**: needs `CAP_BPF`/root (or `CAP_PERFMON`), kernel ≥ 5.8 for ring buffer,
  a BPF toolchain (`bcc`/`libbpf`/`bpftrace`). Not portable (Linux only).

### B. auditd (`auditctl` rule on `execve` syscall)
- **How**: install an audit rule (`-a exit,always -F arch=b64 -S execve`); read events from
  `auditd`/`audispd` or the netlink socket; map to command events.
- **Pros**: ubiquitous on enterprise Linux, no compiler, battle-tested for compliance.
- **Cons**: needs root to add rules; global (must filter to session); can interfere with an
  existing site audit config; event volume can be high.

### C. `PTRACE`/`fanotify`/`/proc` polling — rejected
- ptrace is invasive (violates Zero Interference); /proc polling has the same race as
  the current poller. Not pursued.

## Recommendation (to be ratified by ADR)

Ship **B (auditd)** first as an opt-in `--capture kernel` on Linux when running as root
(widest availability, no build step), and **A (eBPF via `bpftrace`)** as a second backend
when `bpftrace` is present. Both are **opt-in** and **degrade gracefully** to the shell hook
then poll mode. Never require root for the default experience.

## Requirements

- **FR-001**: Provide a Linux-only `KernelCommandMonitor` with the same
  `start(cwd, callback)` / `stop()` interface as `CommandMonitor`, so `watcher.py`
  can select it via `--capture kernel` with zero pipeline changes.
- **FR-002**: Capture MUST be scoped to the watched session (descendants of the watch
  process or commands whose cwd is under the watched directory) — never the whole host.
- **FR-003**: MUST detect capability at start; if unavailable (not Linux, not root, no
  backend), print an honest warning and fall back (hook → poll). Never crash, never
  silently pretend to capture (honesty contract).
- **FR-004**: MUST NOT modify or delete a pre-existing site `auditd` ruleset; add and
  remove only Unworldly's own rule, restoring prior state on stop.
- **FR-005**: `unworldly doctor` MUST report kernel-capture availability and which backend
  would be used.

## Non-Functional Requirements

- **Security**: root/`CAP_BPF` is a real escalation — document it, keep it opt-in, and scope
  rules tightly. Never run the target through the probe with elevated privileges.
- **Performance**: < 2% overhead under a busy build; ring buffer / audit backlog sized to
  avoid drops (a drop MUST be logged, never silent — see honesty contract).
- **Portability**: Linux only. macOS (EndpointSecurity) and Windows (ETW) are future specs.

## Out of Scope

- macOS EndpointSecurity and Windows ETW backends (separate specs).
- Capturing network syscalls or file opens at the kernel level (this is exec-only).

## Architectural Decision (ADR candidate)

Adding a root-requiring, platform-specific capture backend is architecturally significant:
it introduces an optional privileged component, a new dependency surface (bcc/libbpf or
auditd), and a capability-detection + graceful-degradation contract across the CLI. The
backend choice (auditd-first vs eBPF-first vs both) has long-term maintenance consequences.

📋 Architectural decision detected: kernel-level command-capture backend (auditd vs eBPF,
opt-in privileged component) — Document reasoning and tradeoffs? Run
`/sp.adr kernel-command-capture-backend`

## Definition of Done (future implementation)

- [ ] `KernelCommandMonitor` (auditd backend) behind `--capture kernel`, Linux+root
- [ ] Session-scoped filtering (FR-002); prior audit ruleset preserved (FR-004)
- [ ] Capability detection + graceful fallback + honest warning (FR-003)
- [ ] `unworldly doctor` reports kernel-capture availability (FR-005)
- [ ] eBPF (`bpftrace`) backend as an alternative
- [ ] Tests: capability detection, fallback path, event→CommandInfo mapping
