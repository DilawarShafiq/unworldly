# Tasks: Process Monitoring & Command Detection

**Input**: Design documents from `specs/1-process-monitoring/`
**Prerequisites**: plan.md, spec.md

## Phase 1: Foundation — Type System & Command Risk Engine

**Purpose**: Extend the type system and build the command risk scoring engine that all other tasks depend on.

- [ ] T001 [US1/US2] Extend types in `src/types.ts` — Add `'command'` to `EventType` union, add `CommandInfo` interface (`executable`, `args`, `cwd`, `pid`, `exitCode?`), add optional `command?: CommandInfo` field to `WatchEvent`
- [ ] T002 [US2] Create command risk scoring in `src/command-risk.ts` — Implement `assessCommandRisk(executable: string, args: string[]): RiskResult` with DANGER patterns (`rm -rf`, `sudo`, `curl`, `wget`, `chmod 777`, `dd`, `mkfs`, `kill -9`), CAUTION patterns (`npm install`, `pip install`, `git push`, `docker run`, `brew install`), SAFE patterns (`git add`, `git status`, `ls`, `cat`, `echo`, `node`, `npm test`, `npm run`)
- [ ] T003 [P] [US2] Create unit tests in `tests/command-risk.test.ts` — Test all DANGER/CAUTION/SAFE patterns, test unknown commands default to safe, test pattern matching on full command string (executable + args)

**Checkpoint**: Command risk engine works standalone. Can classify any command string.

---

## Phase 2: Config System

**Purpose**: Allow users to customize command risk patterns via `.unworldly/config.json`

- [ ] T004 [US5] Create config loader in `src/config.ts` — Implement `loadConfig(baseDir: string): MonitorConfig` that reads `.unworldly/config.json`, returns defaults if file doesn't exist, warns and falls back if malformed. Config schema: `{ commands: { allowlist: [{pattern, risk, reason}], blocklist: [{pattern, risk, reason}] } }`
- [ ] T005 [US5] Integrate config into command risk scoring — Modify `assessCommandRisk()` to accept optional `MonitorConfig` parameter, check custom allowlist/blocklist BEFORE default patterns
- [ ] T006 [P] [US5] Create unit tests in `tests/config.test.ts` — Test config loading from file, test missing file returns defaults, test malformed file warns and returns defaults, test custom patterns override defaults

**Checkpoint**: Config system works. Custom risk patterns override defaults.

---

## Phase 3: Process Monitor (Core Detection)

**Purpose**: Detect shell commands spawned in the watched directory — the core new capability.

- [ ] T007 [US1] Create process monitor in `src/command-monitor.ts` — Implement `CommandMonitor` class with `start(cwd: string, callback: (cmd: CommandInfo) => void)` and `stop()` methods. Uses periodic polling (500ms interval) to detect new processes:
  - Linux/macOS: Parse output of `ps -eo pid,ppid,comm,args` filtered by CWD
  - Windows: Parse output of `wmic process get ProcessId,ParentProcessId,CommandLine,ExecutablePath`
  - Track seen PIDs to only report new processes
  - Emit callback for each new process detected
- [ ] T008 [US1] Add platform detection and graceful degradation — If process monitoring fails (unsupported platform, permission denied), emit a warning to stderr and return a no-op monitor that never fires events. Feature degrades to file-only monitoring.
- [ ] T009 [P] [US1] Create unit tests in `tests/command-monitor.test.ts` — Test PID tracking (don't report same process twice), test platform detection, test graceful degradation on unsupported platform, test stop() cleans up interval

**Checkpoint**: Process monitor detects commands on the current platform or degrades gracefully.

---

## Phase 4: Display & Integration

**Purpose**: Wire everything together — command events appear in real-time output and session recordings.

- [ ] T010 [US4] Update display in `src/display.ts` — Add `COMMAND` to `EVENT_ICONS` with `$>` prefix and distinct styling. Update `formatEvent()` to handle `'command'` event type, showing the command string instead of file path. For commands, show executable + args as the path.
- [ ] T011 [US1/US3] Integrate command monitor into watcher in `src/watcher.ts` — Import `CommandMonitor` and `assessCommandRisk`. Start the monitor alongside chokidar. On command detection: create a `WatchEvent` with `type: 'command'`, risk-score it, call `addEvent()`, display it with `formatEvent()`, save incrementally. On shutdown: stop the monitor alongside chokidar. Load config at start and pass to risk scorer.
- [ ] T012 [US3] Update replay in `src/replay.ts` — Handle `'command'` event type in replay output. Command events use the same `formatEvent()` function (which now handles commands). No timing changes needed — commands replay at their recorded timestamps.
- [ ] T013 [US3] Update report in `src/report.ts` — Include command events in both terminal and markdown reports. In "Dangerous Actions" section, show commands alongside file events. In markdown timeline table, show command events with `COMMAND` action type and the command string. Add a "Commands Executed" subsection listing all commands with risk levels.
- [ ] T014 [P] [US1] Update exports in `src/index.ts` — Export `CommandMonitor`, `assessCommandRisk`, `loadConfig`, and `CommandInfo` type from index.

**Checkpoint**: Full integration complete. `unworldly watch` captures both files and commands. `replay` and `report` show both.

---

## Phase 5: Polish

**Purpose**: Final quality and consistency improvements.

- [ ] T015 End-to-end manual test — Run `unworldly watch .`, execute various commands (`npm install`, `git status`, `rm test.txt`, `curl example.com`), verify command events appear with correct risk levels. Run `unworldly replay` and `unworldly report` on the resulting session.
- [ ] T016 [P] Update session version — Bump session `version` in `createSession()` from `'0.1.0'` to `'0.2.0'` to indicate sessions may now contain command events. Existing sessions without command events remain valid (backward compatible).

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Foundation)**: No dependencies — start immediately
- **Phase 2 (Config)**: Depends on T002 (command risk types)
- **Phase 3 (Monitor)**: Depends on T001 (types)
- **Phase 4 (Integration)**: Depends on Phases 1, 2, and 3
- **Phase 5 (Polish)**: Depends on Phase 4

### Parallel Opportunities

- T003 (risk tests) can run in parallel with T001/T002 implementation
- T006 (config tests) can run in parallel with T004/T005
- T009 (monitor tests) can run in parallel with T007/T008
- T014 (exports) can run in parallel with T010-T013
- T016 (version bump) can run in parallel with T015

### Critical Path

T001 → T002 → T005 → T007 → T011 → T015

### Execution Order (Sequential)

1. T001 (types) → T002 (risk patterns) → T003 (risk tests)
2. T004 (config loader) → T005 (config integration) → T006 (config tests)
3. T007 (process monitor) → T008 (graceful degradation) → T009 (monitor tests)
4. T010 (display) → T011 (watcher integration) → T012 (replay) → T013 (report) → T014 (exports)
5. T015 (e2e test) → T016 (version bump)
