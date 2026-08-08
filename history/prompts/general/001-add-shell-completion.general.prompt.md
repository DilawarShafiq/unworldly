---
id: 001
title: Add Shell Completion Docs
stage: general
date: 2026-08-09
surface: agent
model: openai/gpt-5.5
feature: none
branch: add-shell-completion-docs
user: idityage
command: clone this repo : https://github.com/idityaGE/unworldly.git and handle this issue : https://github.com/DilawarShafiq/unworldly/issues/11 and create a pr using gh cli
labels: [docs, cli, completion]
links:
  spec: null
  ticket: https://github.com/DilawarShafiq/unworldly/issues/11
  adr: null
  pr: null
files:
  - README.md
  - history/prompts/general/001-add-shell-completion.general.prompt.md
tests:
  - uv run unworldly --help
  - env _UNWORLDLY_COMPLETE=bash_source uv run unworldly
  - env _UNWORLDLY_COMPLETE=zsh_source uv run unworldly
  - env _UNWORLDLY_COMPLETE=fish_source uv run unworldly
  - uv run --extra dev pytest
---

## Prompt

clone this repo : https://github.com/idityaGE/unworldly.git

and handle this issue :
https://github.com/DilawarShafiq/unworldly/issues/11

and create a pr using gh cli

## Response snapshot

Cloned the fork, reviewed upstream issue #11, confirmed the Click-based CLI already generates shell completion scripts for the installed `unworldly` command, documented bash, zsh, and fish setup commands in the README, verified completion generation, and ran the full pytest suite.

## Outcome

- Impact: README now documents how to enable Click shell completion for bash, zsh, and fish.
- Tests: PASS: `uv run unworldly --help`; PASS: bash, zsh, and fish completion script generation; PASS: `uv run --extra dev pytest` with 210 tests passing.
- Files: Modified `README.md`; added this Prompt History Record.
- Next prompts: Open a PR against `DilawarShafiq/unworldly` for issue #11.
- Reflection: The smallest viable change was documentation because Click completion was already wired through the existing console script.

## Evaluation notes (flywheel)

- Failure modes observed: Local `python` lacked `pip`; `uv run pytest` without dev extras did not include pytest.
- Graders run and results (PASS/FAIL): PASS: full pytest suite; PASS: manual completion generation checks.
- Prompt variant (if applicable): N/A
- Next experiment (smallest change to try): Add automated CLI completion tests only if maintainers ask for executable coverage.
