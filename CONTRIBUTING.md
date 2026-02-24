# Contributing to Unworldly

Thanks for your interest in making AI agents more observable and accountable.

## Quick Start

```bash
git clone https://github.com/DilawarShafiq/unworldly.git
cd unworldly
npm install
npm run build
npx vitest run
```

## Development

```bash
# Run in dev mode (no build step)
npm run dev -- watch

# Run tests
npx vitest run

# Run tests in watch mode
npx vitest

# Build
npm run build
```

## Making Changes

1. Fork the repo
2. Create a branch (`git checkout -b my-feature`)
3. Make your changes
4. Run tests (`npx vitest run`) — all 139+ tests must pass
5. Commit with a clear message
6. Open a PR

## What We're Looking For

- **New agent detections** — Know an AI agent we don't detect yet? Add it to `src/agent-detect.ts`
- **New risk patterns** — Found a dangerous command we miss? Add it to `src/command-risk.ts`
- **Platform support** — Windows/Linux/macOS edge cases
- **Performance** — Faster process monitoring, lower overhead
- **Integrations** — MCP server, CI/CD plugins, dashboard

## Code Style

- TypeScript strict mode, no `any` types
- ESM modules (`.js` extensions in imports)
- Tests with vitest
- Keep functions small and focused

## Architecture

```
src/
  cli.ts          — CLI entry point (commander)
  watcher.ts      — Main watch loop (chokidar + process monitor)
  risk.ts         — File risk scoring
  command-risk.ts — Command risk scoring
  command-monitor.ts — Process monitoring
  integrity.ts    — SHA-256 hash chain
  agent-detect.ts — AI agent detection
  session.ts      — Session management
  display.ts      — Terminal output
  replay.ts       — Session replay
  report.ts       — Report generation
  config.ts       — User config loading
  types.ts        — Type definitions
```

## Questions?

Open an issue or start a discussion. We're friendly.
