import path from 'node:path';
import chokidar from 'chokidar';
import type { EventType, Session, WatchEvent } from './types.js';
import { assessRisk, shouldIgnore } from './risk.js';
import { assessCommandRisk } from './command-risk.js';
import { createCommandMonitor } from './command-monitor.js';
import { loadConfig } from './config.js';
import { addEvent, createSession, saveSession, ensureSessionsDir } from './session.js';
import { banner, formatEvent, sessionSummary, watchHeader } from './display.js';

function formatTime(date: Date): string {
  return date.toLocaleTimeString('en-US', { hour12: false });
}

function mapChokidarEvent(event: string): EventType | null {
  switch (event) {
    case 'add': return 'create';
    case 'change': return 'modify';
    case 'unlink': return 'delete';
    default: return null;
  }
}

export async function watch(directory: string): Promise<void> {
  const absDir = path.resolve(directory);
  const session: Session = createSession(absDir);

  console.log(banner());
  console.log(watchHeader(absDir));

  const watcher = chokidar.watch(absDir, {
    ignored: [
      /node_modules/,
      /\.git/,
      /dist\//,
      /build\//,
      /\.unworldly/,
      /\.DS_Store/,
    ],
    persistent: true,
    ignoreInitial: true,
    awaitWriteFinish: {
      stabilityThreshold: 300,
      pollInterval: 100,
    },
  });

  const handleEvent = (chokidarEvent: string, filePath: string) => {
    const eventType = mapChokidarEvent(chokidarEvent);
    if (!eventType) return;

    const relativePath = path.relative(absDir, filePath);
    if (shouldIgnore(relativePath)) return;

    const { level, reason } = assessRisk(relativePath, eventType);
    const now = new Date();

    const event: WatchEvent = {
      timestamp: now.toISOString(),
      type: eventType,
      path: relativePath,
      risk: level,
      ...(reason && { reason }),
    };

    addEvent(session, event);
    console.log(formatEvent(formatTime(now), eventType, relativePath, level, reason));

    // Save incrementally so no data is lost on abrupt exit
    saveSession(session, absDir);
  };

  watcher.on('add', (p) => handleEvent('add', p));
  watcher.on('change', (p) => handleEvent('change', p));
  watcher.on('unlink', (p) => handleEvent('unlink', p));

  // Load user config for command risk overrides
  const config = loadConfig(absDir);

  // Start command monitor
  const cmdMonitor = createCommandMonitor();
  if (cmdMonitor) {
    cmdMonitor.start(absDir, (cmd) => {
      const { level, reason } = assessCommandRisk(cmd.executable, cmd.args, config.commands);
      const now = new Date();
      const commandStr = [cmd.executable, ...cmd.args].join(' ');

      const event: WatchEvent = {
        timestamp: now.toISOString(),
        type: 'command',
        path: commandStr,
        risk: level,
        reason,
        command: cmd,
      };

      addEvent(session, event);
      console.log(formatEvent(formatTime(now), 'command', commandStr, level, reason));
      saveSession(session, absDir);
    });
  } else {
    console.log('  ⚠ Process monitoring unavailable — tracking file changes only');
  }

  // Pre-create session dir and save initial empty session
  ensureSessionsDir(absDir);
  saveSession(session, absDir);

  // Graceful shutdown
  const shutdown = async () => {
    if (cmdMonitor) cmdMonitor.stop();
    await watcher.close();
    const sessionPath = saveSession(session, absDir);
    console.log(sessionSummary(session.summary, sessionPath));
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('exit', () => {
    saveSession(session, absDir);
  });

  // Keep alive
  await new Promise(() => {});
}
