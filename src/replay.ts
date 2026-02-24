import chalk from 'chalk';
import type { Session } from './types.js';
import { loadSession } from './session.js';
import { verifySession } from './integrity.js';
import { banner, formatEvent, replayHeader, sessionSummary, agentBadge, verifyDisplay } from './display.js';

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function formatTime(isoString: string): string {
  return new Date(isoString).toLocaleTimeString('en-US', { hour12: false });
}

export async function replay(
  sessionPath: string,
  options: { speed?: number } = {},
): Promise<void> {
  const session: Session = loadSession(sessionPath);
  const speed = options.speed ?? 1;

  console.log(banner());
  console.log(replayHeader(session.id, session.directory, session.startTime));
  if (session.agent) {
    console.log(agentBadge(session.agent));
  }

  // Show integrity status before replaying
  const integrity = verifySession(session);
  if (!integrity.valid) {
    console.log(chalk.red.bold('  ⚠ WARNING: Session integrity check failed — events may have been tampered with'));
    console.log('');
  }

  if (session.events.length === 0) {
    console.log(chalk.gray('  No events recorded in this session.'));
    return;
  }

  for (let i = 0; i < session.events.length; i++) {
    const event = session.events[i];

    // Calculate delay between events
    if (i > 0) {
      const prev = new Date(session.events[i - 1].timestamp).getTime();
      const curr = new Date(event.timestamp).getTime();
      const delay = Math.min((curr - prev) / speed, 2000); // Cap at 2s
      if (delay > 0) {
        await sleep(delay);
      }
    }

    console.log(formatEvent(
      formatTime(event.timestamp),
      event.type,
      event.path,
      event.risk,
      event.reason,
    ));
  }

  console.log(sessionSummary(session.summary, sessionPath));
}

export async function listCommand(baseDir: string): Promise<void> {
  const fs = await import('node:fs');
  const path = await import('node:path');

  const sessionsDir = path.join(baseDir, '.unworldly/sessions');
  if (!fs.existsSync(sessionsDir)) {
    console.log(chalk.gray('  No sessions found. Run `unworldly watch` first.'));
    return;
  }

  const files = fs.readdirSync(sessionsDir)
    .filter((f: string) => f.endsWith('.json'))
    .sort()
    .reverse();

  if (files.length === 0) {
    console.log(chalk.gray('  No sessions found. Run `unworldly watch` first.'));
    return;
  }

  console.log(banner());
  console.log(chalk.white.bold('  Recorded Sessions\n'));

  for (const file of files) {
    const filepath = path.join(sessionsDir, file);
    const content = fs.readFileSync(filepath, 'utf-8');
    const session: Session = JSON.parse(content);

    const riskColor = session.summary.riskScore >= 7
      ? chalk.red
      : session.summary.riskScore >= 4
        ? chalk.yellow
        : chalk.green;

    const date = new Date(session.startTime).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });

    const agentTag = session.agent ? chalk.cyan(` [${session.agent.name}]`) : '';
    const integrityTag = session.integrityHash ? chalk.green(' ✓') : chalk.gray(' ○');

    console.log(
      `  ${chalk.white.bold(session.id)}` +
      `  ${chalk.gray(date)}` +
      `  ${chalk.gray(session.summary.totalEvents + ' events')}` +
      `  Risk: ${riskColor(session.summary.riskScore + '/10')}` +
      integrityTag +
      agentTag,
    );
  }

  console.log('');
}
