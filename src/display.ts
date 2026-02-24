import chalk from 'chalk';
import type { EventType, RiskLevel, SessionSummary } from './types.js';

const RISK_ICONS: Record<RiskLevel, string> = {
  safe: chalk.green('  safe  '),
  caution: chalk.yellow(' caution'),
  danger: chalk.red.bold(' DANGER '),
};

const EVENT_ICONS: Record<EventType, string> = {
  create: chalk.green('CREATE '),
  modify: chalk.blue('MODIFY '),
  delete: chalk.red('DELETE '),
  command: chalk.magenta('$> CMD '),
};

export function banner(): string {
  const lines = [
    '',
    chalk.red.bold('  ╔═══════════════════════════════════════════════════╗'),
    chalk.red.bold('  ║') + chalk.white.bold('  UNWORLDLY') + chalk.gray(' v0.1.0') + chalk.red.bold('                            ║'),
    chalk.red.bold('  ║') + chalk.gray('  The Flight Recorder for AI Agents') + chalk.red.bold('              ║'),
    chalk.red.bold('  ╚═══════════════════════════════════════════════════╝'),
    '',
  ];
  return lines.join('\n');
}

export function watchHeader(directory: string): string {
  return [
    chalk.red('  ●') + chalk.white.bold(' REC') + chalk.gray(` — Watching: ${directory}`),
    chalk.gray('  Press Ctrl+C to stop recording'),
    chalk.gray('  ─'.repeat(28)),
    '',
  ].join('\n');
}

export function formatEvent(
  timestamp: string,
  type: EventType,
  filePath: string,
  risk: RiskLevel,
  reason?: string,
): string {
  const time = chalk.gray(timestamp);
  const event = EVENT_ICONS[type];
  const riskBadge = RISK_ICONS[risk];
  const file = risk === 'danger'
    ? chalk.red.bold(filePath)
    : risk === 'caution'
      ? chalk.yellow(filePath)
      : chalk.white(filePath);

  let line = `  ${time}  ${event}  ${file}  ${riskBadge}`;

  if (reason) {
    const reasonLine = risk === 'danger'
      ? chalk.red.bold(`  ┗━ ${reason}!`)
      : chalk.yellow(`  ┗━ ${reason}`);
    line += '\n' + reasonLine;
  }

  return line;
}

export function sessionSummary(summary: SessionSummary, sessionPath: string): string {
  const { totalEvents, safe, caution, danger, riskScore } = summary;

  const scoreColor = riskScore >= 7
    ? chalk.red.bold
    : riskScore >= 4
      ? chalk.yellow.bold
      : chalk.green.bold;

  return [
    '',
    chalk.gray('  ─'.repeat(28)),
    chalk.white.bold('  Session Summary'),
    '',
    `  Events: ${chalk.white.bold(totalEvents.toString())}` +
    `  ${chalk.green('●')} Safe: ${safe}` +
    `  ${chalk.yellow('●')} Caution: ${caution}` +
    `  ${chalk.red('●')} Danger: ${danger}`,
    '',
    `  Risk Score: ${scoreColor(riskScore + '/10')}`,
    '',
    chalk.gray(`  Session saved: ${sessionPath}`),
    '',
  ].join('\n');
}

export function replayHeader(sessionId: string, directory: string, startTime: string): string {
  return [
    chalk.blue.bold('  ▶ REPLAY') + chalk.gray(` — Session: ${sessionId}`),
    chalk.gray(`  Directory: ${directory}`),
    chalk.gray(`  Recorded: ${startTime}`),
    chalk.gray('  ─'.repeat(28)),
    '',
  ].join('\n');
}

export function reportDivider(): string {
  return chalk.gray('─'.repeat(56));
}
