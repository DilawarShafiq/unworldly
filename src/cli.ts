#!/usr/bin/env node

import { Command } from 'commander';
import { watch } from './watcher.js';
import { replay, listCommand } from './replay.js';
import { report } from './report.js';
import { getLatestSession } from './session.js';

const program = new Command();

program
  .name('unworldly')
  .description('The flight recorder for AI agents. Record, replay, and audit everything AI agents do on your system.')
  .version('0.1.0');

program
  .command('watch')
  .description('Start recording AI agent activity in the current directory')
  .argument('[directory]', 'Directory to watch', '.')
  .action(async (directory: string) => {
    await watch(directory);
  });

program
  .command('replay')
  .description('Replay a recorded session in the terminal')
  .argument('[session]', 'Session ID or path (defaults to latest)')
  .option('-s, --speed <speed>', 'Playback speed multiplier', '1')
  .action(async (session: string | undefined, options: { speed: string }) => {
    const sessionPath = session ?? getLatestSession(process.cwd());
    if (!sessionPath) {
      console.error('No sessions found. Run `unworldly watch` first.');
      process.exit(1);
    }
    await replay(sessionPath, { speed: parseFloat(options.speed) });
  });

program
  .command('report')
  .description('Generate a security report from a recorded session')
  .argument('[session]', 'Session ID or path (defaults to latest)')
  .option('-f, --format <format>', 'Output format: terminal, md', 'terminal')
  .option('-o, --output <path>', 'Output file path (for md format)')
  .action(async (session: string | undefined, options: { format: string; output?: string }) => {
    const sessionPath = session ?? getLatestSession(process.cwd());
    if (!sessionPath) {
      console.error('No sessions found. Run `unworldly watch` first.');
      process.exit(1);
    }
    await report(sessionPath, options);
  });

program
  .command('list')
  .alias('ls')
  .description('List all recorded sessions')
  .action(async () => {
    await listCommand(process.cwd());
  });

program.parse();
