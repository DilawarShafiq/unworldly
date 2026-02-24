import { execSync } from 'node:child_process';
import { platform } from 'node:os';
import path from 'node:path';
import type { CommandInfo } from './types.js';

interface ProcessEntry {
  pid: number;
  command: string;
  args: string;
}

export class CommandMonitor {
  private interval: ReturnType<typeof setInterval> | null = null;
  private seenPids: Set<number> = new Set();
  private watchDir: string = '';
  private selfPid: number = process.pid;

  start(cwd: string, callback: (cmd: CommandInfo) => void): void {
    this.watchDir = path.resolve(cwd);
    this.seenPids.clear();

    // Snapshot current processes to avoid reporting pre-existing ones
    try {
      const initial = this.listProcesses();
      for (const proc of initial) {
        this.seenPids.add(proc.pid);
      }
    } catch {
      // If initial snapshot fails, we'll start clean
    }

    this.interval = setInterval(() => {
      try {
        const processes = this.listProcesses();
        for (const proc of processes) {
          if (this.seenPids.has(proc.pid)) continue;
          if (proc.pid === this.selfPid) continue;

          this.seenPids.add(proc.pid);

          // Parse command and args
          const parts = proc.args.trim().split(/\s+/);
          const executable = parts[0] || proc.command;
          const args = parts.slice(1);

          // Skip system/internal processes
          if (this.shouldSkip(executable)) continue;

          const info: CommandInfo = {
            executable: path.basename(executable),
            args,
            cwd: this.watchDir,
            pid: proc.pid,
          };

          callback(info);
        }
      } catch {
        // Silently skip poll failures — Zero Interference
      }
    }, 500);
  }

  stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    this.seenPids.clear();
  }

  private shouldSkip(executable: string): boolean {
    const skip = [
      'ps', 'wmic', 'powershell', 'cmd.exe', 'conhost',
      'unworldly', 'node_modules/.bin',
      'Get-Process', 'WMIC.exe',
    ];
    const base = path.basename(executable).toLowerCase();
    return skip.some(s => base.includes(s.toLowerCase()));
  }

  private listProcesses(): ProcessEntry[] {
    const os = platform();

    if (os === 'win32') {
      return this.listProcessesWindows();
    }

    return this.listProcessesUnix();
  }

  private listProcessesUnix(): ProcessEntry[] {
    const output = execSync('ps -eo pid,comm,args --no-headers 2>/dev/null', {
      encoding: 'utf-8',
      timeout: 2000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const entries: ProcessEntry[] = [];

    for (const line of output.trim().split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      const match = trimmed.match(/^(\d+)\s+(\S+)\s+(.*)$/);
      if (!match) continue;

      entries.push({
        pid: parseInt(match[1], 10),
        command: match[2],
        args: match[3],
      });
    }

    return entries;
  }

  private listProcessesWindows(): ProcessEntry[] {
    const output = execSync(
      'wmic process get ProcessId,Name,CommandLine /format:csv 2>nul',
      {
        encoding: 'utf-8',
        timeout: 3000,
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    const entries: ProcessEntry[] = [];
    const lines = output.trim().split('\n');

    // Skip header line (first non-empty line after filtering)
    for (const line of lines.slice(1)) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      // CSV format: Node,CommandLine,Name,ProcessId
      const parts = trimmed.split(',');
      if (parts.length < 4) continue;

      const commandLine = parts.slice(1, -2).join(','); // CommandLine may contain commas
      const name = parts[parts.length - 2];
      const pid = parseInt(parts[parts.length - 1], 10);

      if (isNaN(pid)) continue;

      entries.push({
        pid,
        command: name,
        args: commandLine || name,
      });
    }

    return entries;
  }
}

export function createCommandMonitor(): CommandMonitor | null {
  try {
    const monitor = new CommandMonitor();
    return monitor;
  } catch {
    return null;
  }
}
