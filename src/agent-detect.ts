import { execSync } from 'node:child_process';
import { platform } from 'node:os';
import type { AgentInfo } from './types.js';

interface AgentSignature {
  name: string;
  envVars: string[];
  processNames: string[];
  parentProcessNames: string[];
}

const KNOWN_AGENTS: AgentSignature[] = [
  {
    name: 'Claude Code',
    envVars: ['CLAUDE_CODE', 'ANTHROPIC_API_KEY'],
    processNames: ['claude'],
    parentProcessNames: ['claude'],
  },
  {
    name: 'Cursor',
    envVars: ['CURSOR_SESSION', 'CURSOR_TRACE_ID'],
    processNames: ['cursor', 'Cursor', 'Cursor.exe'],
    parentProcessNames: ['cursor', 'Cursor'],
  },
  {
    name: 'GitHub Copilot',
    envVars: ['GITHUB_COPILOT', 'COPILOT_AGENT'],
    processNames: ['copilot-agent', 'copilot'],
    parentProcessNames: ['copilot'],
  },
  {
    name: 'Windsurf',
    envVars: ['WINDSURF_SESSION'],
    processNames: ['windsurf', 'Windsurf'],
    parentProcessNames: ['windsurf'],
  },
  {
    name: 'Devin',
    envVars: ['DEVIN_SESSION', 'DEVIN_API'],
    processNames: ['devin'],
    parentProcessNames: ['devin'],
  },
  {
    name: 'Aider',
    envVars: ['AIDER_MODEL'],
    processNames: ['aider'],
    parentProcessNames: ['aider'],
  },
  {
    name: 'OpenClaw',
    envVars: ['OPENCLAW_SESSION'],
    processNames: ['openclaw'],
    parentProcessNames: ['openclaw'],
  },
  {
    name: 'Cline',
    envVars: ['CLINE_SESSION'],
    processNames: ['cline'],
    parentProcessNames: ['cline'],
  },
];

/**
 * Detect which AI agent is running by checking environment variables
 * and active processes. Returns null if no known agent is detected.
 *
 * ISO 42001 A.3.2: Establish clear accountability — identify the agent.
 */
export function detectAgent(): AgentInfo | null {
  // Strategy 1: Check environment variables (fastest, most reliable)
  for (const agent of KNOWN_AGENTS) {
    for (const envVar of agent.envVars) {
      if (process.env[envVar]) {
        return {
          name: agent.name,
          detectedVia: `environment variable: ${envVar}`,
        };
      }
    }
  }

  // Strategy 2: Check parent process tree
  try {
    const parentInfo = getParentProcessName();
    if (parentInfo) {
      for (const agent of KNOWN_AGENTS) {
        for (const name of agent.parentProcessNames) {
          if (parentInfo.toLowerCase().includes(name.toLowerCase())) {
            return {
              name: agent.name,
              detectedVia: `parent process: ${parentInfo}`,
            };
          }
        }
      }
    }
  } catch {
    // Can't read parent process — not critical
  }

  // Strategy 3: Check running processes
  try {
    const processes = getRunningProcesses();
    for (const agent of KNOWN_AGENTS) {
      for (const name of agent.processNames) {
        if (processes.some(p => p.toLowerCase().includes(name.toLowerCase()))) {
          return {
            name: agent.name,
            detectedVia: `running process: ${name}`,
          };
        }
      }
    }
  } catch {
    // Can't list processes — not critical
  }

  return null;
}

function getParentProcessName(): string | null {
  try {
    const ppid = process.ppid;
    if (!ppid) return null;

    const os = platform();
    if (os === 'win32') {
      const output = execSync(
        `wmic process where ProcessId=${ppid} get Name /format:csv 2>nul`,
        { encoding: 'utf-8', timeout: 2000, stdio: ['pipe', 'pipe', 'pipe'] },
      );
      const lines = output.trim().split('\n').filter(l => l.trim());
      if (lines.length >= 2) {
        const parts = lines[1].trim().split(',');
        return parts[parts.length - 1]?.trim() || null;
      }
    } else {
      const output = execSync(
        `ps -p ${ppid} -o comm= 2>/dev/null`,
        { encoding: 'utf-8', timeout: 2000, stdio: ['pipe', 'pipe', 'pipe'] },
      );
      return output.trim() || null;
    }
  } catch {
    return null;
  }
  return null;
}

function getRunningProcesses(): string[] {
  try {
    const os = platform();
    if (os === 'win32') {
      const output = execSync('tasklist /fo csv /nh 2>nul', {
        encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'pipe'],
      });
      return output.split('\n').map(l => l.split(',')[0]?.replace(/"/g, '') ?? '').filter(Boolean);
    } else {
      const output = execSync('ps -eo comm --no-headers 2>/dev/null', {
        encoding: 'utf-8', timeout: 2000, stdio: ['pipe', 'pipe', 'pipe'],
      });
      return output.split('\n').map(l => l.trim()).filter(Boolean);
    }
  } catch {
    return [];
  }
}
