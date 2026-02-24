import type { RiskLevel } from './types.js';

export interface CommandRiskResult {
  level: RiskLevel;
  reason: string;
}

export interface CommandRiskPattern {
  pattern: RegExp;
  risk: RiskLevel;
  reason: string;
}

export interface CommandRiskConfig {
  allowlist: Array<{ pattern: string; risk: RiskLevel; reason: string }>;
  blocklist: Array<{ pattern: string; risk: RiskLevel; reason: string }>;
}

const DANGER_PATTERNS: CommandRiskPattern[] = [
  { pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--force.*--recursive|--recursive.*--force|-[a-zA-Z]*f[a-zA-Z]*r)\b/, risk: 'danger', reason: 'Destructive recursive deletion' },
  { pattern: /\brm\s+-rf\b/, risk: 'danger', reason: 'Destructive recursive deletion' },
  { pattern: /\bsudo\b/, risk: 'danger', reason: 'Elevated privilege command' },
  { pattern: /\bcurl\b/, risk: 'danger', reason: 'Network request to external URL' },
  { pattern: /\bwget\b/, risk: 'danger', reason: 'Network download from external URL' },
  { pattern: /\bchmod\s+777\b/, risk: 'danger', reason: 'Setting world-writable permissions' },
  { pattern: /\bchmod\s+\+s\b/, risk: 'danger', reason: 'Setting setuid/setgid bit' },
  { pattern: /\bdd\s+/, risk: 'danger', reason: 'Low-level disk operation' },
  { pattern: /\bmkfs\b/, risk: 'danger', reason: 'Filesystem format operation' },
  { pattern: /\bkill\s+-9\b/, risk: 'danger', reason: 'Force-killing process' },
  { pattern: /\bkill\s+-SIGKILL\b/, risk: 'danger', reason: 'Force-killing process' },
  { pattern: /\bformat\b/, risk: 'danger', reason: 'Disk format operation' },
  { pattern: /\bdel\s+\/[fF]\s+\/[sS]\b/, risk: 'danger', reason: 'Destructive recursive deletion (Windows)' },
  { pattern: /\beval\b/, risk: 'danger', reason: 'Dynamic code execution' },
  { pattern: /\bnc\s+-l\b/, risk: 'danger', reason: 'Opening network listener' },
  { pattern: /\bssh\b.*@/, risk: 'danger', reason: 'Remote SSH connection' },
  { pattern: /\bscp\b/, risk: 'danger', reason: 'Remote file copy' },
  { pattern: /\bgit\s+push\s+--force\b/, risk: 'danger', reason: 'Force-pushing to remote repository' },
  { pattern: /\bgit\s+reset\s+--hard\b/, risk: 'danger', reason: 'Hard reset discards changes' },
];

const CAUTION_PATTERNS: CommandRiskPattern[] = [
  { pattern: /\bnpm\s+install\b/, risk: 'caution', reason: 'Installing npm package' },
  { pattern: /\bnpm\s+i\b/, risk: 'caution', reason: 'Installing npm package' },
  { pattern: /\bpip\s+install\b/, risk: 'caution', reason: 'Installing Python package' },
  { pattern: /\bbrew\s+install\b/, risk: 'caution', reason: 'Installing Homebrew package' },
  { pattern: /\bapt\s+install\b/, risk: 'caution', reason: 'Installing system package' },
  { pattern: /\bapt-get\s+install\b/, risk: 'caution', reason: 'Installing system package' },
  { pattern: /\byarn\s+add\b/, risk: 'caution', reason: 'Installing yarn package' },
  { pattern: /\bpnpm\s+add\b/, risk: 'caution', reason: 'Installing pnpm package' },
  { pattern: /\bgit\s+push\b/, risk: 'caution', reason: 'Pushing to remote repository' },
  { pattern: /\bdocker\s+run\b/, risk: 'caution', reason: 'Running Docker container' },
  { pattern: /\bdocker\s+exec\b/, risk: 'caution', reason: 'Executing in Docker container' },
  { pattern: /\bchmod\b/, risk: 'caution', reason: 'Changing file permissions' },
  { pattern: /\bchown\b/, risk: 'caution', reason: 'Changing file ownership' },
  { pattern: /\brm\b/, risk: 'caution', reason: 'Deleting files' },
  { pattern: /\bgit\s+checkout\s+--\b/, risk: 'caution', reason: 'Discarding file changes' },
  { pattern: /\bnpx\b/, risk: 'caution', reason: 'Executing remote npm package' },
];

const SAFE_PATTERNS: CommandRiskPattern[] = [
  { pattern: /\bgit\s+add\b/, risk: 'safe', reason: 'Staging files' },
  { pattern: /\bgit\s+status\b/, risk: 'safe', reason: 'Checking git status' },
  { pattern: /\bgit\s+diff\b/, risk: 'safe', reason: 'Viewing git diff' },
  { pattern: /\bgit\s+log\b/, risk: 'safe', reason: 'Viewing git log' },
  { pattern: /\bgit\s+branch\b/, risk: 'safe', reason: 'Managing branches' },
  { pattern: /\bgit\s+stash\b/, risk: 'safe', reason: 'Stashing changes' },
  { pattern: /\bls\b/, risk: 'safe', reason: 'Listing directory' },
  { pattern: /\bcat\b/, risk: 'safe', reason: 'Reading file' },
  { pattern: /\becho\b/, risk: 'safe', reason: 'Echoing output' },
  { pattern: /\bpwd\b/, risk: 'safe', reason: 'Printing working directory' },
  { pattern: /\bnode\b/, risk: 'safe', reason: 'Running Node.js' },
  { pattern: /\bnpm\s+test\b/, risk: 'safe', reason: 'Running tests' },
  { pattern: /\bnpm\s+run\s+build\b/, risk: 'safe', reason: 'Building project' },
  { pattern: /\bnpm\s+run\s+dev\b/, risk: 'safe', reason: 'Running dev server' },
  { pattern: /\bnpm\s+run\s+lint\b/, risk: 'safe', reason: 'Running linter' },
  { pattern: /\btsc\b/, risk: 'safe', reason: 'Running TypeScript compiler' },
  { pattern: /\bvitest\b/, risk: 'safe', reason: 'Running tests' },
  { pattern: /\bmkdir\b/, risk: 'safe', reason: 'Creating directory' },
  { pattern: /\bcp\b/, risk: 'safe', reason: 'Copying files' },
  { pattern: /\bmv\b/, risk: 'safe', reason: 'Moving files' },
  { pattern: /\bhead\b/, risk: 'safe', reason: 'Reading file head' },
  { pattern: /\btail\b/, risk: 'safe', reason: 'Reading file tail' },
  { pattern: /\bgrep\b/, risk: 'safe', reason: 'Searching content' },
  { pattern: /\bfind\b/, risk: 'safe', reason: 'Finding files' },
];

export function assessCommandRisk(
  executable: string,
  args: string[],
  config?: CommandRiskConfig,
): CommandRiskResult {
  const fullCommand = [executable, ...args].join(' ');

  // Check custom config patterns first (allowlist then blocklist)
  if (config) {
    for (const entry of config.allowlist) {
      if (new RegExp(entry.pattern).test(fullCommand)) {
        return { level: entry.risk, reason: entry.reason };
      }
    }
    for (const entry of config.blocklist) {
      if (new RegExp(entry.pattern).test(fullCommand)) {
        return { level: entry.risk, reason: entry.reason };
      }
    }
  }

  // Check danger patterns first (highest priority)
  for (const { pattern, reason } of DANGER_PATTERNS) {
    if (pattern.test(fullCommand)) {
      return { level: 'danger', reason };
    }
  }

  // Then safe patterns (before caution, to allow specific safe overrides)
  for (const { pattern, reason } of SAFE_PATTERNS) {
    if (pattern.test(fullCommand)) {
      return { level: 'safe', reason };
    }
  }

  // Then caution patterns
  for (const { pattern, reason } of CAUTION_PATTERNS) {
    if (pattern.test(fullCommand)) {
      return { level: 'caution', reason };
    }
  }

  // Unknown commands default to safe
  return { level: 'safe', reason: 'Standard command' };
}
