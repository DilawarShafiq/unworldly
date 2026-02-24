import fs from 'node:fs';
import path from 'node:path';
import type { CommandRiskConfig } from './command-risk.js';

export interface MonitorConfig {
  commands: CommandRiskConfig;
}

const DEFAULT_CONFIG: MonitorConfig = {
  commands: {
    allowlist: [],
    blocklist: [],
  },
};

export function loadConfig(baseDir: string): MonitorConfig {
  const configPath = path.join(baseDir, '.unworldly', 'config.json');

  if (!fs.existsSync(configPath)) {
    return DEFAULT_CONFIG;
  }

  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    const parsed = JSON.parse(content) as Partial<MonitorConfig>;

    return {
      commands: {
        allowlist: parsed.commands?.allowlist ?? [],
        blocklist: parsed.commands?.blocklist ?? [],
      },
    };
  } catch {
    console.error(`Warning: Failed to parse .unworldly/config.json — using defaults`);
    return DEFAULT_CONFIG;
  }
}
