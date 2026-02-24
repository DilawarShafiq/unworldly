import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'unworldly-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return defaults when no config file exists', () => {
    const config = loadConfig(tmpDir);
    expect(config.commands.allowlist).toEqual([]);
    expect(config.commands.blocklist).toEqual([]);
  });

  it('should load config from .unworldly/config.json', () => {
    const configDir = path.join(tmpDir, '.unworldly');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, 'config.json'),
      JSON.stringify({
        commands: {
          allowlist: [{ pattern: 'my-tool', risk: 'safe', reason: 'Internal tool' }],
          blocklist: [{ pattern: 'evil-pkg', risk: 'danger', reason: 'Malicious' }],
        },
      }),
      'utf-8',
    );

    const config = loadConfig(tmpDir);
    expect(config.commands.allowlist).toHaveLength(1);
    expect(config.commands.allowlist[0].pattern).toBe('my-tool');
    expect(config.commands.blocklist).toHaveLength(1);
    expect(config.commands.blocklist[0].pattern).toBe('evil-pkg');
  });

  it('should return defaults for malformed JSON', () => {
    const configDir = path.join(tmpDir, '.unworldly');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, 'config.json'), 'not valid json{{{', 'utf-8');

    const config = loadConfig(tmpDir);
    expect(config.commands.allowlist).toEqual([]);
    expect(config.commands.blocklist).toEqual([]);
  });

  it('should handle partial config gracefully', () => {
    const configDir = path.join(tmpDir, '.unworldly');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, 'config.json'),
      JSON.stringify({ commands: { allowlist: [{ pattern: 'foo', risk: 'safe', reason: 'OK' }] } }),
      'utf-8',
    );

    const config = loadConfig(tmpDir);
    expect(config.commands.allowlist).toHaveLength(1);
    expect(config.commands.blocklist).toEqual([]);
  });
});
