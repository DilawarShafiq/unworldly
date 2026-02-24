import { describe, it, expect } from 'vitest';
import { banner, watchHeader, formatEvent, sessionSummary, replayHeader, reportDivider } from '../src/display.js';

describe('display', () => {
  describe('banner', () => {
    it('should contain UNWORLDLY', () => {
      const output = banner();
      expect(output).toContain('UNWORLDLY');
    });

    it('should contain version', () => {
      const output = banner();
      expect(output).toContain('v0.3.0');
    });

    it('should contain tagline', () => {
      const output = banner();
      expect(output).toContain('Flight Recorder');
    });
  });

  describe('watchHeader', () => {
    it('should contain REC indicator', () => {
      const output = watchHeader('/test/dir');
      expect(output).toContain('REC');
    });

    it('should contain the directory', () => {
      const output = watchHeader('/my/project');
      expect(output).toContain('/my/project');
    });

    it('should contain Ctrl+C hint', () => {
      const output = watchHeader('/test');
      expect(output).toContain('Ctrl+C');
    });
  });

  describe('formatEvent', () => {
    it('should contain the timestamp', () => {
      const output = formatEvent('14:23:01', 'create', 'src/index.ts', 'safe');
      expect(output).toContain('14:23:01');
    });

    it('should contain the file path', () => {
      const output = formatEvent('14:23:01', 'modify', 'src/utils.ts', 'safe');
      expect(output).toContain('src/utils.ts');
    });

    it('should contain reason when provided', () => {
      const output = formatEvent('14:23:01', 'modify', '.env', 'danger', 'Credential file accessed');
      expect(output).toContain('Credential file accessed');
    });

    it('should not contain reason line when no reason', () => {
      const output = formatEvent('14:23:01', 'create', 'file.ts', 'safe');
      expect(output).not.toContain('┗━');
    });

    it('should handle command event type', () => {
      const output = formatEvent('14:23:01', 'command', 'npm install lodash', 'caution', 'Installing package');
      expect(output).toContain('npm install lodash');
      expect(output).toContain('Installing package');
    });
  });

  describe('sessionSummary', () => {
    it('should contain event counts', () => {
      const summary = { totalEvents: 10, safe: 7, caution: 2, danger: 1, riskScore: 3.5 };
      const output = sessionSummary(summary, '/path/to/session.json');
      expect(output).toContain('10');
      expect(output).toContain('7');
      expect(output).toContain('2');
      expect(output).toContain('1');
    });

    it('should contain risk score', () => {
      const summary = { totalEvents: 5, safe: 5, caution: 0, danger: 0, riskScore: 0 };
      const output = sessionSummary(summary, '/path/to/session.json');
      expect(output).toContain('0/10');
    });

    it('should contain session path', () => {
      const summary = { totalEvents: 0, safe: 0, caution: 0, danger: 0, riskScore: 0 };
      const output = sessionSummary(summary, '/my/session.json');
      expect(output).toContain('/my/session.json');
    });
  });

  describe('replayHeader', () => {
    it('should contain REPLAY', () => {
      const output = replayHeader('abc123', '/test', '2026-01-01T00:00:00Z');
      expect(output).toContain('REPLAY');
    });

    it('should contain session ID', () => {
      const output = replayHeader('abc12345', '/test', '2026-01-01T00:00:00Z');
      expect(output).toContain('abc12345');
    });

    it('should contain directory', () => {
      const output = replayHeader('abc', '/my/project', '2026-01-01T00:00:00Z');
      expect(output).toContain('/my/project');
    });
  });

  describe('reportDivider', () => {
    it('should return a string', () => {
      const output = reportDivider();
      expect(typeof output).toBe('string');
      expect(output.length).toBeGreaterThan(0);
    });
  });
});
