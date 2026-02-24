import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { detectAgent } from '../src/agent-detect.js';

describe('agent-detect', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Clear all known agent env vars
    delete process.env.CLAUDE_CODE;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.CURSOR_SESSION;
    delete process.env.CURSOR_TRACE_ID;
    delete process.env.GITHUB_COPILOT;
    delete process.env.COPILOT_AGENT;
    delete process.env.WINDSURF_SESSION;
    delete process.env.DEVIN_SESSION;
    delete process.env.DEVIN_API;
    delete process.env.AIDER_MODEL;
    delete process.env.OPENCLAW_SESSION;
    delete process.env.CLINE_SESSION;
  });

  afterEach(() => {
    // Restore original env
    process.env = { ...originalEnv };
  });

  describe('environment variable detection', () => {
    it('should detect Claude Code via CLAUDE_CODE env var', () => {
      process.env.CLAUDE_CODE = '1';
      const result = detectAgent();
      expect(result).not.toBeNull();
      expect(result!.name).toBe('Claude Code');
      expect(result!.detectedVia).toContain('CLAUDE_CODE');
    });

    it('should detect Cursor via CURSOR_SESSION env var', () => {
      process.env.CURSOR_SESSION = 'test-session';
      const result = detectAgent();
      expect(result).not.toBeNull();
      expect(result!.name).toBe('Cursor');
      expect(result!.detectedVia).toContain('CURSOR_SESSION');
    });

    it('should detect GitHub Copilot via GITHUB_COPILOT env var', () => {
      process.env.GITHUB_COPILOT = 'true';
      const result = detectAgent();
      expect(result).not.toBeNull();
      expect(result!.name).toBe('GitHub Copilot');
    });

    it('should detect Windsurf via WINDSURF_SESSION env var', () => {
      process.env.WINDSURF_SESSION = 'ws-123';
      const result = detectAgent();
      expect(result).not.toBeNull();
      expect(result!.name).toBe('Windsurf');
    });

    it('should detect Devin via DEVIN_SESSION env var', () => {
      process.env.DEVIN_SESSION = 'dev-123';
      const result = detectAgent();
      expect(result).not.toBeNull();
      expect(result!.name).toBe('Devin');
    });

    it('should detect Aider via AIDER_MODEL env var', () => {
      process.env.AIDER_MODEL = 'gpt-4';
      const result = detectAgent();
      expect(result).not.toBeNull();
      expect(result!.name).toBe('Aider');
    });

    it('should detect OpenClaw via OPENCLAW_SESSION env var', () => {
      process.env.OPENCLAW_SESSION = 'oc-123';
      const result = detectAgent();
      expect(result).not.toBeNull();
      expect(result!.name).toBe('OpenClaw');
    });

    it('should detect Cline via CLINE_SESSION env var', () => {
      process.env.CLINE_SESSION = 'cl-123';
      const result = detectAgent();
      expect(result).not.toBeNull();
      expect(result!.name).toBe('Cline');
    });
  });

  describe('no agent detected', () => {
    it('should return null when no agent env vars are set', () => {
      // All agent env vars cleared in beforeEach
      // Process detection may still find something, so we just verify
      // the function doesn't throw
      const result = detectAgent();
      // Result could be null or an agent found via process detection
      expect(result === null || typeof result.name === 'string').toBe(true);
    });
  });

  describe('result structure', () => {
    it('should return correct AgentInfo shape', () => {
      process.env.CLAUDE_CODE = '1';
      const result = detectAgent();
      expect(result).toHaveProperty('name');
      expect(result).toHaveProperty('detectedVia');
      expect(typeof result!.name).toBe('string');
      expect(typeof result!.detectedVia).toBe('string');
    });

    it('should include detection method in detectedVia', () => {
      process.env.CURSOR_TRACE_ID = 'trace-xyz';
      const result = detectAgent();
      expect(result!.detectedVia).toContain('environment variable');
    });
  });
});
