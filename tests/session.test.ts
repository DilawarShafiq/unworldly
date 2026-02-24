import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  createSession,
  addEvent,
  saveSession,
  loadSession,
  listSessions,
  getLatestSession,
  ensureSessionsDir,
  generateId,
} from '../src/session.js';
import type { WatchEvent } from '../src/types.js';

describe('session', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'unworldly-session-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('generateId', () => {
    it('should return an 8-character hex string', () => {
      const id = generateId();
      expect(id).toMatch(/^[0-9a-f]{8}$/);
    });

    it('should generate unique IDs', () => {
      const ids = new Set(Array.from({ length: 100 }, () => generateId()));
      expect(ids.size).toBe(100);
    });
  });

  describe('ensureSessionsDir', () => {
    it('should create .unworldly/sessions/ directory', () => {
      const dir = ensureSessionsDir(tmpDir);
      expect(fs.existsSync(dir)).toBe(true);
      expect(dir).toContain('.unworldly');
      expect(dir).toContain('sessions');
    });

    it('should be idempotent', () => {
      ensureSessionsDir(tmpDir);
      ensureSessionsDir(tmpDir);
      expect(fs.existsSync(path.join(tmpDir, '.unworldly', 'sessions'))).toBe(true);
    });
  });

  describe('createSession', () => {
    it('should create a session with correct structure', () => {
      const session = createSession('/test/dir');
      expect(session.version).toBe('0.3.0');
      expect(session.id).toMatch(/^[0-9a-f]{8}$/);
      expect(session.startTime).toBeTruthy();
      expect(session.endTime).toBe('');
      expect(session.directory).toBe('/test/dir');
      expect(session.events).toEqual([]);
      expect(session.summary.totalEvents).toBe(0);
      expect(session.summary.safe).toBe(0);
      expect(session.summary.caution).toBe(0);
      expect(session.summary.danger).toBe(0);
      expect(session.summary.riskScore).toBe(0);
    });
  });

  describe('addEvent', () => {
    it('should add event and update summary counts', () => {
      const session = createSession('/test');
      const event: WatchEvent = {
        timestamp: new Date().toISOString(),
        type: 'create',
        path: 'src/index.ts',
        risk: 'safe',
      };

      addEvent(session, event);
      expect(session.events).toHaveLength(1);
      expect(session.summary.totalEvents).toBe(1);
      expect(session.summary.safe).toBe(1);
    });

    it('should increment danger count for danger events', () => {
      const session = createSession('/test');
      const event: WatchEvent = {
        timestamp: new Date().toISOString(),
        type: 'modify',
        path: '.env',
        risk: 'danger',
        reason: 'Credential file accessed',
      };

      addEvent(session, event);
      expect(session.summary.danger).toBe(1);
      expect(session.summary.riskScore).toBeGreaterThan(0);
    });

    it('should update risk score after each event', () => {
      const session = createSession('/test');

      addEvent(session, { timestamp: new Date().toISOString(), type: 'create', path: 'a.ts', risk: 'safe' });
      const scoreAfterSafe = session.summary.riskScore;

      addEvent(session, { timestamp: new Date().toISOString(), type: 'modify', path: '.env', risk: 'danger', reason: 'test' });
      expect(session.summary.riskScore).toBeGreaterThan(scoreAfterSafe);
    });
  });

  describe('saveSession / loadSession', () => {
    it('should save and load a session', () => {
      const session = createSession(tmpDir);
      addEvent(session, {
        timestamp: new Date().toISOString(),
        type: 'create',
        path: 'test.ts',
        risk: 'safe',
      });

      const filepath = saveSession(session, tmpDir);
      expect(fs.existsSync(filepath)).toBe(true);

      const loaded = loadSession(filepath);
      expect(loaded.id).toBe(session.id);
      expect(loaded.events).toHaveLength(1);
      expect(loaded.summary.totalEvents).toBe(1);
    });

    it('should set endTime on save', () => {
      const session = createSession(tmpDir);
      expect(session.endTime).toBe('');

      saveSession(session, tmpDir);
      expect(session.endTime).not.toBe('');
    });

    it('should throw for non-existent session', () => {
      expect(() => loadSession('nonexistent-id-12345')).toThrow('Session not found');
    });
  });

  describe('listSessions', () => {
    it('should return empty array when no sessions', () => {
      expect(listSessions(tmpDir)).toEqual([]);
    });

    it('should list saved sessions', () => {
      const s1 = createSession(tmpDir);
      const s2 = createSession(tmpDir);
      saveSession(s1, tmpDir);
      saveSession(s2, tmpDir);

      const sessions = listSessions(tmpDir);
      expect(sessions).toHaveLength(2);
    });
  });

  describe('getLatestSession', () => {
    it('should return null when no sessions', () => {
      expect(getLatestSession(tmpDir)).toBeNull();
    });

    it('should return path to latest session', () => {
      const session = createSession(tmpDir);
      saveSession(session, tmpDir);

      const latest = getLatestSession(tmpDir);
      expect(latest).not.toBeNull();
      expect(latest).toContain(session.id);
    });
  });
});
