import { describe, it, expect } from 'vitest';
import {
  hashEvent,
  computeSessionHash,
  signEvent,
  getLastHash,
  genesisHash,
  verifySession,
} from '../src/integrity.js';
import { createSession, addEvent } from '../src/session.js';
import type { WatchEvent } from '../src/types.js';

describe('integrity', () => {
  describe('genesisHash', () => {
    it('should return a 64-char hex string', () => {
      const hash = genesisHash('abc123');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should be deterministic for same session ID', () => {
      expect(genesisHash('test')).toBe(genesisHash('test'));
    });

    it('should differ for different session IDs', () => {
      expect(genesisHash('a')).not.toBe(genesisHash('b'));
    });
  });

  describe('hashEvent', () => {
    it('should return a 64-char hex string', () => {
      const event: WatchEvent = {
        timestamp: '2026-01-01T00:00:00Z',
        type: 'create',
        path: 'test.ts',
        risk: 'safe',
      };
      const hash = hashEvent(event, 'prev-hash');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should be deterministic', () => {
      const event: WatchEvent = {
        timestamp: '2026-01-01T00:00:00Z',
        type: 'modify',
        path: 'file.ts',
        risk: 'caution',
        reason: 'test',
      };
      expect(hashEvent(event, 'abc')).toBe(hashEvent(event, 'abc'));
    });

    it('should change when previous hash changes', () => {
      const event: WatchEvent = {
        timestamp: '2026-01-01T00:00:00Z',
        type: 'create',
        path: 'test.ts',
        risk: 'safe',
      };
      expect(hashEvent(event, 'hash1')).not.toBe(hashEvent(event, 'hash2'));
    });

    it('should change when event data changes', () => {
      const event1: WatchEvent = {
        timestamp: '2026-01-01T00:00:00Z',
        type: 'create',
        path: 'test.ts',
        risk: 'safe',
      };
      const event2: WatchEvent = {
        timestamp: '2026-01-01T00:00:00Z',
        type: 'delete',
        path: 'test.ts',
        risk: 'safe',
      };
      expect(hashEvent(event1, 'same')).not.toBe(hashEvent(event2, 'same'));
    });
  });

  describe('signEvent', () => {
    it('should add hash to event', () => {
      const event: WatchEvent = {
        timestamp: '2026-01-01T00:00:00Z',
        type: 'create',
        path: 'test.ts',
        risk: 'safe',
      };
      expect(event.hash).toBeUndefined();
      signEvent(event, 'prev');
      expect(event.hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('getLastHash', () => {
    it('should return genesis hash for empty session', () => {
      const session = createSession('/test');
      const hash = getLastHash(session);
      expect(hash).toBe(genesisHash(session.id));
    });

    it('should return last event hash when events exist', () => {
      const session = createSession('/test');
      const event: WatchEvent = {
        timestamp: '2026-01-01T00:00:00Z',
        type: 'create',
        path: 'test.ts',
        risk: 'safe',
      };
      addEvent(session, event);
      expect(getLastHash(session)).toBe(session.events[0].hash);
    });
  });

  describe('verifySession', () => {
    it('should verify a valid session', () => {
      const session = createSession('/test');
      const events: WatchEvent[] = [
        { timestamp: '2026-01-01T00:00:01Z', type: 'create', path: 'a.ts', risk: 'safe' },
        { timestamp: '2026-01-01T00:00:02Z', type: 'modify', path: 'b.ts', risk: 'caution', reason: 'test' },
        { timestamp: '2026-01-01T00:00:03Z', type: 'delete', path: 'c.ts', risk: 'danger', reason: 'rm' },
      ];
      for (const e of events) {
        addEvent(session, e);
      }
      // Seal the session
      session.endTime = new Date().toISOString();
      session.integrityHash = computeSessionHash(session);

      const result = verifySession(session);
      expect(result.valid).toBe(true);
      expect(result.totalEvents).toBe(3);
      expect(result.validEvents).toBe(3);
      expect(result.sessionHashValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should detect tampered event', () => {
      const session = createSession('/test');
      addEvent(session, { timestamp: '2026-01-01T00:00:01Z', type: 'create', path: 'a.ts', risk: 'safe' });
      addEvent(session, { timestamp: '2026-01-01T00:00:02Z', type: 'modify', path: 'b.ts', risk: 'caution' });

      session.endTime = new Date().toISOString();
      session.integrityHash = computeSessionHash(session);

      // Tamper with event
      session.events[0].path = 'TAMPERED.ts';

      const result = verifySession(session);
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(0);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should detect missing integrity hash', () => {
      const session = createSession('/test');
      addEvent(session, { timestamp: '2026-01-01T00:00:01Z', type: 'create', path: 'a.ts', risk: 'safe' });

      const result = verifySession(session);
      expect(result.valid).toBe(false);
      expect(result.sessionHashValid).toBe(false);
      expect(result.errors).toContain('No session integrity hash present (legacy session format)');
    });

    it('should handle empty session', () => {
      const session = createSession('/test');
      const result = verifySession(session);
      expect(result.totalEvents).toBe(0);
      expect(result.validEvents).toBe(0);
    });

    it('should detect tampered session hash', () => {
      const session = createSession('/test');
      addEvent(session, { timestamp: '2026-01-01T00:00:01Z', type: 'create', path: 'a.ts', risk: 'safe' });
      session.endTime = new Date().toISOString();
      session.integrityHash = 'fake-hash-that-does-not-match';

      const result = verifySession(session);
      expect(result.valid).toBe(false);
      expect(result.sessionHashValid).toBe(false);
    });
  });
});
