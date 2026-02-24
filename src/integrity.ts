import crypto from 'node:crypto';
import type { WatchEvent, Session } from './types.js';

/**
 * Compute SHA-256 hash of an event, chaining to the previous event's hash.
 * This creates a tamper-evident chain — modifying any event invalidates
 * all subsequent hashes and the session integrity hash.
 *
 * ISO 42001 A.6.2.8: Defensible, immutable event logs.
 */
export function hashEvent(event: WatchEvent, previousHash: string): string {
  const payload = JSON.stringify({
    timestamp: event.timestamp,
    type: event.type,
    path: event.path,
    risk: event.risk,
    reason: event.reason,
    command: event.command,
    previousHash,
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Compute the session-level integrity hash from all event hashes.
 * This is the "seal" on the session — if any event was tampered with,
 * this hash won't match on verification.
 */
export function computeSessionHash(session: Session): string {
  const payload = JSON.stringify({
    id: session.id,
    startTime: session.startTime,
    directory: session.directory,
    agent: session.agent,
    eventHashes: session.events.map(e => e.hash),
    summary: session.summary,
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Add hash to an event and return it. Mutates the event.
 */
export function signEvent(event: WatchEvent, previousHash: string): WatchEvent {
  event.hash = hashEvent(event, previousHash);
  return event;
}

/**
 * Get the last hash in the event chain, or the genesis hash.
 */
export function getLastHash(session: Session): string {
  if (session.events.length === 0) {
    return genesisHash(session.id);
  }
  return session.events[session.events.length - 1].hash ?? genesisHash(session.id);
}

/**
 * Genesis hash — the starting point for the hash chain, derived from session ID.
 */
export function genesisHash(sessionId: string): string {
  return crypto.createHash('sha256').update(`unworldly:genesis:${sessionId}`).digest('hex');
}

export interface VerifyResult {
  valid: boolean;
  totalEvents: number;
  validEvents: number;
  brokenAt?: number;
  sessionHashValid: boolean;
  errors: string[];
}

/**
 * Verify the integrity of an entire session.
 * Checks every event hash in the chain and the session integrity hash.
 *
 * Returns detailed results showing exactly where tampering occurred (if any).
 */
export function verifySession(session: Session): VerifyResult {
  const errors: string[] = [];
  let previousHash = genesisHash(session.id);
  let validEvents = 0;
  let brokenAt: number | undefined;

  for (let i = 0; i < session.events.length; i++) {
    const event = session.events[i];

    if (!event.hash) {
      // Legacy session without hashes — can't verify but not necessarily tampered
      errors.push(`Event ${i}: No hash present (legacy session format)`);
      if (brokenAt === undefined) brokenAt = i;
      continue;
    }

    const expectedHash = hashEvent(event, previousHash);
    if (event.hash !== expectedHash) {
      errors.push(`Event ${i}: Hash mismatch — event may have been tampered with`);
      if (brokenAt === undefined) brokenAt = i;
    } else {
      validEvents++;
    }

    previousHash = event.hash;
  }

  // Verify session integrity hash
  let sessionHashValid = false;
  if (session.integrityHash) {
    const expectedSessionHash = computeSessionHash(session);
    sessionHashValid = session.integrityHash === expectedSessionHash;
    if (!sessionHashValid) {
      errors.push('Session integrity hash mismatch — session metadata may have been tampered with');
    }
  } else {
    errors.push('No session integrity hash present (legacy session format)');
  }

  return {
    valid: errors.length === 0,
    totalEvents: session.events.length,
    validEvents,
    brokenAt,
    sessionHashValid,
    errors,
  };
}
