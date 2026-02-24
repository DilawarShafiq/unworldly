import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { Session, WatchEvent } from './types.js';
import { calculateRiskScore } from './risk.js';

const SESSIONS_DIR = '.unworldly/sessions';

export function generateId(): string {
  return crypto.randomBytes(4).toString('hex');
}

export function ensureSessionsDir(baseDir: string): string {
  const dir = path.join(baseDir, SESSIONS_DIR);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function createSession(directory: string): Session {
  return {
    version: '0.2.0',
    id: generateId(),
    startTime: new Date().toISOString(),
    endTime: '',
    directory,
    events: [],
    summary: {
      totalEvents: 0,
      safe: 0,
      caution: 0,
      danger: 0,
      riskScore: 0,
    },
  };
}

export function addEvent(session: Session, event: WatchEvent): void {
  session.events.push(event);
  session.summary.totalEvents++;
  session.summary[event.risk]++;
  session.summary.riskScore = calculateRiskScore(
    session.summary.safe,
    session.summary.caution,
    session.summary.danger,
  );
}

export function saveSession(session: Session, baseDir: string): string {
  session.endTime = new Date().toISOString();
  const dir = ensureSessionsDir(baseDir);
  const filename = `${session.id}.json`;
  const filepath = path.join(dir, filename);
  fs.writeFileSync(filepath, JSON.stringify(session, null, 2), 'utf-8');
  return filepath;
}

export function loadSession(sessionPath: string): Session {
  const resolved = resolveSessionPath(sessionPath);
  const content = fs.readFileSync(resolved, 'utf-8');
  return JSON.parse(content) as Session;
}

export function resolveSessionPath(input: string): string {
  // If it's already a full path to a JSON file
  if (input.endsWith('.json') && fs.existsSync(input)) {
    return input;
  }

  // If it's a session ID, look in the sessions directory
  const sessionsDir = path.join(process.cwd(), SESSIONS_DIR);
  const byId = path.join(sessionsDir, `${input}.json`);
  if (fs.existsSync(byId)) {
    return byId;
  }

  // Try as relative path
  const relative = path.resolve(input);
  if (fs.existsSync(relative)) {
    return relative;
  }

  throw new Error(`Session not found: ${input}`);
}

export function listSessions(baseDir: string): string[] {
  const dir = path.join(baseDir, SESSIONS_DIR);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse();
}

export function getLatestSession(baseDir: string): string | null {
  const sessions = listSessions(baseDir);
  if (sessions.length === 0) return null;
  return path.join(baseDir, SESSIONS_DIR, sessions[0]);
}
