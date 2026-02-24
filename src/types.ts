export type RiskLevel = 'safe' | 'caution' | 'danger';

export type EventType = 'create' | 'modify' | 'delete';

export interface WatchEvent {
  timestamp: string;
  type: EventType;
  path: string;
  risk: RiskLevel;
  reason?: string;
}

export interface SessionSummary {
  totalEvents: number;
  safe: number;
  caution: number;
  danger: number;
  riskScore: number;
}

export interface Session {
  version: string;
  id: string;
  startTime: string;
  endTime: string;
  directory: string;
  events: WatchEvent[];
  summary: SessionSummary;
}
