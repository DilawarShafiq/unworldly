export type RiskLevel = 'safe' | 'caution' | 'danger';

export type EventType = 'create' | 'modify' | 'delete' | 'command';

export interface CommandInfo {
  executable: string;
  args: string[];
  cwd: string;
  pid: number;
  exitCode?: number;
}

export interface WatchEvent {
  timestamp: string;
  type: EventType;
  path: string;
  risk: RiskLevel;
  reason?: string;
  command?: CommandInfo;
  hash?: string;
}

export interface AgentInfo {
  name: string;
  pid?: number;
  version?: string;
  detectedVia: string;
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
  agent?: AgentInfo;
  events: WatchEvent[];
  summary: SessionSummary;
  integrityHash?: string;
}
