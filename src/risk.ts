import path from 'node:path';
import type { EventType, RiskLevel } from './types.js';

interface RiskResult {
  level: RiskLevel;
  reason?: string;
}

const DANGER_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\.env$/, reason: 'Credential file accessed' },
  { pattern: /\.env\.[a-z]+$/i, reason: 'Environment config accessed' },
  { pattern: /\.pem$/, reason: 'Certificate/key file accessed' },
  { pattern: /\.key$/, reason: 'Private key file accessed' },
  { pattern: /\.p12$/, reason: 'Certificate file accessed' },
  { pattern: /\.pfx$/, reason: 'Certificate file accessed' },
  { pattern: /id_rsa/, reason: 'SSH private key accessed' },
  { pattern: /id_ed25519/, reason: 'SSH private key accessed' },
  { pattern: /id_ecdsa/, reason: 'SSH private key accessed' },
  { pattern: /\.keystore$/, reason: 'Keystore accessed' },
  { pattern: /\.jks$/, reason: 'Java keystore accessed' },
  { pattern: /credentials/i, reason: 'Credentials file accessed' },
  { pattern: /secret/i, reason: 'Secrets file accessed' },
  { pattern: /\.aws\//, reason: 'AWS credentials accessed' },
  { pattern: /\.azure\//, reason: 'Azure config accessed' },
  { pattern: /\.gcloud\//, reason: 'Google Cloud config accessed' },
  { pattern: /kubeconfig/i, reason: 'Kubernetes config accessed' },
  { pattern: /\.kube\//, reason: 'Kubernetes config accessed' },
  { pattern: /shadow$/, reason: 'System password file accessed' },
  { pattern: /passwd$/, reason: 'System user file accessed' },
];

const CAUTION_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /package\.json$/, reason: 'Dependency manifest modified' },
  { pattern: /package-lock\.json$/, reason: 'Lock file modified' },
  { pattern: /yarn\.lock$/, reason: 'Lock file modified' },
  { pattern: /pnpm-lock\.yaml$/, reason: 'Lock file modified' },
  { pattern: /Gemfile\.lock$/, reason: 'Lock file modified' },
  { pattern: /requirements\.txt$/, reason: 'Python dependencies modified' },
  { pattern: /Pipfile\.lock$/, reason: 'Lock file modified' },
  { pattern: /go\.sum$/, reason: 'Go checksum modified' },
  { pattern: /Cargo\.lock$/, reason: 'Rust lock file modified' },
  { pattern: /Dockerfile/i, reason: 'Container config modified' },
  { pattern: /docker-compose/i, reason: 'Container orchestration modified' },
  { pattern: /\.github\/workflows\//, reason: 'CI/CD pipeline modified' },
  { pattern: /\.gitlab-ci/i, reason: 'CI/CD pipeline modified' },
  { pattern: /Jenkinsfile/i, reason: 'CI/CD pipeline modified' },
  { pattern: /\.gitignore$/, reason: 'Git ignore rules modified' },
  { pattern: /\.gitattributes$/, reason: 'Git attributes modified' },
  { pattern: /nginx/i, reason: 'Server config modified' },
  { pattern: /\.htaccess$/i, reason: 'Server config modified' },
  { pattern: /webpack\.config/i, reason: 'Build config modified' },
  { pattern: /vite\.config/i, reason: 'Build config modified' },
  { pattern: /rollup\.config/i, reason: 'Build config modified' },
  { pattern: /tsconfig/i, reason: 'TypeScript config modified' },
  { pattern: /eslint/i, reason: 'Linter config modified' },
  { pattern: /prettier/i, reason: 'Formatter config modified' },
];

const IGNORE_PATTERNS: RegExp[] = [
  /node_modules/,
  /\.git\//,
  /\.git$/,
  /dist\//,
  /build\//,
  /\.unworldly\//,
  /\.DS_Store/,
  /\.swp$/,
  /~$/,
  /\.tmp$/,
  /\.temp$/,
  /\.cache/,
  /__pycache__/,
  /\.pyc$/,
  /\.class$/,
  /\.o$/,
  /\.obj$/,
];

export function shouldIgnore(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return IGNORE_PATTERNS.some(p => p.test(normalized));
}

export function assessRisk(filePath: string, eventType: EventType): RiskResult {
  const normalized = filePath.replace(/\\/g, '/');
  const basename = path.basename(normalized);

  for (const { pattern, reason } of DANGER_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(basename)) {
      return { level: 'danger', reason };
    }
  }

  for (const { pattern, reason } of CAUTION_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(basename)) {
      return { level: 'caution', reason };
    }
  }

  if (eventType === 'delete') {
    return { level: 'caution', reason: 'File deleted' };
  }

  return { level: 'safe' };
}

export function calculateRiskScore(safe: number, caution: number, danger: number): number {
  const total = safe + caution + danger;
  if (total === 0) return 0;
  const score = ((caution * 3) + (danger * 10)) / total;
  return Math.min(10, Math.round(score * 10) / 10);
}
