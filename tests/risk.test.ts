import { describe, it, expect } from 'vitest';
import { shouldIgnore, assessRisk, calculateRiskScore } from '../src/risk.js';

describe('shouldIgnore', () => {
  it('should ignore node_modules', () => {
    expect(shouldIgnore('node_modules/lodash/index.js')).toBe(true);
  });

  it('should ignore .git directory', () => {
    expect(shouldIgnore('.git/HEAD')).toBe(true);
  });

  it('should ignore dist directory', () => {
    expect(shouldIgnore('dist/index.js')).toBe(true);
  });

  it('should ignore build directory', () => {
    expect(shouldIgnore('build/output.js')).toBe(true);
  });

  it('should ignore .unworldly directory', () => {
    expect(shouldIgnore('.unworldly/sessions/abc.json')).toBe(true);
  });

  it('should ignore .DS_Store', () => {
    expect(shouldIgnore('.DS_Store')).toBe(true);
  });

  it('should ignore .swp files', () => {
    expect(shouldIgnore('file.ts.swp')).toBe(true);
  });

  it('should ignore .tmp files', () => {
    expect(shouldIgnore('data.tmp')).toBe(true);
  });

  it('should ignore __pycache__', () => {
    expect(shouldIgnore('__pycache__/module.cpython-311.pyc')).toBe(true);
  });

  it('should NOT ignore regular source files', () => {
    expect(shouldIgnore('src/index.ts')).toBe(false);
  });

  it('should NOT ignore README', () => {
    expect(shouldIgnore('README.md')).toBe(false);
  });

  it('should handle Windows backslash paths', () => {
    expect(shouldIgnore('node_modules\\lodash\\index.js')).toBe(true);
  });
});

describe('assessRisk', () => {
  describe('danger files', () => {
    it('should flag .env as danger', () => {
      const result = assessRisk('.env', 'modify');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Credential');
    });

    it('should flag .env.production as danger', () => {
      const result = assessRisk('.env.production', 'modify');
      expect(result.level).toBe('danger');
    });

    it('should flag .pem files as danger', () => {
      const result = assessRisk('cert.pem', 'create');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Certificate');
    });

    it('should flag .key files as danger', () => {
      const result = assessRisk('private.key', 'create');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Private key');
    });

    it('should flag id_rsa as danger', () => {
      const result = assessRisk('.ssh/id_rsa', 'modify');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('SSH');
    });

    it('should flag id_ed25519 as danger', () => {
      const result = assessRisk('id_ed25519', 'modify');
      expect(result.level).toBe('danger');
    });

    it('should flag credentials files as danger', () => {
      const result = assessRisk('config/credentials.json', 'modify');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Credentials');
    });

    it('should flag secrets files as danger', () => {
      const result = assessRisk('secrets.yaml', 'create');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Secrets');
    });

    it('should flag .aws/ directory as danger', () => {
      const result = assessRisk('.aws/config', 'modify');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('AWS');
    });

    it('should flag kubeconfig as danger', () => {
      const result = assessRisk('kubeconfig', 'modify');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('Kubernetes');
    });

    it('should flag .kube/ directory as danger', () => {
      const result = assessRisk('.kube/config', 'modify');
      expect(result.level).toBe('danger');
    });

    it('should flag passwd as danger', () => {
      const result = assessRisk('/etc/passwd', 'modify');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('System user');
    });

    it('should flag shadow as danger', () => {
      const result = assessRisk('/etc/shadow', 'modify');
      expect(result.level).toBe('danger');
      expect(result.reason).toContain('System password');
    });
  });

  describe('caution files', () => {
    it('should flag package.json as caution', () => {
      const result = assessRisk('package.json', 'modify');
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('Dependency manifest');
    });

    it('should flag package-lock.json as caution', () => {
      const result = assessRisk('package-lock.json', 'modify');
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('Lock file');
    });

    it('should flag yarn.lock as caution', () => {
      const result = assessRisk('yarn.lock', 'modify');
      expect(result.level).toBe('caution');
    });

    it('should flag Dockerfile as caution', () => {
      const result = assessRisk('Dockerfile', 'modify');
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('Container');
    });

    it('should flag docker-compose.yml as caution', () => {
      const result = assessRisk('docker-compose.yml', 'modify');
      expect(result.level).toBe('caution');
    });

    it('should flag GitHub workflow files as caution', () => {
      const result = assessRisk('.github/workflows/ci.yml', 'modify');
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('CI/CD');
    });

    it('should flag .gitignore as caution', () => {
      const result = assessRisk('.gitignore', 'modify');
      expect(result.level).toBe('caution');
    });

    it('should flag tsconfig.json as caution', () => {
      const result = assessRisk('tsconfig.json', 'modify');
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('TypeScript config');
    });

    it('should flag webpack.config.js as caution', () => {
      const result = assessRisk('webpack.config.js', 'modify');
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('Build config');
    });

    it('should flag eslint config as caution', () => {
      const result = assessRisk('.eslintrc.js', 'modify');
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('Linter');
    });

    it('should flag file deletion as caution', () => {
      const result = assessRisk('src/utils.ts', 'delete');
      expect(result.level).toBe('caution');
      expect(result.reason).toContain('File deleted');
    });
  });

  describe('safe files', () => {
    it('should flag regular .ts files as safe', () => {
      const result = assessRisk('src/index.ts', 'modify');
      expect(result.level).toBe('safe');
      expect(result.reason).toBeUndefined();
    });

    it('should flag regular .js files as safe', () => {
      const result = assessRisk('lib/utils.js', 'create');
      expect(result.level).toBe('safe');
    });

    it('should flag .md files as safe', () => {
      const result = assessRisk('README.md', 'modify');
      expect(result.level).toBe('safe');
    });

    it('should flag .css files as safe', () => {
      const result = assessRisk('styles/main.css', 'modify');
      expect(result.level).toBe('safe');
    });

    it('should flag new file creation as safe', () => {
      const result = assessRisk('src/newfile.ts', 'create');
      expect(result.level).toBe('safe');
    });
  });
});

describe('calculateRiskScore', () => {
  it('should return 0 for empty session', () => {
    expect(calculateRiskScore(0, 0, 0)).toBe(0);
  });

  it('should return 0 for all safe events', () => {
    expect(calculateRiskScore(10, 0, 0)).toBe(0);
  });

  it('should return 10 for all danger events', () => {
    expect(calculateRiskScore(0, 0, 1)).toBe(10);
  });

  it('should return moderate score for mixed events', () => {
    const score = calculateRiskScore(5, 3, 2);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(10);
  });

  it('should cap at 10', () => {
    const score = calculateRiskScore(0, 0, 100);
    expect(score).toBe(10);
  });

  it('should weight danger higher than caution', () => {
    const cautionScore = calculateRiskScore(10, 5, 0);
    const dangerScore = calculateRiskScore(10, 0, 5);
    expect(dangerScore).toBeGreaterThan(cautionScore);
  });
});
