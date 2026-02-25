# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Unworldly, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email **dilawar.gopang@gmail.com** with:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

You can expect:

- **Acknowledgment** within 48 hours
- **Assessment** within 7 days
- **Fix or mitigation** within 30 days for confirmed vulnerabilities

## Scope

The following are in scope:

- Hash chain integrity bypass (forging valid hashes)
- Session tampering that passes `unworldly verify`
- Path traversal in file monitoring or session storage
- Command injection via config parsing
- Denial of service via crafted session files

The following are out of scope:

- Issues requiring physical access to the machine
- Social engineering attacks
- Vulnerabilities in dependencies (report those upstream)

## Security Design

Unworldly's security model is documented in the README under [ISO 42001 Compliance](README.md#iso-42001-compliance). Key properties:

- **SHA-256 hash chains** on every event (tamper-evident)
- **Session seals** for end-to-end integrity verification
- **Local-first** — no data leaves the machine, no network calls, no telemetry
- **Read-only monitoring** — Unworldly never modifies watched files or executes watched commands

## Acknowledgments

We appreciate responsible disclosure and will credit reporters in the CHANGELOG (unless you prefer to remain anonymous).
