# Demo Recording

Choreographed simulation that shows Unworldly catching an AI agent doing increasingly dangerous things. Used to generate the GIF in the main README.

## Files

| File | Purpose |
|------|---------|
| `simulate.py` | Python script that imports real `unworldly.display` functions |
| `demo.tape` | VHS config for recording (preferred method) |
| `record.sh` | Fallback recording via asciinema + agg |

## Generate the GIF

### Option A: VHS (preferred)

Install [VHS](https://github.com/charmbracelet/vhs), then:

```bash
vhs demo/demo.tape
# Outputs: assets/demo.gif
```

### Option B: asciinema + agg

Install [asciinema](https://asciinema.org) and [agg](https://github.com/asciinema/agg), then:

```bash
bash demo/record.sh
# Outputs: assets/demo.gif
```

### Option C: Preview (no recording)

```bash
python demo/simulate.py
```

## How It Works

`simulate.py` imports real functions from the `unworldly` package:
- `unworldly.display` — banner, event formatting, summaries, verify output
- `unworldly.types` — EventType, RiskLevel, AgentInfo, SessionSummary
- `unworldly.integrity` — VerifyResult
- `unworldly.risk` — calculate_risk_score

This means the demo always matches actual Unworldly output. If display formatting changes, the demo updates automatically.

## The Story Arc

1. **Act 1 — Calm**: One safe file creation
2. **Act 2 — Tension**: Dependency changes, npm install, Dockerfile modification
3. **Act 3 — Danger**: Credential theft, AWS access, data exfiltration, SSH key theft, privilege escalation, remote code execution, destructive deletion
4. **Act 4 — Resolution**: Session summary with risk score, integrity verification passes
