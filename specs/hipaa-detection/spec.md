# Feature Spec: HIPAA PHI Detection

## Summary

Add opt-in HIPAA mode to Unworldly that detects Protected Health Information (PHI) exposure in file paths and shell commands. When enabled, Unworldly flags HL7 messages, FHIR resources, DICOM images, EHR exports, patient database queries, and healthcare API calls — extending the existing risk engine with healthcare-specific patterns.

## Motivation

HIPAA 45 CFR § 164.312(b) **requires** audit controls that "record and examine activity in information systems that contain or use electronic protected health information." Unworldly's existing SHA-256 hash chain already satisfies the tamper-evidence requirement. Adding PHI-aware patterns makes it a complete 164.312(b) audit tool for AI agents in healthcare environments.

## Regulatory Mapping

| HIPAA Control | Requirement | Unworldly Implementation |
|---------------|-------------|--------------------------|
| **164.312(b)** | Record activity in ePHI systems | PHI file/command detection + event logging |
| **164.308(a)(1)(ii)(D)** | Review audit logs | `unworldly report --format md` with PHI section |
| **164.316(b)(2)(i)** | 6-year log retention | Session JSON files (user manages retention) |
| **164.312(c)(1)** | Integrity controls | SHA-256 hash chain (existing) |

### ISO 42001 → HIPAA Bridge

| ISO 42001 | Maps to HIPAA | What Unworldly Provides |
|-----------|---------------|------------------------|
| A.6.2.8 (Event logging) | 164.312(b) (Audit controls) | Every AI action logged with hash chain |
| A.3.2 (Roles/accountability) | 164.312(a)(2)(i) (Unique user ID) | Agent identity detection |
| A.9.2 (Performance monitoring) | 164.308(a)(1)(ii)(D) (Log review) | Risk-scored reports |

## Scope

### In Scope
- File path pattern matching for healthcare data formats (HL7, FHIR, DICOM, CDA, X12, EHR exports)
- Command pattern matching for healthcare data access (SQL on patient tables, FHIR APIs, DB dumps)
- HIPAA mode toggle via `--hipaa` CLI flag and `.unworldly/config.json`
- PHI-tagged events in session JSON
- CAUTION and DANGER tiers matching existing risk levels

### Out of Scope
- **File content scanning** — no reading file bodies for SSN/MRN patterns (privacy risk, performance cost)
- **Real-time blocking** — Unworldly is passive monitoring only
- **HIPAA certification** — Unworldly is a tool, not a certified product
- **BAA generation** — legal agreements are outside software scope

## Design

### Activation

```bash
# CLI flag
unworldly watch --hipaa

# Or config file
# .unworldly/config.json
{
  "hipaa": true
}
```

### File Path Patterns

**DANGER** — ePHI highly probable:
- `.hl7`, `.dcm`, `.dicom`, `.cda`, `.ccda` — clinical data formats
- `.x12`, `.834`, `.835`, `.837`, `.270`, `.271` — insurance transactions
- `fhir/*patient*.json`, `fhir/*observation*.json` — FHIR resources
- `patient_record*`, `ehr_export*`, `emr_dump*` — data exports
- `lab_result*`, `pathology_report*`, `radiology_report*` — clinical reports

**CAUTION** — PHI possible:
- `patient*.csv`, `patient*.json` — generic patient files
- `clinical_trial*` — research data
- Healthcare DB schema files (`.sql` with patient/encounter tables)
- EHR system logs (Epic, Cerner, Meditech)

### Command Patterns

**DANGER** — direct PHI access:
- SQL: `SELECT` from patient/clinical tables, `DROP TABLE patients`
- API: `curl` to FHIR endpoints, EHR vendor APIs, cloud healthcare APIs
- Export: `mysqldump`/`pg_dump` of health databases
- Copy: `scp`/`rsync` of `.hl7`/`.dcm` files

**CAUTION** — possible PHI access:
- Database client connecting to health-named databases
- Installing healthcare libraries (`pip install fhir`, `npm install hapi`)
- Opening healthcare files with editors/viewers

### Module: `unworldly/hipaa_risk.py`

Exports:
- `assess_hipaa_file_risk(file_path, event_type) -> RiskResult | None`
- `assess_hipaa_command_risk(executable, args) -> CommandRiskResult | None`

Returns `None` when no HIPAA pattern matches (falls through to standard risk engine).

### Integration Point

In `risk.py` and `command_risk.py`, when HIPAA mode is enabled:
1. Check HIPAA patterns first (before standard patterns)
2. If match found, return HIPAA result (with healthcare-specific reason)
3. If no match, fall through to standard risk engine

## Acceptance Criteria

- [ ] `unworldly watch --hipaa` enables PHI detection
- [ ] `.unworldly/config.json` with `"hipaa": true` enables PHI detection
- [ ] HL7 files flagged as DANGER with reason "HL7 message file — likely contains PHI"
- [ ] FHIR Patient resource files flagged as DANGER
- [ ] DICOM files flagged as DANGER
- [ ] SQL queries on patient tables flagged as DANGER
- [ ] FHIR API calls via curl flagged as DANGER
- [ ] `patient*.csv` flagged as CAUTION
- [ ] Standard risk patterns still work when HIPAA mode is off
- [ ] All existing 139 tests still pass
- [ ] New HIPAA tests cover all pattern categories

## Non-Goals

- No performance regression on non-HIPAA mode (patterns only loaded when enabled)
- No false positives on standard dev files (test fixtures, mock data)
- No content scanning (path-only matching)
