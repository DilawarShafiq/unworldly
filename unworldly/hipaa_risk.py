"""HIPAA PHI detection for Unworldly.

Opt-in module that detects Protected Health Information (PHI) exposure
in file paths and shell commands. Covers HL7, FHIR, DICOM, CDA, X12,
EHR exports, patient database queries, and healthcare API calls.

Satisfies HIPAA 45 CFR § 164.312(b) audit control requirements.
Activate via `unworldly watch --hipaa` or `"hipaa": true` in config.
"""

from __future__ import annotations

import re

from .command_risk import CommandRiskPattern, CommandRiskResult
from .risk import RiskResult
from .types import EventType, RiskLevel

# ---------------------------------------------------------------------------
# FILE PATH PATTERNS — DANGER (ePHI highly probable)
# ---------------------------------------------------------------------------

PHI_FILE_DANGER: list[tuple[re.Pattern[str], str]] = [
    # HL7 v2 message files
    (re.compile(r"\.hl7$", re.IGNORECASE), "HL7 message file — likely contains PHI"),
    # FHIR resource files
    (re.compile(r"fhir.*patient.*\.json$", re.IGNORECASE), "FHIR Patient resource — PHI"),
    (re.compile(r"fhir.*observation.*\.json$", re.IGNORECASE), "FHIR Observation — clinical data"),
    (re.compile(r"fhir.*condition.*\.json$", re.IGNORECASE), "FHIR Condition — diagnosis data"),
    (re.compile(r"fhir.*medicationrequest.*\.json$", re.IGNORECASE), "FHIR MedicationRequest — prescription data"),
    (re.compile(r"fhir.*allergyintolerance.*\.json$", re.IGNORECASE), "FHIR AllergyIntolerance — PHI"),
    (re.compile(r"fhir.*diagnosticreport.*\.json$", re.IGNORECASE), "FHIR DiagnosticReport — lab results"),
    (re.compile(r"fhir.*immunization.*\.json$", re.IGNORECASE), "FHIR Immunization — PHI"),
    (re.compile(r"fhir.*bundle.*\.json$", re.IGNORECASE), "FHIR Bundle — may contain multiple PHI resources"),
    # DICOM medical imaging
    (re.compile(r"\.dcm$", re.IGNORECASE), "DICOM medical image — contains patient identifiers"),
    (re.compile(r"\.dicom$", re.IGNORECASE), "DICOM file — embedded PHI"),
    # CDA / C-CDA clinical documents
    (re.compile(r"\.cda$", re.IGNORECASE), "Clinical Document Architecture — PHI"),
    (re.compile(r"\.ccda$", re.IGNORECASE), "Consolidated CDA — PHI"),
    (re.compile(r"ccd\.xml$", re.IGNORECASE), "Continuity of Care Document — PHI"),
    # X12 EDI healthcare transactions
    (re.compile(r"\.x12$", re.IGNORECASE), "X12 EDI transaction — insurance/billing PHI"),
    (re.compile(r"\.834$", re.IGNORECASE), "X12 834 enrollment — PHI"),
    (re.compile(r"\.835$", re.IGNORECASE), "X12 835 remittance — PHI"),
    (re.compile(r"\.837$", re.IGNORECASE), "X12 837 claim — diagnosis + patient PHI"),
    (re.compile(r"\.270$", re.IGNORECASE), "X12 270 eligibility inquiry — PHI"),
    (re.compile(r"\.271$", re.IGNORECASE), "X12 271 eligibility response — PHI"),
    # EHR exports and patient records
    (re.compile(r"patient[_\-]?(?:record|data|export|dump)", re.IGNORECASE), "Patient data export — PHI"),
    (re.compile(r"ehr[_\-]?export", re.IGNORECASE), "EHR export — bulk PHI"),
    (re.compile(r"emr[_\-]?(?:export|dump|backup)", re.IGNORECASE), "EMR data dump — PHI"),
    # Clinical reports
    (re.compile(r"lab[_\-]?result", re.IGNORECASE), "Lab results — PHI"),
    (re.compile(r"pathology[_\-]?report", re.IGNORECASE), "Pathology report — PHI"),
    (re.compile(r"radiology[_\-]?report", re.IGNORECASE), "Radiology report — PHI"),
    # Explicit PHI markers
    (re.compile(r"phi[_\-]?(?:export|data|dump|backup)", re.IGNORECASE), "Explicit PHI data file"),
]

# ---------------------------------------------------------------------------
# FILE PATH PATTERNS — CAUTION (PHI possible)
# ---------------------------------------------------------------------------

PHI_FILE_CAUTION: list[tuple[re.Pattern[str], str]] = [
    # Generic patient data files
    (re.compile(r"patient.*\.csv$", re.IGNORECASE), "Patient CSV — may contain PHI"),
    (re.compile(r"patient.*\.json$", re.IGNORECASE), "Patient JSON — may contain PHI"),
    (re.compile(r"patient.*\.xml$", re.IGNORECASE), "Patient XML — may contain PHI"),
    (re.compile(r"patient.*\.xlsx?$", re.IGNORECASE), "Patient spreadsheet — may contain PHI"),
    # Healthcare DB schemas
    (
        re.compile(r"(?:patients|encounters|diagnoses|prescriptions).*\.sql$", re.IGNORECASE),
        "Healthcare DB schema — PHI risk",
    ),
    # Clinical trial data
    (re.compile(r"clinical[_\-]?trial.*\.(?:csv|json|xml)$", re.IGNORECASE), "Clinical trial data — may contain PHI"),
    # EHR system logs
    (re.compile(r"(?:epic|cerner|meditech|allscripts|athena).*\.log$", re.IGNORECASE), "EHR system log — PHI risk"),
    # FHIR/HL7 config files
    (re.compile(r"fhir.*config.*\.json$", re.IGNORECASE), "FHIR config — check for patient IDs"),
    (re.compile(r"hl7.*config", re.IGNORECASE), "HL7 configuration file"),
    # PHI identifiers in filenames
    (re.compile(r"mrn[-_]\d+", re.IGNORECASE), "MRN in filename — potential PHI"),
    (re.compile(r"ssn[-_]\d", re.IGNORECASE), "SSN in filename — PHI"),
]

# ---------------------------------------------------------------------------
# COMMAND PATTERNS — DANGER (direct PHI access)
# ---------------------------------------------------------------------------

PHI_CMD_DANGER: list[CommandRiskPattern] = [
    # SQL on patient/clinical tables
    CommandRiskPattern(
        re.compile(
            r"\bSELECT\b.{0,200}\b(?:patients?|encounters|diagnoses|prescriptions"
            r"|medications|lab_results|clinical_notes)\b",
            re.IGNORECASE,
        ),
        RiskLevel.DANGER,
        "SQL query on patient/clinical table — PHI access",
    ),
    CommandRiskPattern(
        re.compile(
            r"\bSELECT\b.{0,100}\b(?:ssn|social_security|mrn|medical_record|date_of_birth|insurance_id)\b",
            re.IGNORECASE,
        ),
        RiskLevel.DANGER,
        "SQL query selecting PHI identifier columns",
    ),
    CommandRiskPattern(
        re.compile(r"\b(?:DROP\s+TABLE|DELETE\s+FROM|TRUNCATE)\s+(?:patients?|clinical|health)\w*\b", re.IGNORECASE),
        RiskLevel.DANGER,
        "Destructive operation on patient/clinical table",
    ),
    # FHIR API calls
    CommandRiskPattern(
        re.compile(
            r"\b(?:curl|wget)\b.{0,300}/fhir/(?:r[2-5]/)?(?:Patient|Observation|Condition|MedicationRequest|DiagnosticReport|Encounter|Immunization)",
            re.IGNORECASE,
        ),
        RiskLevel.DANGER,
        "FHIR API call to patient resource — PHI access",
    ),
    # EHR vendor API calls
    CommandRiskPattern(
        re.compile(
            r"\b(?:curl|wget)\b.{0,200}(?:epic|cerner|athena|allscripts).{0,100}(?:api|fhir|patient)",
            re.IGNORECASE,
        ),
        RiskLevel.DANGER,
        "API call to EHR vendor endpoint — PHI access",
    ),
    # Cloud healthcare APIs
    CommandRiskPattern(
        re.compile(r"\b(?:curl|wget)\b.{0,200}healthcare(?:apis?)?\.googleapis\.com", re.IGNORECASE),
        RiskLevel.DANGER,
        "Google Cloud Healthcare API — PHI access",
    ),
    CommandRiskPattern(
        re.compile(r"\b(?:curl|wget)\b.{0,200}healthcareapis\.azure\.com", re.IGNORECASE),
        RiskLevel.DANGER,
        "Azure Health Data Services — PHI access",
    ),
    # Database dumps of healthcare systems
    CommandRiskPattern(
        re.compile(r"\b(?:mysqldump|pg_dump|mongodump)\b.{0,200}(?:patient|clinical|health|ehr|emr)\w*", re.IGNORECASE),
        RiskLevel.DANGER,
        "Database dump of healthcare DB — bulk PHI export",
    ),
    # PHI file copy/transfer
    CommandRiskPattern(
        re.compile(r"\b(?:cp|mv|scp|rsync)\b.{0,100}\.(?:hl7|dcm|dicom|cda|ccda|x12|834|835|837)\b", re.IGNORECASE),
        RiskLevel.DANGER,
        "Copying healthcare data file — PHI",
    ),
    # Cloud storage operations on PHI paths
    CommandRiskPattern(
        re.compile(r"\b(?:aws\s+s3|gsutil)\s+(?:cp|sync|mv)\b.{0,200}(?:phi|patient|hipaa|ehr)", re.IGNORECASE),
        RiskLevel.DANGER,
        "Cloud storage operation on PHI-tagged path",
    ),
]

# ---------------------------------------------------------------------------
# COMMAND PATTERNS — CAUTION (possible PHI access)
# ---------------------------------------------------------------------------

PHI_CMD_CAUTION: list[CommandRiskPattern] = [
    # Database client connecting to health-named databases
    CommandRiskPattern(
        re.compile(r"\b(?:mysql|psql|sqlite3|sqlcmd)\b.{0,100}(?:health|medical|clinical|ehr|emr)\w*", re.IGNORECASE),
        RiskLevel.CAUTION,
        "Database client connecting to health-named database",
    ),
    # Healthcare library installs
    CommandRiskPattern(
        re.compile(r"\b(?:npm|pip|gem)\s+install\b.{0,100}(?:fhir|hl7|hapi|smart-on-fhir)", re.IGNORECASE),
        RiskLevel.CAUTION,
        "Installing healthcare interoperability library",
    ),
    # Opening healthcare data files
    CommandRiskPattern(
        re.compile(
            r"\b(?:cat|less|more|head|tail|vim|nano|code)\b.{0,100}\.(?:hl7|dcm|dicom|cda|ccda)\b",
            re.IGNORECASE,
        ),
        RiskLevel.CAUTION,
        "Opening healthcare data file for viewing",
    ),
    # Healthcare env vars
    CommandRiskPattern(
        re.compile(r"\bexport\b.{0,50}(?:FHIR|HL7|EHR|EMR|HIPAA|PHI).{0,50}=", re.IGNORECASE),
        RiskLevel.CAUTION,
        "Exporting healthcare-related environment variable",
    ),
]


def assess_hipaa_file_risk(file_path: str, event_type: EventType) -> RiskResult | None:
    """Assess HIPAA-specific risk for a file path.

    Returns a RiskResult if a PHI pattern matches, or None to fall through
    to the standard risk engine.
    """
    normalized = file_path.replace("\\", "/")

    for pattern, reason in PHI_FILE_DANGER:
        if pattern.search(normalized):
            return RiskResult(level=RiskLevel.DANGER, reason=reason)

    for pattern, reason in PHI_FILE_CAUTION:
        if pattern.search(normalized):
            return RiskResult(level=RiskLevel.CAUTION, reason=reason)

    return None


def assess_hipaa_command_risk(executable: str, args: list[str]) -> CommandRiskResult | None:
    """Assess HIPAA-specific risk for a shell command.

    Returns a CommandRiskResult if a PHI pattern matches, or None to fall
    through to the standard command risk engine.
    """
    full_command = " ".join([executable] + args)

    for cmd_pattern in PHI_CMD_DANGER:
        if cmd_pattern.pattern.search(full_command):
            return CommandRiskResult(level=cmd_pattern.risk, reason=cmd_pattern.reason)

    for cmd_pattern in PHI_CMD_CAUTION:
        if cmd_pattern.pattern.search(full_command):
            return CommandRiskResult(level=cmd_pattern.risk, reason=cmd_pattern.reason)

    return None
