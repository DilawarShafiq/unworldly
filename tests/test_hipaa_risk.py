"""Tests for HIPAA PHI detection patterns."""

from unworldly.hipaa_risk import assess_hipaa_command_risk, assess_hipaa_file_risk
from unworldly.types import EventType, RiskLevel


class TestHipaaFileRisk:
    """Tests for PHI file path detection."""

    # --- DANGER: clinical data formats ---

    class TestHL7:
        def test_flag_hl7_file(self):
            result = assess_hipaa_file_risk("data/patient_msg.hl7", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER
            assert "HL7" in result.reason

        def test_flag_hl7_case_insensitive(self):
            result = assess_hipaa_file_risk("exports/ADT_A01.HL7", EventType.MODIFY)
            assert result is not None
            assert result.level == RiskLevel.DANGER

    class TestFHIR:
        def test_flag_fhir_patient_resource(self):
            result = assess_hipaa_file_risk("fhir/r4/patient_123.json", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER
            assert "Patient" in result.reason

        def test_flag_fhir_observation(self):
            result = assess_hipaa_file_risk("fhir/observation_vitals.json", EventType.MODIFY)
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_fhir_diagnosticreport(self):
            result = assess_hipaa_file_risk("fhir/diagnosticreport_lab.json", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_fhir_bundle(self):
            result = assess_hipaa_file_risk("fhir/bundle_export.json", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER

    class TestDICOM:
        def test_flag_dcm_file(self):
            result = assess_hipaa_file_risk("imaging/scan_001.dcm", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER
            assert "DICOM" in result.reason

        def test_flag_dicom_extension(self):
            result = assess_hipaa_file_risk("radiology/ct_head.dicom", EventType.MODIFY)
            assert result is not None
            assert result.level == RiskLevel.DANGER

    class TestX12:
        def test_flag_x12_claim_837(self):
            result = assess_hipaa_file_risk("claims/batch_20260101.837", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER
            assert "837" in result.reason

        def test_flag_x12_remittance_835(self):
            result = assess_hipaa_file_risk("payments/era_20260101.835", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_x12_enrollment_834(self):
            result = assess_hipaa_file_risk("enrollment/members.834", EventType.MODIFY)
            assert result is not None
            assert result.level == RiskLevel.DANGER

    class TestCDA:
        def test_flag_cda_file(self):
            result = assess_hipaa_file_risk("documents/discharge.cda", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_ccda_file(self):
            result = assess_hipaa_file_risk("records/summary.ccda", EventType.MODIFY)
            assert result is not None
            assert result.level == RiskLevel.DANGER

    class TestEHRExports:
        def test_flag_patient_export(self):
            result = assess_hipaa_file_risk("exports/patient_data_20260101.csv", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_ehr_export(self):
            result = assess_hipaa_file_risk("backups/ehr_export_full.zip", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_emr_dump(self):
            result = assess_hipaa_file_risk("dumps/emr_backup_2026.sql", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_lab_results(self):
            result = assess_hipaa_file_risk("reports/lab_results_batch.csv", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.DANGER

    # --- CAUTION: possible PHI ---

    class TestCautionFiles:
        def test_flag_patient_csv(self):
            result = assess_hipaa_file_risk("data/patients_2026.csv", EventType.MODIFY)
            assert result is not None
            assert result.level == RiskLevel.CAUTION

        def test_flag_patient_json(self):
            result = assess_hipaa_file_risk("api/patient_list.json", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.CAUTION

        def test_flag_healthcare_db_schema(self):
            result = assess_hipaa_file_risk("db/patients_schema.sql", EventType.MODIFY)
            assert result is not None
            assert result.level == RiskLevel.CAUTION

        def test_flag_ehr_log(self):
            result = assess_hipaa_file_risk("logs/epic_access.log", EventType.MODIFY)
            assert result is not None
            assert result.level == RiskLevel.CAUTION

        def test_flag_mrn_in_filename(self):
            result = assess_hipaa_file_risk("exports/mrn-12345678.pdf", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.CAUTION

        def test_flag_clinical_trial(self):
            result = assess_hipaa_file_risk("research/clinical_trial_data.csv", EventType.CREATE)
            assert result is not None
            assert result.level == RiskLevel.CAUTION

    # --- No match (should return None) ---

    class TestNoMatch:
        def test_normal_source_file(self):
            result = assess_hipaa_file_risk("src/app.py", EventType.MODIFY)
            assert result is None

        def test_normal_config_file(self):
            result = assess_hipaa_file_risk("config/settings.json", EventType.MODIFY)
            assert result is None

        def test_normal_readme(self):
            result = assess_hipaa_file_risk("README.md", EventType.MODIFY)
            assert result is None


class TestHipaaCommandRisk:
    """Tests for PHI command detection."""

    # --- DANGER: direct PHI access ---

    class TestSQLPatterns:
        def test_flag_select_from_patients(self):
            result = assess_hipaa_command_risk("psql", ["-c", "SELECT * FROM patients WHERE id=123"])
            assert result is not None
            assert result.level == RiskLevel.DANGER
            assert "patient" in result.reason.lower()

        def test_flag_select_ssn_column(self):
            result = assess_hipaa_command_risk("mysql", ["-e", "SELECT ssn, name FROM users"])
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_drop_patient_table(self):
            result = assess_hipaa_command_risk("psql", ["-c", "DROP TABLE patients"])
            assert result is not None
            assert result.level == RiskLevel.DANGER
            assert "Destructive" in result.reason

    class TestFHIRAPI:
        def test_flag_curl_fhir_patient(self):
            result = assess_hipaa_command_risk("curl", ["https://ehr.example.com/fhir/r4/Patient/123"])
            assert result is not None
            assert result.level == RiskLevel.DANGER
            assert "FHIR" in result.reason

        def test_flag_curl_fhir_observation(self):
            result = assess_hipaa_command_risk("curl", ["https://api.example.com/fhir/Observation?patient=123"])
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_curl_epic_api(self):
            result = assess_hipaa_command_risk(
                "curl", ["-H", "Bearer token", "https://epic.example.com/api/fhir/Patient"]
            )
            assert result is not None
            assert result.level == RiskLevel.DANGER

    class TestCloudAPIs:
        def test_flag_google_healthcare_api(self):
            result = assess_hipaa_command_risk(
                "curl", ["https://healthcare.googleapis.com/v1/projects/my-proj/datasets"]
            )
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_azure_health_api(self):
            result = assess_hipaa_command_risk("curl", ["https://myworkspace.healthcareapis.azure.com/fhir/Patient"])
            assert result is not None
            assert result.level == RiskLevel.DANGER

    class TestDBDumps:
        def test_flag_pg_dump_patient_db(self):
            result = assess_hipaa_command_risk("pg_dump", ["--dbname=patient_records", "-f", "dump.sql"])
            assert result is not None
            assert result.level == RiskLevel.DANGER
            assert "dump" in result.reason.lower()

        def test_flag_mysqldump_ehr(self):
            result = assess_hipaa_command_risk("mysqldump", ["ehr_production", "--single-transaction"])
            assert result is not None
            assert result.level == RiskLevel.DANGER

    class TestFileCopy:
        def test_flag_scp_hl7(self):
            result = assess_hipaa_command_risk("scp", ["data/messages.hl7", "remote:/backups/"])
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_rsync_dicom(self):
            result = assess_hipaa_command_risk("rsync", ["-avz", "imaging/scan.dcm", "backup:/archive/"])
            assert result is not None
            assert result.level == RiskLevel.DANGER

        def test_flag_aws_s3_phi(self):
            result = assess_hipaa_command_risk("aws", ["s3", "cp", "s3://hipaa-bucket/patient_data/", "local/"])
            assert result is not None
            assert result.level == RiskLevel.DANGER

    # --- CAUTION: possible PHI access ---

    class TestCautionCommands:
        def test_flag_health_db_connection(self):
            result = assess_hipaa_command_risk("psql", ["-d", "clinical_db", "-U", "admin"])
            assert result is not None
            assert result.level == RiskLevel.CAUTION

        def test_flag_fhir_library_install(self):
            result = assess_hipaa_command_risk("pip", ["install", "fhir.resources"])
            assert result is not None
            assert result.level == RiskLevel.CAUTION

        def test_flag_viewing_hl7_file(self):
            result = assess_hipaa_command_risk("cat", ["messages/adt.hl7"])
            assert result is not None
            assert result.level == RiskLevel.CAUTION

        def test_flag_hipaa_env_var(self):
            result = assess_hipaa_command_risk("export", ["FHIR_SERVER_URL=https://ehr.example.com"])
            assert result is not None
            assert result.level == RiskLevel.CAUTION

    # --- No match ---

    class TestCommandNoMatch:
        def test_normal_git_command(self):
            result = assess_hipaa_command_risk("git", ["add", "."])
            assert result is None

        def test_normal_npm_test(self):
            result = assess_hipaa_command_risk("npm", ["test"])
            assert result is None

        def test_normal_ls(self):
            result = assess_hipaa_command_risk("ls", ["-la"])
            assert result is None
