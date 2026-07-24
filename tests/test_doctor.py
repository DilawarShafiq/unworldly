"""Tests for `unworldly doctor` capture diagnostics."""

from unworldly.doctor import INFO, OK, WARN, DoctorReport, format_report, run_doctor


class TestRunDoctor:
    def test_returns_report_with_checks(self):
        report = run_doctor(".")
        assert isinstance(report, DoctorReport)
        assert len(report.checks) >= 5

    def test_all_statuses_are_valid(self):
        for c in run_doctor(".").checks:
            assert c.status in (OK, WARN, INFO)

    def test_reports_filesystem_layer(self):
        names = [c.name for c in run_doctor(".").checks]
        assert any("L1 file capture" in n for n in names)

    def test_poll_mode_is_flagged_best_effort_or_missing(self):
        # Poll mode is never advertised as reliable — it must always warn.
        poll = [c for c in run_doctor(".").checks if "poll" in c.name.lower()]
        assert poll and poll[0].status == WARN

    def test_states_what_it_cannot_see(self):
        details = " ".join(c.detail.lower() for c in run_doctor(".").checks)
        assert "will not see" in " ".join(c.name.lower() for c in run_doctor(".").checks) or "cloud" in details

    def test_warnings_property(self):
        report = run_doctor(".")
        assert report.warnings == [c for c in report.checks if c.status == WARN]


class TestFormatReport:
    def test_renders_all_check_names(self):
        report = run_doctor(".")
        out = format_report(report)
        for c in report.checks:
            assert c.name in out

    def test_mentions_warning_count_or_healthy(self):
        out = format_report(run_doctor("."))
        assert "warning" in out.lower() or "healthy" in out.lower()
