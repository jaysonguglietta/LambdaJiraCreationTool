from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reports import (  # noqa: E402
    ReportValidationError,
    group_findings,
    parse_issue_report,
    parse_risk_report,
    validate_report_counts,
)


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.risk_body = (ROOT / "tests/fixtures/risk.csv").read_bytes()
        cls.issues_body = (ROOT / "tests/fixtures/issues.csv").read_bytes()

    def test_filters_to_open_critical_and_parses_repository(self) -> None:
        findings = parse_issue_report(self.issues_body)
        self.assertEqual(3, len(findings))
        self.assertEqual("example/service-a", findings[0].repository)
        self.assertEqual("src/App.csproj", findings[0].target)
        self.assertEqual("SNYK-DOTNET-PACKAGEA-100", findings[0].snyk_id)
        self.assertEqual(("CVE-2020-0001",), findings[0].cves)

    def test_groups_repeated_finding_within_repository(self) -> None:
        groups = group_findings(parse_issue_report(self.issues_body))
        self.assertEqual(2, len(groups))
        first = next(group for group in groups if group.repository == "example/service-a")
        self.assertEqual(2, len(first.targets))
        self.assertIn("src/App.csproj", first.targets)
        self.assertIn("tests/App.Tests.csproj", first.targets)

    def test_reconciles_aggregate_count(self) -> None:
        risk = parse_risk_report(self.risk_body)
        findings = parse_issue_report(self.issues_body)
        self.assertEqual(3, risk.critical_total)
        self.assertEqual([], validate_report_counts(risk, findings, enforce=True))

    def test_count_mismatch_fails_closed(self) -> None:
        risk = parse_risk_report(self.risk_body)
        with self.assertRaisesRegex(ReportValidationError, "Critical count mismatch"):
            validate_report_counts(risk, parse_issue_report(self.issues_body)[:2], enforce=True)

    def test_count_mismatch_can_be_reported_as_warning(self) -> None:
        risk = parse_risk_report(self.risk_body)
        warnings = validate_report_counts(
            risk, parse_issue_report(self.issues_body)[:2], enforce=False
        )
        self.assertEqual(1, len(warnings))
        self.assertIn("Critical count mismatch", warnings[0])

    def test_rejects_non_https_snyk_url(self) -> None:
        body = self.issues_body.replace(b"https://app.snyk.io", b"http://app.snyk.io", 1)
        with self.assertRaisesRegex(ReportValidationError, "HTTPS"):
            parse_issue_report(body)

    def test_rejects_missing_required_column(self) -> None:
        body = self.issues_body.replace(b"ISSUE_STATUS_INDICATOR,", b"", 1)
        with self.assertRaisesRegex(ReportValidationError, "missing columns"):
            parse_issue_report(body)


if __name__ == "__main__":
    unittest.main()
