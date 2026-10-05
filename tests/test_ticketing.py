from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from adf import plain_text  # noqa: E402
from reports import group_findings, parse_issue_report  # noqa: E402
from ticketing import child_description, child_labels, child_title  # noqa: E402


class TicketingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        findings = parse_issue_report((ROOT / "tests/fixtures/issues.csv").read_bytes())
        cls.group = next(
            group for group in group_findings(findings) if group.repository == "example/service-a"
        )

    def test_title_prominently_contains_repository(self) -> None:
        title = child_title(self.group)
        self.assertTrue(title.startswith("[Critical] example/service-a —"))
        self.assertIn("CVE-2020-0001", title)
        self.assertIn("Remote Code Execution", title)
        self.assertNotIn("DOTNET:PACKAGEA", title)
        self.assertLessEqual(len(title), 255)

    def test_description_contains_required_work_item_data(self) -> None:
        description = child_description(self.group, "SEC-100", "2026-07-31")
        flattened = plain_text(description)
        for expected in (
            "Security source facts",
            "example/service-a",
            "SNYK-DOTNET-PACKAGEA-100",
            "CVE-2020-0001",
            "SEC-100",
            "post-deployment Snyk scan",
        ):
            self.assertIn(expected, flattened)

    def test_labels_are_deterministic_and_safe(self) -> None:
        labels = child_labels(self.group)
        self.assertIn("severity-critical", labels)
        self.assertTrue(any(label.startswith("repo-example-service-a-") for label in labels))
        self.assertTrue(any(label.startswith("snyk-auto-") for label in labels))
        self.assertEqual(labels, child_labels(self.group))


if __name__ == "__main__":
    unittest.main()
