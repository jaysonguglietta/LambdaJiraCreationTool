from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from test_service import FakeSource, config  # noqa: E402

from adf import plain_text  # noqa: E402
from config import ConfigurationError  # noqa: E402
from products import FindingBatch, load_profiles, parse_mapped_csv  # noqa: E402
from reports import ReportValidationError, group_findings, parse_issue_report  # noqa: E402
from ticketing import child_description, child_labels  # noqa: E402


def product_config():
    return dataclasses.replace(
        config(),
        product_profiles_json=(ROOT / "config/alertlogic-profile.example.json").read_text(),
    )


class ProductTests(unittest.TestCase):
    def setUp(self):
        self.config = product_config()
        self.profile = load_profiles(self.config)[0]
        self.body = (ROOT / "tests/fixtures/alertlogic-normalized-example.csv").read_bytes()

    def test_filters_and_groups_by_source_asset_group_and_stable_id(self):
        findings = parse_mapped_csv(self.body, self.profile)
        groups = group_findings(findings)
        self.assertEqual(2, len(findings))
        self.assertEqual(1, len(groups))
        self.assertEqual({"web01", "web02"}, groups[0].targets)
        self.assertIn("alertlogic", child_labels(groups[0]))
        self.assertIn(
            "Upgrade to the vendor-supported",
            plain_text(child_description(groups[0], "SEC-100", "2026-07-31")),
        )
        self.assertNotIn("Snyk", plain_text(child_description(groups[0], "SEC-100", "2026-07-31")))

    def test_product_namespace_does_not_collide_with_existing_snyk_fingerprint(self):
        snyk = parse_issue_report(FakeSource().pair[1].body)[0]
        other = dataclasses.replace(snyk, source="alertlogic", source_name="Alert Logic")
        self.assertNotEqual(
            group_findings([snyk])[0].fingerprint, group_findings([other])[0].fingerprint
        )
        self.assertEqual(2, len(group_findings([snyk, other])))
        self.assertNotEqual(
            FindingBatch("snyk", "Snyk", FakeSource().pair, []).fingerprint,
            FindingBatch("alertlogic", "Alert Logic", FakeSource().pair, []).fingerprint,
        )

    def test_missing_headers_and_blank_status_fail_before_creating_tickets(self):
        with self.assertRaises(ReportValidationError):
            parse_mapped_csv(self.body.replace(b"FindingId", b"WrongId", 1), self.profile)
        with self.assertRaisesRegex(ReportValidationError, "Blank"):
            parse_mapped_csv(self.body.replace(b",Critical,Open,", b",Critical,,", 1), self.profile)

    def test_rejects_unsafe_reference_urls(self):
        columns = {**self.profile.columns, "issue_url": "Remediation"}
        columns.pop("remediation")
        profile = dataclasses.replace(self.profile, columns=columns)
        with self.assertRaisesRegex(ReportValidationError, "HTTPS"):
            parse_mapped_csv(self.body, profile)

    def test_profile_cannot_route_outside_allowed_products_folder(self):
        raw = self.config.product_profiles_json.replace(
            "products/alertlogic/", "snyk/issues-detail/"
        )
        with self.assertRaises(ConfigurationError):
            load_profiles(dataclasses.replace(self.config, product_profiles_json=raw))

    def test_group_and_target_may_share_a_host_column(self):
        import json

        raw = json.loads(self.config.product_profiles_json)
        raw["alertlogic"]["columns"]["group"] = "Asset"
        profile = load_profiles(
            dataclasses.replace(self.config, product_profiles_json=json.dumps(raw))
        )[0]
        findings = parse_mapped_csv(self.body, profile)
        self.assertEqual({"web01", "web02"}, {finding.repository for finding in findings})

    def test_legacy_finding_label_retained_but_observation_identity_is_versioned(self):
        import hashlib

        reports = FakeSource().pair
        legacy_run = hashlib.sha256(
            f"{reports[0].sha256}\n{reports[1].sha256}".encode()
        ).hexdigest()[:32]
        self.assertNotEqual(legacy_run, FindingBatch("snyk", "Snyk", reports, []).fingerprint)
        changed = (dataclasses.replace(reports[0], version_id="new-version"), reports[1])
        self.assertNotEqual(
            FindingBatch("snyk", "Snyk", reports, []).fingerprint,
            FindingBatch("snyk", "Snyk", changed, []).fingerprint,
        )
        group = group_findings(parse_issue_report(reports[1].body))[0]
        legacy_finding = hashlib.sha256(
            f"{group.repository}\n{group.snyk_id}".encode()
        ).hexdigest()[:24]
        self.assertEqual(legacy_finding, group.fingerprint)

    def test_profiles_apply_root_and_reject_overlap(self):
        import json

        raw = json.loads(self.config.product_profiles_json)
        raw["other"] = {**raw["alertlogic"], "prefix": "products/alertlogic/nested/"}
        with self.assertRaisesRegex(ConfigurationError, "overlap"):
            load_profiles(dataclasses.replace(self.config, product_profiles_json=json.dumps(raw)))
        rooted = load_profiles(
            dataclasses.replace(
                self.config, ingestion_prefix="incoming/", products_prefix="incoming/products/"
            )
        )
        self.assertEqual("incoming/products/alertlogic/", rooted[0].prefix)
