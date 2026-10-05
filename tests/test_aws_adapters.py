from __future__ import annotations

import io
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aws_adapters import InputError, ReportsNotReady, S3ReportSource, SupersededUpload  # noqa: E402


class FakeS3:
    def __init__(self, objects: dict[str, tuple[bytes, datetime]], clean: bool = True) -> None:
        self.objects = objects
        self.clean = clean

    def list_objects_v2(self, Bucket, Prefix, MaxKeys, **kwargs):
        contents = [
            {"Key": key, "Size": len(body), "LastModified": modified}
            for key, (body, modified) in self.objects.items()
            if key.startswith(Prefix)
        ]
        return {"Contents": contents, "IsTruncated": False}

    def get_object(self, Bucket, Key, **kwargs):
        body = self.objects[Key][0]
        content_type = "application/pdf" if Key.endswith(".pdf") else "text/csv"
        return {
            "Body": io.BytesIO(body),
            "ContentLength": len(body),
            "ContentType": content_type,
            "LastModified": self.objects[Key][1],
            "ETag": '"test-etag"',
            "VersionId": kwargs.get("VersionId", "current-version"),
        }

    def list_object_versions(self, Bucket, Prefix, MaxKeys):
        return {
            "Versions": [{"Key": Prefix, "VersionId": "current-version"}]
            if Prefix in self.objects
            else []
        }

    def head_object(self, Bucket, Key, **kwargs):
        return {"VersionId": kwargs.get("VersionId", "current-version")}

    def get_object_tagging(self, Bucket, Key, **kwargs):
        value = "CLEAN" if self.clean else "PENDING"
        return {"TagSet": [{"Key": "malware-scan-status", "Value": value}]}


class S3ReportSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
        self.objects = {
            "risk/snyk_risk_exposure_by_introduction_category_07_30_2026_old.csv": (
                b"old-risk",
                datetime(2026, 7, 30, 11, 0, tzinfo=UTC),
            ),
            "issues/snyk_issues_detail_07_30_2026_old.csv": (
                b"old-issues",
                datetime(2026, 7, 30, 11, 0, tzinfo=UTC),
            ),
            "risk/snyk_risk_exposure_by_introduction_category_07_31_2026_new.csv": (
                b"new-risk",
                datetime(2026, 7, 31, 10, 0, tzinfo=UTC),
            ),
            "issues/snyk_issues_detail_07_31_2026_new.csv": (
                b"new-issues",
                datetime(2026, 7, 31, 10, 5, tzinfo=UTC),
            ),
        }

    def source(self, objects=None, max_age_hours=36):
        return S3ReportSource(
            FakeS3(objects or self.objects),
            "bucket",
            "risk/",
            "issues/",
            max_age_hours=max_age_hours,
            max_bytes=1024,
            require_same_report_date=True,
            now=lambda: self.now,
        )

    def test_selects_newest_common_report_date(self) -> None:
        risk, issues = self.source().latest_pair()
        self.assertEqual(b"new-risk", risk.body)
        self.assertEqual(b"new-issues", issues.body)
        self.assertEqual("2026-07-31", risk.report_date.isoformat())

    def test_upload_selects_its_own_date_instead_of_latest_pair(self) -> None:
        risk, issues = self.source().pair_for_upload(
            "risk/snyk_risk_exposure_by_introduction_category_07_30_2026_old.csv",
            version_id="current-version",
            etag="test-etag",
        )
        self.assertEqual(b"old-risk", risk.body)
        self.assertEqual(b"old-issues", issues.body)
        self.assertEqual("current-version", risk.version_id)

    def test_waits_for_companion_instead_of_falling_back_to_old_pair(self) -> None:
        objects = {
            key: value
            for key, value in self.objects.items()
            if not key.startswith("issues/") or "07_30_2026" in key
        }
        with self.assertRaises(ReportsNotReady):
            self.source(objects).pair_for_upload(
                "risk/snyk_risk_exposure_by_introduction_category_07_31_2026_new.csv"
            )

    def test_replaced_unversioned_object_is_not_processed(self) -> None:
        with self.assertRaises(SupersededUpload):
            self.source().pair_for_upload(
                "issues/snyk_issues_detail_07_31_2026_new.csv", etag="old-etag"
            )

    def test_upload_requires_report_date(self) -> None:
        with self.assertRaisesRegex(InputError, "filename"):
            self.source().pair_for_upload("issues/report.csv")

    def test_bad_historical_objects_do_not_block_a_new_report_pair(self) -> None:
        objects = {
            **self.objects,
            "issues/snyk_issues_detail_13_99_2026_bad.csv": (b"bad", self.now),
            "issues/snyk_issues_detail_07_29_2026_oversized.csv": (b"x" * 2000, self.now),
            "issues/unrelated.bin": (b"x" * 2000, self.now),
        }
        risk, issues = self.source(objects).pair_for_upload(
            "risk/snyk_risk_exposure_by_introduction_category_07_31_2026_new.csv"
        )
        self.assertEqual(b"new-risk", risk.body)
        self.assertEqual(b"new-issues", issues.body)

    def test_rejects_reports_without_common_date(self) -> None:
        objects = {
            key: value
            for key, value in self.objects.items()
            if "risk/" in key and "07_31_2026" in key or "issues/" in key and "07_30_2026" in key
        }
        with self.assertRaisesRegex(InputError, "share the same filename date"):
            self.source(objects).latest_pair()

    def test_rejects_stale_latest_pair(self) -> None:
        with self.assertRaisesRegex(InputError, "older than"):
            self.source(max_age_hours=1).latest_pair()

    def test_loads_clean_allowlisted_attachment(self) -> None:
        objects = dict(self.objects)
        objects["attachments/evidence.pdf"] = (b"safe evidence", self.now)
        source = S3ReportSource(
            FakeS3(objects),
            "bucket",
            "risk/",
            "issues/",
            attachment_prefix="attachments/",
            max_age_hours=36,
            max_bytes=1024,
            require_same_report_date=True,
            max_attachment_bytes=1024,
            allowed_attachment_types=frozenset({"application/pdf"}),
            require_clean_attachment_tag=True,
            now=lambda: self.now,
        )
        attachment = source.get_attachment("attachments/evidence.pdf")
        self.assertEqual(b"safe evidence", attachment.body)
        self.assertRegex(attachment.jira_filename, r"evidence--[a-f0-9]{32}\.pdf")

    def test_rejects_attachment_without_clean_scan_tag(self) -> None:
        objects = dict(self.objects)
        objects["attachments/evidence.pdf"] = (b"unscanned", self.now)
        source = S3ReportSource(
            FakeS3(objects, clean=False),
            "bucket",
            "risk/",
            "issues/",
            attachment_prefix="attachments/",
            max_age_hours=36,
            max_bytes=1024,
            require_same_report_date=True,
            max_attachment_bytes=1024,
            allowed_attachment_types=frozenset({"application/pdf"}),
            require_clean_attachment_tag=True,
            now=lambda: self.now,
        )
        with self.assertRaisesRegex(InputError, "not tagged"):
            source.get_attachment("attachments/evidence.pdf")

    def test_rejects_attachment_outside_prefix(self) -> None:
        with self.assertRaisesRegex(InputError, "must be an object under"):
            self.source().get_attachment("risk/report.csv")


if __name__ == "__main__":
    unittest.main()
