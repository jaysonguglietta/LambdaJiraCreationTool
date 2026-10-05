from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import security_operator as operator  # noqa: E402
from build_release import build_release  # noqa: E402


class OperatorTests(unittest.TestCase):
    def test_full_export_follows_pinned_hash_checked_audit_artifacts(self):
        bodies = {}

        def reference(identifier, value):
            key = f"snapshots/{identifier}/" + "a" * 32 + ".json"
            body = json.dumps(value).encode()
            bodies[key] = body
            return {
                "bucket": "audit",
                "key": key,
                "version_id": "v1",
                "sha256": hashlib.sha256(body).hexdigest(),
            }

        child = reference(
            "child",
            {
                "finding": "synthetic",
                "input_objects": [
                    {
                        "bucket": "private-input",
                        "key": "detail.csv",
                        "version_id": "input-v1",
                        "sha256": "b" * 64,
                    }
                ],
                "enrichment": {
                    "bucket": "private-input",
                    "key": "enrichment/detail.csv.json",
                    "version_id": "enrichment-v1",
                    "sha256": "c" * 64,
                },
            },
        )
        parent = reference("parent", {"previous": child})
        calls = []

        def get_object(**kwargs):
            calls.append(kwargs)
            return {"Body": io.BytesIO(bodies[kwargs["Key"]])}

        sdk = {
            "boto3": SimpleNamespace(
                client=lambda *args, **kwargs: SimpleNamespace(get_object=get_object)
            ),
            "botocore.config": SimpleNamespace(Config=lambda **kwargs: None),
        }
        with patch.dict(sys.modules, sdk):
            result = operator.export_artifacts({"job": {"snapshot": parent}}, "audit")
            self.assertEqual(2, len(result["artifacts"]))
            self.assertTrue(all(call["VersionId"] == "v1" for call in calls))
            with self.assertRaisesRegex(ValueError, "outside"):
                operator.export_artifacts({"job": {"snapshot": parent}}, "other-bucket")
            bodies[parent["key"]] = b"tampered"
            with self.assertRaisesRegex(ValueError, "integrity"):
                operator.export_artifacts({"job": {"snapshot": parent}}, "audit")

    def test_export_paginates_and_checks_stable_snapshot(self):
        job = {"source": "snyk", "cursor": 101, "status": "COMPLETE"}
        with patch.object(
            operator,
            "invoke",
            side_effect=[
                {"job": job, "actions": [{"index": 0}], "next_offset": 100},
                {"job": job, "actions": [{"index": 100}], "next_offset": None},
            ],
        ):
            result = operator.export_job("function", "a" * 32, "snyk")
        self.assertEqual(2, len(result["actions"]))

    def test_export_refuses_to_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "export.json"
            operator.write_export(output, {"job": "test"})
            with self.assertRaises(FileExistsError):
                operator.write_export(output, {"job": "changed"})
            self.assertEqual({"job": "test"}, json.loads(output.read_text()))
            self.assertEqual(0o600, output.stat().st_mode & 0o777)

    def test_offline_preview_has_complete_ticket_fields(self):
        result = operator.local_preview(
            ROOT / "tests/fixtures/risk.csv", ROOT / "tests/fixtures/issues.csv"
        )
        self.assertEqual("OFFLINE_PREVIEW", result["status"])
        self.assertEqual(2, result["tickets"])
        self.assertEqual(2, result["campaigns"])
        self.assertTrue(all(p["repository"] in p["summary"] for p in result["previews"]))

    def test_cli_runs_as_a_script_without_shadowing_stdlib(self):
        result = subprocess.run(  # noqa: S603 - fixed local interpreter, script and synthetic fixtures
            [
                sys.executable,
                str(ROOT / "scripts/security_operator.py"),
                "preview",
                "--risk",
                str(ROOT / "tests/fixtures/risk.csv"),
                "--issues",
                str(ROOT / "tests/fixtures/issues.csv"),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual("OFFLINE_PREVIEW", json.loads(result.stdout)["status"])

    def test_mutating_operations_require_explicit_apply_before_loading_aws(self):
        for name in ("verify", "exception", "repair", "resume", "monitor", "restore"):
            with self.assertRaisesRegex(ValueError, "apply"):
                operator.invoke("test-function", {"operation": name})

    def test_profile_preview_is_review_only(self):
        output = io.StringIO()
        with redirect_stdout(output):
            operator.main(
                [
                    "profile-preview",
                    "--profiles",
                    str(ROOT / "config/alertlogic-profile.example.json"),
                    "--sample",
                    str(ROOT / "tests/fixtures/alertlogic-normalized-example.csv"),
                    "--product",
                    "alertlogic",
                ]
            )
        result = json.loads(output.getvalue())
        self.assertEqual("REVIEW_REQUIRED", result["status"])
        self.assertEqual(2, result["critical_occurrences"])
        self.assertEqual(64, len(result["sample_sha256"]))

    def test_release_archive_is_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            package.mkdir()
            first = build_release(package, Path(directory) / "a.zip")
            second = build_release(package, Path(directory) / "b.zip")
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertGreater(first["files"], 12)

    def test_release_omits_installer_local_records_and_cli_shebangs(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            package.mkdir()
            (package / "bin").mkdir()
            (package / "bin/cli.py").write_text("#!/machine-specific/interpreter\n")
            info = package / "synthetic.dist-info"
            info.mkdir()
            (info / "direct_url.json").write_text('{"url":"file:///machine-specific/wheel"}')
            (info / "METADATA").write_text("Name: synthetic\nVersion: 1.0\n")
            first = build_release(package, Path(directory) / "a.zip")
            (package / "bin/cli.py").write_text("#!/another/interpreter\n")
            (info / "direct_url.json").write_text('{"url":"file:///another/wheel"}')
            second = build_release(package, Path(directory) / "b.zip")
            self.assertEqual(first["sha256"], second["sha256"])
