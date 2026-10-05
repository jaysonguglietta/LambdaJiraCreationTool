from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import jira_attachment_smoke as smoke  # noqa: E402


class FakeJiraClient:
    existing: list[dict] = []
    uploads: list[tuple[str, str, str, bytes]] = []

    def __init__(self, credentials, project):
        self.credentials = credentials
        self.project = project

    def preflight(self):
        return {"accountId": "test-account"}

    def get_issue(self, key, fields=None):
        return {"key": key, "fields": {"summary": "Test", "attachment": self.existing}}

    def get_attachment_settings(self):
        return {"enabled": True, "uploadLimit": 1_000_000}

    def list_attachments(self, key):
        return self.existing

    def upload_attachment(self, key, filename, content_type, body):
        self.uploads.append((key, filename, content_type, body))
        return {"id": "123", "filename": filename, "size": len(body)}


class SmokeCliTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeJiraClient.existing = []
        FakeJiraClient.uploads = []
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "evidence.png"
        self.path.write_bytes(b"safe-test-image")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_cli(self, *extra: str) -> dict:
        output = io.StringIO()
        arguments = [
            "--project",
            "SEC",
            "--issue",
            "SEC-3",
            "--file",
            str(self.path),
            "--secret-id",
            "test-secret",
            "--origin",
            "https://jira-example.atlassian.net",
            *extra,
        ]
        with (
            patch.object(smoke, "JiraClient", FakeJiraClient),
            patch.object(smoke, "_load_credentials", return_value=object()),
            redirect_stdout(output),
        ):
            self.assertEqual(0, smoke.main(arguments))
        return json.loads(output.getvalue())

    def test_default_is_read_only(self) -> None:
        result = self.run_cli()
        self.assertEqual("DRY_RUN", result["status"])
        self.assertEqual([], FakeJiraClient.uploads)
        self.assertRegex(result["filename"], r"evidence--[a-f0-9]{32}\.png")

    def test_project_must_be_selected_before_any_secret_lookup(self) -> None:
        with (
            patch.object(smoke, "_load_secret") as secret_loader,
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                smoke.main(
                    [
                        "--issue",
                        "SEC-3",
                        "--file",
                        str(self.path),
                        "--secret-id",
                        "test-secret",
                        "--origin",
                        "https://jira-example.atlassian.net",
                    ]
                )
            secret_loader.assert_not_called()

    def test_upload_requires_explicit_flag(self) -> None:
        result = self.run_cli("--upload")
        self.assertEqual("UPLOADED", result["status"])
        self.assertEqual(1, len(FakeJiraClient.uploads))
        self.assertEqual("SEC-3", FakeJiraClient.uploads[0][0])

    def test_duplicate_is_not_uploaded(self) -> None:
        first = self.run_cli()
        FakeJiraClient.existing = [
            {"id": "existing", "filename": first["filename"], "size": self.path.stat().st_size}
        ]
        result = self.run_cli("--upload")
        self.assertEqual("ALREADY_ATTACHED", result["status"])
        self.assertEqual([], FakeJiraClient.uploads)


if __name__ == "__main__":
    unittest.main()
