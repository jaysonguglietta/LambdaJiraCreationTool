from __future__ import annotations

import sys
import unittest
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jira_client import JiraClient, JiraCredentials, JiraError  # noqa: E402


class FakeResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


class CapturingOpener:
    def __init__(self) -> None:
        self.request = None

    def __call__(self, request, timeout):
        self.request = request
        return FakeResponse(b'[{"filename":"evidence--abc123.pdf","size":8}]')


class JiraCredentialsTests(unittest.TestCase):
    def test_uncertain_create_is_not_retried_in_place(self) -> None:
        attempts = []

        def timeout_opener(request, timeout):
            attempts.append(request)
            raise urllib.error.URLError("connection lost after request was sent")

        client = JiraClient(
            JiraCredentials("https://jira-example.atlassian.net", "test@example.com", "test"),
            "SEC",
            opener=timeout_opener,
            sleep=lambda _: None,
        )
        with self.assertRaisesRegex(JiraError, "uncertain"):
            client.create_issue({"summary": "Critical finding"})
        self.assertEqual(1, len(attempts))

    def test_accepts_allowlisted_https_jira_url(self) -> None:
        credentials = JiraCredentials.from_secret(
            {
                "base_url": "https://jira-example.atlassian.net/",
                "email": "automation@example.com",
                "api_token": "secret-token",
            },
            "atlassian.net",
        )
        self.assertEqual("https://jira-example.atlassian.net", credentials.base_url)

    def test_rejects_http_and_non_allowlisted_hosts(self) -> None:
        base = {"email": "automation@example.com", "api_token": "secret-token"}
        with self.assertRaises(JiraError):
            JiraCredentials.from_secret(
                {**base, "base_url": "http://jira-example.atlassian.net"}, "atlassian.net"
            )
        with self.assertRaises(JiraError):
            JiraCredentials.from_secret(
                {**base, "base_url": "https://attacker.example"}, "atlassian.net"
            )
        with self.assertRaises(JiraError):
            JiraCredentials.from_secret(
                {**base, "base_url": "https://atlassian.net.attacker.example"},
                "atlassian.net",
            )

    def test_upload_attachment_uses_required_multipart_headers(self) -> None:
        opener = CapturingOpener()
        credentials = JiraCredentials.from_secret(
            {
                "base_url": "https://jira-example.atlassian.net",
                "email": "automation@example.com",
                "api_token": "secret-token",
            },
            "atlassian.net",
        )
        client = JiraClient(credentials, "SEC", opener=opener, sleep=lambda _: None)
        result = client.upload_attachment(
            "SEC-3",
            "evidence--abc123.pdf",
            "application/pdf",
            b"evidence",
        )
        self.assertEqual("evidence--abc123.pdf", result["filename"])
        self.assertEqual("no-check", opener.request.get_header("X-atlassian-token"))
        self.assertTrue(opener.request.get_header("Content-type").startswith("multipart/form-data"))
        self.assertIn(b'name="file"', opener.request.data)
        self.assertIn(b"evidence", opener.request.data)

    def test_find_campaign_does_not_require_epic_issue_type(self) -> None:
        class CampaignOpener:
            def __init__(self) -> None:
                self.request = None

            def __call__(self, request, timeout):
                self.request = request
                return FakeResponse(
                    b'{"issues":[{"key":"SEC-2","fields":'
                    b'{"summary":"[Repo Security] Remediate Critical Snyk findings in '
                    b'example/lambda-leanplum","issuetype":{"name":"Task"}}}]}'
                )

        opener = CampaignOpener()
        credentials = JiraCredentials.from_secret(
            {
                "base_url": "https://jira-example.atlassian.net",
                "email": "automation@example.com",
                "api_token": "secret-token",
            },
            "atlassian.net",
        )
        client = JiraClient(credentials, "SEC", opener=opener, sleep=lambda _: None)
        title = "[Repo Security] Remediate Critical Snyk findings in example/lambda-leanplum"
        issue = client.find_epic(
            "example/lambda-leanplum",
            "repo-example-lambda-leanplum",
            title,
        )
        self.assertEqual("SEC-2", issue["key"])
        self.assertNotIn("issuetype = Epic", opener.request.data.decode("utf-8"))

    def test_rejects_credentials_embedded_in_url(self) -> None:
        with self.assertRaises(JiraError):
            JiraCredentials.from_secret(
                {
                    "base_url": "https://user:password@jira-example.atlassian.net",
                    "email": "automation@example.com",
                    "api_token": "secret-token",
                },
                "atlassian.net",
            )


if __name__ == "__main__":
    unittest.main()
