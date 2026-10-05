from __future__ import annotations

import copy
import sys
import unittest
from datetime import UTC, date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from config import Config  # noqa: E402
from identity import PROPERTY_KEY  # noqa: E402
from models import AttachmentFile, ReportObject  # noqa: E402
from policy import Policy  # noqa: E402
from service import AutomationService  # noqa: E402


class FakeSource:
    def __init__(self) -> None:
        now = datetime(2026, 7, 31, 11, 0, tzinfo=UTC)
        self.pair = (
            ReportObject(
                bucket="bucket",
                key="snyk/risk-exposure/snyk_risk_exposure_by_introduction_category_07_31_2026_a.csv",
                last_modified=now,
                report_date=date(2026, 7, 31),
                body=(ROOT / "tests/fixtures/risk.csv").read_bytes(),
            ),
            ReportObject(
                bucket="bucket",
                key="snyk/issues-detail/snyk_issues_detail_07_31_2026_b.csv",
                last_modified=now,
                report_date=date(2026, 7, 31),
                body=(ROOT / "tests/fixtures/issues.csv").read_bytes(),
            ),
        )

    def latest_pair(self):
        return self.pair

    def get_json(self, key, allowed_prefix, **kwargs):
        if kwargs.get("optional"):
            return None
        raise ValueError("No test evidence configured")

    def get_attachment(self, key, display_name=None, version_id=None):
        return AttachmentFile(
            s3_key=key,
            filename=display_name or key.rsplit("/", 1)[-1],
            content_type="application/pdf",
            body=b"sanitized test evidence",
            version_id=version_id or "evidence-v1",
        )


class FakeSecretLoader:
    def load_json(self, _arn: str):
        return {
            "base_url": "https://jira-example.atlassian.net",
            "email": "automation@example.com",
            "api_token": "not-a-real-token",
            "identity_key": "test-signing-key-not-real-01234567890123456789",
        }


class FakeState:
    def __init__(self) -> None:
        self.runs = {}
        self.mappings = {}
        self.mapping_records = {}
        self.records = {}
        self.locks = set()

    def acquire_lock(self, name, seconds=330):
        if name in self.locks:
            return False
        self.locks.add(name)
        return True

    def release_lock(self, name):
        self.locks.remove(name)

    def get_record(self, key):
        return copy.deepcopy(self.records.get(key))

    def put_record(self, key, value):
        self.records[key] = copy.deepcopy(value)

    def list_status(self, status, before=None):
        return [
            copy.deepcopy(v)
            for v in self.records.values()
            if v.get("status") == status and (before is None or v.get("deadline", 0) <= before)
        ]

    def mapping_record(self, fingerprint):
        return copy.deepcopy(self.mapping_records.get(("V2", fingerprint)))

    def count_unmapped(self, fingerprints, budget):
        return sum(not self.get_mapping("V2", fp) for fp in fingerprints)

    def get_run(self, fingerprint):
        return self.runs.get(fingerprint)

    def mark_run(self, fingerprint, status, payload):
        self.runs[fingerprint] = {"status": status, "payload": payload}

    def get_mapping(self, mapping_type, fingerprint):
        return self.mappings.get((mapping_type, fingerprint))

    def claim_mapping(self, mapping_type, fingerprint, metadata, lease_seconds=300):
        key = (mapping_type, fingerprint)
        if key in self.mappings:
            return False
        self.mappings[key] = None
        self.mapping_records[key] = {"status": "PENDING", "metadata": copy.deepcopy(metadata)}
        return True

    def put_mapping(self, mapping_type, fingerprint, jira_key, metadata):
        self.mappings[(mapping_type, fingerprint)] = jira_key
        self.mapping_records[(mapping_type, fingerprint)] = {
            "jira_key": jira_key,
            "status": "COMPLETE",
            "metadata": copy.deepcopy(metadata),
        }


class FakeAudit:
    def __init__(self):
        self.values = {}

    def check(self):
        return {"bucket": "audit", "versioning": "Enabled"}

    def put(self, category, identifier, value):
        key = f"{category}/{identifier}/{len(self.values)}.json"
        self.values[key] = copy.deepcopy(value)
        return {"bucket": "audit", "key": key, "version_id": "v1", "sha256": "test"}

    def get(self, ref):
        return copy.deepcopy(self.values[ref["key"]])


class FakePublisher:
    def __init__(self) -> None:
        self.messages = []

    def publish(self, subject, payload):
        self.messages.append((subject, payload))


class FakeJira:
    def __init__(self) -> None:
        self.issues = {}
        self.created_fields = []
        self.updated = []
        self.next_number = 100
        self.attachments = {}
        self.issue_links = []
        self.properties = {}

    def validate_setup(self, config, custom_fields):
        return {"project_id": "10001", "project_key": "SEC"}

    def validate_payload(self, kind, payload):
        pass

    def get_property(self, key):
        return copy.deepcopy(self.properties.get(key))

    def put_property(self, key, value):
        self.properties[key] = copy.deepcopy(value)

    def find_identity(self, identity, legacy):
        matches = []
        for issue in self.issues.values():
            if any(
                label in issue["fields"].get("labels", []) for label in [identity.label, *legacy]
            ):
                prop = self.get_property(issue["key"])
                if (
                    not identity.matches(prop, FakeSecretLoader().load_json("")["identity_key"])
                    or prop.get("jira_key") != issue["key"]
                ):
                    from jira_client import IdentityReviewRequired

                    raise IdentityReviewRequired("Ambiguous/untrusted ticket candidates")
                matches.append(issue)
        if len(matches) > 1:
            raise ValueError("Ambiguous identities")
        return copy.deepcopy(matches[0]) if matches else None

    def update_labels(self, key, add, remove):
        labels = set(self.issues[key]["fields"].get("labels", []))
        self.issues[key]["fields"]["labels"] = sorted((labels | add) - remove)

    def preflight(self):
        return {"accountId": "test"}

    def try_get_issue(self, key):
        return copy.deepcopy(self.issues.get(key))

    def get_issue(self, key, fields=None):
        return copy.deepcopy(self.issues[key])

    def find_epic(self, repository, repository_label, expected_title):
        return next(
            (
                issue
                for issue in self.issues.values()
                if repository in issue["fields"].get("summary", "")
            ),
            None,
        )

    def find_child(self, repository, snyk_id, automation_label):
        return next(
            (
                issue
                for issue in self.issues.values()
                if issue["fields"].get("issuetype") == "Bug"
                and automation_label in issue["fields"].get("labels", [])
            ),
            None,
        )

    def create_issue(self, fields, properties=None):
        key = f"SEC-{self.next_number}"
        self.next_number += 1
        stored = copy.deepcopy(fields)
        stored["project"] = {"id": "10001", "key": "SEC"}
        stored["issuetype"] = fields["issuetype"]["name"]
        issue = {"key": key, "fields": stored}
        self.issues[key] = issue
        self.created_fields.append(fields)
        if properties:
            self.properties[key] = next(p["value"] for p in properties if p["key"] == PROPERTY_KEY)
        return {"key": key, "id": str(self.next_number)}

    def update_issue(self, key, fields):
        self.issues[key]["fields"].update(fields)
        self.updated.append((key, fields))

    def create_issue_link(self, campaign_key, child_key, link_type="Relates"):
        self.issue_links.append((campaign_key, child_key, link_type))
        self.issues[child_key]["fields"].setdefault("issuelinks", []).append(
            {"type": {"name": link_type}, "inwardIssue": {"key": campaign_key}}
        )

    def get_attachment_settings(self):
        return {"enabled": True, "uploadLimit": 10_000_000}

    def list_attachments(self, key):
        return self.attachments.get(key, [])

    def upload_attachment(self, key, filename, content_type, body):
        item = {"filename": filename, "size": len(body), "mimeType": content_type}
        self.attachments.setdefault(key, []).append(item)
        return item


def config() -> Config:
    return Config(
        input_bucket="bucket",
        risk_prefix="snyk/risk-exposure/",
        issues_prefix="snyk/issues-detail/",
        attachment_prefix="snyk/attachments/",
        jira_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
        jira_project_key="SEC",
        jira_epic_issue_type="Epic",
        jira_child_issue_type="Bug",
        jira_priority_name="Major",
        jira_allowed_host_suffix="atlassian.net",
        jira_origin="https://jira-example.atlassian.net",
        state_table_name="state",
        summary_topic_arn=None,
        max_input_age_hours=36,
        max_input_bytes=20 * 1024 * 1024,
        max_attachment_bytes=10 * 1024 * 1024,
        max_attachments_per_run=20,
        allowed_attachment_types=frozenset({"application/pdf"}),
        require_clean_attachment_tag=True,
        enforce_count_match=True,
        require_same_report_date=True,
        update_existing_titles=True,
        dry_run_default=True,
        activation_approved=True,
    )


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.jira = FakeJira()
        self.state = FakeState()
        self.publisher = FakePublisher()
        self.service = AutomationService(
            config(),
            FakeSource(),
            FakeSecretLoader(),
            self.state,
            self.publisher,
            jira_factory=lambda credentials, project_key: self.jira,
            audit_store=FakeAudit(),
        )

    def test_creates_one_epic_per_repo_and_one_ticket_per_repo_finding(self) -> None:
        result = self.service.run(dry_run=False)
        self.assertEqual("COMPLETE", result["status"])
        self.assertEqual(2, result["epics_created"])
        self.assertEqual(2, result["tickets_created"])
        self.assertEqual(4, len(self.jira.created_fields))
        bug_fields = [
            item for item in self.jira.created_fields if item["issuetype"]["name"] == "Bug"
        ]
        self.assertEqual(2, len(bug_fields))
        self.assertTrue(
            all(field["summary"].startswith("[Critical] example/") for field in bug_fields)
        )
        self.assertTrue(
            all("parent" in self.jira.issues[a["jira_key"]]["fields"] for a in result["actions"])
        )

    def test_second_identical_run_is_skipped(self) -> None:
        self.service.run(dry_run=False)
        result = self.service.run(dry_run=False)
        self.assertEqual("SKIPPED_ALREADY_PROCESSED", result["status"])
        self.assertEqual(4, len(self.jira.created_fields))

    def test_forced_run_reuses_every_issue(self) -> None:
        self.service.run(dry_run=False)
        result = self.service.run(dry_run=False, force=True)
        self.assertEqual(0, result["epics_created"])
        self.assertEqual(2, result["epics_reused"])
        self.assertEqual(0, result["tickets_created"])
        self.assertEqual(2, result["tickets_reused"])
        self.assertEqual(4, len(self.jira.created_fields))

    def test_dry_run_never_creates_or_writes_state(self) -> None:
        result = self.service.run(dry_run=True, force=True)
        self.assertEqual("DRY_RUN", result["status"])
        self.assertEqual(0, len(self.jira.created_fields))
        self.assertEqual({}, self.state.runs)
        self.assertEqual({}, self.state.mappings)
        self.assertEqual(2, result["tickets_created"])

    def test_optional_attachment_is_routed_to_finding_ticket_and_deduplicated(self) -> None:
        self.service.run(dry_run=False)
        request = {
            "s3_key": "snyk/attachments/evidence.pdf",
            "repository": "example/lambda-b",
            "snyk_id": "SNYK-PYTHON-REQUESTS-200",
        }
        result = self.service.run(dry_run=False, attachment_requests=[request])
        self.assertEqual(1, result["attachments_uploaded"])
        attached_issue = next(key for key, values in self.jira.attachments.items() if values)
        self.assertTrue(attached_issue.startswith("SEC-"))
        rerun = self.service.run(dry_run=False, force=True, attachment_requests=[request])
        self.assertEqual(0, rerun["attachments_uploaded"])
        self.assertEqual(1, rerun["attachments_reused"])

    def test_no_attachment_request_performs_no_attachment_calls(self) -> None:
        result = self.service.run(dry_run=False)
        self.assertEqual(0, result["attachments_uploaded"])
        self.assertEqual({}, self.jira.attachments)

    def test_dry_run_attachment_does_not_upload(self) -> None:
        self.service.run(dry_run=False)
        request = {
            "s3_key": "snyk/attachments/evidence.pdf",
            "repository": "example/lambda-b",
            "snyk_id": "SNYK-PYTHON-REQUESTS-200",
        }
        result = self.service.run(dry_run=True, force=True, attachment_requests=[request])
        self.assertEqual(0, result["attachments_uploaded"])
        self.assertEqual({}, self.jira.attachments)
        self.assertTrue(any(item["action"] == "WOULD_UPLOAD" for item in result["actions"]))

    def test_new_child_links_to_migrated_task_campaign(self) -> None:
        campaign_key = "SEC-2"
        self.jira.issues[campaign_key] = {
            "key": campaign_key,
            "fields": {
                "summary": "[Repo Security] Remediate Critical Snyk findings in example/lambda-b",
                "issuetype": "Task",
                "project": {"id": "10001", "key": "SEC"},
                "labels": ["repo-example-lambda-b", "snyk"],
            },
        }
        self.service.policy = Policy(
            adoptions=(
                {"source": "snyk", "repository": "example/lambda-b", "jira_key": campaign_key},
            )
        )
        result = self.service.run(dry_run=False)
        self.assertEqual("COMPLETE", result["status"])
        linked_children = [link for link in self.jira.issue_links if link[0] == campaign_key]
        self.assertEqual(1, len(linked_children))
        created_child = next(
            fields
            for fields in self.jira.created_fields
            if fields["summary"].startswith("[Critical] example/lambda-b")
        )
        self.assertNotIn("parent", created_child)


if __name__ == "__main__":
    unittest.main()
