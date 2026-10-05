from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from test_service import (
    FakeAudit,
    FakeJira,
    FakePublisher,
    FakeSecretLoader,
    FakeSource,
    FakeState,
    config,
)

from adf import plain_text
from identity import Identity
from jira_client import IdentityReviewRequired, JiraClient, JiraCredentials, JiraError
from products import FindingBatch, SnykAdapter
from reports import ReportValidationError, _reader, parse_issue_report
from service import AutomationService, ReviewRequired


class ScopeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.jira, self.state, self.audit = FakeJira(), FakeState(), FakeAudit()
        self.service = AutomationService(
            config(),
            FakeSource(),
            FakeSecretLoader(),
            self.state,
            FakePublisher(),
            jira_factory=lambda *_: self.jira,
            audit_store=self.audit,
        )
        self.identity = Identity(
            "https://jira-example.atlassian.net",
            "10001",
            "snyk",
            "example/service-a",
            "SNYK-DOTNET-PACKAGEA-100",
        )

    def reduce_scope(self):
        risk, details = self.service.source.pair
        lines = details.body.splitlines(keepends=True)
        self.service.source.pair = (
            replace(
                risk,
                body=risk.body.replace(b"Issue,2,", b"Issue,1,"),
                last_modified=datetime(2026, 8, 1, tzinfo=UTC),
            ),
            replace(
                details,
                body=b"".join(lines[:2] + lines[3:]),
                last_modified=datetime(2026, 8, 1, tzinfo=UTC),
            ),
        )

    def metadata(self):
        return self.state.mapping_record(self.identity.fingerprint)["metadata"]

    def verify(self, targets):
        now = datetime.now(UTC)
        value = {
            "schema": 1,
            "source": self.identity.source,
            "repository": self.identity.repository,
            "finding_id": self.identity.finding_id,
            "owner": "approved-owner",
            "approved_by": "security-reviewer",
            "targets": targets,
            "disposition": "resolved",
            "scanned_at": now.isoformat(),
            "deployed_at": (now - timedelta(minutes=10)).isoformat(),
            "artifact_digest": "sha256:" + "a" * 64,
            "scan_url": "https://scanner.example/scan",
            "deployment_url": "https://ci.example/deploy",
        }
        with patch.object(
            self.service.source, "get_json", return_value=(value, {"version_id": "v1"})
        ):
            return self.service.evidence(
                {
                    "repository": self.identity.repository,
                    "finding_id": self.identity.finding_id,
                    "s3_key": "verification/scan.json",
                    "version_id": "v1",
                    "sha256": "a" * 64,
                }
            )

    def test_missing_critical_target_is_retained_and_requires_full_verification(self):
        self.service.run(dry_run=False)
        original = self.metadata()
        self.reduce_scope()
        self.assertEqual("COMPLETE", self.service.run(dry_run=False)["status"])
        current = self.metadata()
        self.assertEqual(original["targets"], current["targets"])
        self.assertEqual(2, len(current["occurrences"]))
        key = self.state.get_mapping("V2", self.identity.fingerprint)
        description = plain_text(self.jira.issues[key]["fields"]["description"])
        self.assertIn("unresolved pending positive evidence", description)
        self.assertIn("tests/App.Tests.csproj", description)
        with self.assertRaisesRegex(ValueError, "exactly all"):
            self.verify(current["targets"][:1])
        self.assertEqual("OPEN", self.metadata()["lifecycle"])
        self.assertEqual(4, len(self.jira.created_fields))
        self.assertEqual("VERIFIED", self.verify(current["targets"])["status"])
        description = plain_text(self.jira.issues[key]["fields"]["description"])
        self.assertNotIn("unresolved pending positive evidence", description)
        self.assertIn("now covered by approved verification", description)

    def test_restore_rejects_audit_scope_inconsistent_with_its_signed_hash(self):
        self.service.run(dry_run=False)
        metadata = self.metadata()
        reference = metadata["audit"]
        self.audit.values[reference["key"]]["metadata"]["targets"] = ["not-the-signed-target"]
        before = copy.deepcopy(self.state.mapping_records)
        with self.assertRaisesRegex(ReviewRequired, "recorded hash"):
            self.service.restore_mapping(
                {
                    "fingerprint": self.identity.fingerprint,
                    "audit": reference,
                    "approved_reason": "Recovery must validate full scope",
                }
            )
        self.assertEqual(before, self.state.mapping_records)

    def test_lost_scope_blocks_refresh_and_reviewed_audit_restore_recovers_it(self):
        self.service.run(dry_run=False)
        original = self.metadata()
        key = self.state.get_mapping("V2", self.identity.fingerprint)
        self.state.mappings.pop(("V2", self.identity.fingerprint))
        self.state.mapping_records.pop(("V2", self.identity.fingerprint))
        self.reduce_scope()
        with self.assertRaisesRegex(ReviewRequired, "Restore audited target scope"):
            self.service.run(dry_run=False)
        restored = self.service.restore_mapping(
            {
                "fingerprint": self.identity.fingerprint,
                "audit": original["audit"],
                "approved_reason": "Reviewed lost state against signed ticket and audit",
            }
        )
        self.assertEqual("MAPPING_RESTORED", restored["status"])
        self.assertEqual(key, restored["jira_key"])
        self.assertEqual(original["targets"], self.metadata()["targets"])
        self.assertEqual("COMPLETE", self.service.run(dry_run=False, force=True)["status"])
        self.assertEqual(original["targets"], self.metadata()["targets"])
        self.assertEqual(4, len(self.jira.created_fields))

    def test_pre_verification_subset_does_not_reopen_or_shrink_verified_scope(self):
        self.service.run(dry_run=False)
        targets = self.metadata()["targets"]
        self.assertEqual("VERIFIED", self.verify(targets)["status"])
        self.reduce_scope()
        self.service.run(dry_run=False)
        metadata = self.metadata()
        self.assertEqual("VERIFIED", metadata["lifecycle"])
        self.assertEqual(targets, metadata["targets"])
        self.assertTrue(
            any("predates verification" in f["observation_note"] for f in metadata["occurrences"])
        )

    def test_transient_identity_search_failure_is_retryable_not_review(self):
        with patch.object(self.jira, "find_identity", side_effect=JiraError("Search unavailable")):
            with self.assertRaises(JiraError):
                self.service.run(dry_run=False)
        jobs = [v for k, v in self.state.records.items() if k.startswith("JOB#")]
        self.assertEqual("FAILED", jobs[0]["status"])
        self.assertEqual("COMPLETE", self.service.run(dry_run=False)["status"])
        self.assertEqual(4, len(self.jira.created_fields))

    def test_parser_policy_is_snapshotted_and_changes_block_resume(self):
        batch = self.service.adapter.load()
        changed = replace(batch, processing_policy={"parser_schema": "future-schema"})
        self.assertNotEqual(batch.fingerprint, changed.fingerprint)
        self.assertEqual(batch.fingerprint, FindingBatch.restore(batch.snapshot()).fingerprint)
        self.service.config = replace(config(), max_groups_per_invocation=1)
        result = self.service.run(dry_run=False)
        self.assertEqual("PENDING", result["status"])
        with patch.object(self.service.adapter, "processing_policy", changed.processing_policy):
            with self.assertRaisesRegex(ReviewRequired, "parser/profile changed"):
                self.service.resume(result["job_id"])
        self.assertEqual([], self.jira.created_fields)

    def test_empty_detail_requires_matching_zero_aggregate_and_never_closes_work(self):
        self.service.run(dry_run=False)
        risk, details = self.service.source.pair
        empty = details.body.splitlines()[0] + b"\n"
        with self.assertRaisesRegex(ReportValidationError, "no data rows"):
            parse_issue_report(empty)
        self.service.source.pair = (
            replace(
                risk,
                body=risk.body.replace(b"Issue,2,", b"Issue,0,").replace(b"Issue,1,", b"Issue,0,"),
            ),
            replace(details, body=empty),
        )
        self.assertEqual([], SnykAdapter(config(), self.service.source).load().findings)
        self.assertEqual("COMPLETE", self.service.run(dry_run=False)["status"])
        self.assertEqual("OPEN", self.metadata()["lifecycle"])
        self.assertEqual(4, len(self.jira.created_fields))

    def test_csv_row_limit_is_enforced(self):
        reader = _reader(b"header\nvalue\n")
        reader.total_rows = 50000
        with self.assertRaisesRegex(ReportValidationError, "50,000-row"):
            next(reader)

    def test_shared_finding_id_in_another_signed_repo_does_not_block_new_work(self):
        signing = FakeSecretLoader().load_json("")["identity_key"]
        client = JiraClient(
            JiraCredentials(
                "https://jira-example.atlassian.net", "test@example.com", "test", signing
            ),
            "SEC",
        )
        other = Identity(
            "https://jira-example.atlassian.net", "10001", "snyk", "other/repo", "SNYK-ID"
        )
        candidate = {
            "key": "SEC-1",
            "fields": {
                "project": {"id": "10001"},
                "summary": "other/repo SNYK-ID; notes mention wanted/repo",
            },
        }
        prop = other.signed(signing, {"jira_key": "SEC-1"})
        with (
            patch.object(client, "search", side_effect=[[], [candidate]]),
            patch.object(client, "get_property", return_value=prop),
        ):
            self.assertIsNone(client.find_child("wanted/repo", "SNYK-ID", "snyk-auto-test"))
        with (
            patch.object(client, "search", side_effect=[[], [copy.deepcopy(candidate)]]),
            patch.object(client, "get_property", return_value=None),
        ):
            with self.assertRaises(IdentityReviewRequired):
                client.find_child("wanted/repo", "SNYK-ID", "snyk-auto-test")
