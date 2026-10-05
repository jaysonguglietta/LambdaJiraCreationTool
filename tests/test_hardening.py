from __future__ import annotations

import copy
import io
import json
import unittest
import urllib.error
import urllib.request
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from test_aws_adapters import FakeS3
from test_jira_client import FakeResponse
from test_service import (
    FakeAudit,
    FakeJira,
    FakePublisher,
    FakeSecretLoader,
    FakeSource,
    FakeState,
    config,
)

from adf import paragraph, plain_text
from audit import AuditStore
from aws_adapters import InputError, S3ReportSource, SummaryPublisher, SupersededUpload
from budget import Budget
from bundles import propose_bundles
from config import ConfigurationError
from identity import Identity
from jira_client import JiraClient, JiraCredentials, JiraError, RejectRedirects
from lifecycle import validate_evidence
from models import AttachmentFile
from policy import Policy
from products import SnykAdapter
from reports import ReportValidationError, group_findings, parse_issue_report, parse_risk_report
from service import AutomationService, ReviewRequired
from state_store import StateStore
from ticketing import child_description, managed_hash, refresh_description


class HardeningTests(unittest.TestCase):
    def approval_for(self, service):
        result = service.run(dry_run=False)
        action = result["actions"][0]
        identity = service.identity(action["repository"], action["finding_id"])
        metadata = self.state.mapping_record(identity.fingerprint)["metadata"]
        now = datetime.now(UTC)
        return (
            identity,
            action,
            {
                "schema": 1,
                "source": identity.source,
                "repository": identity.repository,
                "finding_id": identity.finding_id,
                "owner": "approved-owner",
                "approved_by": "security-reviewer",
                "targets": metadata["targets"],
                "disposition": "resolved",
                "scanned_at": now.isoformat(),
                "deployed_at": (now - timedelta(minutes=10)).isoformat(),
                "artifact_digest": "sha256:" + "a" * 64,
                "scan_url": "https://scanner.example/scan",
                "deployment_url": "https://ci.example/deploy",
            },
        )

    def test_known_create_key_survives_audit_failure_and_retries_without_duplicate(self):
        service = self.service()
        real_put = self.audit.put

        def fail_mapping(category, identifier, value):
            if category == "mappings":
                raise RuntimeError("Audit temporarily unavailable")
            return real_put(category, identifier, value)

        with patch.object(self.audit, "put", side_effect=fail_mapping):
            with self.assertRaisesRegex(RuntimeError, "Audit"):
                service.run(dry_run=False)
        self.assertEqual(1, len(self.jira.created_fields))
        self.assertTrue(any(v.get("jira_key") for v in self.state.mapping_records.values()))
        service.budget = Budget(240)
        result = service.run(dry_run=False)
        self.assertEqual("COMPLETE", result["status"])
        self.assertEqual(4, len(self.jira.created_fields))

    def test_signed_recovery_from_older_snapshot_restores_mapping_without_new_ticket(self):
        service = self.service()
        service.run(dry_run=False)
        newer = datetime(2026, 8, 1, tzinfo=UTC)
        original = service.source.pair
        service.source.pair = tuple(replace(r, last_modified=newer) for r in original)
        service.run(dry_run=False)
        self.state.mappings.clear()
        self.state.mapping_records.clear()
        service.source.pair = original
        result = service.run(dry_run=False, force=True)
        self.assertEqual("COMPLETE", result["status"])
        self.assertEqual(4, len(self.jira.created_fields))
        self.assertTrue(all("campaign_audit" in a for a in result["actions"]))
        for mapping in self.state.mapping_records.values():
            self.assertEqual(newer.isoformat(), mapping["metadata"]["last_seen"])
            self.assertNotIn("targets", mapping["metadata"])

    def test_live_reconciliation_cannot_be_disabled(self):
        service = self.service(config=replace(config(), enforce_count_match=False))
        with self.assertRaisesRegex(ReviewRequired, "reconciliation"):
            service.run(dry_run=False)
        self.assertEqual([], self.jira.created_fields)

    def test_repeated_report_listing_token_is_bounded(self):
        source = S3ReportSource(
            FakeS3({}),
            "bucket",
            "risk/",
            "issues/",
            max_age_hours=36,
            max_bytes=1024,
            require_same_report_date=True,
        )
        with patch.object(
            source.s3,
            "list_objects_v2",
            return_value={"IsTruncated": True, "NextContinuationToken": "repeated", "Contents": []},
        ) as listing:
            with self.assertRaisesRegex(InputError, "bounded"):
                source._list("risk/")
        self.assertEqual(2, listing.call_count)

    def test_attachments_respect_destination_lock(self):
        service = self.service()
        result = service.run(dry_run=False)
        from identity import digest

        self.state.locks.add(digest((service.credentials.base_url, service.project_id)))
        from service import IdempotencyConflict

        with self.assertRaises(IdempotencyConflict):
            service.attachments(
                [
                    {
                        "jira_issue_key": result["actions"][0]["jira_key"],
                        "s3_key": "snyk/attachments/evidence.pdf",
                    }
                ],
                dry_run=False,
            )
        self.assertEqual({}, self.jira.attachments)

    def test_positive_evidence_is_visible_in_jira_and_preserves_notes(self):
        service = self.service()
        identity, action, value = self.approval_for(service)
        key = action["jira_key"]
        self.jira.issues[key]["fields"]["description"]["content"].append(
            paragraph("Keep developer PR")
        )
        with patch.object(service.source, "get_json", return_value=(value, {"version_id": "v1"})):
            result = service.evidence(
                {
                    "repository": identity.repository,
                    "finding_id": identity.finding_id,
                    "s3_key": "verification/scan.json",
                    "version_id": "v1",
                    "sha256": "a" * 64,
                }
            )
        self.assertEqual("VERIFIED", result["status"])
        description = plain_text(self.jira.issues[key]["fields"]["description"])
        self.assertIn("security-reviewer", description)
        self.assertIn("VERIFIED", description)
        self.assertIn("Keep developer PR", description)
        self.assertIn("security-verified", self.jira.issues[key]["fields"]["labels"])
        self.assertEqual(
            "VERIFIED", self.state.mapping_record(identity.fingerprint)["metadata"]["lifecycle"]
        )

    def test_expired_exception_is_flagged_in_jira_without_deleting_notes(self):
        service = self.service()
        identity, action, value = self.approval_for(service)
        value.update(
            expires_at=(datetime.now(UTC) + timedelta(days=1)).isoformat(),
            compensating_controls="Restricted egress",
            migration_plan="Replace runtime",
            reason="No supported fix",
            approval_url="https://review.example/approval",
        )
        for name in (
            "disposition",
            "scanned_at",
            "deployed_at",
            "artifact_digest",
            "scan_url",
            "deployment_url",
        ):
            value.pop(name)
        with patch.object(service.source, "get_json", return_value=(value, {"version_id": "v1"})):
            service.evidence(
                {
                    "repository": identity.repository,
                    "finding_id": identity.finding_id,
                    "s3_key": "verification/exception.json",
                    "version_id": "v1",
                    "sha256": "a" * 64,
                },
                exception=True,
            )
        metadata = self.state.mapping_record(identity.fingerprint)["metadata"]
        metadata["deadline"] = 1
        self.state.put_mapping("V2", identity.fingerprint, action["jira_key"], metadata)
        result = service.expire_exception({"identity": asdict(identity)})
        self.assertEqual("EXCEPTION_EXPIRED", result["status"])
        labels = self.jira.issues[action["jira_key"]]["fields"]["labels"]
        self.assertIn("exception-needs-review", labels)
        self.assertNotIn("security-exception-approved", labels)
        self.assertIn(
            "exception expired",
            plain_text(self.jira.issues[action["jira_key"]]["fields"]["description"]),
        )

    def test_every_occurrence_source_url_is_rendered(self):
        first = parse_issue_report(FakeSource().pair[1].body)[0]
        second = replace(first, target="another-target", issue_url="https://app.snyk.io/second")
        group = group_findings([first, second])[0]
        rendered = json.dumps(child_description(group, "SEC-1", "2026-07-31"))
        self.assertIn(first.issue_url, rendered)
        self.assertIn(second.issue_url, rendered)

    def test_verification_rejects_unbounded_or_unknown_evidence_before_writes(self):
        service = self.service()
        identity, action, value = self.approval_for(service)
        event = {
            "repository": identity.repository,
            "finding_id": identity.finding_id,
            "s3_key": "verification/scan.json",
            "version_id": "v1",
            "sha256": "a" * 64,
        }
        original = copy.deepcopy(self.jira.issues[action["jira_key"]])
        for invalid in (
            {**value, "unexpected": "data"},
            {**value, "owner": "a" * 5001},
            {**value, "targets": value["targets"] * 2},
        ):
            with patch.object(
                service.source, "get_json", return_value=(invalid, {"version_id": "v1"})
            ):
                with self.assertRaises(ValueError):
                    service.evidence(event)
            self.assertEqual(original, self.jira.issues[action["jira_key"]])

    def test_evidence_transition_failure_can_be_retried_without_managed_section_conflict(self):
        service = self.service(policy=Policy(transitions={"verified": "31"}))
        identity, action, value = self.approval_for(service)
        event = {
            "repository": identity.repository,
            "finding_id": identity.finding_id,
            "s3_key": "verification/scan.json",
            "version_id": "v1",
            "sha256": "a" * 64,
        }
        with patch.object(service.source, "get_json", return_value=(value, {"version_id": "v1"})):
            with patch.object(
                self.jira,
                "transition",
                create=True,
                side_effect=RuntimeError("workflow unavailable"),
            ):
                with self.assertRaisesRegex(RuntimeError, "workflow"):
                    service.evidence(event)
            metadata = self.state.mapping_record(identity.fingerprint)["metadata"]
            self.assertEqual("VERIFIED", metadata["lifecycle"])
            self.assertEqual(
                metadata["managed_hash"],
                managed_hash(self.jira.issues[action["jira_key"]]["fields"]["description"]),
            )
            with patch.object(self.jira, "transition", create=True):
                self.assertEqual("VERIFIED", service.evidence(event)["status"])
        self.assertEqual(4, len(self.jira.created_fields))

    def service(self, **options):
        self.jira, self.state, self.audit = FakeJira(), FakeState(), FakeAudit()
        return AutomationService(
            options.pop("config", config()),
            FakeSource(),
            FakeSecretLoader(),
            self.state,
            options.pop("publisher", FakePublisher()),
            jira_factory=lambda *_: self.jira,
            audit_store=self.audit,
            **options,
        )

    def test_activation_gate_prevents_all_jira_mutations(self):
        service = self.service(config=replace(config(), activation_approved=False))
        with self.assertRaisesRegex(ReviewRequired, "Activation"):
            service.run(dry_run=False)
        self.assertEqual([], self.jira.created_fields)

    def test_exact_origin_rejects_another_allowlisted_tenant(self):
        with self.assertRaisesRegex(JiraError, "exact"):
            JiraCredentials.from_secret(
                FakeSecretLoader().load_json(""), "atlassian.net", "https://other.atlassian.net"
            )

    def test_redirects_never_forward_auth(self):
        req = urllib.request.Request("https://jira-example.atlassian.net/rest/api/3/myself")
        req.add_unredirected_header("Authorization", "test-only")
        with self.assertRaisesRegex(JiraError, "redirects"):
            RejectRedirects().redirect_request(
                req, None, 302, "Found", {}, "https://attacker.example"
            )
        self.assertNotIn("Authorization", req.headers)

    def test_identity_scopes_destination_and_signs_details(self):
        identity = Identity("https://jira-example.atlassian.net", "10001", "snyk", "repo", "id")
        key = "test-only-signing-material" * 2
        signed = identity.signed(key, {"jira_key": "SEC-1"})
        self.assertTrue(identity.matches(signed, key))
        for changed in (
            replace(identity, project_id="10002"),
            replace(identity, source="other"),
            replace(identity, origin="https://other.atlassian.net"),
        ):
            self.assertNotEqual(identity.fingerprint, changed.fingerprint)
            self.assertFalse(changed.matches(signed, key))
        signed["jira_key"] = "SEC-2"
        self.assertFalse(identity.matches(signed, key))

    def test_copied_ticket_identity_is_rejected(self):
        service = self.service()
        service.run(dry_run=False)
        key = next(k for k, i in self.jira.issues.items() if i["fields"]["issuetype"] == "Bug")
        duplicated = copy.deepcopy(self.jira.issues[key])
        duplicated["key"] = "SEC-999"
        self.jira.issues["SEC-999"] = duplicated
        self.jira.properties["SEC-999"] = copy.deepcopy(self.jira.properties[key])
        self.state.mappings.clear()
        self.state.mapping_records.clear()
        with self.assertRaises(ReviewRequired):
            service.run(dry_run=False, force=True)
        self.assertEqual(4, len(self.jira.created_fields))

    def test_deleted_mapping_does_not_recreate(self):
        service = self.service()
        service.run(dry_run=False)
        child = next(k for k, i in self.jira.issues.items() if i["fields"]["issuetype"] == "Bug")
        del self.jira.issues[child]
        with self.assertRaisesRegex(ReviewRequired, "missing"):
            service.run(dry_run=False, force=True)
        self.assertEqual(4, len(self.jira.created_fields))

    def test_uncertain_create_requires_review_not_retry(self):
        service = self.service()
        with patch.object(self.jira, "create_issue", side_effect=JiraError("uncertain")):
            with self.assertRaises(JiraError):
                service.run(dry_run=False)
        # The prior job FAILED; it resumes but the PENDING create claim is not reused.
        with self.assertRaisesRegex(ReviewRequired, "uncertain"):
            service.run(dry_run=False)
        self.assertEqual([], self.jira.created_fields)

    def test_chunk_resume_uses_snapshot_without_duplicates(self):
        scheduled = []
        service = self.service(
            config=replace(config(), max_groups_per_invocation=1),
            continuation=lambda job, source: scheduled.append((job, source)),
        )
        first = service.run(dry_run=False)
        self.assertEqual("PENDING", first["status"])
        self.assertEqual(0, first["cursor"])
        self.assertEqual(1, first["validation_cursor"])
        service.budget = Budget(240)
        with patch.object(
            service.adapter, "load", side_effect=AssertionError("Do not reread input")
        ):
            second = service.resume(first["job_id"])
            self.assertEqual("PENDING", second["status"])
            service.budget = Budget(240)
            second = service.resume(first["job_id"])
        self.assertEqual("COMPLETE", second["status"])
        self.assertEqual(4, len(self.jira.created_fields))
        self.assertEqual(2, len(service.inspect(first["job_id"])["actions"]))
        self.assertEqual(2, len(scheduled))

    def test_managed_refresh_preserves_notes_and_refuses_source_edits(self):
        group = group_findings(parse_issue_report(FakeSource().pair[1].body))[0]
        original = child_description(group, "SEC-1", "2026-07-31")
        expected_hash = managed_hash(original)
        original["content"].append(paragraph("Developer PR-123"))
        fresh = child_description(group, "SEC-1", "2026-08-01")
        merged = refresh_description(original, fresh, expected_hash)
        self.assertIn("Developer PR-123", plain_text(merged))
        self.assertIn("2026-08-01", plain_text(merged))
        original["content"][1] = paragraph("Developer modified source facts")
        with self.assertRaisesRegex(ValueError, "developer edited"):
            refresh_description(original, fresh, expected_hash)

    def test_manual_assignment_notes_and_labels_survive_refresh(self):
        service = self.service()
        first = service.run(dry_run=False)
        key = first["actions"][0]["jira_key"]
        fields = self.jira.issues[key]["fields"]
        fields["description"]["content"].append(paragraph("Keep PR note"))
        fields["assignee"] = {"accountId": "human-override"}
        fields["labels"].append("human-label")
        service.run(dry_run=False, force=True)
        current = self.jira.issues[key]["fields"]
        self.assertIn("Keep PR note", plain_text(current["description"]))
        self.assertEqual("human-override", current["assignee"]["accountId"])
        self.assertIn("human-label", current["labels"])

    def test_volume_guard_requires_explicit_approval(self):
        service = self.service(config=replace(config(), max_new_tickets=1))
        first = service.run(dry_run=False)
        self.assertEqual("REVIEW_REQUIRED", first["status"])
        self.assertEqual([], self.jira.created_fields)
        self.assertEqual("COMPLETE", service.resume(first["job_id"], 4)["status"])

    def test_notification_failure_does_not_fail_completed_work(self):
        publisher = FakePublisher()
        with patch.object(publisher, "publish", side_effect=RuntimeError("SNS unavailable")):
            service = self.service(publisher=publisher)
            result = service.run(dry_run=False)
        self.assertEqual("COMPLETE", result["status"])
        self.assertEqual("COMPLETE", self.state.get_record("JOB#" + result["job_id"])["status"])
        self.assertEqual(1, len(self.state.list_status("NOTIFICATION_FAILED")))

    def test_attachment_only_operation_validates_all_before_upload(self):
        service = self.service()
        result = service.run(dry_run=False)
        request = {
            "jira_issue_key": result["actions"][0]["jira_key"],
            "s3_key": "snyk/attachments/evidence.pdf",
        }
        with patch.object(service.adapter, "load", side_effect=AssertionError("No CSV needed")):
            self.assertEqual(
                1, service.attachments([request], dry_run=False)["attachments_uploaded"]
            )
        self.jira.attachments.clear()
        with self.assertRaises(ValueError):
            service.attachments([request, {**request, "jira_issue_key": "OTHER-1"}], dry_run=False)
        self.assertEqual({}, self.jira.attachments)

    def test_attachment_scan_and_download_use_same_version(self):
        class RacingS3(FakeS3):
            def get_object_tagging(self, **kwargs):
                self.tag_version = kwargs["VersionId"]
                return super().get_object_tagging(**kwargs)

            def get_object(self, **kwargs):
                self.download_version = kwargs["VersionId"]
                return super().get_object(**kwargs)

        s3 = RacingS3({"attachments/file.pdf": (b"safe", datetime.now(UTC))})
        source = S3ReportSource(
            s3,
            "bucket",
            "risk/",
            "issues/",
            "attachments/",
            max_age_hours=36,
            max_bytes=1000,
            require_same_report_date=True,
        )
        result = source.get_attachment("attachments/file.pdf")
        self.assertEqual(s3.tag_version, s3.download_version)
        self.assertEqual(result.version_id, s3.download_version)
        self.assertTrue(
            AttachmentFile("file", "résumé.png", "image/png", b"safe").jira_filename.isascii()
        )

    def test_csv_blank_status_fractional_counts_and_malformed_rows_fail(self):
        body = FakeSource().pair[1].body
        with self.assertRaises(ReportValidationError):
            parse_issue_report(body.replace(b",Open,", b",,", 1))
        with self.assertRaises(ReportValidationError):
            parse_risk_report(FakeSource().pair[0].body.replace(b",2,", b",2.8,", 1))
        with self.assertRaises(ReportValidationError):
            parse_issue_report(body.splitlines()[0] + b'\n"unterminated')

    def test_jira_response_size_and_retry_after_are_bounded(self):
        creds = JiraCredentials("https://jira-example.atlassian.net", "test@example.com", "test")
        client = JiraClient(
            creds,
            "SEC",
            opener=lambda *_args, **_kwargs: FakeResponse(b"x" * 100),
            max_response_bytes=32,
        )
        with self.assertRaisesRegex(JiraError, "byte limit"):
            client.preflight()
        attempts, sleeps = [], []

        def rate_limited(request, timeout):
            attempts.append(request)
            if len(attempts) == 1:
                raise urllib.error.HTTPError(
                    request.full_url, 429, "slow", {"Retry-After": "999999999"}, io.BytesIO()
                )
            return FakeResponse(b"{}")

        JiraClient(creds, "SEC", opener=rate_limited, sleep=sleeps.append).preflight()
        self.assertEqual([15], sleeps)

    def test_state_and_notifications_never_truncate_json(self):
        with self.assertRaises(ValueError):
            StateStore._json({"value": "x" * 250000})

        class Sns:
            def publish(self, **kwargs):
                self.payload = json.loads(kwargs["Message"])

        sns = Sns()
        SummaryPublisher(sns, "topic").publish(
            "summary", {"status": "COMPLETE", "large": "x" * 300000}
        )
        self.assertEqual("COMPLETE", sns.payload["status"])

    def test_verification_requires_all_targets_and_post_deployment_scan(self):
        now = datetime.now(UTC)
        metadata = {
            "identity": asdict(
                Identity("https://jira-example.atlassian.net", "10001", "snyk", "repo", "id")
            ),
            "last_seen": (now - timedelta(hours=1)).isoformat(),
            "targets": ["a", "b"],
        }
        evidence = {
            "schema": 1,
            "source": "snyk",
            "repository": "repo",
            "finding_id": "id",
            "owner": "owner",
            "approved_by": "security",
            "targets": ["a", "b"],
            "disposition": "resolved",
            "scanned_at": now.isoformat(),
            "deployed_at": (now - timedelta(minutes=30)).isoformat(),
            "artifact_digest": "sha256:" + "a" * 64,
            "scan_url": "https://scanner.example/scan",
            "deployment_url": "https://ci.example/deploy",
        }
        self.assertEqual("VERIFIED", validate_evidence(evidence, metadata, now=now)["lifecycle"])
        with self.assertRaisesRegex(ValueError, "exactly all"):
            validate_evidence({**evidence, "targets": ["a"]}, metadata, now=now)

    def test_owner_matching_is_exact_and_fallback_is_triage(self):
        policy = Policy.parse(
            {
                "schema": 1,
                "owners": [
                    {
                        "source": "snyk",
                        "repository": "repo",
                        "account_id": "approved",
                        "sla_hours": 24,
                    }
                ],
            }
        )
        first = datetime.now(UTC).isoformat()
        self.assertEqual("approved", policy.route("snyk", "repo", first, "Major")["owner"])
        self.assertTrue(policy.route("snyk", "repo-extra", first, "Major")["needs_owner"])

    def test_audit_refuses_unversioned_writes(self):
        class S3:
            def put_object(self, **_kwargs):
                return {}

        with self.assertRaisesRegex(ValueError, "versioning"):
            AuditStore(S3(), "audit").put("actions", "id", {"valid": True})

    def test_hash_bound_count_approval_does_not_apply_to_another_pair(self):
        source = FakeSource()
        source.pair = (
            replace(source.pair[0], body=source.pair[0].body.replace(b",2,", b",1,", 1)),
            source.pair[1],
        )
        adapter = SnykAdapter(config(), source)
        with self.assertRaisesRegex(ReportValidationError, "count mismatch"):
            adapter.load()
        approval = {
            "risk_sha256": source.pair[0].sha256,
            "issues_sha256": source.pair[1].sha256,
            "risk_count": 2,
            "detail_count": 3,
            "approved_by": "test reviewer",
            "reason": "Verified export scope difference",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        }
        adapter.approval_policy = Policy.parse({"schema": 1, "reconciliations": [approval]})
        batch = adapter.load()
        self.assertEqual(3, len(batch.findings))
        self.assertIn("explicitly approved", batch.warnings[1])
        adapter.approval_policy = Policy.parse(
            {"schema": 1, "reconciliations": [{**approval, "issues_sha256": "a" * 64}]}
        )
        with self.assertRaises(ReportValidationError):
            adapter.load()

    def test_same_day_overwrites_and_old_version_events_are_not_paired(self):
        now = datetime(2026, 7, 31, 12, tzinfo=UTC)
        key = "risk/export_07_31_2026_a.csv"
        s3 = FakeS3({key: (b"content", now)})
        source = S3ReportSource(
            s3,
            "bucket",
            "risk/",
            "issues/",
            max_age_hours=36,
            max_bytes=1000,
            require_same_report_date=True,
            now=lambda: now,
        )
        with self.assertRaises(SupersededUpload):
            source.get_report(key, allowed_prefix="risk/", version_id="older-version")
        with patch.object(
            s3,
            "list_object_versions",
            return_value={
                "Versions": [{"Key": key, "VersionId": "a"}, {"Key": key, "VersionId": "b"}]
            },
        ):
            with self.assertRaisesRegex(InputError, "write-once"):
                source.get_report(key, allowed_prefix="risk/")

    def test_bundle_proposals_are_review_only_and_require_shared_fix_evidence(self):
        original = parse_issue_report(FakeSource().pair[1].body)[0]
        fixed = replace(
            original,
            fix_state="reported_fix",
            package_name="example-package",
            fixed_version="2.0",
            dependency_path="app > example-package",
            evidence_url="https://scanner.example/advisory",
        )
        other = replace(fixed, snyk_id="SNYK-TEST-OTHER-123", target="other-target")
        result = propose_bundles([fixed, other])
        self.assertEqual("REVIEW_ONLY", result["status"])
        self.assertEqual(1, len(result["candidates"]))
        self.assertEqual(
            [], propose_bundles([fixed, replace(other, evidence_url="")])["candidates"]
        )

    def test_duplicate_adoption_destinations_are_rejected_before_any_mutation(self):
        entries = [
            {"source": "snyk", "repository": repo, "jira_key": "SEC-1"} for repo in ("one", "two")
        ]
        with self.assertRaises(ConfigurationError):
            Policy.parse({"adoptions": entries})

    def test_old_observation_does_not_reopen_verified_remediation(self):
        service = self.service()
        result = service.run(dry_run=False)
        key = result["actions"][0]["jira_key"]
        record_key = next(
            k for k, v in self.state.mapping_records.items() if v.get("jira_key") == key
        )
        metadata = self.state.mapping_records[record_key]["metadata"]
        metadata.update(lifecycle="VERIFIED", verified_at=datetime.now(UTC).isoformat())
        service.run(dry_run=False, force=True)
        current = self.state.mapping_records[record_key]["metadata"]
        self.assertEqual("VERIFIED", current["lifecycle"])
        self.assertNotIn("source-still-open", self.jira.issues[key]["fields"]["labels"])

    def test_partial_link_failure_reuses_child_and_repairs_relationship(self):
        service = self.service(
            policy=Policy(
                adoptions=(
                    {"source": "snyk", "repository": "example/lambda-b", "jira_key": "SEC-1"},
                )
            )
        )
        self.jira.issues["SEC-1"] = {
            "key": "SEC-1",
            "fields": {
                "project": {"id": "10001", "key": "SEC"},
                "issuetype": "Task",
                "summary": "Existing campaign",
            },
        }
        with patch.object(self.jira, "create_issue_link", side_effect=RuntimeError("transient")):
            with self.assertRaises(RuntimeError):
                service.run(dry_run=False)
        count = len([f for f in self.jira.created_fields if f["issuetype"]["name"] == "Bug"])
        self.assertEqual(1, count)
        final = service.run(dry_run=False)
        self.assertEqual("COMPLETE", final["status"])
        self.assertEqual(
            2, len([f for f in self.jira.created_fields if f["issuetype"]["name"] == "Bug"])
        )
        self.assertEqual(1, len(self.jira.issue_links))
