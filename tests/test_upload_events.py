from __future__ import annotations

import dataclasses
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from test_products import product_config  # noqa: E402
from test_service import (  # noqa: E402
    FakeAudit,
    FakeJira,
    FakePublisher,
    FakeSecretLoader,
    FakeSource,
    FakeState,
)

import handler  # noqa: E402
from aws_adapters import ReportsNotReady  # noqa: E402
from handler import IngestionRuntime  # noqa: E402
from upload_events import Upload, parse_uploads  # noqa: E402


def object_event(key="snyk/issues-detail/snyk_issues_detail_07_31_2026_b.csv"):
    return {
        "source": "aws.s3",
        "detail-type": "Object Created",
        "detail": {
            "bucket": {"name": "bucket"},
            "object": {"key": key, "version-id": "v1", "size": 100},
        },
    }


class UploadSource(FakeSource):
    def __init__(self):
        super().__init__()
        self.ready = True
        self.uploaded_key = None

    def pair_for_upload(self, key, **kwargs):
        self.uploaded_key = key
        if not self.ready:
            raise ReportsNotReady("Waiting for companion report")
        return self.pair

    def get_report(self, key, **kwargs):
        return dataclasses.replace(
            self.pair[1],
            key=key,
            body=(ROOT / "tests/fixtures/alertlogic-normalized-example.csv").read_bytes(),
        )


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.source = UploadSource()
        self.jira, self.state = FakeJira(), FakeState()
        self.runtime = IngestionRuntime(
            dataclasses.replace(product_config(), dry_run_default=False),
            self.source,
            FakeSecretLoader(),
            self.state,
            FakePublisher(),
            jira_factory=lambda *_: self.jira,
            audit_store=FakeAudit(),
        )

    def test_native_s3_keys_are_decoded_but_eventbridge_keys_are_preserved(self):
        event = {
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventName": "ObjectCreated:Put",
                    "s3": {"bucket": {"name": "bucket"}, "object": {"key": "folder%2Fa+b%2Bc.csv"}},
                }
            ]
        }
        self.assertEqual("folder/a b+c.csv", parse_uploads(event)[0].key)
        self.assertEqual(
            "folder/a+b%2Bc.csv", parse_uploads(object_event("folder/a+b%2Bc.csv"))[0].key
        )
        self.assertEqual([], parse_uploads({"Event": "s3:TestEvent"}))

    def test_first_upload_waits_and_second_upload_creates_once(self):
        self.source.ready = False
        upload = parse_uploads(object_event())[0]
        first = self.runtime.process_upload(upload)
        self.assertEqual("WAITING_FOR_REPORT_PAIR", first["status"])
        self.assertEqual([], self.jira.created_fields)
        self.assertEqual({}, self.state.runs)
        self.source.ready = True
        self.assertEqual("COMPLETE", self.runtime.process_upload(upload)["status"])
        self.assertEqual("SKIPPED_ALREADY_PROCESSED", self.runtime.process_upload(upload)["status"])
        self.assertEqual(4, len(self.jira.created_fields))

    def test_alertlogic_mapping_creates_its_own_group_and_remediation_ticket(self):
        # Test certification only; the shipped example remains unverified.
        service = self.runtime.services["alertlogic"]
        service.adapter.profile = dataclasses.replace(
            service.adapter.profile,
            schema_version="test-normalized-v1",
            certification={"approved_by": "test reviewer", "sample_sha256": "a" * 64},
        )
        self.runtime.process_upload(parse_uploads(object_event())[0])
        result = self.runtime.process_upload(Upload("bucket", "products/alertlogic/export.csv"))
        self.assertEqual("alertlogic", result["source"])
        self.assertEqual(1, result["tickets_created"])
        bugs = [item for item in self.jira.created_fields if item["issuetype"]["name"] == "Bug"]
        other = next(item for item in bugs if "alertlogic" in item["labels"])
        self.assertNotIn("snyk", other["labels"])
        self.assertEqual(
            "SKIPPED_ALREADY_PROCESSED",
            self.runtime.process_upload(Upload("bucket", "products/alertlogic/export.csv"))[
                "status"
            ],
        )

    def test_other_buckets_and_attachment_uploads_do_not_create_tickets(self):
        self.assertEqual(
            "IGNORED_BUCKET",
            self.runtime.process_upload(Upload("other", "products/alertlogic/x.csv"))["status"],
        )
        self.assertEqual(
            "IGNORED_PREFIX",
            self.runtime.process_upload(Upload("bucket", "snyk/attachments/evidence.csv"))[
                "status"
            ],
        )
        self.assertEqual(
            "IGNORED_NON_CSV",
            self.runtime.process_upload(Upload("bucket", "products/alertlogic/x.png"))["status"],
        )
        self.assertEqual([], self.jira.created_fields)

    def test_oversized_upload_and_unconfigured_product_are_rejected(self):
        with self.assertRaisesRegex(Exception, "size"):
            self.runtime.process_upload(
                Upload("bucket", "products/alertlogic/x.csv", size=99_000_000)
            )
        with self.assertRaisesRegex(Exception, "mapping"):
            self.runtime.process_upload(Upload("bucket", "products/unknown/x.csv"))
        self.assertEqual([], self.jira.created_fields)

    def test_sqs_returns_partial_failures_and_does_not_accept_manual_jira_instructions(self):
        event = {
            "Records": [
                {
                    "eventSource": "aws:sqs",
                    "messageId": "bad",
                    "body": json.dumps({"dryRun": False}),
                },
                {"eventSource": "aws:sqs", "messageId": "next", "body": json.dumps(object_event())},
            ]
        }
        with patch.object(handler, "_RUNTIME", self.runtime), self.assertLogs(level="ERROR"):
            result = handler.lambda_handler(event, None)
        self.assertEqual(
            [{"itemIdentifier": "bad"}, {"itemIdentifier": "next"}], result["batchItemFailures"]
        )
        self.assertEqual([], self.jira.created_fields)

    def test_sqs_acknowledges_success_and_waiting_events(self):
        event = {
            "Records": [
                {"eventSource": "aws:sqs", "messageId": "ok", "body": json.dumps(object_event())}
            ]
        }
        self.source.ready = False
        with patch.object(handler, "_RUNTIME", self.runtime):
            self.assertEqual({"batchItemFailures": []}, handler.lambda_handler(event, None))
            self.source.ready = True
            self.assertEqual({"batchItemFailures": []}, handler.lambda_handler(event, None))
        self.assertEqual(4, len(self.jira.created_fields))

    def test_upload_cannot_override_dry_run_or_request_attachments(self):
        self.runtime.config = dataclasses.replace(self.runtime.config, dry_run_default=True)
        event = {
            **object_event(),
            "dryRun": False,
            "force": True,
            "attachments": [{"s3_key": "snyk/attachments/secret.pdf"}],
        }
        with patch.object(handler, "_RUNTIME", self.runtime):
            result = handler.lambda_handler(event, None)
        self.assertEqual("DRY_RUN", result["results"][0]["status"])
        self.assertEqual([], self.jira.created_fields)
        self.assertEqual({}, self.jira.attachments)

    def test_manual_daily_invocation_remains_compatible(self):
        with patch.object(handler, "_RUNTIME", self.runtime):
            result = handler.lambda_handler({"dryRun": True, "force": True}, None)
        self.assertEqual("DRY_RUN", result["status"])
        self.assertEqual(2, result["tickets_created"])

    def test_manual_product_key_must_match_product_folder(self):
        with self.assertRaisesRegex(ValueError, "folder"):
            self.runtime.process_manual(
                {"product": "alertlogic", "s3Key": "snyk/issues-detail/x.csv"}
            )
