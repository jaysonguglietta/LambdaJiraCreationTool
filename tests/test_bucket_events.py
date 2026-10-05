import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from configure_bucket_events import enable_eventbridge


class FakeBucketClient:
    def __init__(self):
        self.current = {
            "LambdaFunctionConfigurations": [{"Id": "existing", "Events": ["s3:ObjectCreated:*"]}],
            "QueueConfigurations": [{"Id": "existing-queue"}],
            "ResponseMetadata": {"RequestId": "metadata"},
        }
        self.written = None

    def get_bucket_location(self, **kwargs):
        return {"LocationConstraint": None}

    def get_bucket_notification_configuration(self, **kwargs):
        return self.current

    def put_bucket_notification_configuration(self, **kwargs):
        self.written = kwargs["NotificationConfiguration"]
        self.current = dict(self.written)


class BucketEventsTests(unittest.TestCase):
    def test_default_does_not_mutate_notifications(self):
        client = FakeBucketClient()
        self.assertEqual(
            "WOULD_ENABLE", enable_eventbridge(client, "bucket", "us-east-1")["status"]
        )
        self.assertIsNone(client.written)

    def test_apply_preserves_existing_notifications_and_removes_response_metadata(self):
        client = FakeBucketClient()
        enable_eventbridge(
            client, "bucket", "us-east-1", apply=True, backup=lambda _: "memory-backup"
        )
        self.assertEqual(
            client.current["LambdaFunctionConfigurations"],
            client.written["LambdaFunctionConfigurations"],
        )
        self.assertEqual(
            client.current["QueueConfigurations"], client.written["QueueConfigurations"]
        )
        self.assertEqual({}, client.written["EventBridgeConfiguration"])
        self.assertNotIn("ResponseMetadata", client.written)

    def test_region_mismatch_is_rejected_before_mutation(self):
        client = FakeBucketClient()
        with self.assertRaisesRegex(ValueError, "region"):
            enable_eventbridge(client, "bucket", "us-west-2", apply=True)
        self.assertIsNone(client.written)

    def test_apply_requires_backup(self):
        client = FakeBucketClient()
        with self.assertRaisesRegex(ValueError, "backup"):
            enable_eventbridge(client, "bucket", "us-east-1", apply=True)
        self.assertIsNone(client.written)

    def test_concurrent_change_is_not_overwritten(self):
        client = FakeBucketClient()

        def backup(_value):
            client.current["TopicConfigurations"] = [{"Id": "new-other-team"}]
            return "memory-backup"

        with self.assertRaisesRegex(ValueError, "concurrently"):
            enable_eventbridge(client, "bucket", "us-east-1", apply=True, backup=backup)
        self.assertIsNone(client.written)
