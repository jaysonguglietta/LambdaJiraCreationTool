"""Enable S3 EventBridge delivery on an existing bucket without replacing other notifications."""

from __future__ import annotations

import argparse
import json


def enable_eventbridge(s3, bucket: str, region: str, *, apply: bool = False, backup=None) -> dict:
    location = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    actual_region = "us-east-1" if not location else ("eu-west-1" if location == "EU" else location)
    if actual_region != region:
        raise ValueError(
            f"Bucket is in {actual_region}; deploy the Lambda and EventBridge rule in that region"
        )
    current = s3.get_bucket_notification_configuration(Bucket=bucket)
    allowed = {
        "TopicConfigurations",
        "QueueConfigurations",
        "LambdaFunctionConfigurations",
        "EventBridgeConfiguration",
    }
    proposed = {name: value for name, value in current.items() if name in allowed}
    already_enabled = "EventBridgeConfiguration" in proposed
    proposed["EventBridgeConfiguration"] = {}
    backup_reference = None
    if apply and not already_enabled:
        if backup is None:
            raise ValueError("Applying bucket notifications requires a recoverable backup")
        original = {name: value for name, value in current.items() if name in allowed}
        backup_reference = backup({"bucket": bucket, "region": region, "configuration": original})
        if not isinstance(backup_reference, str) or not backup_reference:
            raise ValueError("Backup did not return a durable reference")
        latest = s3.get_bucket_notification_configuration(Bucket=bucket)
        if {name: value for name, value in latest.items() if name in allowed} != original:
            raise ValueError(
                "Bucket notifications changed concurrently; re-review instead of overwriting"
            )
        s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration=proposed)
        verified = s3.get_bucket_notification_configuration(Bucket=bucket)
        if {name: value for name, value in verified.items() if name in allowed} != proposed:
            raise ValueError(
                "Notification readback differs; use the backup to investigate before retrying"
            )
    return {
        "bucket": bucket,
        "region": region,
        "backup": backup_reference,
        "status": "ALREADY_ENABLED"
        if already_enabled
        else ("ENABLED" if apply else "WOULD_ENABLE"),
        "preserved_notifications": {
            name: len(proposed.get(name, []))
            for name in sorted(allowed - {"EventBridgeConfiguration"})
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--backup-file", help="New local backup filename; required with --apply")
    parser.add_argument(
        "--apply", action="store_true", help="Enable EventBridge delivery; default is read-only"
    )
    args = parser.parse_args()
    if args.apply and not args.backup_file:
        parser.error("--apply requires --backup-file")

    def save_backup(value):
        from pathlib import Path

        path = Path(args.backup_file).expanduser().resolve()
        with path.open("x") as handle:
            json.dump(value, handle, indent=2)
        return str(path)

    import boto3

    result = enable_eventbridge(
        boto3.client("s3", region_name=args.region),
        args.bucket,
        args.region,
        apply=args.apply,
        backup=save_backup if args.apply else None,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
