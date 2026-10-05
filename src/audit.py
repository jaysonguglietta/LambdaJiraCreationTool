"""Immutable full artifacts; compact state never truncates JSON."""

from __future__ import annotations

import hashlib
import json
import re
import uuid


class AuditStore:
    def __init__(self, s3, bucket: str, *, max_bytes: int = 32 * 1024 * 1024):
        self.s3, self.bucket, self.max_bytes = s3, bucket, max_bytes

    def check(self) -> dict:
        if not self.bucket:
            raise ValueError("AUDIT_BUCKET is required")
        result = self.s3.get_bucket_versioning(Bucket=self.bucket)
        if result.get("Status") != "Enabled":
            raise ValueError("Audit bucket must have versioning enabled")
        return {"bucket": self.bucket, "versioning": "Enabled"}

    def put(self, category: str, identifier: str, value: dict) -> dict:
        if not self.bucket:
            raise ValueError("AUDIT_BUCKET is required for durable jobs")
        if not re.fullmatch(r"[a-z-]+", category) or not re.fullmatch(r"[A-Za-z0-9-]+", identifier):
            raise ValueError("Invalid artifact identifier")
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if len(body) > self.max_bytes:
            raise ValueError("Audit artifact exceeds the byte limit")
        key = f"{category}/{identifier}/{uuid.uuid4().hex}.json"
        response = self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        if response.get("VersionId") in {None, "", "null"}:
            raise ValueError("Audit bucket versioning is required")
        return {
            "bucket": self.bucket,
            "key": key,
            "version_id": response.get("VersionId"),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    def get(self, reference: dict) -> dict:
        if reference.get("bucket") != self.bucket or not re.fullmatch(
            r"[a-z-]+/[A-Za-z0-9-]+/[a-f0-9]{32}\.json", reference.get("key", "")
        ):
            raise ValueError("Artifact is outside the configured audit bucket")
        if not reference.get("version_id"):
            raise ValueError("Audit artifacts require versioning")
        response = self.s3.get_object(
            Bucket=self.bucket, Key=reference["key"], VersionId=reference["version_id"]
        )
        try:
            body = response["Body"].read(self.max_bytes + 1)
            if (
                len(body) > self.max_bytes
                or hashlib.sha256(body).hexdigest() != reference["sha256"]
            ):
                raise ValueError("Audit artifact integrity check failed")
            value = json.loads(body)
            if not isinstance(value, dict):
                raise ValueError("Invalid audit artifact")
            return value
        finally:
            response["Body"].close()
