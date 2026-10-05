from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class Upload:
    bucket: str
    key: str
    version_id: str | None = None
    etag: str | None = None
    size: int | None = None


def _upload(bucket: object, obj: object, *, encoded_key: bool) -> Upload:
    if not isinstance(bucket, dict) or not isinstance(obj, dict):
        raise ValueError("Invalid S3 bucket or object in upload event")
    name, key = bucket.get("name"), obj.get("key")
    if not isinstance(name, str) or not name or not isinstance(key, str) or not key:
        raise ValueError("S3 upload event requires bucket name and object key")
    version = obj.get("version-id", obj.get("versionId"))
    etag = obj.get("etag", obj.get("eTag"))
    size = obj.get("size")
    if version is not None and not isinstance(version, str):
        raise ValueError("Invalid S3 version ID")
    if etag is not None and not isinstance(etag, str):
        raise ValueError("Invalid S3 ETag")
    if size is not None and (type(size) is not int or size < 0):
        raise ValueError("Invalid S3 object size")
    return Upload(name, unquote_plus(key) if encoded_key else key, version, etag, size)


def parse_uploads(event: dict) -> list[Upload] | None:
    """None denotes a manual/scheduled event, [] denotes an irrelevant S3 event."""
    if event.get("source") == "aws.s3":
        if event.get("detail-type") != "Object Created":
            return []
        detail = event.get("detail")
        if not isinstance(detail, dict):
            raise ValueError("S3 EventBridge event is missing its detail")
        # EventBridge keys are raw. Native S3 notification keys are URL encoded.
        return [_upload(detail.get("bucket"), detail.get("object"), encoded_key=False)]
    if event.get("Event") == "s3:TestEvent":
        return []
    if "Records" not in event:
        return None
    records = event["Records"]
    if not isinstance(records, list):
        raise ValueError("Records must be an array")
    uploads = []
    for record in records:
        if not isinstance(record, dict) or record.get("eventSource") != "aws:s3":
            raise ValueError("Unexpected record; expected an S3 notification")
        if not str(record.get("eventName", "")).startswith("ObjectCreated:"):
            continue
        detail = record.get("s3")
        if not isinstance(detail, dict):
            raise ValueError("S3 notification is missing its object detail")
        uploads.append(_upload(detail.get("bucket"), detail.get("object"), encoded_key=True))
    return uploads
