from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime

from models import AttachmentFile, ReportObject


class InputError(RuntimeError):
    """Raised when the scheduled input pair is unavailable or unsafe to process."""


class ReportsNotReady(InputError):
    """An upload arrived before its companion report; the companion will trigger a run."""


class SupersededUpload(InputError):
    """An unversioned object changed after its notification was generated."""


REPORT_DATE_PATTERN = re.compile(r"_(\d{2})_(\d{2})_(\d{4})(?:_|\.)")


def _report_date(key: str) -> date | None:
    match = REPORT_DATE_PATTERN.search(key.rsplit("/", 1)[-1])
    if not match:
        return None
    month, day, year = (int(part) for part in match.groups())
    try:
        return date(year, month, day)
    except ValueError as exc:
        raise InputError(f"Invalid report date in S3 object key: {key}") from exc


class S3ReportSource:
    def __init__(
        self,
        s3_client,
        bucket: str,
        risk_prefix: str,
        issues_prefix: str,
        attachment_prefix: str = "snyk/attachments/",
        *,
        max_age_hours: int,
        max_bytes: int,
        require_same_report_date: bool,
        max_attachment_bytes: int = 10 * 1024 * 1024,
        allowed_attachment_types: frozenset[str] = frozenset(
            {
                "text/csv",
                "text/plain",
                "application/json",
                "application/pdf",
                "image/png",
                "image/jpeg",
            }
        ),
        require_clean_attachment_tag: bool = True,
        now=lambda: datetime.now(UTC),
    ) -> None:
        self.s3 = s3_client
        self.bucket = bucket
        self.risk_prefix = risk_prefix
        self.issues_prefix = issues_prefix
        self.attachment_prefix = attachment_prefix
        self.max_age_hours = max_age_hours
        self.max_bytes = max_bytes
        self.require_same_report_date = require_same_report_date
        self.max_attachment_bytes = max_attachment_bytes
        self.allowed_attachment_types = allowed_attachment_types
        self.require_clean_attachment_tag = require_clean_attachment_tag
        self.now = now

    def _list(
        self, prefix: str, *, allow_empty: bool = False, report_date: date | None = None
    ) -> list[dict]:
        token = None
        objects: list[dict] = []
        seen_tokens = set()
        pages = 0
        while True:
            pages += 1
            if pages > 20:
                raise InputError("Report listing exceeded its bounded page limit")
            kwargs = {"Bucket": self.bucket, "Prefix": prefix, "MaxKeys": 1000}
            if token:
                kwargs["ContinuationToken"] = token
            response = self.s3.list_objects_v2(**kwargs)
            for item in response.get("Contents", []):
                key = str(item.get("Key", ""))
                size = int(item.get("Size", 0))
                if key.lower().endswith(".csv"):
                    try:
                        parsed_date = _report_date(key)
                    except InputError:
                        # A malformed historical filename must not block later dates.
                        # Its own upload event will report the validation failure.
                        continue
                    if report_date is not None and parsed_date != report_date:
                        continue
                    objects.append(
                        {
                            "Key": key,
                            "Size": size,
                            "LastModified": item["LastModified"],
                            "ReportDate": parsed_date,
                            "ETag": item.get("ETag"),
                        }
                    )
            if not response.get("IsTruncated"):
                break
            token = response.get("NextContinuationToken")
            if not token or token in seen_tokens or len(objects) > 10000:
                raise InputError("Report listing exceeded its bounded selection limit")
            seen_tokens.add(token)
        if not objects and not allow_empty:
            raise InputError(f"No CSV reports found under s3://{self.bucket}/{prefix}")
        return objects

    def _select(self) -> tuple[dict, dict]:
        risk = self._list(self.risk_prefix)
        issues = self._list(self.issues_prefix)
        if self.require_same_report_date:
            risk_dates = {item["ReportDate"] for item in risk if item["ReportDate"]}
            issue_dates = {item["ReportDate"] for item in issues if item["ReportDate"]}
            common = sorted(risk_dates & issue_dates)
            if not common:
                raise InputError(
                    "No Risk Exposure and Issues Detail reports share the same filename date"
                )
            selected_date = common[-1]
            if max(risk_dates | issue_dates) > selected_date:
                raise ReportsNotReady("A newer report date has an incomplete pair")
            risk = [item for item in risk if item["ReportDate"] == selected_date]
            issues = [item for item in issues if item["ReportDate"] == selected_date]
        if len(risk) != 1 or len(issues) != 1:
            raise InputError("Ambiguous same-day revisions; keep one immutable pair per date")
        risk_item, issues_item = risk[0], issues[0]
        return risk_item, issues_item

    def _download(self, item: dict) -> ReportObject:
        if not 0 < int(item["Size"]) <= self.max_bytes:
            raise InputError(f"S3 report is empty or exceeds MAX_INPUT_BYTES: {item['Key']}")
        modified = item["LastModified"]
        if modified.tzinfo is None:
            modified = modified.replace(tzinfo=UTC)
        age_seconds = (self.now() - modified.astimezone(UTC)).total_seconds()
        self._validate_report_date(item["ReportDate"])
        if age_seconds < -300:
            raise InputError(f"S3 report has a future LastModified time: {item['Key']}")
        if age_seconds > self.max_age_hours * 3600:
            raise InputError(
                f"Latest S3 report is older than {self.max_age_hours} hours: {item['Key']}"
            )
        version = self._immutable_version(item["Key"])
        response = self.s3.get_object(Bucket=self.bucket, Key=item["Key"], VersionId=version)
        try:
            if item.get("ETag") and response.get("ETag") != item["ETag"]:
                raise InputError(f"S3 report changed during selection; retry: {item['Key']}")
            body = response["Body"].read(self.max_bytes + 1)
            if len(body) > self.max_bytes:
                raise InputError(f"Downloaded S3 report exceeds MAX_INPUT_BYTES: {item['Key']}")
            if len(body) != int(item["Size"]):
                raise InputError(
                    f"Downloaded S3 report size changed during processing: {item['Key']}"
                )
            return ReportObject(
                bucket=self.bucket,
                key=item["Key"],
                last_modified=modified,
                report_date=item["ReportDate"],
                body=body,
                version_id=response.get("VersionId"),
            )
        finally:
            response["Body"].close()

    def latest_pair(self) -> tuple[ReportObject, ReportObject]:
        risk_item, issues_item = self._select()
        return self._download(risk_item), self._download(issues_item)

    def _validate_report_date(self, report_date: date | None) -> None:
        if report_date:
            days = (self.now().date() - report_date).days
            if days < 0 or days * 24 > self.max_age_hours + 24:
                raise InputError("Report filename date is stale or future-dated")

    def _immutable_version(self, key: str) -> str:
        result = self.s3.list_object_versions(Bucket=self.bucket, Prefix=key, MaxKeys=3)
        versions = [v for v in result.get("Versions", []) if v["Key"] == key]
        deleted = any(v["Key"] == key for v in result.get("DeleteMarkers", []))
        if len(versions) != 1 or deleted or versions[0].get("VersionId") in {None, "", "null"}:
            raise InputError(
                "Snyk pairs require write-once versioned objects; review any revision explicitly"
            )
        return versions[0]["VersionId"]

    def get_report(
        self,
        key: str,
        *,
        allowed_prefix: str,
        version_id: str | None = None,
        etag: str | None = None,
    ) -> ReportObject:
        if not key.startswith(allowed_prefix) or not key.lower().endswith(".csv"):
            raise InputError("Report object is outside the configured CSV folder")
        kwargs = {"Bucket": self.bucket, "Key": key}
        if key.startswith((self.risk_prefix, self.issues_prefix)):
            latest = self._immutable_version(key)
        else:
            latest = self.s3.head_object(**kwargs).get("VersionId")
            if latest in {None, "", "null"}:
                raise InputError("Product reports require S3 versioning")
        if version_id and version_id != latest:
            raise SupersededUpload("An older object version cannot be paired with a newer report")
        version_id = latest
        if version_id:
            kwargs["VersionId"] = version_id
        response = self.s3.get_object(**kwargs)
        try:
            size = int(response.get("ContentLength", 0))
            if not 0 < size <= self.max_bytes:
                raise InputError(f"Report size must be between 1 and {self.max_bytes} bytes")
            actual_etag = str(response.get("ETag", "")).strip('"')
            if etag and actual_etag != etag.strip('"'):
                raise SupersededUpload("The uploaded object was replaced before processing")
            modified = response["LastModified"]
            if modified.tzinfo is None:
                modified = modified.replace(tzinfo=UTC)
            age = (self.now() - modified.astimezone(UTC)).total_seconds()
            self._validate_report_date(_report_date(key))
            if age < -300 or age > self.max_age_hours * 3600:
                raise InputError(
                    "Uploaded report has a future timestamp or exceeds MAX_INPUT_AGE_HOURS"
                )
            body = response["Body"].read(self.max_bytes + 1)
            if len(body) != size or len(body) > self.max_bytes:
                raise InputError("Downloaded report size changed during processing")
            return ReportObject(
                bucket=self.bucket,
                key=key,
                last_modified=modified,
                report_date=_report_date(key),
                body=body,
                version_id=response.get("VersionId"),
            )
        finally:
            response["Body"].close()

    def pair_for_upload(
        self, key: str, *, version_id: str | None = None, etag: str | None = None
    ) -> tuple[ReportObject, ReportObject]:
        if key.startswith(self.risk_prefix):
            uploaded_prefix, companion_prefix = self.risk_prefix, self.issues_prefix
        elif key.startswith(self.issues_prefix):
            uploaded_prefix, companion_prefix = self.issues_prefix, self.risk_prefix
        else:
            raise InputError("Snyk upload is outside the configured report folders")
        report_date = _report_date(key)
        if report_date is None:
            raise InputError("Snyk upload filename must contain _MM_DD_YYYY_ report date")
        companions = [
            item for item in self._list(companion_prefix, allow_empty=True, report_date=report_date)
        ]
        if not companions:
            raise ReportsNotReady(f"Waiting for the second Snyk report for {report_date}")
        uploaded_candidates = self._list(uploaded_prefix, report_date=report_date)
        if len(companions) != 1 or len(uploaded_candidates) != 1:
            raise InputError("Ambiguous same-day revisions; keep one immutable pair per date")
        uploaded = self.get_report(
            key, allowed_prefix=uploaded_prefix, version_id=version_id, etag=etag
        )
        companion = self._download(max(companions, key=lambda item: item["LastModified"]))
        return (
            (uploaded, companion) if uploaded_prefix == self.risk_prefix else (companion, uploaded)
        )

    def get_attachment(
        self, key: str, display_name: str | None = None, *, version_id: str | None = None
    ) -> AttachmentFile:
        if not key.startswith(self.attachment_prefix) or key.endswith("/"):
            raise InputError(
                f"Attachment must be an object under s3://{self.bucket}/{self.attachment_prefix}"
            )
        head = self.s3.head_object(
            Bucket=self.bucket, Key=key, **({"VersionId": version_id} if version_id else {})
        )
        version = head.get("VersionId")
        if not version or version == "null":
            raise InputError("Evidence requires a versioned S3 object")
        kwargs = {"Bucket": self.bucket, "Key": key, "VersionId": version}
        if self.require_clean_attachment_tag:
            tagging = self.s3.get_object_tagging(**kwargs)
            tags = {item["Key"]: item["Value"] for item in tagging.get("TagSet", [])}
            if tags.get("malware-scan-status", "").upper() != "CLEAN":
                raise InputError(f"Attachment is not tagged malware-scan-status=CLEAN: {key}")
        response = self.s3.get_object(**kwargs)
        try:
            size = int(response.get("ContentLength", 0))
            if size <= 0 or size > self.max_attachment_bytes:
                raise InputError("Attachment size is outside the configured limit")
            content_type = (
                str(response.get("ContentType", "application/octet-stream"))
                .split(";", 1)[0]
                .lower()
            )
            if content_type not in self.allowed_attachment_types:
                raise InputError("Attachment content type is not allowed")
            if response.get("VersionId") != version:
                raise InputError("Evidence version changed during retrieval")
            body = response["Body"].read(self.max_attachment_bytes + 1)
        finally:
            response["Body"].close()
        if len(body) != size or len(body) > self.max_attachment_bytes:
            raise InputError(f"Attachment size changed during processing: {key}")
        filename = (display_name or key.rsplit("/", 1)[-1]).strip()
        if not filename:
            raise InputError("Attachment display name cannot be blank")
        return AttachmentFile(
            s3_key=key,
            filename=filename,
            content_type=content_type,
            body=body,
            version_id=version,
        )

    def get_json(
        self,
        key: str,
        allowed_prefix: str,
        *,
        sha256: str = "",
        optional: bool = False,
        version_id: str | None = None,
    ) -> tuple[dict, dict] | None:
        import hashlib

        if not key.startswith(allowed_prefix) or not key.endswith(".json"):
            raise InputError("JSON object is outside its approved folder")
        try:
            response = self.s3.get_object(
                Bucket=self.bucket, Key=key, **({"VersionId": version_id} if version_id else {})
            )
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if optional and code in {"NoSuchKey", "404"}:
                return None
            raise
        try:
            body = response["Body"].read(self.max_bytes + 1)
            if len(body) > self.max_bytes:
                raise InputError("JSON object exceeds the byte limit")
            checksum = hashlib.sha256(body).hexdigest()
            if sha256 and checksum != sha256:
                raise InputError("JSON object does not match the approved SHA-256")
            if version_id and response.get("VersionId") != version_id:
                raise InputError("JSON evidence does not match the requested version")
            value = json.loads(body)
            if not isinstance(value, dict):
                raise InputError("JSON object must contain an object")
            return value, {"key": key, "version_id": response.get("VersionId"), "sha256": checksum}
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise InputError("Invalid JSON evidence/configuration") from exc
        finally:
            response["Body"].close()


class SecretLoader:
    def __init__(self, secrets_client) -> None:
        self.client = secrets_client

    def load_json(self, secret_arn: str) -> dict[str, object]:
        response = self.client.get_secret_value(SecretId=secret_arn)
        if "SecretString" in response:
            raw = response["SecretString"]
        else:
            import base64

            binary = response["SecretBinary"]
            raw = (binary if isinstance(binary, bytes) else base64.b64decode(binary)).decode(
                "utf-8"
            )
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise InputError("Jira secret must be a UTF-8 JSON object") from exc
        if not isinstance(parsed, dict):
            raise InputError("Jira secret must be a JSON object")
        return parsed


class SummaryPublisher:
    def __init__(self, sns_client, topic_arn: str | None) -> None:
        self.client = sns_client
        self.topic_arn = topic_arn

    def publish(self, subject: str, payload: dict[str, object]) -> None:
        if not self.topic_arn:
            return
        compact = {
            key: value
            for key, value in payload.items()
            if key not in {"actions", "previews", "findings", "snapshot"}
        }
        message = json.dumps(compact, sort_keys=True, default=str)
        if len(message.encode()) > 240_000:
            message = json.dumps(
                {
                    "status": payload.get("status"),
                    "job_id": payload.get("job_id"),
                    "audit": payload.get("audit"),
                    "message": "Full details are available in the audit artifact",
                }
            )
        self.client.publish(
            TopicArn=self.topic_arn,
            Subject=subject[:100],
            Message=message,
        )
