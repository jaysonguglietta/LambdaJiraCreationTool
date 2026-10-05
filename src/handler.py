from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict
from typing import Any

from audit import AuditStore
from aws_adapters import (
    InputError,
    ReportsNotReady,
    S3ReportSource,
    SecretLoader,
    SummaryPublisher,
    SupersededUpload,
)
from budget import Budget
from bundles import propose_bundles
from config import Config
from identity import digest
from products import MappedCsvAdapter, SnykAdapter, load_profiles
from reports import ReportValidationError
from service import AutomationService
from state_store import StateStore
from upload_events import Upload, parse_uploads

LOGGER = logging.getLogger("security_automation")
LOGGER.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
# SDK debug logs can include Secrets Manager response bodies. Application DEBUG
# must never enable credential-bearing SDK transport logs.
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("boto3").setLevel(logging.WARNING)
_RUNTIME: IngestionRuntime | None = None


class IngestionRuntime:
    def __init__(
        self,
        config: Config,
        source,
        secret_loader,
        state_store,
        publisher,
        *,
        jira_factory=None,
        audit_store=None,
        continuation=None,
    ) -> None:
        self.config = config
        self.state, self.audit, self.publisher = state_store, audit_store, publisher
        self.adapters = [SnykAdapter(config, source)]
        self.adapters.extend(MappedCsvAdapter(profile, source) for profile in load_profiles(config))
        self.services = {}
        for adapter in self.adapters:
            kwargs = {"jira_factory": jira_factory} if jira_factory else {}
            self.services[adapter.source] = AutomationService(
                config,
                source,
                secret_loader,
                state_store,
                publisher,
                adapter=adapter,
                audit_store=audit_store,
                continuation=continuation,
                batch_ready=self.batch_ready,
                **kwargs,
            )

    def batch_ready(self, source: str, metadata: dict) -> None:
        keys = {obj["key"] for obj in metadata.get("input_objects", [])}
        for pending in self.state.list_status("WAITING_FOR_REPORT_PAIR"):
            if pending["source"] == source and pending["upload"]["key"] in keys:
                self.state.put_record(
                    "PAIR#" + pending["id"], {**pending, "status": "PAIR_COMPLETED"}
                )

    def process_upload(self, upload: Upload) -> dict[str, object]:
        if upload.bucket != self.config.input_bucket:
            return {"status": "IGNORED_BUCKET"}
        if not upload.key.lower().endswith(".csv"):
            return {"status": "IGNORED_NON_CSV"}
        adapter = next((item for item in self.adapters if item.matches(upload.key)), None)
        if not adapter:
            if upload.key.startswith(self.config.products_prefix):
                raise InputError("No product CSV mapping is configured for this report folder")
            return {"status": "IGNORED_PREFIX"}
        if upload.size is not None and not 0 < upload.size <= self.config.max_input_bytes:
            raise InputError("Upload size is outside the configured report limit")
        try:
            # S3 content cannot override dry-run, force, or attachment instructions.
            result = self.services[adapter.source].run(
                dry_run=self.config.dry_run_default, upload=upload
            )
        except ReportsNotReady as exc:
            result = {
                "status": "WAITING_FOR_REPORT_PAIR",
                "source": adapter.source,
                "message": str(exc),
            }
            if not self.config.dry_run_default and self.audit:
                # Pending pairs survive acknowledgement of the first upload.
                identifier = digest(
                    (
                        self.config.jira_origin,
                        self.config.jira_project_key,
                        adapter.source,
                        upload.key,
                    )
                )[:32]
                existing = self.state.get_record("PAIR#" + identifier)
                ref = self.audit.put("pending", identifier, {"upload": asdict(upload), **result})
                self.state.put_record(
                    "PAIR#" + identifier,
                    {
                        **result,
                        "id": identifier,
                        "upload": asdict(upload),
                        "audit": ref,
                        "deadline": existing["deadline"]
                        if existing
                        else int(time.time()) + self.config.pair_wait_hours * 3600,
                    },
                )
        except SupersededUpload:
            result = {"status": "SKIPPED_SUPERSEDED_UPLOAD", "source": adapter.source}
        result.update(trigger="s3_upload", uploaded_key=upload.key)
        if result["status"] in {"COMPLETE", "SKIPPED_ALREADY_PROCESSED"}:
            for pending in self.state.list_status("WAITING_FOR_REPORT_PAIR"):
                if pending["source"] == adapter.source and any(
                    obj["key"] == pending["upload"]["key"]
                    for obj in result.get("input_objects", [])
                ):
                    self.state.put_record(
                        "PAIR#" + pending["id"], {**pending, "status": "PAIR_COMPLETED"}
                    )
        return result

    def process_manual(self, event: dict[str, Any]) -> dict[str, object]:
        product = event.get("product", "snyk")
        if not isinstance(product, str) or product not in self.services:
            raise ValueError("Manual event product is not configured")
        service = self.services[product]
        operation = event.get("operation", "attachments" if event.get("attachments") else "ingest")
        if operation == "check":
            return service.check()
        if operation == "inspect":
            return service.inspect(
                event.get("job_id", ""),
                offset=event.get("offset", 0),
                limit=event.get("limit", 100),
            )
        if operation == "resume":
            return service.resume(event.get("job_id", ""), event.get("approved_new_ticket_limit"))
        if operation == "restore":
            return service.restore_mapping(event)
        if operation == "bundles":
            return propose_bundles(service.adapter.load().findings)
        if operation in {"verify", "exception"}:
            return service.evidence(event, exception=operation == "exception")
        if operation == "repair":
            service._jira(False)
            fingerprint = event.get("fingerprint", "")
            if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{32}", fingerprint):
                raise ValueError("Repair requires an exact v2 fingerprint")
            record = self.state.mapping_record(fingerprint)
            identity = record.get("metadata", {}).get("identity", {}) if record else {}
            if (
                not record
                or identity.get("project_id") != service.project_id
                or identity.get("origin") != service.credentials.base_url
            ):
                raise ValueError("Repair mapping is outside the current destination")
            reason = event.get("approved_reason", "")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("Repair requires a reviewed reason")
            with service.destination_write(False):
                current = self.state.mapping_record(fingerprint)
                if current != record:
                    raise ValueError("Mapping changed during repair review; inspect it again")
                ref = self.audit.put(
                    "repairs", fingerprint, {"before": record, "approved_reason": reason}
                )
                self.state.repair_mapping(fingerprint, reason)
            return {"status": "REPAIR_APPROVED", "audit": ref}
        if operation == "monitor":
            return self.monitor()
        if operation not in {"ingest", "attachments"}:
            raise ValueError("Unknown operator operation")
        attachments = event.get("attachments", [])
        if not isinstance(attachments, list):
            raise ValueError("Event field 'attachments' must be an array")
        if operation == "attachments":
            return service.attachments(
                attachments, dry_run=_bool_event(event, "dryRun", self.config.dry_run_default)
            )
        upload = None
        if "s3Key" in event:
            key, version = event["s3Key"], event.get("versionId")
            if (
                not isinstance(key, str)
                or not key
                or (version is not None and not isinstance(version, str))
            ):
                raise ValueError("Manual s3Key/versionId must be strings")
            adapter = next(item for item in self.adapters if item.source == product)
            if not adapter.matches(key):
                raise ValueError("Manual object key does not match the selected product folder")
            upload = Upload(self.config.input_bucket, key, version_id=version)
        return service.run(
            dry_run=_bool_event(event, "dryRun", self.config.dry_run_default),
            force=_bool_event(event, "force", False),
            attachment_requests=attachments,
            upload=upload,
            approved_new_ticket_limit=event.get("approved_new_ticket_limit"),
        )

    def quarantine(self, upload: Upload, error: Exception) -> dict:
        if not self.audit:
            raise error
        identifier = uuid.uuid4().hex
        payload = {
            "status": "QUARANTINED",
            "id": identifier,
            "upload": asdict(upload),
            "error_type": type(error).__name__,
            "reason": str(error)[:1000],
        }
        payload["audit"] = self.audit.put("quarantine", identifier, payload)
        self.state.put_record("QUARANTINE#" + identifier, payload)
        return payload

    def monitor(self) -> dict:
        if self.config.dry_run_default or not self.config.activation_approved:
            return {"status": "DRY_RUN", "message": "Operational monitor writes are not activated"}
        outcomes = []
        for status, prefix in (("WAITING_FOR_REPORT_PAIR", "PAIR"), ("EXCEPTION", "LIFECYCLE")):
            for record in self.state.list_status(status, before=int(time.time())):
                identifier = record.get("id") or digest(record["identity"])[:32]
                payload = {
                    **record,
                    "status": "PAIR_EXPIRED" if prefix == "PAIR" else "EXCEPTION_EXPIRED",
                }
                service = self.services[
                    record.get("source", record.get("identity", {}).get("source", "snyk"))
                ]
                if prefix == "LIFECYCLE":
                    payload.update(service.expire_exception(record))
                service._notify(identifier, payload)
                self.state.put_record(prefix + "#" + identifier, payload)
                outcomes.append({"id": identifier, "status": payload["status"]})
        for notice in self.state.list_status("NOTIFICATION_FAILED", before=int(time.time())):
            self.services[notice["source"]]._notify(notice["id"], notice["payload"])
        return {"status": "MONITOR_COMPLETE", "actions": outcomes}


def _build_runtime() -> IngestionRuntime:
    # The release pins its own SDK; pure event tests do not require it.
    import boto3

    config = Config.from_env()
    from botocore.config import Config as SdkConfig

    sdk = SdkConfig(
        connect_timeout=5, read_timeout=15, retries={"total_max_attempts": 3, "mode": "standard"}
    )
    s3 = boto3.client("s3", config=sdk)
    secrets = boto3.client("secretsmanager", config=sdk)
    dynamodb = boto3.client("dynamodb", config=sdk)
    sns = boto3.client("sns", config=sdk)
    sqs = boto3.client("sqs", config=sdk)

    def continuation(job_id, product):
        sqs.send_message(
            QueueUrl=config.upload_queue_url,
            MessageBody=json.dumps({"kind": "resume", "job_id": job_id, "product": product}),
            MessageGroupId="security-csv-ingestion",
            MessageDeduplicationId=uuid.uuid4().hex,
        )

    source = S3ReportSource(
        s3,
        config.input_bucket,
        config.risk_prefix,
        config.issues_prefix,
        attachment_prefix=config.attachment_prefix,
        max_age_hours=config.max_input_age_hours,
        max_bytes=config.max_input_bytes,
        require_same_report_date=config.require_same_report_date,
        max_attachment_bytes=config.max_attachment_bytes,
        allowed_attachment_types=config.allowed_attachment_types,
        require_clean_attachment_tag=config.require_clean_attachment_tag,
    )
    return IngestionRuntime(
        config,
        source,
        SecretLoader(secrets),
        StateStore(dynamodb, config.state_table_name, retention_days=config.state_retention_days),
        SummaryPublisher(sns, config.summary_topic_arn),
        audit_store=AuditStore(s3, config.audit_bucket),
        continuation=continuation if config.upload_queue_url else None,
    )


def _bool_event(event: dict[str, Any], name: str, default: bool) -> bool:
    value = event.get(name, default)
    if isinstance(value, bool):
        return value
    raise ValueError(f"Event field {name!r} must be a boolean")


def _emit_metrics(result: dict[str, object]) -> None:
    metrics = [
        {"Name": "CriticalFindings", "Unit": "Count"},
        {"Name": "TicketsCreated", "Unit": "Count"},
        {"Name": "TicketsReused", "Unit": "Count"},
        {"Name": "TicketsUpdated", "Unit": "Count"},
        {"Name": "AttachmentsUploaded", "Unit": "Count"},
        {"Name": "AttachmentsReused", "Unit": "Count"},
    ]
    payload = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": "SecurityAutomation/Jira",
                    "Dimensions": [["Project", "Source"]],
                    "Metrics": metrics,
                }
            ],
        },
        "Project": os.getenv("JIRA_PROJECT_KEY", "").strip().upper() or "UNCONFIGURED",
        "Source": result.get("source", "snyk"),
        "CriticalFindings": int(result.get("critical_findings", 0)),
        "TicketsCreated": int(result.get("tickets_created", 0)),
        "TicketsReused": int(result.get("tickets_reused", 0)),
        "TicketsUpdated": int(result.get("tickets_updated", 0)),
        "AttachmentsUploaded": int(result.get("attachments_uploaded", 0)),
        "AttachmentsReused": int(result.get("attachments_reused", 0)),
    }
    LOGGER.info(json.dumps(payload, separators=(",", ":")))


def _log_result(result: dict[str, object], request_id: str) -> None:
    _emit_metrics(result)
    LOGGER.info(
        json.dumps(
            {
                "event": "run_completed",
                "request_id": request_id,
                "status": result.get("status"),
                "source": result.get("source"),
                "report_date": result.get("report_date"),
                "uploaded_key": result.get("uploaded_key"),
            },
            separators=(",", ":"),
        )
    )


def _compact(result: dict) -> dict:
    if len(result.get("actions", [])) <= 10:
        return result
    return {
        **result,
        "actions": result["actions"][:10],
        "actions_truncated": True,
        "response_note": "Inspect the job's paginated action history. For complete offline "
        "previews, use scripts/security_operator.py preview.",
    }


def _process_sqs(event: dict, runtime: IngestionRuntime, request_id: str) -> dict:
    failures = []
    for record in event["Records"]:
        message_id = record.get("messageId")
        if not isinstance(message_id, str) or not message_id:
            raise ValueError("SQS record is missing messageId")
        if failures:
            # For FIFO queues, stop after the first failure to preserve group order.
            failures.append({"itemIdentifier": message_id})
            continue
        try:
            payload = json.loads(record["body"])
            if not isinstance(payload, dict):
                raise ValueError("SQS body must contain a JSON object")
            if payload.get("kind") == "resume":
                # Queue writers are restricted to EventBridge and this Lambda role.
                if set(payload) != {"kind", "job_id", "product"}:
                    raise ValueError("Invalid continuation envelope")
                _log_result(runtime.process_manual({**payload, "operation": "resume"}), request_id)
                continue
            uploads = parse_uploads(payload)
            if uploads is None:
                raise ValueError("SQS only accepts S3 upload events")
            for upload in uploads:
                try:
                    result = runtime.process_upload(upload)
                except (InputError, ReportValidationError) as exc:
                    result = runtime.quarantine(upload, exc)
                    LOGGER.error(
                        json.dumps({"event": "upload_rejected", "error_type": type(exc).__name__})
                    )
                _log_result(result, request_id)
        except Exception as exc:
            LOGGER.error(
                json.dumps(
                    {
                        "event": "upload_failed",
                        "request_id": request_id,
                        "message_id": message_id,
                        "error_type": type(exc).__name__,
                    }
                )
            )
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}


def lambda_handler(event: dict[str, Any] | None, context: Any) -> dict[str, object]:
    global _RUNTIME
    if event is None:
        event = {}
    if not isinstance(event, dict):
        raise ValueError("Lambda event must be a JSON object")
    if _RUNTIME is None:
        _RUNTIME = _build_runtime()
    request_id = getattr(context, "aws_request_id", "local")
    remaining = (
        context.get_remaining_time_in_millis() / 1000
        if hasattr(context, "get_remaining_time_in_millis")
        else 300
    )
    for service in _RUNTIME.services.values():
        service.budget = Budget(max(1, min(service.config.work_seconds, remaining - 45)))
    LOGGER.info(json.dumps({"event": "run_started", "request_id": request_id}))
    records = event.get("Records")
    if (
        isinstance(records, list)
        and records
        and any(
            isinstance(record, dict) and record.get("eventSource") == "aws:sqs"
            for record in records
        )
    ):
        if not all(
            isinstance(record, dict) and record.get("eventSource") == "aws:sqs"
            for record in records
        ):
            raise ValueError("Mixed SQS and other event records are not supported")
        return _process_sqs(event, _RUNTIME, request_id)
    uploads = parse_uploads(event)
    if uploads is not None:
        results = [_RUNTIME.process_upload(upload) for upload in uploads]
        for result in results:
            _log_result(result, request_id)
        return {"results": [_compact(result) for result in results]}
    result = _RUNTIME.process_manual(event)
    _log_result(result, request_id)
    return _compact(result)
