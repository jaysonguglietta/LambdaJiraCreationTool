"""Offline previews and explicit, IAM-authenticated Lambda operator actions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bundles import propose_bundles  # noqa: E402
from config import Config  # noqa: E402
from policy import Policy  # noqa: E402
from products import load_profiles, parse_mapped_csv  # noqa: E402
from reports import (  # noqa: E402
    group_findings,
    parse_issue_report,
    parse_risk_report,
    validate_report_counts,
)
from ticketing import child_description, child_labels, child_title  # noqa: E402


def read_bounded(path: Path, limit: int = 20 * 1024 * 1024) -> bytes:
    if not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Input must be a nonempty regular file within the byte limit")
    with path.open("rb") as handle:
        body = handle.read(limit + 1)
    if len(body) > limit:
        raise ValueError("Input changed or exceeds the byte limit")
    return body


def local_preview(risk: Path, issues: Path) -> dict:
    summary = parse_risk_report(read_bounded(risk))
    findings = parse_issue_report(read_bounded(issues), allow_empty=summary.critical_total == 0)
    warnings = validate_report_counts(summary, findings, False)
    groups = group_findings(findings)
    return {
        "status": "REVIEW_REQUIRED" if warnings else "OFFLINE_PREVIEW",
        "warnings": warnings,
        "risk_critical_count": summary.critical_total,
        "critical_occurrences": len(findings),
        "tickets": len(groups),
        "campaigns": len({g.repository for g in groups}),
        "previews": [
            {
                "repository": g.repository,
                "finding_id": g.finding_id,
                "summary": child_title(g),
                "labels": child_labels(g),
                "description": child_description(g, "Pending campaign", "Offline preview"),
            }
            for g in groups
        ],
        "bundles": propose_bundles(findings),
    }


def invoke(function: str, event: dict, *, apply: bool = False, region: str | None = None) -> dict:
    allowed = {
        "check",
        "inspect",
        "ingest",
        "bundles",
        "attachments",
        "resume",
        "verify",
        "exception",
        "repair",
        "monitor",
        "restore",
    }
    operation = event.get("operation", "ingest")
    if operation not in allowed:
        raise ValueError("Unknown operator operation")
    mutates = operation in {"resume", "verify", "exception", "repair", "monitor", "restore"}
    if operation in {"ingest", "attachments"}:
        event = {**event, "dryRun": not apply}
    elif mutates and not apply:
        raise ValueError("This operator action changes state; review its JSON and supply --apply")
    import boto3
    from botocore.config import Config as SdkConfig

    client = boto3.client(
        "lambda",
        region_name=region,
        config=SdkConfig(connect_timeout=5, read_timeout=310, retries={"total_max_attempts": 1}),
    )
    response = client.invoke(
        FunctionName=function, InvocationType="RequestResponse", Payload=json.dumps(event).encode()
    )
    try:
        body = response["Payload"].read(6 * 1024 * 1024 + 1)
        if len(body) > 6 * 1024 * 1024:
            raise RuntimeError("Lambda response exceeded its byte limit")
        result = json.loads(body)
    finally:
        response["Payload"].close()
    if response.get("FunctionError"):
        raise RuntimeError("Lambda action failed; inspect the protected logs/job audit for details")
    return result


def export_job(function: str, job_id: str, product: str, region: str | None = None) -> dict:
    if not re.fullmatch(r"[a-f0-9]{32}(?:-[a-f0-9]{12})?", job_id):
        raise ValueError("Export requires an exact job ID")
    result, offset, seen = {"schema": 1, "actions": []}, 0, set()
    for _ in range(100):
        page = invoke(
            function,
            {"operation": "inspect", "job_id": job_id, "product": product, "offset": offset},
            region=region,
        )
        if page.get("job", {}).get("source") != product:
            raise ValueError("Export product differs from the recorded job")
        if result.get("job") and (
            page["job"].get("cursor") != result["job"].get("cursor")
            or page["job"].get("status") != result["job"].get("status")
        ):
            raise ValueError("Job changed during export; wait for a stable checkpoint and retry")
        result["job"] = page["job"]
        result["actions"].extend(page["actions"])
        offset = page.get("next_offset")
        if offset is None:
            return result
        if type(offset) is not int or offset in seen:
            raise ValueError("Export received an invalid pagination cursor")
        seen.add(offset)
    raise ValueError("Export exceeded its bounded page limit")


def export_artifacts(value: dict, audit_bucket: str, region: str | None = None) -> dict:
    import boto3
    from botocore.config import Config as SdkConfig

    snapshot = value.get("job", {}).get("snapshot", {})
    if snapshot.get("bucket") != audit_bucket:
        raise ValueError("Job snapshot is outside the configured audit bucket")
    from audit import AuditStore

    store = AuditStore(
        boto3.client(
            "s3",
            region_name=region,
            config=SdkConfig(connect_timeout=5, read_timeout=15, retries={"total_max_attempts": 3}),
        ),
        audit_bucket,
    )
    pending, artifacts, total = [value], {}, 0
    while pending:
        entry = pending.pop()
        if isinstance(entry, dict):
            if {"bucket", "key", "version_id", "sha256"}.issubset(entry) and entry[
                "bucket"
            ] == audit_bucket:
                name = entry["key"] + "@" + entry["version_id"]
                if name in artifacts:
                    continue
                if len(artifacts) >= 10000:
                    raise ValueError("Artifact export limit reached; export separately by job")
                artifact = store.get(entry)
                total += len(json.dumps(artifact).encode())
                if total > 128 * 1024 * 1024:
                    raise ValueError("Artifact export exceeds 128 MiB; retain the manifest instead")
                artifacts[name] = {"reference": entry, "value": artifact}
                pending.append(artifact)
            else:
                # Source CSV/enrichment references stay in the manifest. They are
                # provenance, not permission to read outside the approved audit bucket.
                pending.extend(entry.values())
        elif isinstance(entry, list):
            pending.extend(entry)
    return {**value, "artifacts": artifacts}


def write_export(output: Path, value: dict) -> None:
    # Exclusive creation avoids overwriting evidence; restrict local export permissions.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preview = commands.add_parser("preview", help="Offline Snyk preview; no credentials or network")
    preview.add_argument("--risk", required=True, type=Path)
    preview.add_argument("--issues", required=True, type=Path)
    policy = commands.add_parser("validate-policy")
    policy.add_argument("--file", required=True, type=Path)
    profile = commands.add_parser(
        "profile-preview", help="Validate a real sample; propose certification only"
    )
    profile.add_argument("--profiles", required=True, type=Path)
    profile.add_argument("--sample", required=True, type=Path)
    profile.add_argument("--product", required=True)
    cloud = commands.add_parser("invoke", help="Run a reviewed JSON operation via AWS IAM")
    cloud.add_argument("--function", required=True)
    cloud.add_argument("--region")
    cloud.add_argument("--event", required=True, type=Path)
    cloud.add_argument("--apply", action="store_true")
    export = commands.add_parser("export", help="Read-only paginated job/evidence export via IAM")
    export.add_argument("--function", required=True)
    export.add_argument("--job-id", required=True)
    export.add_argument("--product", default="snyk")
    export.add_argument("--region")
    export.add_argument("--output", required=True, type=Path)
    export.add_argument("--audit-bucket", help="Include version-pinned full artifact history")
    args = parser.parse_args(argv)
    if args.command == "preview":
        result = local_preview(args.risk, args.issues)
    elif args.command == "validate-policy":
        body = read_bounded(args.file)
        value = Policy.parse(json.loads(body))
        result = {
            "status": "VALID",
            "sha256": hashlib.sha256(body).hexdigest(),
            "semantic_policy_hash": value.fingerprint,
            "policy": asdict(value),
        }
    elif args.command == "profile-preview":
        # Construct configuration only for namespace/mapping validation; no cloud clients.
        profiles = load_profiles(
            Config.from_mapping(
                {
                    "INPUT_BUCKET": "offline",
                    "JIRA_SECRET_ARN": "offline",
                    "STATE_TABLE_NAME": "offline",
                    "JIRA_ORIGIN": "https://jira-example.atlassian.net",
                    "JIRA_PROJECT_KEY": "OFFLINE",
                    "PRODUCT_PROFILES_JSON": read_bounded(args.profiles).decode(),
                }
            )
        )
        selected = next((p for p in profiles if p.source == args.product), None)
        if not selected:
            raise ValueError("Requested product is not mapped")
        sample = read_bounded(args.sample)
        findings = parse_mapped_csv(sample, selected)
        result = {
            "status": "REVIEW_REQUIRED",
            "critical_occurrences": len(findings),
            "groups": len(group_findings(findings)),
            "sample_sha256": hashlib.sha256(sample).hexdigest(),
            "required_review": "Confirm actual export schema/version, severity/status semantics, "
            "stable IDs, asset grouping, remediation evidence and expected row counts. "
            "Add a real approver and this sample checksum before enabling live ingestion.",
        }
    elif args.command == "export":
        result = export_job(args.function, args.job_id, args.product, args.region)
        if args.audit_bucket:
            result = export_artifacts(result, args.audit_bucket, args.region)
        write_export(args.output, result)
        result = {
            "status": "EXPORTED",
            "path": str(args.output.resolve()),
            "actions": len(result["actions"]),
            "artifacts": len(result.get("artifacts", {})),
        }
    else:
        event = json.loads(read_bounded(args.event, 256 * 1024))
        if not isinstance(event, dict):
            raise ValueError("Operator event must be a JSON object")
        result = invoke(args.function, event, apply=args.apply, region=args.region)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
