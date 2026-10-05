#!/usr/bin/env python3
"""Browser-free Jira attachment smoke test using the production REST client."""

from __future__ import annotations

import argparse
import json
import mimetypes
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jira_client import JiraClient, JiraCredentials  # noqa: E402
from models import AttachmentFile  # noqa: E402

ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/pdf",
    "image/jpeg",
    "image/png",
    "text/csv",
    "text/plain",
}


def _load_secret(secret_id: str, region: str | None) -> dict[str, object]:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - depends on operator environment
        raise RuntimeError("boto3 is required when --secret-id is used") from exc
    client = boto3.client("secretsmanager", region_name=region or None)
    response = client.get_secret_value(SecretId=secret_id)
    raw = response.get("SecretString")
    if not isinstance(raw, str):
        raise RuntimeError("The Jira secret must use SecretString JSON")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("The Jira secret must be a JSON object")
    return parsed


def _load_credentials(args: argparse.Namespace) -> JiraCredentials:
    secret = _load_secret(args.secret_id, args.region)
    return JiraCredentials.from_secret(secret, args.allowed_host_suffix, args.origin)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify or upload one Jira attachment through the REST API without a browser."
    )
    parser.add_argument("--issue", required=True, help="Target Jira key, for example SEC-123")
    parser.add_argument("--file", required=True, type=Path, help="Local file to validate or upload")
    parser.add_argument(
        "--display-name",
        help="Optional Jira display filename; a checksum suffix is always added",
    )
    parser.add_argument("--content-type", help="Override MIME type detection")
    parser.add_argument(
        "--secret-id", required=True, help="Secrets Manager ARN or name; no inline tokens"
    )
    parser.add_argument("--region", help="AWS region used with --secret-id")
    parser.add_argument("--project", required=True, help="Explicitly selected Jira project key")
    parser.add_argument(
        "--origin",
        required=True,
        help="Exact approved Jira origin; checked against credentials",
    )
    parser.add_argument(
        "--allowed-host-suffix",
        default="atlassian.net",
        help="Allowed Jira hostname suffix",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Perform the upload; without this flag the command is a read-only dry run",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    project = args.project.strip().upper()
    issue = args.issue.strip().upper()
    if not re.fullmatch(rf"{re.escape(project)}-\d+", issue):
        raise ValueError(f"--issue must be a work item in project {project}")

    path = args.file.expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError("--file must identify a regular file")
    if not 0 < path.stat().st_size <= 10 * 1024 * 1024:
        raise ValueError("The attachment must be nonempty and at most 10 MiB")
    with path.open("rb") as handle:
        body = handle.read(10 * 1024 * 1024 + 1)
    if not body or len(body) > 10 * 1024 * 1024:
        raise ValueError("The attachment changed or exceeds the local byte limit")

    content_type = (
        (args.content_type or mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        .split(";", 1)[0]
        .lower()
    )
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise ValueError(f"Attachment content type is not allowed: {content_type}")

    attachment = AttachmentFile(
        s3_key=f"local-smoke-test/{path.name}",
        filename=(args.display_name or path.name),
        content_type=content_type,
        body=body,
    )
    client = JiraClient(_load_credentials(args), project)
    identity = client.preflight()
    client.get_issue(issue, fields=["summary", "attachment"])
    settings = client.get_attachment_settings()
    if not settings.get("enabled", False):
        raise RuntimeError("Jira attachments are disabled")
    upload_limit = int(settings.get("uploadLimit", 0))
    if upload_limit <= 0 or len(body) > upload_limit:
        raise RuntimeError(
            f"Attachment is {len(body)} bytes; Jira's reported limit is {upload_limit} bytes"
        )

    existing = client.list_attachments(issue)
    duplicate = next(
        (
            item
            for item in existing
            if item.get("filename") == attachment.jira_filename
            and int(item.get("size", -1)) == len(body)
        ),
        None,
    )
    result: dict[str, object] = {
        "status": "ALREADY_ATTACHED" if duplicate else "DRY_RUN",
        "issue": issue,
        "filename": attachment.jira_filename,
        "size": len(body),
        "content_type": content_type,
        "authenticated_account_id": identity.get("accountId", "unknown"),
    }
    if duplicate:
        result["attachment_id"] = duplicate.get("id")
    elif args.upload:
        uploaded = client.upload_attachment(
            issue,
            attachment.jira_filename,
            attachment.content_type,
            attachment.body,
        )
        result.update(
            {
                "status": "UPLOADED",
                "attachment_id": uploaded.get("id"),
            }
        )

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
