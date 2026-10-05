"""Positive closure/exception evidence is separate from Critical-only observations."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Evidence timestamps must be timezone-aware ISO strings")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Evidence timestamps require a timezone")
    return parsed.astimezone(UTC)


def _link(value: object) -> None:
    parsed = urlsplit(value) if isinstance(value, str) else None
    if (
        not parsed
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Evidence requires credential-free HTTPS references")


def validate_evidence(
    value: dict, metadata: dict, *, exception: bool = False, now: datetime | None = None
) -> dict:
    now = now or datetime.now(UTC)
    common = {"schema", "source", "repository", "finding_id", "targets", "owner", "approved_by"}
    fields = (
        {"reason", "expires_at", "compensating_controls", "migration_plan", "approval_url"}
        if exception
        else {
            "disposition",
            "scanned_at",
            "deployed_at",
            "artifact_digest",
            "scan_url",
            "deployment_url",
        }
    )
    if not isinstance(value, dict) or set(value) != common | fields:
        raise ValueError("Evidence has missing or unknown fields for this operation")
    for name, entry in value.items():
        if name in {"schema", "targets"}:
            continue
        if not isinstance(entry, str) or len(entry) > 5000 or "\x00" in entry:
            raise ValueError("Evidence fields must be bounded text")
    identity = metadata["identity"]
    if value.get("schema") != 1 or any(
        value.get(k) != identity[k] for k in ("source", "repository", "finding_id")
    ):
        raise ValueError("Evidence identity does not match the mapped finding")
    for field in ("approved_by", "owner"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise ValueError(f"Evidence requires {field}")
    supplied = value.get("targets")
    if "targets" not in metadata:
        raise ValueError("Restore target scope through a reviewed import before verification")
    if (
        not isinstance(supplied, list)
        or len(supplied) > 1000
        or not all(isinstance(t, str) and len(t) <= 2048 for t in supplied)
        or len(set(supplied)) != len(supplied)
    ):
        raise ValueError("Evidence targets must be a string array")
    if set(supplied) != set(metadata["targets"]):
        raise ValueError("Evidence must cover exactly all mapped affected targets")
    if exception:
        expiry = _timestamp(value.get("expires_at"))
        if not now < expiry <= now + timedelta(days=90):
            raise ValueError("Exception expiry must be future and no more than 90 days away")
        for field in ("compensating_controls", "migration_plan", "reason"):
            if not isinstance(value.get(field), str) or not value[field].strip():
                raise ValueError(f"Exception requires {field}")
        _link(value.get("approval_url"))
        return {"lifecycle": "EXCEPTION", "deadline": int(expiry.timestamp())}
    scanned = _timestamp(value.get("scanned_at"))
    deployed = _timestamp(value.get("deployed_at"))
    if not deployed <= scanned <= now + timedelta(minutes=5) or now - scanned > timedelta(hours=36):
        raise ValueError("Verification requires a fresh post-deployment scan")
    if scanned < _timestamp(metadata["last_seen"]):
        raise ValueError("Verification predates the latest open observation")
    if value.get("disposition") != "resolved" or not re.fullmatch(
        r"sha256:[a-f0-9]{64}", value.get("artifact_digest", "")
    ):
        raise ValueError(
            "Verification requires resolved disposition and deployed artifact identity"
        )
    _link(value.get("scan_url"))
    _link(value.get("deployment_url"))
    return {
        "lifecycle": "VERIFIED",
        "verified_at": scanned.isoformat(),
        "deadline": int(now.timestamp()),
    }
