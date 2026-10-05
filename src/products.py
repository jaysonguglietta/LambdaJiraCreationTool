from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, replace
from datetime import date, datetime

from config import Config, ConfigurationError
from models import Finding, ReportObject, jira_label
from reports import (
    ReportValidationError,
    _array,
    _https_url,
    _reader,
    _require_columns,
    parse_issue_report,
    parse_risk_report,
    validate_report_counts,
)
from upload_events import Upload


@dataclass(frozen=True)
class FindingBatch:
    source: str
    source_name: str
    reports: tuple[ReportObject, ...]
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    categories: dict[str, int] = field(default_factory=dict)
    enrichment: dict = field(default_factory=dict)
    processing_policy: dict = field(default_factory=dict)

    @property
    def report_date(self) -> str:
        dated = next(
            (report.report_date for report in reversed(self.reports) if report.report_date), None
        )
        return dated.isoformat() if dated else self.reports[-1].last_modified.date().isoformat()

    @property
    def fingerprint(self) -> str:
        # A new observation is not a duplicate delivery, even when findings are unchanged.
        from identity import digest

        return digest(
            {
                "source": self.source,
                "date": self.report_date,
                "inputs": self.metadata["input_objects"],
                "enrichment": self.enrichment,
                "processing_policy": self.processing_policy,
            }
        )[:32]

    def snapshot(self) -> dict:
        return {
            "schema": 2,
            "source": self.source,
            "source_name": self.source_name,
            "warnings": self.warnings,
            "categories": self.categories,
            "enrichment": self.enrichment,
            "processing_policy": self.processing_policy,
            "findings": [asdict(f) for f in self.findings],
            "reports": [
                {
                    "bucket": r.bucket,
                    "key": r.key,
                    "version_id": r.version_id,
                    "last_modified": r.last_modified.isoformat(),
                    "report_date": r.report_date.isoformat() if r.report_date else None,
                    "sha256": r.sha256,
                }
                for r in self.reports
            ],
        }

    @classmethod
    def restore(cls, value: dict) -> FindingBatch:
        if value.get("schema") != 2:
            raise ReportValidationError("Unsupported job snapshot schema")
        reports = tuple(
            ReportObject(
                r["bucket"],
                r["key"],
                datetime.fromisoformat(r["last_modified"]),
                date.fromisoformat(r["report_date"]) if r["report_date"] else None,
                b"",
                r.get("version_id"),
                r["sha256"],
            )
            for r in value["reports"]
        )
        findings = []
        for row in value["findings"]:
            row = dict(row)
            for key in ("cves", "cve_urls", "cwes"):
                row[key] = tuple(row[key])
            findings.append(Finding(**row))
        return cls(
            value["source"],
            value["source_name"],
            reports,
            findings,
            value["warnings"],
            value["categories"],
            value.get("enrichment", {}),
            value.get("processing_policy", {}),
        )

    @property
    def metadata(self) -> dict[str, object]:
        metadata: dict[str, object] = {
            "source": self.source,
            "source_name": self.source_name,
            "processing_policy": self.processing_policy,
            "input_objects": [
                {
                    "bucket": report.bucket,
                    "key": report.key,
                    "version_id": report.version_id,
                    "sha256": report.sha256,
                    "last_modified": report.last_modified.isoformat(),
                }
                for report in self.reports
            ],
        }
        if self.source == "snyk":
            metadata.update(
                risk_report_key=self.reports[0].key,
                issues_report_key=self.reports[1].key,
                introduction_categories=self.categories,
            )
        return metadata


class SnykAdapter:
    source = "snyk"
    source_name = "Snyk"
    processing_policy = {"parser_schema": "snyk-csv-v2"}

    def __init__(self, config: Config, report_source) -> None:
        self.config = config
        self.report_source = report_source
        self.approval_policy = None

    def matches(self, key: str) -> bool:
        return key.startswith((self.config.risk_prefix, self.config.issues_prefix))

    def load(self, upload: Upload | None = None) -> FindingBatch:
        if upload:
            reports = self.report_source.pair_for_upload(
                upload.key, version_id=upload.version_id, etag=upload.etag
            )
        else:
            reports = self.report_source.latest_pair()
        risk = parse_risk_report(reports[0].body)
        findings = parse_issue_report(reports[1].body, allow_empty=risk.critical_total == 0)
        warnings = validate_report_counts(risk, findings, False)
        if warnings and self.config.enforce_count_match:
            approval = (
                self.approval_policy.reconciliation(
                    reports[0].sha256, reports[1].sha256, risk.critical_total, len(findings)
                )
                if self.approval_policy
                else None
            )
            if not approval:
                raise ReportValidationError(
                    warnings[0] + "; matching reports or a hash-bound approval required"
                )
            warnings.append(
                f"Count exception explicitly approved by {approval['approved_by']}: "
                f"{approval['reason']}; expires {approval['expires_at']}"
            )
        batch = FindingBatch(
            self.source,
            self.source_name,
            reports,
            findings,
            warnings,
            risk.categories,
            processing_policy=self.processing_policy,
        )
        return enrich_batch(batch, self.config, self.report_source)


REQUIRED_MAPPING = {"finding_id", "group", "title", "severity", "status"}
OPTIONAL_MAPPING = {
    "target",
    "remediation",
    "issue_url",
    "cve",
    "cve_url",
    "cwe",
    "fixability",
    "exploit_maturity",
    "first_introduced",
    "issue_type",
    "package_name",
    "installed_version",
    "fixed_version",
    "dependency_path",
    "location",
    "environment",
    "evidence_url",
    "scan_completed_at",
}


def _filter_values(
    profile: dict, source: str, field_name: str, default: list[str]
) -> frozenset[str]:
    supplied = profile.get(field_name, default)
    if (
        not isinstance(supplied, list)
        or not supplied
        or any(not isinstance(value, str) or not value.strip() for value in supplied)
    ):
        raise ConfigurationError(f"Product {source} requires non-empty {field_name}")
    return frozenset(value.strip().casefold() for value in supplied)


def _cell(row: dict, columns: dict, field_name: str, default: str = "") -> str:
    column = columns.get(field_name)
    return (row[column] if column else default).strip()


@dataclass(frozen=True)
class CsvProfile:
    source: str
    name: str
    prefix: str
    columns: dict[str, str]
    critical_values: frozenset[str]
    open_values: frozenset[str]
    schema_version: str = "unverified"
    certification: dict = field(default_factory=dict)
    noncritical_values: frozenset[str] = frozenset({"high", "medium", "low", "info"})
    closed_values: frozenset[str] = frozenset({"closed", "resolved", "ignored"})

    @property
    def fingerprint(self) -> str:
        from identity import digest

        return digest(
            {
                "source": self.source,
                "name": self.name,
                "prefix": self.prefix,
                "columns": self.columns,
                "schema_version": self.schema_version,
                "certification": self.certification,
                "critical": sorted(self.critical_values),
                "open": sorted(self.open_values),
                "noncritical": sorted(self.noncritical_values),
                "closed": sorted(self.closed_values),
            }
        )

    @property
    def certified(self) -> bool:
        return bool(
            self.certification.get("approved_by")
            and self.schema_version != "unverified"
            and re.fullmatch(r"[a-f0-9]{64}", self.certification.get("sample_sha256", ""))
        )

    @property
    def group_label_prefix(self) -> str:
        return f"{self.source}-group"


def load_profiles(config: Config) -> list[CsvProfile]:
    try:
        raw = json.loads(config.product_profiles_json)
    except json.JSONDecodeError as exc:
        raise ConfigurationError("PRODUCT_PROFILES_JSON must contain valid JSON") from exc
    if not isinstance(raw, dict) or len(raw) > 10:
        raise ConfigurationError("PRODUCT_PROFILES_JSON must be an object with at most 10 products")
    profiles = []
    for source, profile in raw.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", source) or source == "snyk":
            raise ConfigurationError("Additional product IDs must be lowercase and cannot be snyk")
        if not isinstance(profile, dict) or set(profile) - {
            "name",
            "prefix",
            "columns",
            "critical_values",
            "open_values",
            "schema_version",
            "certification",
            "noncritical_values",
            "closed_values",
        }:
            raise ConfigurationError(f"Invalid profile properties for {source}")
        name = profile.get("name", source)
        relative_prefix = profile.get("prefix")
        columns = profile.get("columns")
        if not isinstance(name, str) or not name.strip() or len(name) > 80:
            raise ConfigurationError(
                f"Product {source} requires a display name under 80 characters"
            )
        if any(ord(char) < 32 for char in name):
            raise ConfigurationError(f"Product {source} name contains control characters")
        if (
            not isinstance(relative_prefix, str)
            or not relative_prefix
            or relative_prefix.startswith("/")
            or not relative_prefix.endswith("/")
        ):
            raise ConfigurationError(f"Product {source} requires a relative prefix ending in /")
        prefix = config.ingestion_prefix + relative_prefix
        if not prefix.startswith(config.products_prefix) or prefix == config.products_prefix:
            raise ConfigurationError(
                f"Product {source} prefix must be inside PRODUCTS_REPORT_PREFIX"
            )
        if any(prefix.startswith(p.prefix) or p.prefix.startswith(prefix) for p in profiles):
            raise ConfigurationError("Product report prefixes cannot overlap")
        if (
            not isinstance(columns, dict)
            or not REQUIRED_MAPPING.issubset(columns)
            or set(columns) - REQUIRED_MAPPING - OPTIONAL_MAPPING
            or any(not isinstance(value, str) or not value.strip() for value in columns.values())
        ):
            raise ConfigurationError(f"Product {source} requires an explicit CSV column mapping")
        certification = profile.get("certification", {})
        if not isinstance(certification, dict) or set(certification) - {
            "approved_by",
            "sample_sha256",
        }:
            raise ConfigurationError("Certification requires approved_by and sample_sha256")
        if any(not isinstance(v, str) for v in certification.values()):
            raise ConfigurationError("Certification fields must be strings")
        if not isinstance(profile.get("schema_version", "unverified"), str):
            raise ConfigurationError("Profile schema_version must be a string")

        profiles.append(
            CsvProfile(
                source,
                name.strip(),
                prefix,
                columns,
                _filter_values(profile, source, "critical_values", ["Critical"]),
                _filter_values(profile, source, "open_values", ["Open"]),
                str(profile.get("schema_version", "unverified")),
                certification,
                _filter_values(
                    profile, source, "noncritical_values", ["High", "Medium", "Low", "Info"]
                ),
                _filter_values(profile, source, "closed_values", ["Closed", "Resolved", "Ignored"]),
            )
        )
        parsed = profiles[-1]
        if (
            parsed.critical_values & parsed.noncritical_values
            or parsed.open_values & parsed.closed_values
        ):
            raise ConfigurationError("Critical/open profile values cannot overlap excluded values")
    return profiles


def parse_mapped_csv(body: bytes, profile: CsvProfile) -> list[Finding]:
    from functools import partial

    reader = _reader(body)
    _require_columns(reader, set(profile.columns.values()), profile.name)
    findings = []
    saw_row = False
    for index, row in enumerate(reader, start=2):
        if index > 100_001:
            raise ReportValidationError(f"{profile.name} report exceeds 100,000 rows")
        if None in row or any(value is None for value in row.values()):
            raise ReportValidationError(
                f"{profile.name} has an invalid column count on row {index}"
            )
        saw_row = True

        value = partial(_cell, row, profile.columns)

        severity, status = value("severity").casefold(), value("status").casefold()
        # Blank filters indicate an invalid export, not a zero-finding success.
        if not severity or not status:
            raise ReportValidationError(f"Blank severity or status on row {index}")
        if severity not in profile.critical_values | profile.noncritical_values:
            raise ReportValidationError(f"Unknown severity in source contract on row {index}")
        if status not in profile.open_values | profile.closed_values:
            raise ReportValidationError(f"Unknown status in source contract on row {index}")
        if severity not in profile.critical_values or status not in profile.open_values:
            continue
        group, finding_id, title = value("group"), value("finding_id"), value("title")
        for field_name, supplied, limit in (
            ("group", group, 300),
            ("finding_id", finding_id, 300),
            ("title", title, 1000),
        ):
            if not supplied or len(supplied) > limit or any(ord(char) < 32 for char in supplied):
                raise ReportValidationError(f"Invalid {field_name} on row {index}")
        remediation = value("remediation")
        target = value("target", group)
        if len(remediation) > 20_000 or len(target) > 2000 or "\x00" in remediation:
            raise ReportValidationError(f"Oversized target or remediation on row {index}")
        findings.append(
            Finding(
                repository=group,
                target=target,
                snyk_id=finding_id,
                issue_url=_https_url(value("issue_url"), "issue_url", index),
                project_url="",
                cves=_array(value("cve")),
                cve_urls=tuple(
                    _https_url(url, "cve_url", index) for url in _array(value("cve_url"))
                ),
                cwes=_array(value("cwe")),
                problem_title=title,
                score=None,
                exploit_maturity=value("exploit_maturity", "Unknown"),
                fixability=value("fixability", "Unknown"),
                first_introduced=value("first_introduced"),
                product_name=profile.name,
                issue_type=value("issue_type", "Security finding"),
                source=profile.source,
                source_name=profile.name,
                remediation=remediation,
                package_name=value("package_name"),
                installed_version=value("installed_version"),
                fixed_version=value("fixed_version"),
                dependency_path=value("dependency_path"),
                location=value("location", target),
                environment=value("environment"),
                evidence_url=_https_url(value("evidence_url"), "evidence_url", index),
                scan_completed_at=value("scan_completed_at"),
                fix_state="reported_fix"
                if value("remediation") or value("fixed_version")
                else "missing_data",
            )
        )
    if not saw_row:
        raise ReportValidationError(f"{profile.name} report contains no data rows")
    return findings


class MappedCsvAdapter:
    def __init__(self, profile: CsvProfile, report_source) -> None:
        self.profile = profile
        self.source = profile.source
        self.source_name = profile.name
        self.report_source = report_source

    def matches(self, key: str) -> bool:
        return key.startswith(self.profile.prefix)

    def load(self, upload: Upload | None = None) -> FindingBatch:
        if upload is None:
            raise ValueError(f"{self.source_name} requires an explicit upload event")
        report = self.report_source.get_report(
            upload.key,
            allowed_prefix=self.profile.prefix,
            version_id=upload.version_id,
            etag=upload.etag,
        )
        return FindingBatch(
            self.source,
            self.source_name,
            (report,),
            parse_mapped_csv(report.body, self.profile),
            processing_policy=self.processing_policy,
        )

    @property
    def processing_policy(self) -> dict:
        return {"parser_schema": "mapped-csv-v2", "profile_sha256": self.profile.fingerprint}


def campaign_label(source: str, group: str) -> str:
    prefix = "repo" if source == "snyk" else f"{source}-group"
    suffix = hashlib.sha256(group.encode()).hexdigest()[:12]
    return f"{prefix}-{jira_label(group, max_length=65)}-{suffix}"


def enrich_batch(batch: FindingBatch, config: Config, source) -> FindingBatch:
    """An approved producer may supply a versioned, report-bound enrichment sidecar."""
    key = config.enrichment_prefix + batch.reports[-1].key.rsplit("/", 1)[-1] + ".json"
    result = source.get_json(key, config.enrichment_prefix, optional=True)
    if result is None:
        return batch
    value, reference = result
    if value.get("schema") != 1 or value.get("source") != batch.source:
        raise ReportValidationError("Enrichment has the wrong source/schema")
    if value.get("report_sha256") != batch.reports[-1].sha256:
        raise ReportValidationError("Enrichment is not bound to this report")
    if not reference.get("version_id"):
        raise ReportValidationError("Enrichment must be versioned")
    allowed = {
        "package_name",
        "installed_version",
        "fixed_version",
        "dependency_path",
        "location",
        "environment",
        "evidence_url",
        "remediation",
        "fix_state",
        "scan_completed_at",
    }
    facts = {}
    rows = value.get("occurrences")
    if not isinstance(rows, list) or len(rows) > 100_000:
        raise ReportValidationError("Enrichment occurrences must be a bounded array")
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or set(row) - allowed - {"repository", "finding_id", "target"}:
            raise ReportValidationError("Unknown enrichment fields")
        if any(not isinstance(v, str) or len(v) > 20_000 or "\x00" in v for v in row.values()):
            raise ReportValidationError("Enrichment fields must be bounded text")
        identity = tuple(row.get(k, "") for k in ("repository", "finding_id", "target"))
        if not all(identity) or identity in facts:
            raise ReportValidationError("Missing or duplicate occurrence identity")
        supplied = {k: v for k, v in row.items() if k in allowed}
        supplied["evidence_url"] = _https_url(row.get("evidence_url", ""), "evidence_url", index)
        state = row.get("fix_state", "missing_data")
        if state not in {"missing_data", "reported_fix", "no_supported_fix"}:
            raise ReportValidationError("Unknown fix state")
        if state != "missing_data" and not supplied["evidence_url"]:
            raise ReportValidationError("A reported fix/no-fix decision requires a provenance URL")
        if state == "reported_fix" and not row.get("remediation") and not row.get("fixed_version"):
            raise ReportValidationError("Reported fix requires remediation or a supported version")
        facts[identity] = supplied
    known = {(f.repository, f.finding_id, f.target) for f in batch.findings}
    if set(facts) - known:
        raise ReportValidationError(
            "Enrichment refers to findings outside the selected report scope"
        )
    return replace(
        batch,
        findings=[
            replace(f, **facts.get((f.repository, f.finding_id, f.target), {}))
            for f in batch.findings
        ],
        enrichment=reference,
    )
