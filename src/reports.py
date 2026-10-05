from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse

from models import Finding, FindingGroup, RiskSummary


class ReportValidationError(ValueError):
    """Raised when an input report is incomplete, malformed, or inconsistent."""


ISSUE_REQUIRED_COLUMNS = {
    "ISSUE_SEVERITY",
    "SCORE",
    "PROBLEM_TITLE",
    "CVE",
    "CVE_URL",
    "CWE",
    "PROJECT_NAME",
    "PROJECT_URL",
    "EXPLOIT_MATURITY",
    "COMPUTED_FIXABILITY",
    "FIRST_INTRODUCED",
    "PRODUCT_NAME",
    "ISSUE_URL",
    "ISSUE_STATUS_INDICATOR",
    "ISSUE_TYPE",
}

RISK_REQUIRED_COLUMNS = {
    "INTRODUCTION_CATEGORY",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "IMPACTED_ASSETS",
    "ASSET_IDS",
}

SNYK_ID_PATTERN = re.compile(r"(?:#|[?&])issue-([A-Za-z0-9._-]+)")


class SafeDictReader(csv.DictReader):
    def __next__(self):
        try:
            row = super().__next__()
        except csv.Error as exc:
            raise ReportValidationError(f"Malformed CSV near row {self.line_num}") from exc
        self.total_rows = getattr(self, "total_rows", 0) + 1
        if self.total_rows > 50000:
            raise ReportValidationError("CSV exceeds the 50,000-row safety limit")
        for value in row.values():
            if isinstance(value, str) and (
                len(value) > 20000 or any(ord(c) < 32 and c not in "\n\r\t" for c in value)
            ):
                raise ReportValidationError(f"Unsafe/oversized cell near row {self.line_num}")
        return row


def _reader(body: bytes) -> csv.DictReader:
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ReportValidationError("CSV must be UTF-8 encoded") from exc
    if "\x00" in text:
        raise ReportValidationError("CSV contains NUL bytes")
    csv.field_size_limit(20000)
    return SafeDictReader(io.StringIO(text, newline=""), strict=True)


def _require_columns(reader: csv.DictReader, required: set[str], report_name: str) -> None:
    try:
        fieldnames = reader.fieldnames or []
    except csv.Error as exc:
        raise ReportValidationError("Malformed CSV headers") from exc
    if len(fieldnames) > 100 or any(not name or len(name) > 256 for name in fieldnames):
        raise ReportValidationError("CSV has blank, oversized or too many headers")
    headers = set(fieldnames)
    if len(fieldnames) != len(headers):
        raise ReportValidationError(f"{report_name} contains duplicate column names")
    missing = sorted(required - headers)
    if missing:
        raise ReportValidationError(f"{report_name} is missing columns: {', '.join(missing)}")


def _integer(value: str, field_name: str, *, allow_blank: bool = False) -> int | None:
    raw = (value or "").strip()
    if not raw and allow_blank:
        return None
    try:
        number = Decimal(raw)
        if not number.is_finite() or number != number.to_integral_value():
            raise ValueError
        if abs(number) > 1_000_000_000:
            raise ValueError
        return int(number)
    except (InvalidOperation, ValueError, OverflowError) as exc:
        raise ReportValidationError(f"Invalid integer in {field_name}") from exc


def _array(value: str) -> tuple[str, ...]:
    raw = (value or "").strip()
    if not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = [part.strip() for part in re.split(r"[;,]", raw) if part.strip()]
    if isinstance(parsed, str):
        parsed = [parsed]
    if not isinstance(parsed, list):
        raise ReportValidationError("Expected a JSON array or delimited list")
    if len(parsed) > 500 or any(not isinstance(item, str) for item in parsed):
        raise ReportValidationError("Reference arrays require at most 500 strings")
    return tuple(sorted({str(item).strip() for item in parsed if str(item).strip()}))


def _repository_and_target(project_name: str) -> tuple[str, str]:
    value = (project_name or "").strip()
    if not value:
        raise ReportValidationError("PROJECT_NAME cannot be blank")
    repository, separator, target = value.partition(":")
    repository = repository.strip()
    target = target.strip() if separator else "(project root)"
    if not repository or repository in {".", ".."}:
        raise ReportValidationError(f"Invalid repository in PROJECT_NAME: {value!r}")
    if any(ord(char) < 32 for char in repository + target):
        raise ReportValidationError("PROJECT_NAME contains control characters")
    if len(repository) > 300 or len(target) > 2000:
        raise ReportValidationError("PROJECT_NAME exceeds the supported length")
    return repository, target or "(project root)"


def _https_url(value: str, field_name: str, row_number: int, *, snyk_host: bool = False) -> str:
    url = (value or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        raise ReportValidationError(
            f"{field_name} must use credential-free HTTPS on row {row_number}"
        )
    if snyk_host and host != "snyk.io" and not host.endswith(".snyk.io"):
        raise ReportValidationError(f"{field_name} must use a Snyk host on row {row_number}")
    if len(url) > 4096:
        raise ReportValidationError(f"{field_name} is too long on row {row_number}")
    return url


def _snyk_id(issue_url: str, row: dict[str, str]) -> str:
    match = SNYK_ID_PATTERN.search(issue_url or "")
    if match:
        return match.group(1)
    direct = re.search(r"/vuln/(SNYK-[A-Za-z0-9._-]+)(?:$|[?#])", issue_url or "")
    if direct:
        return direct.group(1)
    raise ReportValidationError("Critical Snyk finding lacks a stable source issue ID")


def parse_risk_report(body: bytes) -> RiskSummary:
    reader = _reader(body)
    _require_columns(reader, RISK_REQUIRED_COLUMNS, "Risk Exposure report")
    categories: dict[str, int] = {}
    for index, row in enumerate(reader, start=2):
        if index > 100_001:
            raise ReportValidationError("Risk Exposure report exceeds 100,000 rows")
        if None in row or any(value is None for value in row.values()):
            raise ReportValidationError(f"Risk Exposure report has extra columns on row {index}")
        category = (row.get("INTRODUCTION_CATEGORY") or "").strip()
        if not category:
            raise ReportValidationError(f"Blank introduction category on row {index}")
        critical = _integer(row.get("CRITICAL", ""), f"CRITICAL row {index}")
        if critical is None or critical < 0:
            raise ReportValidationError(f"Negative Critical count on row {index}")
        categories[category] = categories.get(category, 0) + critical
    if not categories:
        raise ReportValidationError("Risk Exposure report contains no data rows")
    return RiskSummary(critical_total=sum(categories.values()), categories=categories)


def parse_issue_report(body: bytes, *, allow_empty: bool = False) -> list[Finding]:
    reader = _reader(body)
    _require_columns(reader, ISSUE_REQUIRED_COLUMNS, "Issues Detail report")
    findings: list[Finding] = []
    saw_row = False
    for index, row in enumerate(reader, start=2):
        if index > 100_001:
            raise ReportValidationError("Issues Detail report exceeds 100,000 rows")
        if None in row or any(value is None for value in row.values()):
            raise ReportValidationError(f"Issues Detail report has extra columns on row {index}")
        saw_row = True
        severity = (row.get("ISSUE_SEVERITY") or "").strip().casefold()
        status = (row.get("ISSUE_STATUS_INDICATOR") or "").strip().casefold()
        if severity not in {"critical", "high", "medium", "low", "info", "informational"}:
            raise ReportValidationError(f"Blank or unknown severity on row {index}")
        if status not in {"open", "closed", "resolved", "ignored"}:
            raise ReportValidationError(f"Blank or unknown status on row {index}")
        if severity != "critical" or status != "open":
            continue
        repository, target = _repository_and_target(row.get("PROJECT_NAME", ""))
        issue_url = _https_url(row.get("ISSUE_URL", ""), "ISSUE_URL", index, snyk_host=True)
        project_url = _https_url(row.get("PROJECT_URL", ""), "PROJECT_URL", index, snyk_host=True)
        cve_urls = tuple(
            _https_url(url, "CVE_URL", index) for url in _array(row.get("CVE_URL", ""))
        )
        findings.append(
            Finding(
                repository=repository,
                target=target,
                snyk_id=_snyk_id(issue_url, row),
                issue_url=issue_url,
                project_url=project_url,
                cves=_array(row.get("CVE", "")),
                cve_urls=cve_urls,
                cwes=_array(row.get("CWE", "")),
                problem_title=(row.get("PROBLEM_TITLE") or "Unspecified vulnerability").strip(),
                score=_integer(row.get("SCORE", ""), f"SCORE row {index}", allow_blank=True),
                exploit_maturity=(row.get("EXPLOIT_MATURITY") or "Unknown").strip(),
                fixability=(row.get("COMPUTED_FIXABILITY") or "Unknown").strip(),
                first_introduced=(row.get("FIRST_INTRODUCED") or "").strip(),
                product_name=(row.get("PRODUCT_NAME") or "Snyk").strip(),
                issue_type=(row.get("ISSUE_TYPE") or "Vulnerability").strip(),
                package_name=(row.get("PACKAGE_NAME") or "").strip(),
                installed_version=(row.get("INSTALLED_VERSION") or "").strip(),
                fixed_version=(row.get("FIXED_VERSION") or "").strip(),
                dependency_path=(row.get("DEPENDENCY_PATH") or "").strip(),
                location=(row.get("LOCATION") or target).strip(),
                environment=(row.get("ENVIRONMENT") or "").strip(),
                remediation=(row.get("REMEDIATION") or "").strip(),
                scan_completed_at=(row.get("SCAN_COMPLETED_AT") or "").strip(),
                evidence_url=_https_url(row.get("EVIDENCE_URL", ""), "EVIDENCE_URL", index),
                fix_state="reported_fix"
                if (row.get("FIXED_VERSION") or "").strip()
                or (row.get("REMEDIATION") or "").strip()
                else "missing_data",
            )
        )
    if not saw_row and not allow_empty:
        raise ReportValidationError("Issues Detail report contains no data rows")
    return findings


def group_findings(findings: Iterable[Finding]) -> list[FindingGroup]:
    grouped: dict[str, FindingGroup] = {}
    for finding in findings:
        if finding.group_key not in grouped:
            grouped[finding.group_key] = FindingGroup.from_finding(finding)
        else:
            grouped[finding.group_key].add(finding)
    return sorted(grouped.values(), key=lambda item: (item.repository.casefold(), item.snyk_id))


def validate_report_counts(risk: RiskSummary, findings: list[Finding], enforce: bool) -> list[str]:
    if risk.critical_total == len(findings):
        return []
    message = (
        "Critical count mismatch: Risk Exposure reports "
        f"{risk.critical_total}, but Issues Detail contains {len(findings)} open Critical rows"
    )
    if enforce:
        raise ReportValidationError(message)
    return [message]
