from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import date, datetime


def _digest(value: str, length: int = 20) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def jira_label(value: str, *, max_length: int = 255) -> str:
    normalized = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    normalized = re.sub(r"-{2,}", "-", normalized)
    if not normalized:
        normalized = f"value-{_digest(value)}"
    if len(normalized) > max_length:
        normalized = f"{normalized[: max_length - 21].rstrip('-')}-{_digest(value)}"
    return normalized


@dataclass(frozen=True)
class ReportObject:
    bucket: str
    key: str
    last_modified: datetime
    report_date: date | None
    body: bytes
    version_id: str | None = None
    content_sha256: str = ""

    @property
    def sha256(self) -> str:
        return self.content_sha256 or hashlib.sha256(self.body).hexdigest()


@dataclass(frozen=True)
class RiskSummary:
    critical_total: int
    categories: dict[str, int]


@dataclass(frozen=True)
class AttachmentFile:
    s3_key: str
    filename: str
    content_type: str
    body: bytes
    version_id: str = ""

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    @property
    def jira_filename(self) -> str:
        name = self.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        name = "".join(char if ord(char) >= 32 and char not in {'"', ";"} else "_" for char in name)
        name = name.encode("ascii", "replace").decode("ascii").strip(" .") or "attachment"
        if "." in name and not name.startswith("."):
            stem, suffix = name.rsplit(".", 1)
            rendered = f"{stem[:150]}--{self.sha256[:32]}.{suffix[:20]}"
        else:
            rendered = f"{name[:170]}--{self.sha256[:32]}"
        return rendered


@dataclass(frozen=True)
class Finding:
    repository: str
    target: str
    snyk_id: str
    issue_url: str
    project_url: str
    cves: tuple[str, ...]
    cve_urls: tuple[str, ...]
    cwes: tuple[str, ...]
    problem_title: str
    score: int | None
    exploit_maturity: str
    fixability: str
    first_introduced: str
    product_name: str
    issue_type: str
    source: str = "snyk"
    source_name: str = "Snyk"
    remediation: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    dependency_path: str = ""
    location: str = ""
    environment: str = ""
    evidence_url: str = ""
    fix_state: str = "missing_data"
    scan_completed_at: str = ""
    observation_note: str = ""

    @property
    def finding_id(self) -> str:
        # Keep the original field for compatibility with Snyk attachments and callers.
        return self.snyk_id

    @property
    def group_key(self) -> str:
        return f"{self.source}\n{self.repository}\n{self.finding_id}"


@dataclass
class FindingGroup:
    repository: str
    snyk_id: str
    problem_title: str
    issue_url: str
    product_name: str
    exploit_maturity: str
    fixability: str
    issue_type: str
    score: int | None = None
    first_introduced: str = ""
    targets: set[str] = field(default_factory=set)
    project_urls: set[str] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    cve_urls: set[str] = field(default_factory=set)
    cwes: set[str] = field(default_factory=set)
    source: str = "snyk"
    source_name: str = "Snyk"
    remediations: set[str] = field(default_factory=set)
    occurrences: list[Finding] = field(default_factory=list)

    @property
    def finding_id(self) -> str:
        return self.snyk_id

    @classmethod
    def from_finding(cls, finding: Finding) -> FindingGroup:
        group = cls(
            repository=finding.repository,
            snyk_id=finding.snyk_id,
            problem_title=finding.problem_title,
            issue_url=finding.issue_url,
            product_name=finding.product_name,
            exploit_maturity=finding.exploit_maturity,
            fixability=finding.fixability,
            issue_type=finding.issue_type,
            score=finding.score,
            first_introduced=finding.first_introduced,
            source=finding.source,
            source_name=finding.source_name,
        )
        group.add(finding)
        return group

    def add(self, finding: Finding) -> None:
        if (finding.source, finding.repository, finding.finding_id) != (
            self.source,
            self.repository,
            self.finding_id,
        ):
            raise ValueError("Cannot merge findings with different source, group, or finding ID")
        self.targets.add(finding.target)
        if finding not in self.occurrences:
            self.occurrences.append(finding)
        if finding.project_url:
            self.project_urls.add(finding.project_url)
        self.cves.update(finding.cves)
        self.cve_urls.update(finding.cve_urls)
        self.cwes.update(finding.cwes)
        if finding.remediation:
            self.remediations.add(finding.remediation)
        if finding.score is not None:
            self.score = max(self.score or finding.score, finding.score)
        if finding.first_introduced and (
            not self.first_introduced or finding.first_introduced < self.first_introduced
        ):
            self.first_introduced = finding.first_introduced

    @property
    def fingerprint(self) -> str:
        material = f"{self.repository}\n{self.finding_id}"
        if self.source != "snyk":
            material = f"{self.source}\n{material}"
        return _digest(material, 24)

    @property
    def automation_label(self) -> str:
        return f"{self.source}-auto-{self.fingerprint}"

    @property
    def repository_label(self) -> str:
        slug = jira_label(self.repository, max_length=80)
        prefix = "repo" if self.source == "snyk" else f"{self.source}-group"
        return f"{prefix}-{slug}"


@dataclass
class RunSummary:
    report_date: str
    dry_run: bool
    critical_findings: int
    remediation_groups: int
    repositories: int
    epics_created: int = 0
    epics_reused: int = 0
    tickets_created: int = 0
    tickets_reused: int = 0
    tickets_updated: int = 0
    attachments_uploaded: int = 0
    attachments_reused: int = 0
    actions: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    status: str = "RUNNING"

    def as_dict(self) -> dict[str, object]:
        return {
            "report_date": self.report_date,
            "dry_run": self.dry_run,
            "status": self.status,
            "critical_findings": self.critical_findings,
            "remediation_groups": self.remediation_groups,
            "repositories": self.repositories,
            "epics_created": self.epics_created,
            "epics_reused": self.epics_reused,
            "tickets_created": self.tickets_created,
            "tickets_reused": self.tickets_reused,
            "tickets_updated": self.tickets_updated,
            "attachments_uploaded": self.attachments_uploaded,
            "attachments_reused": self.attachments_reused,
            "warnings": self.warnings,
            "actions": self.actions,
        }
