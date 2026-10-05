from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

# Application-owned settings only. AWS credentials and reserved Lambda variables
# come from IAM/the SDK, never from the tracked configuration templates.
ENVIRONMENT_DEFAULTS = {
    "INPUT_BUCKET": "",
    "INGESTION_PREFIX": "",
    "RISK_REPORT_PREFIX": "snyk/risk-exposure/",
    "ISSUES_REPORT_PREFIX": "snyk/issues-detail/",
    "ATTACHMENT_PREFIX": "snyk/attachments/",
    "PRODUCTS_REPORT_PREFIX": "products/",
    "PRODUCT_PROFILES_JSON": "{}",
    "JIRA_SECRET_ARN": "",
    "JIRA_PROJECT_KEY": "",
    "JIRA_EPIC_ISSUE_TYPE": "Epic",
    "JIRA_CHILD_ISSUE_TYPE": "Bug",
    "JIRA_PRIORITY_NAME": "Major",
    "JIRA_ALLOWED_HOST_SUFFIX": "atlassian.net",
    "JIRA_ORIGIN": "",
    "STATE_TABLE_NAME": "",
    "AUDIT_BUCKET": "",
    "SUMMARY_TOPIC_ARN": "",
    "UPLOAD_QUEUE_URL": "",
    "POLICY_KEY": "",
    "POLICY_SHA256": "",
    "MAX_INPUT_AGE_HOURS": "36",
    "MAX_INPUT_BYTES": "20971520",
    "MAX_ATTACHMENT_BYTES": "10485760",
    "MAX_ATTACHMENTS_PER_RUN": "20",
    "ALLOWED_ATTACHMENT_TYPES": (
        "text/csv,text/plain,application/json,application/pdf,image/png,image/jpeg"
    ),
    "REQUIRE_CLEAN_ATTACHMENT_TAG": "true",
    "ENFORCE_COUNT_MATCH": "true",
    "REQUIRE_SAME_REPORT_DATE": "true",
    "UPDATE_EXISTING_TITLES": "true",
    "DRY_RUN": "true",
    "ACTIVATION_APPROVED": "false",
    "MAX_GROUPS_PER_RUN": "5000",
    "MAX_GROUPS_PER_INVOCATION": "20",
    "MAX_NEW_TICKETS": "50",
    "WORK_SECONDS": "240",
    "PAIR_WAIT_HOURS": "4",
    "STATE_RETENTION_DAYS": "90",
    "LOG_LEVEL": "INFO",
}


class ConfigurationError(ValueError):
    """Raised when required runtime configuration is missing or unsafe."""


def _boolean(name: str, default: bool, env: Mapping[str, str]) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _positive_int(name: str, default: int, env: Mapping[str, str]) -> int:
    raw = env.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be greater than zero")
    limits = {
        "MAX_INPUT_AGE_HOURS": 168,
        "MAX_INPUT_BYTES": 20 * 1024 * 1024,
        "MAX_ATTACHMENT_BYTES": 10 * 1024 * 1024,
        "MAX_ATTACHMENTS_PER_RUN": 20,
        "MAX_GROUPS_PER_RUN": 5000,
        "MAX_GROUPS_PER_INVOCATION": 100,
        "MAX_NEW_TICKETS": 10000,
        "WORK_SECONDS": 240,
        "PAIR_WAIT_HOURS": 72,
        "STATE_RETENTION_DAYS": 2555,
    }
    if value > limits.get(name, value):
        raise ConfigurationError(f"{name} exceeds its supported safety limit")
    return value


def _required(name: str, env: Mapping[str, str]) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class Config:
    input_bucket: str
    risk_prefix: str
    issues_prefix: str
    attachment_prefix: str
    jira_secret_arn: str
    jira_project_key: str
    jira_epic_issue_type: str
    jira_child_issue_type: str
    jira_priority_name: str
    jira_allowed_host_suffix: str
    state_table_name: str
    summary_topic_arn: str | None
    max_input_age_hours: int
    max_input_bytes: int
    max_attachment_bytes: int
    max_attachments_per_run: int
    allowed_attachment_types: frozenset[str]
    require_clean_attachment_tag: bool
    enforce_count_match: bool
    require_same_report_date: bool
    update_existing_titles: bool
    dry_run_default: bool
    ingestion_prefix: str = ""
    products_prefix: str = "products/"
    product_profiles_json: str = "{}"
    jira_origin: str = ""
    activation_approved: bool = False
    audit_bucket: str = ""
    policy_key: str = ""
    policy_sha256: str = ""
    max_groups_per_run: int = 5000
    max_groups_per_invocation: int = 20
    max_new_tickets: int = 50
    work_seconds: int = 240
    pair_wait_hours: int = 4
    upload_queue_url: str = ""
    state_retention_days: int = 90
    log_level: str = "INFO"

    @property
    def configuration_prefix(self) -> str:
        return self.ingestion_prefix + "configuration/"

    @property
    def enrichment_prefix(self) -> str:
        return self.ingestion_prefix + "enrichment/"

    @property
    def verification_prefix(self) -> str:
        return self.ingestion_prefix + "verification/"

    @classmethod
    def from_env(cls) -> Config:
        return cls.from_mapping(os.environ)

    @classmethod
    def from_mapping(cls, values: Mapping[str, str]) -> Config:
        # Blank template values mean use the safe default, not an empty boolean/int.
        env = {
            name: values.get(name, "").strip() or value
            for name, value in ENVIRONMENT_DEFAULTS.items()
        }
        project_key = _required("JIRA_PROJECT_KEY", env).upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", project_key):
            raise ConfigurationError("JIRA_PROJECT_KEY contains unsupported characters")

        ingestion_prefix = env.get("INGESTION_PREFIX", "").strip()
        if ingestion_prefix and (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_-]*/", ingestion_prefix)
        ):
            raise ConfigurationError(
                "INGESTION_PREFIX must be empty or a relative folder ending in /"
            )

        def folder(name: str, default: str) -> str:
            relative = env.get(name, default).strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_-]*/", relative):
                raise ConfigurationError(f"{name} must be a relative folder ending in /")
            return ingestion_prefix + relative

        risk_prefix = folder("RISK_REPORT_PREFIX", "snyk/risk-exposure/")
        issues_prefix = folder("ISSUES_REPORT_PREFIX", "snyk/issues-detail/")
        attachment_prefix = folder("ATTACHMENT_PREFIX", "snyk/attachments/")
        products_prefix = folder("PRODUCTS_REPORT_PREFIX", "products/")
        prefixes = {risk_prefix, issues_prefix, attachment_prefix, products_prefix}
        if len(prefixes) != 4:
            raise ConfigurationError("Report and attachment prefixes must be distinct")
        for first in prefixes:
            for second in prefixes:
                if first != second and first.startswith(second):
                    raise ConfigurationError("Report and attachment prefixes cannot overlap")
            for protected in ("configuration/", "enrichment/", "verification/"):
                reserved = ingestion_prefix + protected
                if first.startswith(reserved) or reserved.startswith(first):
                    raise ConfigurationError(
                        "Report folders cannot overlap protected settings/evidence"
                    )

        allowed_types = frozenset(
            item.strip().lower()
            for item in env.get(
                "ALLOWED_ATTACHMENT_TYPES",
                "text/csv,text/plain,application/json,application/pdf,image/png,image/jpeg",
            ).split(",")
            if item.strip()
        )
        if not allowed_types or any(
            not re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", t) for t in allowed_types
        ):
            raise ConfigurationError("ALLOWED_ATTACHMENT_TYPES cannot be empty")

        topic = env.get("SUMMARY_TOPIC_ARN", "").strip() or None
        origin = _required("JIRA_ORIGIN", env)
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not re.fullmatch(r"[a-z0-9-]+[.]atlassian[.]net", parsed.netloc)
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ConfigurationError("JIRA_ORIGIN must be an exact HTTPS Jira Cloud origin")
        if env["JIRA_ALLOWED_HOST_SUFFIX"] != "atlassian.net":
            raise ConfigurationError("This deployment supports the atlassian.net host suffix only")
        if env["LOG_LEVEL"] not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigurationError("LOG_LEVEL is unsupported")
        return cls(
            input_bucket=_required("INPUT_BUCKET", env),
            risk_prefix=risk_prefix,
            issues_prefix=issues_prefix,
            attachment_prefix=attachment_prefix,
            jira_secret_arn=_required("JIRA_SECRET_ARN", env),
            jira_project_key=project_key,
            jira_epic_issue_type=env.get("JIRA_EPIC_ISSUE_TYPE", "Epic").strip() or "Epic",
            jira_child_issue_type=env.get("JIRA_CHILD_ISSUE_TYPE", "Bug").strip() or "Bug",
            jira_priority_name=env.get("JIRA_PRIORITY_NAME", "Major").strip() or "Major",
            jira_allowed_host_suffix=env.get("JIRA_ALLOWED_HOST_SUFFIX", "atlassian.net")
            .strip()
            .lower(),
            state_table_name=_required("STATE_TABLE_NAME", env),
            summary_topic_arn=topic,
            max_input_age_hours=_positive_int("MAX_INPUT_AGE_HOURS", 36, env),
            max_input_bytes=_positive_int("MAX_INPUT_BYTES", 20 * 1024 * 1024, env),
            max_attachment_bytes=_positive_int("MAX_ATTACHMENT_BYTES", 10 * 1024 * 1024, env),
            max_attachments_per_run=_positive_int("MAX_ATTACHMENTS_PER_RUN", 20, env),
            allowed_attachment_types=allowed_types,
            require_clean_attachment_tag=_boolean("REQUIRE_CLEAN_ATTACHMENT_TAG", True, env),
            enforce_count_match=_boolean("ENFORCE_COUNT_MATCH", True, env),
            require_same_report_date=_boolean("REQUIRE_SAME_REPORT_DATE", True, env),
            update_existing_titles=_boolean("UPDATE_EXISTING_TITLES", True, env),
            dry_run_default=_boolean("DRY_RUN", True, env),
            ingestion_prefix=ingestion_prefix,
            products_prefix=products_prefix,
            product_profiles_json=env.get("PRODUCT_PROFILES_JSON", "{}").strip(),
            jira_origin=origin,
            activation_approved=_boolean("ACTIVATION_APPROVED", False, env),
            audit_bucket=env.get("AUDIT_BUCKET", "").strip(),
            policy_key=env.get("POLICY_KEY", "").strip(),
            policy_sha256=env.get("POLICY_SHA256", "").strip(),
            max_groups_per_run=_positive_int("MAX_GROUPS_PER_RUN", 5000, env),
            max_groups_per_invocation=_positive_int("MAX_GROUPS_PER_INVOCATION", 20, env),
            max_new_tickets=_positive_int("MAX_NEW_TICKETS", 50, env),
            work_seconds=_positive_int("WORK_SECONDS", 240, env),
            pair_wait_hours=_positive_int("PAIR_WAIT_HOURS", 4, env),
            upload_queue_url=env.get("UPLOAD_QUEUE_URL", "").strip(),
            state_retention_days=_positive_int("STATE_RETENTION_DAYS", 90, env),
            log_level=env["LOG_LEVEL"],
        )
