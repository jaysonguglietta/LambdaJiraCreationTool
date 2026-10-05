"""Approved deployment policy, not instructions taken from report content."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from config import ConfigurationError
from identity import digest


@dataclass(frozen=True)
class Policy:
    owners: tuple[dict, ...] = ()
    adoptions: tuple[dict, ...] = ()
    custom_fields: dict = field(default_factory=dict)
    transitions: dict = field(default_factory=dict)
    retired_sources: tuple[str, ...] = ()
    triage_name: str = "Security triage: needs-owner"
    triage_account_id: str = ""
    schema: int = 1
    reconciliations: tuple[dict, ...] = ()

    @classmethod
    def parse(cls, value: dict) -> Policy:
        allowed = {
            "schema",
            "owners",
            "adoptions",
            "custom_fields",
            "transitions",
            "retired_sources",
            "triage_name",
            "triage_account_id",
            "reconciliations",
        }
        if not isinstance(value, dict) or set(value) - allowed or value.get("schema", 1) != 1:
            raise ConfigurationError("Unknown policy schema/properties")
        owners, adoptions = value.get("owners", []), value.get("adoptions", [])
        if not isinstance(owners, list) or not isinstance(adoptions, list):
            raise ConfigurationError("Policy owners/adoptions must be arrays")
        if len(owners) > 10000 or len(adoptions) > 10000:
            raise ConfigurationError("Policy routing/adoption rules exceed the bounded limit")
        if len({v.get("jira_key") for v in adoptions if isinstance(v, dict)}) != len(adoptions):
            raise ConfigurationError("Each adoption must use a distinct Jira destination")
        for entries, fields in (
            (owners, {"source", "repository", "account_id", "priority", "sla_hours"}),
            (adoptions, {"source", "repository", "finding_id", "jira_key"}),
        ):
            seen = set()
            for item in entries:
                if not isinstance(item, dict) or set(item) - fields:
                    raise ConfigurationError("Unknown ownership/adoption fields")
                if not all(
                    isinstance(item.get(key), str) and item[key].strip()
                    for key in ("source", "repository")
                ):
                    raise ConfigurationError("Ownership/adoption requires source and repository")
                identity = (item["source"], item["repository"], item.get("finding_id", ""))
                if identity in seen:
                    raise ConfigurationError("Duplicate ownership/adoption rule")
                seen.add(identity)
                if entries is adoptions and not re.fullmatch(
                    r"[A-Z][A-Z0-9_]*-\d+", item.get("jira_key", "")
                ):
                    raise ConfigurationError("Adoption requires a valid destination Jira key")
                if "sla_hours" in item and (
                    type(item["sla_hours"]) is not int or not 1 <= item["sla_hours"] <= 8760
                ):
                    raise ConfigurationError("SLA hours must be an integer from 1 to 8760")
                for key in ("account_id", "priority", "finding_id"):
                    if key in item and not isinstance(item[key], str):
                        raise ConfigurationError(f"Policy {key} must be a string")
        custom = value.get("custom_fields", {})
        if not isinstance(custom, dict) or set(custom) - {"campaign", "finding"}:
            raise ConfigurationError("Custom fields must use campaign/finding sections")
        for section in custom.values():
            if not isinstance(section, dict) or any(
                not re.fullmatch(r"customfield_\d+", key) for key in section
            ):
                raise ConfigurationError("Only explicit Jira customfield IDs may be supplied")
        transitions = value.get("transitions", {})
        if not isinstance(transitions, dict) or set(transitions) - {"verified", "reopen"}:
            raise ConfigurationError("Transitions must be verified/reopen IDs")
        if any(not isinstance(v, str) or not v.isdigit() for v in transitions.values()):
            raise ConfigurationError("Transition IDs must be numeric strings")
        retired = value.get("retired_sources", [])
        if not isinstance(retired, list) or any(not isinstance(v, str) for v in retired):
            raise ConfigurationError("retired_sources must be an array of source IDs")
        for name in ("triage_name", "triage_account_id"):
            if name in value and not isinstance(value[name], str):
                raise ConfigurationError(f"{name} must be a string")
        reconciliations = value.get("reconciliations", [])
        allowed_reconciliation = {
            "risk_sha256",
            "issues_sha256",
            "risk_count",
            "detail_count",
            "approved_by",
            "reason",
            "expires_at",
        }
        if not isinstance(reconciliations, list) or len(reconciliations) > 100:
            raise ConfigurationError("Reconciliations must be a bounded array")
        for approval in reconciliations:
            if not isinstance(approval, dict) or set(approval) != allowed_reconciliation:
                raise ConfigurationError(
                    "Reconciliation requires exact report hashes, counts and approval"
                )
            if any(
                not isinstance(approval[name], str)
                or not re.fullmatch(r"[a-f0-9]{64}", approval[name])
                for name in ("risk_sha256", "issues_sha256")
            ):
                raise ConfigurationError("Reconciliation hashes must be SHA-256 strings")
            if any(
                type(approval[name]) is not int or approval[name] < 0
                for name in ("risk_count", "detail_count")
            ):
                raise ConfigurationError("Reconciliation counts must be nonnegative integers")
            if any(
                not isinstance(approval[name], str) or not approval[name].strip()
                for name in ("approved_by", "reason", "expires_at")
            ):
                raise ConfigurationError("Reconciliation requires a reviewer, reason and expiry")
            try:
                expiry = datetime.fromisoformat(approval["expires_at"])
                if expiry.tzinfo is None or expiry > datetime.now(UTC) + timedelta(hours=72):
                    raise ValueError
            except ValueError as exc:
                raise ConfigurationError(
                    "Reconciliation needs a timezone-aware expiry within 72 hours"
                ) from exc
        return cls(
            tuple(owners),
            tuple(adoptions),
            custom,
            transitions,
            tuple(retired),
            value.get("triage_name", cls.triage_name),
            value.get("triage_account_id", ""),
            reconciliations=tuple(reconciliations),
        )

    @property
    def fingerprint(self) -> str:
        from dataclasses import asdict

        return digest(asdict(self))

    def adoption(self, source: str, repository: str, finding_id: str = "") -> str | None:
        return next(
            (
                item["jira_key"]
                for item in self.adoptions
                if (item["source"], item["repository"], item.get("finding_id", ""))
                == (source, repository, finding_id)
            ),
            None,
        )

    def reconciliation(
        self, risk_hash: str, issues_hash: str, risk_count: int, detail_count: int
    ) -> dict | None:
        return next(
            (
                item
                for item in self.reconciliations
                if (
                    item["risk_sha256"],
                    item["issues_sha256"],
                    item["risk_count"],
                    item["detail_count"],
                )
                == (risk_hash, issues_hash, risk_count, detail_count)
                and datetime.fromisoformat(item["expires_at"]) > datetime.now(UTC)
            ),
            None,
        )

    def route(self, source: str, repository: str, first_seen: str, default_priority: str) -> dict:
        owner = next(
            (
                item
                for item in self.owners
                if (item["source"], item["repository"]) == (source, repository)
            ),
            {},
        )
        account = owner.get("account_id") or self.triage_account_id
        fields = {"priority": {"name": owner.get("priority", default_priority)}}
        if account:
            fields["assignee"] = {"accountId": account}
        if "sla_hours" in owner:
            introduced = datetime.fromisoformat(first_seen).astimezone(UTC)
            fields["duedate"] = (
                (introduced + timedelta(hours=owner["sla_hours"])).date().isoformat()
            )
        return {
            "fields": fields,
            "owner": account or self.triage_name,
            "needs_owner": not bool(owner.get("account_id")),
        }


def load_policy(config, source) -> Policy:
    if bool(config.policy_key) != bool(config.policy_sha256):
        raise ConfigurationError("POLICY_KEY and approved POLICY_SHA256 must be supplied together")
    if not config.policy_key:
        return Policy()
    if not re.fullmatch(r"[a-f0-9]{64}", config.policy_sha256):
        raise ConfigurationError("POLICY_SHA256 must be a lowercase SHA-256")
    result = source.get_json(
        config.policy_key, config.configuration_prefix, sha256=config.policy_sha256
    )
    return Policy.parse(result[0])


def policy_json(policy: Policy) -> str:
    from dataclasses import asdict

    return json.dumps(asdict(policy), sort_keys=True)
