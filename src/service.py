from __future__ import annotations

import re
import time
import uuid
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import UTC, datetime

from budget import Budget, BudgetExhausted
from identity import PROPERTY_KEY, Identity, digest
from jira_client import IdentityReviewRequired, JiraClient, JiraCredentials
from lifecycle import validate_evidence
from models import Finding, FindingGroup, RunSummary, jira_label
from policy import load_policy
from products import FindingBatch, SnykAdapter
from reports import group_findings
from state_store import StateStore
from ticketing import (
    RENDERER_VERSION,
    child_description,
    child_labels,
    child_title,
    disposition_description,
    epic_description,
    epic_labels,
    epic_title,
    managed_hash,
    refresh_description,
)
from upload_events import Upload


class IdempotencyConflict(RuntimeError):
    """Another writer holds the current job or mapping claim."""


class ReviewRequired(ValueError):
    """A human must resolve identity, volume, or lifecycle ambiguity."""


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


class AutomationService:
    def __init__(
        self,
        config,
        source,
        secret_loader,
        state_store,
        publisher,
        jira_factory=JiraClient,
        adapter=None,
        *,
        audit_store=None,
        policy=None,
        continuation=None,
        budget=None,
        batch_ready=None,
    ):
        self.config, self.source = config, source
        self.secret_loader, self.state, self.publisher = secret_loader, state_store, publisher
        self.jira_factory, self.adapter = jira_factory, adapter or SnykAdapter(config, source)
        self.audit, self.policy = audit_store, policy
        self.continuation, self.budget = continuation, budget or Budget(config.work_seconds)
        self.batch_ready = batch_ready

    def _jira(self, dry_run: bool = True):
        if self.policy is None:
            self.policy = load_policy(self.config, self.source)
        if not dry_run:
            if not self.config.activation_approved:
                raise ReviewRequired(
                    "Activation is not approved; use a dry run and setup check first"
                )
            if self.audit is None:
                raise ReviewRequired("Live operations require a versioned audit store")
            if not self.config.require_clean_attachment_tag:
                raise ReviewRequired("Live operations cannot disable attachment scan verification")
            if isinstance(self.adapter, SnykAdapter) and (
                not self.config.enforce_count_match or not self.config.require_same_report_date
            ):
                raise ReviewRequired("Live Snyk imports require count and date reconciliation")
            if self.adapter.source in self.policy.retired_sources:
                raise ReviewRequired("Source is retired in the approved deployment policy")
            profile = getattr(self.adapter, "profile", None)
            if profile and not profile.certified:
                raise ReviewRequired(
                    "Product profile needs real-export schema certification before live writes"
                )
        credentials = JiraCredentials.from_secret(
            self.secret_loader.load_json(self.config.jira_secret_arn),
            self.config.jira_allowed_host_suffix,
            self.config.jira_origin,
        )
        if not dry_run and len(credentials.identity_key) < 32:
            raise ReviewRequired(
                "Live operations require a separate identity_key of at least 32 characters"
            )
        jira = self.jira_factory(credentials, self.config.jira_project_key)
        jira.budget = self.budget
        setup = jira.validate_setup(self.config, self.policy.custom_fields)
        self.project_id = setup["project_id"]
        self.credentials = credentials
        return jira

    def check(self) -> dict:
        jira = self._jira(True)
        return {
            "status": "SETUP_VALIDATED",
            "origin": self.credentials.base_url,
            "project_id": self.project_id,
            "project_key": self.config.jira_project_key,
            "activation_approved": self.config.activation_approved,
            "audit_configured": bool(self.audit),
            "identity_key_ready": len(self.credentials.identity_key) >= 32,
            "profile_certified": not hasattr(self.adapter, "profile")
            or self.adapter.profile.certified,
            "policy_hash": self.policy.fingerprint,
            "attachment_settings": jira.get_attachment_settings(),
            "audit": self.audit.check() if self.audit else None,
        }

    def identity(self, repository: str, finding_id: str = "") -> Identity:
        return Identity(
            self.credentials.base_url, self.project_id, self.adapter.source, repository, finding_id
        )

    def _validate_issue(self, issue: dict, identity: Identity) -> None:
        project = issue.get("fields", {}).get("project", {})
        if str(project.get("id")) != identity.project_id:
            raise ReviewRequired("Mapped/adopted ticket belongs to a different Jira project")
        key = issue.get("key", "")
        if not re.fullmatch(rf"{re.escape(self.config.jira_project_key)}-\d+", key):
            raise ReviewRequired("Mapped/adopted ticket key is outside the configured project")

    def _lookup(self, jira, identity: Identity, legacy: list[str]) -> tuple[dict | None, dict]:
        record = self.state.mapping_record(identity.fingerprint)
        metadata = record.get("metadata", {}) if record else {}
        if record and record.get("jira_key"):
            if metadata.get("identity") != asdict(identity):
                raise ReviewRequired("Mapping identity differs from configured destination")
            issue = jira.try_get_issue(record["jira_key"])
            if not issue:
                raise ReviewRequired(
                    "Mapped ticket is missing; inspect and explicitly repair, not recreate"
                )
            self._validate_issue(issue, identity)
            prop = jira.get_property(issue["key"])
            own_unbound_create = bool(
                metadata.get("creation_nonce")
                and prop
                and prop.get("creation_nonce") == metadata["creation_nonce"]
                and "jira_key" not in prop
            )
            if prop and (
                not identity.matches(prop, self.credentials.identity_key)
                or (prop.get("jira_key") != issue["key"] and not own_unbound_create)
            ):
                raise ReviewRequired("Mapped ticket has a changed/invalid signed identity")
            signed = prop.get("metadata", {}) if prop else {}
            if signed.get("checkpoint_at") and metadata.get("checkpoint_at"):
                if datetime.fromisoformat(metadata["checkpoint_at"]) < datetime.fromisoformat(
                    signed["checkpoint_at"]
                ):
                    raise ReviewRequired(
                        "Mapping predates signed ticket state; restore the latest audited record"
                    )
            if (
                signed.get("target_scope_hash")
                and "targets" in metadata
                and signed["target_scope_hash"] != digest(sorted(metadata["targets"]))
                and (
                    not signed.get("checkpoint_at")
                    or not metadata.get("checkpoint_at")
                    or managed_hash(issue["fields"].get("description"))
                    != metadata.get("managed_hash")
                )
            ):
                raise ReviewRequired("Mapping target scope conflicts with signed ticket state")
            return issue, metadata
        adopted = self.policy.adoption(identity.source, identity.repository, identity.finding_id)
        if adopted:
            issue = jira.try_get_issue(adopted)
            if not issue:
                raise ReviewRequired("Approved adoption target is missing/inaccessible")
            self._validate_issue(issue, identity)
            prop = jira.get_property(adopted)
            if prop and not identity.matches(prop, self.credentials.identity_key):
                raise ReviewRequired("Adoption would overwrite an unrelated identity")
            return issue, prop.get("metadata", {}) if prop else {}
        try:
            issue = jira.find_identity(identity, legacy)
        except IdentityReviewRequired as exc:
            raise ReviewRequired(str(exc)) from exc
        if issue:
            self._validate_issue(issue, identity)
            prop = jira.get_property(issue["key"])
            return issue, prop.get("metadata", {})
        if record and record.get("status") == "PENDING":
            raise ReviewRequired(
                "Previous create result is uncertain; review Jira and adopt or repair"
            )
        return None, {}

    def _persist(self, jira, identity, key, metadata):
        # Persist the known key before secondary effects. Missing property is repaired on retry.
        metadata = {**metadata, "checkpoint_at": now_iso()}
        self.state.put_mapping("V2", identity.fingerprint, key, metadata)
        reference = self.audit.put(
            "mappings", identity.fingerprint, {"jira_key": key, "metadata": metadata}
        )
        metadata = {**metadata, "audit": reference}
        self.state.put_mapping("V2", identity.fingerprint, key, metadata)
        # Full target/evidence history remains in state/audit, below Jira's property ceiling.
        recovery = {
            name: metadata[name]
            for name in (
                "identity",
                "first_seen",
                "last_seen",
                "managed_hash",
                "summary",
                "routing",
                "lifecycle",
                "verified_at",
                "target_scope_hash",
                "checkpoint_at",
            )
            if name in metadata
        }
        jira.put_property(
            key,
            identity.signed(self.credentials.identity_key, {"jira_key": key, "metadata": recovery}),
        )

    def _effective_group(self, group, previous, observed_at):
        verified = previous.get("lifecycle") == "VERIFIED"
        if "targets" not in previous and previous.get("managed_hash"):
            raise ReviewRequired(
                "Restore audited target scope before refreshing recovered finding facts"
            )
        if verified and (
            not previous.get("verified_at")
            or datetime.fromisoformat(observed_at) > datetime.fromisoformat(previous["verified_at"])
            or not group.targets.issubset(set(previous.get("targets", [])))
        ):
            return group
        missing = set(previous.get("targets", [])) - group.targets
        if not missing:
            return group
        result = deepcopy(group)
        facts = previous.get("occurrences", [])
        for target in sorted(missing):
            rows = [r for r in facts if r["target"] == target]
            if not rows:
                rows = [
                    asdict(
                        replace(
                            group.occurrences[0],
                            target=target,
                            issue_url="",
                            project_url="",
                            package_name="",
                            installed_version="",
                            fixed_version="",
                            dependency_path="",
                            environment="",
                            location=target,
                            evidence_url="",
                            fix_state="missing_data",
                            remediation="Retrieve historical source facts before proposing a fix.",
                        )
                    )
                ]
            for row in rows:
                row = dict(row)
                for name in ("cves", "cve_urls", "cwes"):
                    row[name] = tuple(row[name])
                last_seen = previous.get("last_seen", "in a prior import")
                row["observation_note"] = (
                    (
                        f"Covered by verification at {previous['verified_at']}; selected report "
                        "predates verification."
                    )
                    if verified
                    else row.get("observation_note")
                    or (
                        f"Last observed {last_seen}; absent from "
                        "the latest Critical-only report; unresolved pending positive evidence."
                    )
                )
                result.add(Finding(**row))
        return result

    def _ensure(
        self,
        jira,
        identity: Identity,
        fields: dict,
        legacy: list[str],
        dry_run: bool,
        observed_at: str,
        group: FindingGroup | None = None,
    ) -> tuple[str, str, dict]:
        issue, previous = self._lookup(jira, identity, legacy)
        if not issue:
            # Unlabeled legacy findings also need a reviewed adoption map.
            if identity.finding_id:
                try:
                    candidate = jira.find_child(identity.repository, identity.finding_id, legacy[0])
                except IdentityReviewRequired as exc:
                    raise ReviewRequired(str(exc)) from exc
                if candidate:
                    raise ReviewRequired(
                        "Legacy child found; add explicit adoption or restore its mapping"
                    )
            elif jira.find_epic(identity.repository, legacy[0], fields["summary"]):
                raise ReviewRequired("Legacy campaign found; add an explicit adoption entry")
        first_seen = previous.get("first_seen") or now_iso()
        if previous.get("last_seen") and datetime.fromisoformat(
            previous["last_seen"]
        ) > datetime.fromisoformat(observed_at):
            if not dry_run and not self.state.mapping_record(identity.fingerprint):
                # Signed discovery can restore compact authority without pretending
                # an older observation restores the newer target scope.
                self._persist(jira, identity, issue["key"], previous)
            return issue["key"], "REUSE_OLDER_OBSERVATION", previous
        if group:
            group = self._effective_group(group, previous, observed_at)
        route = self.policy.route(
            identity.source, identity.repository, first_seen, self.config.jira_priority_name
        )
        lifecycle = previous.get("lifecycle", "OPEN")
        if lifecycle == "VERIFIED" and (
            not previous.get("verified_at")
            or datetime.fromisoformat(observed_at) > datetime.fromisoformat(previous["verified_at"])
            or (
                group
                and (
                    ("targets" in previous and not group.targets.issubset(set(previous["targets"])))
                    or (
                        "targets" not in previous
                        and previous.get("target_scope_hash") != digest(sorted(group.targets))
                    )
                )
            )
        ):
            lifecycle = "OPEN"
        if lifecycle == "EXCEPTION" and (
            previous.get("deadline", 0) <= time.time()
            or (group and sorted(group.targets) != previous.get("targets"))
        ):
            lifecycle = "OPEN"
        if group:
            fields["description"] = child_description(
                group,
                fields.pop("_campaign"),
                fields.pop("_report_date"),
                owner=route["owner"],
                first_seen=first_seen,
                observed_at=observed_at,
                lifecycle=lifecycle,
            )
            if previous.get("approval"):
                fields["description"] = disposition_description(
                    fields["description"],
                    managed_hash(fields["description"]),
                    lifecycle,
                    previous["approval"],
                )
            fields.update(route["fields"])
            if route["needs_owner"]:
                fields["labels"].append("needs-owner")
            if lifecycle == "VERIFIED":
                fields["labels"].append("security-verified")
            elif lifecycle == "EXCEPTION":
                fields["labels"].append("security-exception-approved")
        fields["labels"] = sorted(set(fields["labels"]) | {identity.label})
        metadata = {
            **previous,
            "identity": asdict(identity),
            "first_seen": first_seen,
            "last_seen": observed_at,
            "targets": sorted(group.targets) if group else [],
            "target_scope_hash": digest(sorted(group.targets)) if group else digest([]),
            "occurrences": [asdict(f) for f in group.occurrences] if group else [],
            "lifecycle": lifecycle,
            "summary": fields["summary"],
            "labels": fields["labels"],
            "routing": route["fields"] if group else {},
            "managed_hash": managed_hash(fields["description"]),
        }
        self._validate_metadata(metadata)
        if dry_run:
            return (
                issue["key"] if issue else f"DRYRUN-{identity.fingerprint[:8]}",
                "WOULD_REFRESH" if issue else "WOULD_CREATE",
                {"fields": fields},
            )
        if not issue:
            nonce = uuid.uuid4().hex
            metadata["creation_nonce"] = nonce
            intent = self.audit.put(
                "intents",
                identity.fingerprint,
                {"identity": asdict(identity), "fields": fields, "creation_nonce": nonce},
            )
            metadata["creation_intent"] = intent
            if not self.state.claim_mapping(
                "V2",
                identity.fingerprint,
                {"identity": asdict(identity), "first_seen": first_seen, "intent": intent},
            ):
                raise IdempotencyConflict("An active creation claim exists")
            created = jira.create_issue(
                fields,
                properties=[
                    {
                        "key": PROPERTY_KEY,
                        "value": identity.signed(
                            self.credentials.identity_key, {"creation_nonce": nonce}
                        ),
                    },
                ],
            )
            key = str(created["key"])
            self._persist(jira, identity, key, metadata)
            return key, "CREATE", metadata
        key, current = issue["key"], issue.get("fields", {})
        updates, notes = {}, []
        try:
            refreshed = refresh_description(
                current.get("description"), fields["description"], previous.get("managed_hash", "")
            )
            if refreshed != current.get("description"):
                updates["description"] = refreshed
            metadata["managed_hash"] = managed_hash(refreshed)
        except ValueError as exc:
            notes.append(str(exc))
            metadata["managed_hash"] = previous.get("managed_hash", "")
        if self.config.update_existing_titles and (
            current.get("summary") == previous.get("summary")
            or (
                not previous
                and identity.repository.casefold() not in str(current.get("summary", "")).casefold()
            )
        ):
            if current.get("summary") != fields["summary"]:
                updates["summary"] = fields["summary"]
        else:
            metadata["summary"] = previous.get("summary", current.get("summary"))
        for name, desired in route["fields"].items() if group else []:
            actual = current.get(name)
            prior = previous.get("routing", {}).get(name)

            # On adoption do not replace an existing assignment/due date/priority.
            def comparable(value):
                return (
                    value.get("accountId", value.get("name")) if isinstance(value, dict) else value
                )

            if actual is None or comparable(actual) == comparable(prior):
                if comparable(actual) != comparable(desired):
                    updates[name] = desired
            elif comparable(actual) != comparable(desired):
                notes.append(f"Preserved manually managed {name}")
                metadata["routing"][name] = previous.get("routing", {}).get(name)
        current_labels = set(current.get("labels", []))
        additions = set(fields["labels"]) - current_labels
        removals = set(previous.get("labels", [])) - set(fields["labels"])
        status = current.get("status", {})
        if (
            lifecycle == "OPEN"
            and isinstance(status, dict)
            and status.get("statusCategory", {}).get("key") == "done"
        ):
            additions.add("source-still-open")
            notes.append("Source is still Open; closure needs review")
        if previous.get("lifecycle") == "VERIFIED" and lifecycle == "OPEN":
            additions.add("source-still-open")
            notes.append("A new open observation follows verification; review/reopen required")
            if (
                self.policy.transitions.get("reopen")
                and status.get("statusCategory", {}).get("key") == "done"
            ):
                jira.transition(key, self.policy.transitions["reopen"])
        if previous.get("lifecycle") == "EXCEPTION" and lifecycle == "OPEN":
            additions.add("exception-needs-review")
            notes.append("Exception expired or target scope changed; obtain a new approval")
        # Re-fetch before PUT to catch common concurrent edits. Jira has no atomic description CAS.
        if updates and jira.get_issue(key).get("fields", {}).get("description") != current.get(
            "description"
        ):
            raise ReviewRequired(
                "Ticket changed during refresh; retry after developer edits settle"
            )
        if updates:
            jira.update_issue(key, updates)
        jira.update_labels(key, additions, removals)
        metadata["review_notes"] = notes
        self._persist(jira, identity, key, metadata)
        return key, "REFRESH" if updates or additions or removals else "REUSE", metadata

    def _relationship(self, jira, campaign: str, child: str, dry_run: bool):
        if dry_run:
            return
        parent_issue = jira.get_issue(campaign)
        kind = parent_issue["fields"].get("issuetype", {})
        is_epic = (isinstance(kind, dict) and kind.get("hierarchyLevel") == 1) or (
            kind.get("name", "") if isinstance(kind, dict) else kind
        ).casefold() == "epic"
        issue = jira.get_issue(child)
        if is_epic:
            actual = issue["fields"].get("parent", {}).get("key")
            if actual and actual != campaign:
                raise ReviewRequired("Child has a different human-managed parent")
            if not actual:
                jira.update_issue(child, {"parent": {"key": campaign}})
        else:
            links = issue["fields"].get("issuelinks", [])
            exists = any(
                link.get("type", {}).get("name") == "Relates"
                and campaign
                in {link.get("inwardIssue", {}).get("key"), link.get("outwardIssue", {}).get("key")}
                for link in links
            )
            if not exists:
                jira.create_issue_link(campaign, child)

    def _fields(
        self, identity, kind: str, title: str, description: dict, labels: list[str]
    ) -> dict:
        return {
            "project": {"key": self.config.jira_project_key},
            "issuetype": {
                "name": self.config.jira_epic_issue_type
                if kind == "campaign"
                else self.config.jira_child_issue_type
            },
            "summary": title,
            "description": description,
            "labels": labels,
            "priority": {"name": self.config.jira_priority_name},
            **self.policy.custom_fields.get(kind, {}),
        }

    def run(
        self,
        *,
        dry_run: bool,
        force: bool = False,
        attachment_requests=None,
        upload: Upload | None = None,
        approved_new_ticket_limit: int | None = None,
    ) -> dict:
        if attachment_requests:
            return self.attachments(attachment_requests, dry_run=dry_run)
        if self.policy is None:
            self.policy = load_policy(self.config, self.source)
        if isinstance(self.adapter, SnykAdapter):
            self.adapter.approval_policy = self.policy
        batch = self.adapter.load(upload)
        if not dry_run and self.batch_ready:
            self.batch_ready(batch.source, batch.metadata)
        jira = self._jira(dry_run)
        groups = group_findings(batch.findings)
        if len(groups) > self.config.max_groups_per_run:
            raise ReviewRequired("Import exceeds the group limit; split or review source scope")
        job_id = digest(
            {
                "batch": batch.fingerprint,
                "origin": self.credentials.base_url,
                "project_id": self.project_id,
                "policy": self.policy.fingerprint,
                "renderer": RENDERER_VERSION,
            }
        )[:32]
        if force:
            job_id += "-" + uuid.uuid4().hex[:12]
        if dry_run:
            return self._execute(
                jira, batch, groups, {"job_id": job_id, "cursor": 0, "started_at": now_iso()}, True
            )
        job = self.state.get_record("JOB#" + job_id)
        if job and job["status"] == "COMPLETE":
            return {"status": "SKIPPED_ALREADY_PROCESSED", "job_id": job_id, **batch.metadata}
        if not job:
            limit = (
                approved_new_ticket_limit
                if approved_new_ticket_limit is not None
                else self.config.max_new_tickets
            )
            if type(limit) is not int or not 1 <= limit <= 10000:
                raise ValueError("Approved new-ticket limit must be an integer from 1 to 10000")
            identities = [self.identity(g.repository, g.finding_id) for g in groups]
            identities += [self.identity(repo) for repo in sorted({g.repository for g in groups})]
            candidates = [
                i.fingerprint
                for i in identities
                if not self.policy.adoption(i.source, i.repository, i.finding_id)
            ]
            missing = self.state.count_unmapped(candidates, self.budget)
            job = {
                "job_id": job_id,
                "source": batch.source,
                "status": "READY",
                "cursor": 0,
                "validation_cursor": 0,
                "started_at": now_iso(),
                "origin": self.credentials.base_url,
                "project_id": self.project_id,
                "policy_hash": self.policy.fingerprint,
                "snapshot": self.audit.put("snapshots", job_id, batch.snapshot()),
                "expected_new_upper_bound": missing,
                "new_ticket_limit": limit,
            }
            if missing > limit:
                job["status"] = "REVIEW_REQUIRED"
                job["reason"] = "New-ticket volume exceeds the approved guardrail"
            self.state.put_record("JOB#" + job_id, job)
        if job["status"] == "REVIEW_REQUIRED":
            if not self.state.get_record("NOTICE#" + job_id):
                self._notify(job_id, job)
            return job
        batch = FindingBatch.restore(self.audit.get(job["snapshot"]))
        if batch.processing_policy != self.adapter.processing_policy:
            raise ReviewRequired("Source parser/profile changed; start a new reviewed import")
        groups = group_findings(batch.findings)
        return self._execute(jira, batch, groups, job, False)

    def resume(self, job_id: str, approved_new_ticket_limit: int | None = None) -> dict:
        jira = self._jira(False)
        job = self.state.get_record("JOB#" + job_id)
        if not job:
            raise ValueError("Job does not exist")
        if (job["origin"], job["project_id"], job["policy_hash"], job["source"]) != (
            self.credentials.base_url,
            self.project_id,
            self.policy.fingerprint,
            self.adapter.source,
        ):
            raise ReviewRequired(
                "Job destination/policy changed; inspect and start a new reviewed import"
            )
        if job["status"] == "COMPLETE":
            return job
        if job["status"] == "REVIEW_REQUIRED":
            if (
                type(approved_new_ticket_limit) is not int
                or not job.get("expected_new_upper_bound", 10001)
                <= approved_new_ticket_limit
                <= 10000
                or "volume" not in job.get("reason", "")
            ):
                raise ReviewRequired("Resolve the recorded review reason before resuming")
            job["new_ticket_limit"] = approved_new_ticket_limit
        batch = FindingBatch.restore(self.audit.get(job["snapshot"]))
        if batch.processing_policy != self.adapter.processing_policy:
            raise ReviewRequired("Source parser/profile changed; start a new reviewed import")
        return self._execute(jira, batch, group_findings(batch.findings), job, False)

    def _execute(self, jira, batch, groups, job, dry_run):
        summary = RunSummary(
            batch.report_date,
            dry_run,
            len(batch.findings),
            len(groups),
            len({g.repository for g in groups}),
            warnings=list(batch.warnings),
        )
        locked = False
        job_id = job["job_id"]
        if not dry_run:
            locked = self.state.acquire_lock(digest((self.credentials.base_url, self.project_id)))
            if not locked:
                raise IdempotencyConflict("Destination writer is busy")
        try:
            job["status"] = "RUNNING"
            if not dry_run:
                self.state.put_record("JOB#" + job_id, job)
            validation_start = job.get("validation_cursor", 0)
            for index in range(validation_start, len(groups)):
                if (
                    not dry_run
                    and index - validation_start >= self.config.max_groups_per_invocation
                ):
                    raise BudgetExhausted("Validation chunk limit reached")
                self.budget.require(35)
                group = groups[index]
                route = self.policy.route(
                    batch.source,
                    group.repository,
                    job["started_at"],
                    self.config.jira_priority_name,
                )
                payload = self._fields(
                    self.identity(group.repository, group.finding_id),
                    "finding",
                    child_title(group),
                    child_description(group, "Pending campaign", batch.report_date),
                    child_labels(group),
                )
                payload.update(route["fields"])
                jira.validate_payload("finding", payload)
                jira.validate_payload(
                    "campaign",
                    self._fields(
                        self.identity(group.repository),
                        "campaign",
                        epic_title(group.repository, batch.source_name),
                        epic_description(group.repository, batch.report_date, batch.source_name),
                        epic_labels(group.repository, batch.source),
                    ),
                )
                job["validation_cursor"] = index + 1
                if not dry_run:
                    self.state.put_record("JOB#" + job_id, job)
            campaigns = {}
            start = job["cursor"]
            for index in range(start, len(groups)):
                if not dry_run and index - start >= self.config.max_groups_per_invocation:
                    raise BudgetExhausted("Chunk limit reached")
                self.budget.require(45)
                group = groups[index]
                repo = group.repository
                if repo not in campaigns:
                    identity = self.identity(repo)
                    fields = self._fields(
                        identity,
                        "campaign",
                        epic_title(repo, batch.source_name),
                        epic_description(repo, batch.report_date, batch.source_name),
                        epic_labels(repo, batch.source),
                    )
                    key, action, _ = self._ensure(
                        jira,
                        identity,
                        fields,
                        [f"repo-{jira_label(repo, max_length=80)}"],
                        dry_run,
                        max(r.last_modified for r in batch.reports).isoformat(),
                    )
                    campaigns[repo] = key
                    summary.epics_created += action in {"CREATE", "WOULD_CREATE"}
                    summary.epics_reused += action not in {"CREATE", "WOULD_CREATE"}
                identity = self.identity(repo, group.finding_id)
                fields = self._fields(
                    identity,
                    "finding",
                    child_title(group),
                    child_description(group, campaigns[repo], batch.report_date),
                    child_labels(group),
                )
                fields.update(_campaign=campaigns[repo], _report_date=batch.report_date)
                key, action, metadata = self._ensure(
                    jira,
                    identity,
                    fields,
                    [group.automation_label],
                    dry_run,
                    max(r.last_modified for r in batch.reports).isoformat(),
                    group,
                )
                self._relationship(jira, campaigns[repo], key, dry_run)
                summary.tickets_created += action in {"CREATE", "WOULD_CREATE"}
                summary.tickets_reused += action not in {"CREATE", "WOULD_CREATE"}
                summary.tickets_updated += action in {"REFRESH", "WOULD_REFRESH"}
                record = {
                    "source": batch.source,
                    "repository": repo,
                    "finding_id": group.finding_id,
                    "jira_key": key,
                    "campaign_key": campaigns[repo],
                    "action": action,
                    "review_notes": metadata.get("review_notes", []),
                    "index": index,
                }
                if not dry_run:
                    record["mapping_audit"] = self.state.mapping_record(identity.fingerprint)[
                        "metadata"
                    ]["audit"]
                    record["campaign_audit"] = self.state.mapping_record(
                        self.identity(repo).fingerprint
                    )["metadata"]["audit"]
                summary.actions.append(record)
                summary.warnings.extend(
                    f"{repo}: {note}"
                    for note in record["review_notes"]
                    if len(summary.warnings) < 100
                )
                if dry_run:
                    record["preview"] = metadata
                else:
                    ref = self.audit.put("actions", job_id, record)
                    self.state.put_record(f"ACTION#{job_id}#{index:06d}", {"audit": ref, **record})
                    job["cursor"] = index + 1
                    self.state.put_record("JOB#" + job_id, job)
            job["status"] = "DRY_RUN" if dry_run else "COMPLETE"
        except BudgetExhausted:
            job["status"] = "PENDING"
        except Exception as exc:
            if not dry_run:
                job.update(
                    status="REVIEW_REQUIRED" if isinstance(exc, ReviewRequired) else "FAILED",
                    error_type=type(exc).__name__,
                    reason=str(exc)[:1000],
                )
                job["attempt"] = self.audit.put("attempts", job_id, {**summary.as_dict(), **job})
                self.state.put_record("JOB#" + job_id, job)
            raise
        finally:
            if locked:
                self.state.release_lock(digest((self.credentials.base_url, self.project_id)))
        result = {
            **summary.as_dict(),
            "status": job["status"],
            "counter_scope": "this_invocation; inspect paginated actions for the complete job",
            "job_id": job_id,
            "cursor": job.get("cursor", 0),
            "validation_cursor": job.get("validation_cursor", 0),
            "total_groups": len(groups),
            **batch.metadata,
        }
        if not dry_run:
            result["audit"] = self.audit.put("attempts", job_id, result)
            job["attempt"] = result["audit"]
            self.state.put_record("JOB#" + job_id, job)
            if job["status"] == "PENDING" and self.continuation:
                self.continuation(job_id, self.adapter.source)
            if job["status"] == "COMPLETE":
                self._notify(job_id, result)
        return result

    def _notify(self, identifier: str, result: dict) -> None:
        try:
            self.publisher.publish(f"{self.adapter.source_name}-to-Jira {result['status']}", result)
        except Exception as exc:
            # Notification failure never rolls completed Jira work back to FAILED.
            self.state.put_record(
                "NOTICE#" + identifier,
                {
                    "status": "NOTIFICATION_FAILED",
                    "id": identifier,
                    "source": self.adapter.source,
                    "payload": {
                        k: v for k, v in result.items() if k not in {"actions", "previews"}
                    },
                    "error_type": type(exc).__name__,
                    "deadline": int(time.time()),
                },
            )
        else:
            self.state.put_record("NOTICE#" + identifier, {"status": "NOTIFIED", "id": identifier})

    def inspect(self, job_id: str, *, offset: int = 0, limit: int = 100) -> dict:
        if not isinstance(job_id, str) or not re.fullmatch(
            r"[a-f0-9]{32}(?:-[a-f0-9]{12})?", job_id
        ):
            raise ValueError("Inspection requires an exact job ID")
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Inspection offset/limit must be bounded integers")
        job = self.state.get_record("JOB#" + job_id)
        if not job:
            raise ValueError("Job not found")
        actions = [
            self.state.get_record(f"ACTION#{job_id}#{index:06d}")
            for index in range(offset, min(job.get("cursor", 0), offset + limit))
        ]
        return {
            "job": job,
            "actions": [a for a in actions if a],
            "next_offset": offset + limit if offset + limit < job.get("cursor", 0) else None,
        }

    @contextmanager
    def destination_write(self, dry_run: bool):
        name = digest((self.credentials.base_url, self.project_id))
        if not dry_run and not self.state.acquire_lock(name):
            raise IdempotencyConflict("Destination writer is busy")
        try:
            yield
        finally:
            if not dry_run:
                self.state.release_lock(name)

    @staticmethod
    def _validate_metadata(metadata):
        try:
            StateStore._json(metadata, 235000)
        except ValueError as exc:
            raise ReviewRequired(
                "Target facts exceed the state budget; review/export scope before writes"
            ) from exc

    def restore_mapping(self, event: dict) -> dict:
        jira = self._jira(False)
        fingerprint, reference, reason = (
            event.get("fingerprint", ""),
            event.get("audit", {}),
            event.get("approved_reason", ""),
        )
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{32}", fingerprint):
            raise ValueError("Restore requires an exact fingerprint")
        if (
            not isinstance(reference, dict)
            or not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > 1000
        ):
            raise ValueError(
                "Restore requires a version-pinned audit reference and reviewed reason"
            )
        artifact = self.audit.get(reference)
        metadata, key = artifact.get("metadata", {}), artifact.get("jira_key", "")
        saved = metadata.get("identity", {})
        identity = self.identity(saved.get("repository", ""), saved.get("finding_id", ""))
        if (
            asdict(identity) != saved
            or identity.fingerprint != fingerprint
            or "targets" not in metadata
        ):
            raise ReviewRequired(
                "Audit mapping identity/target scope is outside the current destination"
            )
        targets = metadata["targets"]
        if (
            not isinstance(targets, list)
            or any(not isinstance(target, str) or not target for target in targets)
            or len(targets) != len(set(targets))
            or metadata.get("target_scope_hash") != digest(sorted(targets))
        ):
            raise ReviewRequired("Audit mapping target scope does not match its recorded hash")
        self._validate_metadata(metadata)
        with self.destination_write(False):
            issue = jira.try_get_issue(key)
            if not issue:
                raise ReviewRequired("Restore target is missing/inaccessible")
            self._validate_issue(issue, identity)
            prop = jira.get_property(key)
            if (
                not identity.matches(prop, self.credentials.identity_key)
                or prop.get("jira_key") != key
            ):
                raise ReviewRequired("Restore requires a valid, issue-bound signed identity")
            signed = prop.get("metadata", {})
            for name in (
                "first_seen",
                "last_seen",
                "managed_hash",
                "target_scope_hash",
                "lifecycle",
                "verified_at",
            ):
                if name in signed and metadata.get(name) != signed[name]:
                    raise ReviewRequired("Audit mapping predates/differs from signed ticket state")
            record = self.state.mapping_record(fingerprint)
            if record and record.get("jira_key") not in {None, key}:
                raise ReviewRequired("Restore would replace a different known Jira mapping")
            restore_audit = self.audit.put(
                "restores",
                fingerprint,
                {"approved_reason": reason, "reference": reference, "jira_key": key},
            )
            metadata = {**metadata, "restored_from": reference, "restore_approval": restore_audit}
            self._persist(jira, identity, key, metadata)
        return {
            "status": "MAPPING_RESTORED",
            "jira_key": key,
            "fingerprint": fingerprint,
            "audit": restore_audit,
        }

    def attachments(self, requests: list[dict], *, dry_run: bool) -> dict:
        jira = self._jira(dry_run)
        with self.destination_write(dry_run):
            return self._attachments(jira, requests, dry_run=dry_run)

    def _attachments(self, jira, requests: list[dict], *, dry_run: bool) -> dict:
        if not requests or len(requests) > self.config.max_attachments_per_run:
            raise ValueError("Supply a nonempty, bounded attachment list")
        settings = jira.get_attachment_settings()
        if not settings.get("enabled") or int(settings.get("uploadLimit", 0)) <= 0:
            raise ValueError("Jira attachments are unavailable")
        prepared = []
        for request in requests:
            allowed = {
                "s3_key",
                "version_id",
                "display_name",
                "jira_issue_key",
                "repository",
                "finding_id",
                "snyk_id",
            }
            if (
                not isinstance(request, dict)
                or set(request) - allowed
                or any(not isinstance(v, str) for v in request.values())
            ):
                raise ValueError("Attachment entries require known string fields")
            explicit = request.get("jira_issue_key")
            repo = request.get("repository")
            finding = request.get("finding_id", request.get("snyk_id", ""))
            if (
                request.get("snyk_id")
                and request.get("finding_id")
                and request["snyk_id"] != finding
            ):
                raise ValueError("Attachment finding IDs disagree")
            if explicit and (repo or finding):
                raise ValueError("Choose an explicit issue or repository/finding target, not both")
            if explicit:
                if not re.fullmatch(rf"{re.escape(self.config.jira_project_key)}-\d+", explicit):
                    raise ValueError("Attachment issue is outside the destination project")
                issue = jira.try_get_issue(explicit)
                if not issue:
                    raise ValueError("Attachment issue not found")
                self._validate_issue(issue, self.identity("", ""))
            elif repo:
                issue, _ = self._lookup(jira, self.identity(repo, finding), [])
                if not issue:
                    raise ValueError("No authoritative mapped attachment target")
                explicit = issue["key"]
            else:
                raise ValueError("Attachment target is required")
            file = self.source.get_attachment(
                request.get("s3_key", ""),
                request.get("display_name"),
                version_id=request.get("version_id"),
            )
            if len(file.body) > int(settings["uploadLimit"]):
                raise ValueError("Attachment exceeds Jira upload limit")
            prepared.append((explicit, file))
            if sum(len(f.body) for _, f in prepared) > 25 * 1024 * 1024:
                raise ValueError("Combined attachments exceed 25 MiB; split into separate requests")
        result = {
            "status": "DRY_RUN" if dry_run else "COMPLETE",
            "source": self.adapter.source,
            "attachments_uploaded": 0,
            "attachments_reused": 0,
            "actions": [],
        }
        identifier = uuid.uuid4().hex
        for index, (key, file) in enumerate(prepared):
            self.budget.require(35)
            existing = jira.list_attachments(key)
            duplicate = any(
                a.get("filename") == file.jira_filename and int(a.get("size", -1)) == len(file.body)
                for a in existing
            )
            action = "REUSE_ATTACHMENT" if duplicate else "WOULD_UPLOAD" if dry_run else "UPLOAD"
            if not dry_run and not duplicate:
                jira.upload_attachment(key, file.jira_filename, file.content_type, file.body)
                result["attachments_uploaded"] += 1
            result["attachments_reused"] += bool(duplicate)
            record = {
                "action": action,
                "jira_key": key,
                "s3_key": file.s3_key,
                "version_id": file.version_id,
                "sha256": file.sha256,
                "filename": file.jira_filename,
            }
            result["actions"].append(record)
            if not dry_run:
                ref = self.audit.put("attachments", identifier, record)
                self.state.put_record(f"ATTACHMENT#{identifier}#{index}", {"audit": ref, **record})
        if not dry_run:
            result["audit"] = self.audit.put("attachments", identifier, result)
            self._notify(identifier, result)
        return result

    def evidence(self, event: dict, *, exception: bool = False) -> dict:
        jira = self._jira(False)
        with self.destination_write(False):
            return self._evidence(jira, event, exception=exception)

    def _evidence(self, jira, event: dict, *, exception: bool = False) -> dict:
        identity = self.identity(event.get("repository", ""), event.get("finding_id", ""))
        issue, metadata = self._lookup(jira, identity, [])
        if not issue or not identity.finding_id:
            raise ValueError("Positive evidence requires an existing mapped finding")
        if not event.get("version_id") or not re.fullmatch(
            r"[a-f0-9]{64}", event.get("sha256", "")
        ):
            raise ValueError("Evidence requires explicit version_id and reviewed SHA-256")
        value, reference = self.source.get_json(
            event.get("s3_key", ""),
            self.config.verification_prefix,
            sha256=event["sha256"],
            version_id=event["version_id"],
        )
        disposition = validate_evidence(value, metadata, exception=exception)
        self._validate_metadata({**metadata, **disposition, "approval": value})
        ref = self.audit.put(
            "evidence", identity.fingerprint, {"evidence": value, "source": reference}
        )
        try:
            description = disposition_description(
                issue["fields"]["description"],
                metadata["managed_hash"],
                disposition["lifecycle"],
                value,
            )
        except ValueError as exc:
            raise ReviewRequired(str(exc)) from exc
        if jira.get_issue(issue["key"])["fields"]["description"] != issue["fields"]["description"]:
            raise ReviewRequired("Ticket changed during evidence review; inspect and retry")
        jira.update_issue(issue["key"], {"description": description})
        metadata.update(
            disposition, verification=ref, approval=value, managed_hash=managed_hash(description)
        )
        metadata["labels"] = sorted(
            (set(metadata.get("labels", [])) - {"security-verified", "security-exception-approved"})
            | {"security-exception-approved" if exception else "security-verified"}
        )
        self._persist(jira, identity, issue["key"], metadata)
        self.state.put_record(
            "LIFECYCLE#" + identity.fingerprint,
            {
                "status": "EXCEPTION" if exception else "VERIFIED",
                "identity": asdict(identity),
                "jira_key": issue["key"],
                "audit": ref,
                **disposition,
            },
        )
        # Positive evidence and owned description hash survive secondary label/transition failure.
        jira.update_labels(
            issue["key"],
            {"security-exception-approved" if exception else "security-verified"},
            {"security-verified" if exception else "security-exception-approved"},
        )
        if (
            not exception
            and self.policy.transitions.get("verified")
            and issue["fields"].get("status", {}).get("statusCategory", {}).get("key") != "done"
        ):
            jira.transition(issue["key"], self.policy.transitions["verified"])
        return {"status": disposition["lifecycle"], "jira_key": issue["key"], "audit": ref}

    def expire_exception(self, record: dict) -> dict:
        jira = self._jira(False)
        identity = self.identity(record["identity"]["repository"], record["identity"]["finding_id"])
        if asdict(identity) != record["identity"]:
            raise ReviewRequired("Expired exception belongs to another destination")
        with self.destination_write(False):
            issue, metadata = self._lookup(jira, identity, [])
            if not issue:
                raise ReviewRequired("Expired exception has no authoritative Jira mapping")
            if (
                metadata.get("lifecycle") != "EXCEPTION"
                or metadata.get("deadline", 0) > time.time()
            ):
                return {"status": "EXCEPTION_SUPERSEDED", "jira_key": issue["key"]}
            notes = list(metadata.get("review_notes", []))
            notes.append("Exception expired; renew approval or resume remediation")
            metadata.update(lifecycle="OPEN", review_notes=notes)
            try:
                description = disposition_description(
                    issue["fields"]["description"],
                    metadata["managed_hash"],
                    "OPEN — exception expired; review required",
                    metadata.get("approval", {}),
                )
            except ValueError:
                notes.append("Preserved manually edited source facts during exception expiry")
            else:
                if (
                    jira.get_issue(issue["key"])["fields"]["description"]
                    != issue["fields"]["description"]
                ):
                    raise ReviewRequired("Ticket changed during exception expiry; retry")
                jira.update_issue(issue["key"], {"description": description})
                metadata["managed_hash"] = managed_hash(description)
            jira.update_labels(
                issue["key"], {"exception-needs-review"}, {"security-exception-approved"}
            )
            metadata["labels"] = sorted(
                (set(metadata.get("labels", [])) - {"security-exception-approved"})
                | {"exception-needs-review"}
            )
            self._persist(jira, identity, issue["key"], metadata)
            return {"status": "EXCEPTION_EXPIRED", "jira_key": issue["key"]}
