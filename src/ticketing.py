from __future__ import annotations

from copy import deepcopy

from adf import bullet_list, document, heading, ordered_list, paragraph, plain_text, table, text
from identity import digest
from models import FindingGroup, jira_label
from products import campaign_label

MANAGED = "Security source facts"
NOTES = "Developer notes"
RENDERER_VERSION = 2


def _truncate(value: str, limit: int = 255) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def child_title(group: FindingGroup) -> str:
    packages = sorted({f.package_name for f in group.occurrences if f.package_name})
    subject = ", ".join(packages) or group.problem_title
    references = ", ".join(sorted(group.cves)) or group.finding_id
    return _truncate(f"[Critical] {group.repository} — {subject} ({references})")


def epic_title(repository: str, source_name: str = "Snyk") -> str:
    return _truncate(f"[Repo Security] Remediate Critical {source_name} findings in {repository}")


def epic_labels(repository: str, source: str = "snyk") -> list[str]:
    return sorted(
        {
            source,
            "security-remediation",
            "severity-critical",
            "repo-security-epic",
            campaign_label(source, repository),
        }
    )


def child_labels(group: FindingGroup) -> list[str]:
    labels = {
        group.source,
        "security-remediation",
        "severity-critical",
        group.automation_label,
        campaign_label(group.source, group.repository),
    }
    labels.update(jira_label(cve) for cve in group.cves)
    if any(f.fix_state == "missing_data" for f in group.occurrences):
        labels.add("remediation-triage")
    if any(f.fix_state == "no_supported_fix" for f in group.occurrences):
        labels.add("no-supported-fix")
    return sorted(labels)


def epic_description(repository: str, report_date: str, source_name: str = "Snyk") -> dict:
    return document(
        [
            heading(2, MANAGED),
            table(
                [
                    ("Repository / asset group", repository),
                    ("Source", source_name),
                    ("Last report", report_date),
                ]
            ),
            paragraph(
                "One child per source + repository + finding ID. Each child retains every "
                "affected target and its own remediation facts."
            ),
            paragraph(
                "Close this campaign only after every child has positive verification evidence "
                "or an approved, expiring exception. Absence from a Critical-only export is "
                "not proof of remediation."
            ),
            heading(2, NOTES),
            paragraph(
                "Add developer decisions, pull requests, deployment links, and review notes here."
            ),
        ]
    )


def _playbook(group: FindingGroup) -> list[str]:
    kind = f"{group.product_name} {group.issue_type}".casefold()
    if "iac" in kind or "configuration" in kind:
        action = (
            "Change the referenced infrastructure resource/configuration; review the plan "
            "diff and confirm the deployed resources match the approved change."
        )
    elif "code" in kind:
        action = (
            "Inspect the reported file/location and source-to-sink flow; implement the "
            "appropriate encoding, authorization, or validation at the affected boundary."
        )
    elif "container" in kind:
        action = (
            "Upgrade the affected OS package or supported base image, rebuild without stale "
            "layers, and record the image digest and installed package version."
        )
    else:
        action = (
            "Upgrade the affected dependency, introducing parent, or supported runtime; "
            "regenerate lock files using the repository's standard tooling."
        )
    return [
        "Confirm every target below against the linked source evidence. If exact fix data is "
        "missing, perform triage first; no package/version is inferred from a finding ID.",
        action,
        "Review compatibility and unrelated changes. Run the repository's unit, integration, "
        "packaging, and security regression checks from a clean build.",
        "Deploy normally; record the artifact identity and rollback plan.",
        f"Obtain a post-deployment {group.source_name} scan for every affected target. "
        "Submit positive verification evidence before closure.",
    ]


def child_description(
    group: FindingGroup,
    epic_key: str,
    report_date: str,
    *,
    owner: str = "Security triage: needs-owner",
    first_seen: str = "",
    observed_at: str = "",
    audit: dict | None = None,
    lifecycle: str = "OPEN",
) -> dict:
    missing = any(f.fix_state == "missing_data" for f in group.occurrences)
    nodes = [
        heading(2, MANAGED),
        paragraph(
            "Remediation triage required: the export does not supply an exact supported fix "
            "for every target."
            if missing
            else "Use the per-target source-backed remediation below; confirm compatibility."
        ),
        table(
            [
                ("Repository / asset group", group.repository),
                ("Finding", f"{group.source_name}: {group.finding_id}"),
                ("Problem", group.problem_title),
                ("Source severity / status", "Critical / Open"),
                ("Remediation lifecycle", lifecycle),
                ("Owner", owner),
                ("Campaign", epic_key),
                ("First seen by automation", first_seen or "Not yet ingested"),
                ("Last observed", observed_at or report_date),
                ("CVE", ", ".join(sorted(group.cves)) or "Not supplied"),
                ("CWE", ", ".join(sorted(group.cwes)) or "Not supplied"),
                ("Product / issue type", f"{group.product_name} / {group.issue_type}"),
            ]
        ),
        heading(3, "Affected targets and source-backed fixes"),
    ]
    for occurrence in sorted(
        group.occurrences, key=lambda f: (f.target, f.environment, f.location)
    ):
        nodes.extend(
            [
                table(
                    [
                        ("Target", occurrence.target),
                        (
                            "Observation",
                            occurrence.observation_note or "Present in selected report",
                        ),
                        ("Environment", occurrence.environment or "Not supplied"),
                        ("Location", occurrence.location or "Not supplied"),
                        ("Package", occurrence.package_name or "Not supplied — confirm in source"),
                        (
                            "Installed → fixed",
                            f"{occurrence.installed_version or 'Not supplied'} → "
                            f"{occurrence.fixed_version or 'Not supplied'}",
                        ),
                        ("Dependency path", occurrence.dependency_path or "Not supplied"),
                        ("Fix disposition", occurrence.fix_state),
                        ("Reported fixability", occurrence.fixability),
                        ("Exploit maturity", occurrence.exploit_maturity),
                        (
                            "Source remediation",
                            occurrence.remediation
                            or "No specific fix supplied; inspect source advisory and repository "
                            "before changing code.",
                        ),
                    ]
                ),
            ]
        )
        for label, url in (
            ("Target finding in source", occurrence.issue_url),
            ("Target project in source", occurrence.project_url),
        ):
            if url:
                nodes.append(paragraph(text(label, href=url)))
        if occurrence.evidence_url:
            nodes.append(paragraph(text("Remediation evidence", href=occurrence.evidence_url)))
    nodes.extend(
        [
            heading(3, "Implementation and validation"),
            ordered_list(_playbook(group)),
            heading(3, "Acceptance criteria"),
            bullet_list(
                [
                    "Document the supported fix, rationale, and every changed target in the PR.",
                    "Tests pass; deploy the reviewed artifact and link the PR, tests and scan.",
                    "A post-deployment scan verifies every target; CSV absence is insufficient.",
                    "If no supported fix exists, record an approved exception with owner, expiry, "
                    "controls and migration plan.",
                    "Keep integrity/TLS checks enabled; use approved sources; redact credentials.",
                ]
            ),
        ]
    )
    for url in sorted({group.issue_url, *group.cve_urls, *group.project_urls} - {""}):
        nodes.append(paragraph(text("Source reference", href=url)))
    if audit:
        nodes.append(
            paragraph(f"Restricted audit artifact: s3://{audit.get('bucket')}/{audit.get('key')}")
        )
    nodes += [
        heading(2, NOTES),
        paragraph(
            "Record implementation decisions and evidence here. Automation preserves this section."
        ),
    ]
    result = document(nodes)
    if len(plain_text(result)) > 30000:
        raise ValueError(
            "Ticket content exceeds 30,000 characters; reduce input or split reviewed scope"
        )
    return result


def managed_nodes(description: object) -> list[dict]:
    if not isinstance(description, dict):
        raise ValueError("No managed ADF section")
    nodes = description.get("content", [])
    markers = [
        i for i, n in enumerate(nodes) if n.get("type") == "heading" and plain_text(n) == NOTES
    ]
    if not nodes or plain_text(nodes[0]) != MANAGED or len(markers) != 1:
        raise ValueError("Managed section markers changed; review required")
    return nodes[: markers[0]]


def managed_hash(description: object) -> str:
    return digest(managed_nodes(description))


def refresh_description(current: object, fresh: dict, previous_hash: str = "") -> dict:
    fresh_nodes = managed_nodes(fresh)
    if previous_hash:
        current_nodes = managed_nodes(current)
        if digest(current_nodes) != previous_hash:
            raise ValueError(
                "A developer edited source facts; preserve and review before refreshing"
            )
        suffix = current["content"][len(current_nodes) :]
    elif current:
        # Only reached for an explicit adoption. Preserve the complete legacy description.
        suffix = [heading(2, NOTES), paragraph("Preserved pre-adoption description:")]
        suffix += (
            current.get("content", []) if isinstance(current, dict) else [paragraph(str(current))]
        )
    else:
        suffix = fresh["content"][len(fresh_nodes) :]
    return document(deepcopy(fresh_nodes + suffix))


def disposition_description(
    current: dict, previous_hash: str, lifecycle: str, approval: dict
) -> dict:
    """Update only owned source facts; retain developer notes and source provenance."""
    nodes = deepcopy(managed_nodes(current))
    if digest(nodes) != previous_hash:
        raise ValueError("A developer edited source facts; review before recording disposition")
    marker = "Verification / exception approval"
    old = next((i for i, n in enumerate(nodes) if plain_text(n) == marker), None)
    if old is not None:
        nodes = nodes[:old]
    for node in nodes:
        if node.get("type") == "table":
            for row in node["content"]:
                if plain_text(row["content"][0]) == "Remediation lifecycle":
                    row["content"][1]["content"] = [paragraph(lifecycle)]
                if (
                    lifecycle == "VERIFIED"
                    and plain_text(row["content"][0]) == "Observation"
                    and "unresolved pending positive evidence" in plain_text(row["content"][1])
                ):
                    row["content"][1]["content"] = [
                        paragraph(
                            "Absent from the selected Critical-only report; now covered by "
                            "approved verification at "
                            f"{approval.get('scanned_at', 'the recorded scan')}."
                        )
                    ]
    if approval:
        rows = [
            (label, str(approval[name]))
            for label, name in (
                ("Owner", "owner"),
                ("Approved by", "approved_by"),
                ("Verified scan time", "scanned_at"),
                ("Deployed artifact", "artifact_digest"),
                ("Exception expiry", "expires_at"),
                ("Reason", "reason"),
                ("Compensating controls", "compensating_controls"),
                ("Migration plan", "migration_plan"),
            )
            if name in approval
        ]
        nodes += [heading(3, marker), table(rows)]
        for name in ("scan_url", "deployment_url", "approval_url"):
            if approval.get(name):
                nodes.append(paragraph(text(name.replace("_", " "), href=approval[name])))
    result = document(nodes + deepcopy(current["content"][len(managed_nodes(current)) :]))
    if len(plain_text(result)) > 30000:
        raise ValueError(
            "Disposition would exceed the ticket content limit; shorten reviewed evidence"
        )
    return result
