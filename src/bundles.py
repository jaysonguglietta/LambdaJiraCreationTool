"""Review-only shared-fix candidates. Never merge tickets or invent a secure version."""

from __future__ import annotations

from collections import defaultdict

from identity import digest
from models import Finding


def propose_bundles(findings: list[Finding]) -> dict:
    grouped = defaultdict(list)
    for f in findings:
        if (
            f.fix_state != "reported_fix"
            or not f.package_name
            or not f.fixed_version
            or not f.dependency_path
            or not f.evidence_url
        ):
            continue
        key = (
            f.source,
            f.repository,
            f.package_name,
            f.fixed_version,
            f.dependency_path,
            f.product_name,
            f.environment,
        )
        grouped[key].append(f)
    candidates = []
    for key, values in sorted(grouped.items()):
        ids = sorted({f.finding_id for f in values})
        if len(ids) < 2:
            continue
        candidates.append(
            {
                "candidate_id": digest(key)[:24],
                "source": key[0],
                "repository": key[1],
                "package": key[2],
                "fixed_version": key[3],
                "dependency_path": key[4],
                "finding_ids": ids,
                "targets": sorted({f.target for f in values}),
                "evidence": sorted({f.evidence_url for f in values}),
                "review_required": True,
            }
        )
    return {
        "status": "REVIEW_ONLY",
        "candidates": candidates,
        "rule": "Confirm one supported change resolves every listed finding and target in a "
        "clean build and post-deployment scan. Ticket grouping remains unchanged.",
    }
