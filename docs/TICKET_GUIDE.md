# Developer ticket guide

Each child ticket should give a developer enough source-backed information to identify, change, test and verify the affected scope. Repository campaigns organize ownership. Independent findings remain separate children so one completed fix does not hide another unresolved issue.

## Grouping rules

Use one repository campaign and one child per source, repository and stable finding ID. Include every affected target in that child. The same CVE in two repositories creates separate ownership scopes. Different finding IDs are not merged automatically, even when they share a package or suggested fix. The bundle operation suggests exact shared-fix candidates for review only.

Title convention: `[Critical] organization/service — Package or problem (CVE or finding ID)`. The stable finding ID always appears in the description. The application includes the repository in both title and description. Jira issue types, priority and transitions must be approved for the actual destination; Epic/Bug are defaults, not a requirement to redesign an existing Jira workflow.

## Description contract

The managed section contains repository, source finding ID, problem, severity/status, lifecycle, owner, campaign and observation dates. Each target includes its environment/location, package, installed and fixed versions, dependency path, exploit/fixability indicators, remediation and source links when supplied.

There are three distinct outcomes:

| Fix information | Developer action |
| --- | --- |
| Source reports a specific fix | Confirm compatibility and implement the reported change for every affected target. |
| Source explicitly reports no supported fix | Evaluate replacement, supported runtime migration or mitigation; obtain a time-limited exception if needed. |
| Exact fix information is missing | Triage in the source advisory and repository first. Fixability alone is not an upgrade command or a fixed version. |

Do not infer package versions from a CVE or finding ID. Provide source-backed enrichment before assigning implementation work when the export lacks actionable facts. Distinguish runtime, test and container targets; the application preserves what the source supplied rather than guessing which targets are production-reachable.

## Working the ticket

1. Confirm affected targets, package path and current deployed version against source evidence.
2. Record the remediation choice, compatibility risks, acceptance tests and rollback plan.
3. Implement through the repository's normal pull request and deployment process.
4. Run unit, integration, packaging and security regression checks relevant to the change.
5. Deploy, identify the artifact and obtain a post-deployment scan for the entire retained scope.
6. Submit approved verification evidence. An operator can record verification and use a reviewed Jira transition; no transition is guessed.

Add PR links, implementation decisions and rollout notes under **Developer notes**. Avoid editing the automation-owned section: a changed managed section stops refresh for review. Intentional manual assignee/priority/due-date changes are preserved where the application can establish that they differ from its prior routing.

Targets omitted from a later Critical-only export remain in scope with an observation note. A target may have disappeared because of a changed scan scope, failed scan or severity change. Only positive evidence resolves it. A newer Open observation after verification flags recurrence; investigate it rather than automatically treating the prior scan as current proof.

## Verification and exceptions

Verification must identify the source/repository/finding, exact target set, accountable owner and approver, deployment time, scan time, artifact SHA-256 and scan/deployment references. It must be fresh, post-deployment and at least as recent as the latest Open observation. Upload to the protected verification folder and approve the exact object version/hash.

An exception additionally records reason, compensating controls, migration plan, approval reference and expiry. Expiry is not remediation and must return to review. Neither an exception nor verification automatically closes a repository campaign; campaign closure needs an approved process covering every child.

## Evidence attachments

Attachments are optional and explicitly requested. They can be uploaded independently of current CSVs, but must target an approved issue or authoritative repository/finding mapping. The cloud path requires clean scanner tags and downloads the same object version that was checked. Do not attach raw credential-bearing logs or full unrelated scanner exports.

## Finding tickets in Jira

Use the labels actually configured by the application. For the default Snyk labels:

```jql
project = YOUR_PROJECT_KEY AND labels = snyk ORDER BY priority DESC, created ASC
```

For all automated sources, use the shared `security-remediation` label. Stable signed identity labels are source-specific; project/label searches are for discovery, not authority to adopt or modify an issue.
