# Security CSV automation implementation status

Version 2.1 implements the reviewed local application changes and private-file configuration workflow for an explicitly approved Jira project. This record distinguishes executable code and test evidence from production activation. Unit tests use synthetic CSVs and simulated AWS/Jira services; they are not live integration tests. Documentation examples and fixtures use generic tenant/repository names. Private customer reports, connection values and inventories are excluded from publication.

## Product backlog coverage

| Item | Implemented behavior and evidence | Remaining approval or boundary |
| --- | --- | --- |
| F01 Setup and activation | `check`, exact destination metadata/permissions, required screen fields, separate activation gate. `service.py`, `jira_client.py`, activation tests. | Actual destination permissions, custom fields, workflow transitions and staging acceptance. |
| F02 Identity and migration | Tenant/project-ID/source/repo/finding identity, signed Jira properties, durable claims, paginated discovery, explicit adoption and reviewed repair. Identity/copy/deletion/uncertain-create tests. | Existing cross-project issues must be migrated separately and their actual destination keys reviewed. No fuzzy adoption. |
| F03 Import and reconciliation | Strict CSV/enums/counts, immutable versioned pairs, freshness, durable companion wait, quarantine, exact-file count approvals. Reports/adapters/hardening tests. | Any real aggregate/detail discrepancy needs explanation or a specific approved exception; stale data cannot authorize live writes. |
| F04 Developer remediation | Per-occurrence package/version/path/environment/source links, fix/no-fix/unknown distinctions, domain checklists and acceptance criteria. Renderer and rich-fact tests. | Real source supplies exact fixes; no source-API enrichment connector. |
| F05 Refresh and lifecycle | Owned-section hashes, notes and manual-routing preservation, first/last observations, retained unresolved targets, positive scan evidence, visible approvals, recurrence flags, exception expiry, audited scope restore. Refresh/evidence/expiry/scope tests. | Trusted operator assertions; authenticated scanner integration and actual transition IDs needed for fully automatic closure. Jira update race remains. |
| F06 Ownership and prioritization | Exact owner rules, assignability/screen validation, triage fallback, approved priority/calendar due date, preserved manual overrides. Policy/routing tests. | Team ownership and SLA approval; no hour-precision business-calendar or proactive overdue escalation engine. |
| F07 Bounded background work | Saved versioned snapshots, validation/apply cursors, chunk/time budgets, destination locks and new-ticket guardrail. Resume/volume/partial-relationship tests. | Load/timeout/rate-limit testing against actual AWS and Jira. Worst-case 5,000-group scale not load-tested. |
| F08 Operations and recovery | Full versioned intents/snapshots/mapping-history/actions/attempts, paginated inspect, independent SNS recovery, queue age/error/quarantine alarms. Audit/notification tests. | Confirm operations subscription, alarms, redrive permissions and live delivery. |
| F09 Independent evidence uploads | Explicit target, no fresh CSV requirement, exact scan-tag/download version, byte/MIME limits, prevalidation, digest filename reuse and audit. Attachment/TOCTOU/lock tests. | Real trusted scanner; partial attachment retries are manual and deduplication trusts filename/size. |
| F10 Additional source onboarding | Explicit schema/column mappings and approved real-sample checksum certification; unknown source/status blocked. Profile/operator tests. | Actual Alert Logic export absent; normalized example remains unverified. |
| F11 Release reliability | Python 3.12 tests, lint/format, template lint, hash-locked runtime wheels, deterministic zip/manifest, pinned CI actions, private settings/publication checks and Dependabot configuration. Release/CLI/configuration regression tests. Sanitized GitHub publication and CI completed. | SAM build/deploy, arm64 runtime and live smoke tests unverified. Full-history independent scanning and repository protection settings need review. |
| F12 Export and retirement | Read-only paginated job and reachable versioned artifact export, exclusive sensitive output, configurable operational retention, non-expiring identity maps and policy retirement. Export/retention tests. | Retention approval, separate attachment/human Jira backups and privileged deletion/legal-hold procedures. |
| F13 Shared-fix review | Evidence-backed shared package/version/path/environment candidates; review-only output. Bundle proposal tests. | Validate usefulness with developers before authorizing automatic bundling. No automatic merges or ticket closures. |

## Security changes and evidence

Jira credentials are constrained to an exact HTTPS origin; redirects and environment proxies are disabled. Authorization uses an unredirected header. REST responses, retries, Retry-After waits, CSV cells, pagination, input sizes and work duration are bounded. Ambiguous write responses are not blindly replayed.

Signed identity includes the destination's real Jira project ID and binds the issue key. A copied property or cross-project mapping cannot authorize a write. Known create keys are checkpointed before secondary audit/property/link operations. If a create result is unknown, the importer stops for reviewed recovery rather than issuing a duplicate create.

Attachment scanning and download use the same pinned object version. Managed-bucket policy separates scanner/enrichment producer from uploaders. Protected policy hashes and explicit version/hash approval prevent report data from authorizing configuration or verification changes. CSV values are encoded as ADF text, not executed or rendered as arbitrary HTML.

Notification failures are independent from import completion. Large audit/state/notification content is never made into invalid JSON by substring truncation. SNS alarm delivery uses a scoped customer-managed key and topic policy; scheduler trust is constrained by account and schedule group.

Dependency audit found no known advisories for the pinned runtime set at implementation time. That result is not a security guarantee or proof against future advisories. Development tools are version-pinned, but their transitive dependencies are not fully hash-locked.

## Test and release evidence

Local checks run on the bundled Python 3.12 interpreter and installed validation tools. The latest exact totals and release checks are reported at handoff; reproduce them using README commands. The test suite covers synthetic empty/malformed/stale/duplicate/mismatched CSVs, explicit legacy adoption, copied identity, failed/uncertain create, snapshot continuation, property/link recovery, manual edits, evidence rejection/approval, exception expiry, attachments, export and deterministic packaging.

Final local verification on October 2, 2026: 132 tests passed on Python 3.12.14; Ruff lint and format checks passed; cfn-lint passed. The two new blank settings templates bring the JSON example inventory to 20. All 38 application environment settings have a tested blank-template and SAM mapping. The runtime dependency audit reported no known vulnerabilities in the checked advisory feed; this is not proof that dependencies are vulnerability-free. Two release builds produced the same SHA-256, and the zip successfully imported its own boto3/botocore plus the application handler/service. Publication preflight checked the staged application files without printing values. No SAM build, arm64 execution, AWS deployment or live Jira test was performed.

Publication preparation on October 5, 2026 removed customer project defaults, legacy project references, historical customer report counts and the prior local-timezone default. Jira origin and project key now require explicit private configuration. Attachment smoke commands also require an explicit project. All 134 tests passed; Ruff lint/format and cfn-lint passed. Environment/deployment templates and local starting copies remain blank. The earlier October 2 dependency advisory result was not refreshed as part of this configuration-only change.

Current sanitized release: `build/security-jira-sanitized.zip`, 15,554,661 bytes, SHA-256 `f7706f2b739055e491c04c1f1b1ad95dda96858564f9b724ee65fe19e0652805`. Two builds matched, and the packaged SDK plus handler/service imported successfully. Its adjacent manifest records the dependency lock and infrastructure template hashes. The earlier package is superseded; regenerate and revalidate after any source or dependency change. Generated packages remain outside Git.

Historical customer preview results are excluded from publication. An offline preview is not authorization to create issues or a comparison against current Jira state. Existing live tickets were not queried or changed during this implementation.

Sanitized publication completed on October 5, 2026 in the approved [GitHub repository](https://github.com/jaysonguglietta/LambdaJiraCreationTool). The [successful published CI run](https://github.com/jaysonguglietta/LambdaJiraCreationTool/actions/runs/37335604413) passed 134 tests, publication preflight, Ruff lint/format, cfn-lint, hash-locked dependency installation, dependency advisory audit, release packaging and offline preview. This refreshes dependency-check evidence for that run, not indefinitely or for untested later dependency changes. GitHub CI does not perform SAM build, cloud deployment or live Jira tests.

The [complete setup guide](docs/SETUP.md) now provides prerequisites and staged operator instructions. It also records a current authentication integration limit: exact-tenant Basic auth only; OAuth, scoped-token gateways and native managed Atlassian Service accounts require an adapter extension before use. Documentation does not remove that implementation limit or activate cloud resources.

## Highest value next steps

1. Complete staging setup and failure-injection tests against actual AWS/Jira without production writes.
2. Approve destination ownership, priorities, SLA dates, required fields and legacy adoption keys.
3. Resolve report reconciliation and supply exact source-backed fix/enrichment facts.
4. Connect trusted malware scanning and authenticated source verification, then approve retention and alert delivery.
5. Validate a real Alert Logic export and certify its schema before enabling that source.

The [deep review](docs/DEEP_REVIEW.md) also prioritizes bounded failure-isolated monitoring, authenticated scan/deployment evidence, record-class retention/restoration and full-history publication checks. These recommendations are distinct from the configuration/logging/publication changes implemented in version 2.1.
