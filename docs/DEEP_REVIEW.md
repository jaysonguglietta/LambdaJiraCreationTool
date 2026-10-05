# Security automation deep review

This review covers the local application, deployment template, operator scripts, synthetic tests and publication controls. It identifies implementation evidence and production gaps without claiming a live AWS/Jira audit. No production credentials, IAM policies, Jira workflow settings or scanner responses were inspected.

## Executive summary

The workflow has meaningful safeguards: signed destination identities, exact-origin API credentials, strict parsing/reconciliation, frozen resumable snapshots, owned-description preservation, retained unresolved scope and positive verification. The highest remaining risks are operational trust and external validation, not a demonstrated unauthenticated remote-code-execution path.

This pass removes a tenant-specific origin default, makes environment settings file-driven, keeps tracked templates blank, adds publication checks, isolates application logging from SDK transport logs and prevents live scan-check bypass. Schedule and monitor switches are now independent. These are local changes with regression tests, not evidence that a deployment is safe to activate.

## System and attacker model

Assets include Jira credentials/signing keys, private vulnerability facts, project identity, target scope, approval records, source evidence, state/checkpoints and audit history. Entry points are S3 reports, mapped CSV profiles, enrichment/verification JSON, optional attachments, IAM-authenticated Lambda events and GitHub contributions.

Likely adversaries include a malicious uploader attempting parser exhaustion or fraudulent scope changes, a compromised developer/Jira client changing labels/properties, a compromised approval/scanner role, a malicious pull request and a compromised AWS administrator. Ordinary report uploaders must not hold Lambda invocation, Secrets Manager, state, configuration, audit or clean-tag write privileges.

No UI authentication, SQL database, shell execution of report data or multi-tenant portal exists. Their absence narrows the attack surface; it does not excuse weak IAM or fabricated verification from a trusted role. See the architecture guide for data flows and invariants.

## Findings addressed in this pass

| Finding | Severity and confidence | Evidence and implemented control |
| --- | --- | --- |
| Root DEBUG logging could enable credential-bearing SDK transport logs | Medium, High | `handler.py` previously set the root logger level from LOG_LEVEL. Dedicated application logger and WARNING SDK levels now isolate debug behavior; logging regression test verifies isolation. |
| Deployment/runtime defaults contained a real tenant origin | Low, High | `config.py`, `template.yaml` and attachment smoke script had a tenant-specific default. Origin is now explicit/required; examples/tests use a generic tenant. |
| Several runtime controls were not configurable through SAM | Informational, High | Prefixes and limits were literal template values while other values existed only in runtime defaults. Blank private-file templates, complete parameter mapping and a drift test now cover the entire inventory. |
| Ignore rules alone did not prevent publishing populated settings | Medium, High | `.gitignore` previously omitted private settings/export paths and no tracked-file check existed. Broader exclusions, blank-template checks, index validation and CI now block recognized cases. This is not comprehensive secret detection. |
| Upload switch also disabled operational monitoring | Low, High | `OperationalMonitor.State` previously referenced UploadTriggerState. MonitorState is now independently configurable, disabled by default. |
| A configured live run could disable attachment scan-tag verification | Medium, High | The source adapter accepted REQUIRE_CLEAN_ATTACHMENT_TAG=false. Live operations now reject it; tests cover bypass without the file generator. |

For logging, the exploitation condition was an operator enabling DEBUG or code enabling root debug in the presence of SDK response logs. The potential impact is credentials in CloudWatch, not an unauthenticated attacker directly reading Secrets Manager. Configuration/file publication findings require access to deployment settings or Git contributions; treat them as dangerous operational assumptions rather than external authentication bypasses.

The pinned SDK should also be reviewed when upgrading: botocore's debug transport/parser paths log request or response details, so application verbosity must not enable them. [Botocore transport implementation](https://github.com/boto/botocore/blob/develop/botocore/endpoint.py)

## Prioritized remaining findings and recommendations

### Positive verification remains a trusted assertion

Priority P1. Severity High if the approver/producer role is compromised; confidence High in the implemented trust boundary. `lifecycle.py` validates scope, freshness, deployment timing and digest/reference shape, but it does not authenticate the scanner or deployment API and independently verify their results. An authorized or compromised writer could submit fabricated evidence that meets the schema. This is a deliberate authority boundary, not a demonstrated report-uploader bypass.

Add an adapter that verifies scan/deployment records against the source API or signed producer messages. Bind source account/project, artifact digest, environment, target set and observation window to the approval. Separate operational invocation from exception approval using narrow IAM roles and an approval record. Tests should reject copied/foreign scan results, wrong artifacts/environments, stale replay, missing target coverage and revoked producer identity. Relevant categories: CWE-345 and OWASP A01 where authorization boundaries are weakened.

### One monitor failure can prevent later work

Priority P1. Severity Medium; confidence High. `IngestionRuntime.monitor` loops through exceptions and notification retries without per-record failure isolation or a work budget. A retired source causes `service._jira(False)` to reject expiry writes; a removed profile can also fail lookup. An early failure can block later alerts until the condition changes. Large operational queues can exceed Lambda duration.

Process each record within a bounded budget, record a review/error outcome, alert and continue where safe. Do not mark an exception successfully expired if its Jira action failed. Keep retired-source monitoring notification-only until disposition is reviewed; preserve an adapter for outstanding work or a dedicated historical resolver. Tests should mix failing, retired and successful sources, exercise timeout checkpoints and prove that alerts are not lost. Relevant category: CWE-703. This improvement is recommended, not implemented in this pass.

### Retention and disaster recovery need an explicit policy

Priority P1. Severity Medium; confidence High. Audit objects have lifecycle expiration, while identity mappings retain full target facts and approvals without TTL. A policy claiming all finding data disappears after the configured days would be inaccurate. A lost mapping may need full audit scope that has already expired.

Approve a record-class retention matrix and preserve evidence needed for unresolved tickets. Design reviewed compaction for verified mappings that retains identity without silently losing unresolved scope. Test PITR restoration, versioned audit export/restore and expired-history failure in staging. Add Object Lock only if a real compliance requirement and approved retention model warrant it; current artifacts are not administrator-proof. Relevant categories: CWE-200 and OWASP A09 for evidence/privacy gaps.

### Developer fixes need authoritative source facts

Priority P1 for usefulness, not a confirmed software vulnerability. The supplied historical detail export lacks exact installed/fixed versions and has a count discrepancy. A generic remediation checklist cannot replace a package path, a supported fixed version or a deployment test.

Prefer source API enrichment or approved source-backed sidecars per occurrence. Include environment, introducing dependency, supported upgrade, compatibility concerns and minimal acceptance tests. Preserve no-supported-fix and unknown-fix states separately. Add reachability/exposure/known-exploitation prioritization only when the source supplies it; do not invent exploitability or broaden the Critical-only scope.

### Live integration and scale are unverified

Priority P1. Severity depends on deployment; confidence High in the limitation. Synthetic tests do not verify actual Jira fields/permissions, existing-bucket policy parity, KMS behavior, EventBridge/SNS delivery, SAM packaging or arm64 runtime behavior. The maximum 5,000-group limit is not a proven throughput guarantee.

Run a disposable staging stack and Jira project with no production data. Test permission revocation, 429/timeout/uncertain POST, S3 version races, pair upload order, scanner tag versions, required fields, partial links, recovery and alarm delivery. Measure memory/duration and queue age before selecting volume limits. Do not scale concurrency without shared authority/locking and recovery design.

### Remaining defense in depth

Priority P2. Preserve read-only CI, add branch ownership/protection and an approved full-history scanner; the local preflight checks a limited set of recognizable patterns. Hash-lock development-tool transitive dependencies if supply-chain policy requires it. Plan signing-key rotation with overlapping trusted key IDs rather than changing the key blindly. Limit human Jira editors who can spoof digest filenames, or verify downloaded attachment hashes before reuse when the threat model requires it. Coordinate human description writers because Jira updates are not atomic compare-and-swap.

### Authentication compatibility is an activation gate

Priority P1 for deployment compatibility; Informational severity, High confidence, not a confirmed credential bypass. `config.py` constrains JiraOrigin to an exact tenant origin; `jira_client.py` sends email/API-token Basic authentication there and rejects redirects/proxy forwarding. Atlassian scoped-token authentication requires a separate gateway/cloud ID, and native managed Service accounts require scoped tokens. Those integrations are not implemented. [Atlassian token requirements](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)

The [setup guide](SETUP.md#step-7-choose-compatible-jira-authentication) distinguishes a regular approved automation account from native Service accounts. If organizational policy requires scopes, native service accounts or OAuth, implement the approved adapter before activation instead of broadening the origin allowlist or weakening token policy. Test origin/cloud-ID binding, least-privilege scopes, redirect rejection, expiry and rotation. No live authentication compatibility test has been performed.

## Combined risk scenarios

- Compromised approval role plus fabricated scan evidence can incorrectly verify an unresolved issue; strict CSV parsing alone does not protect this boundary.
- Expired audit history plus lost full mapping state can block safe refresh/recovery. Blindly adopting a label or recreating issues would turn an availability problem into duplicate or incorrect work.
- A retired-source monitor failure plus an unconfirmed SNS subscription can conceal overdue exceptions. Separate monitor configuration is necessary but does not solve per-record failure handling.
- A populated settings file committed before ignore rules plus a force-push can retain sensitive history in copies. Current-tree checks do not replace revocation and history scanning.

## Remediation roadmap

Before production: resolve source reconciliation/fix data; approve ownership, SLA, retention and source trust; stage the actual IAM/Jira/scanner setup; test restoration and notifications. Next, implement bounded isolated monitoring and authenticated scan/deployment validation. Then improve enrichment, exception approval separation, history scanning and measured scale. Certify a real additional-product export only after these core workflows are usable.

## Security test plan

Local regression tests cover malformed/oversized inputs, count/date mismatch, signed identity/copy attacks, uncertain creates, notes/routing preservation, missing-target retention, full-scope verification, scan-version attachment reads, private settings, publication rejection and configuration drift. Repeat them for every adapter change.

Staging must additionally test IAM denial for each untrusted role, secret rotation and log redaction, actual Jira required fields/transitions, obsolete S3 versions, alarm subscriptions, queue retries/redrive, monitor failure isolation, source retirement and full disaster restoration. Record commit/configuration/artifact hashes and expected outcomes. Never use production issue deletion or irreversible infrastructure changes as a test shortcut.

## Open decisions

The user selected the public [GitHub repository](https://github.com/jaysonguglietta/LambdaJiraCreationTool), and sanitized publication plus CI have completed. Independent full-history scanning and protection settings still need review. Who owns exception approval versus invocation? Which Jira authentication approach is permitted by organizational policy? Which scanner/deployment system can authenticate evidence? What retention is required for unresolved versus verified cases? What recovery objectives and daily volumes are expected? Is the historical report count discrepancy understood? No default assumption in this review substitutes for those approvals.
