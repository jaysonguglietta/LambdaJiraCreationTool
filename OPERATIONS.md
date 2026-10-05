# Operating the security CSV Jira workflow

This guide covers setup, deliberate activation, routine imports, and recovery. All commands below are examples for an authorized operator; no AWS or Jira actions were performed during local implementation. Keep production writes disabled until the staging checklist passes.

For all environment and deployment settings, use the [private configuration workflow](docs/CONFIGURATION.md). Populate only ignored `config/local/` copies. The tracked JSON examples stay blank, and Jira origin and project key must be explicitly configured. Read the [deep review](docs/DEEP_REVIEW.md) for remaining production decisions.

## Prepare the destination

Use a dedicated Jira Cloud service account limited to the approved destination project. Validate Browse Projects, Create Issues, Edit Issues and Link Issues; attachments also need Create Attachments. Confirm configured campaign/finding issue types, assignable account IDs, priority names, parent support, and mandatory create-screen fields. Put required custom fields in the policy rather than inferring them from an export.

Store this shape in AWS Secrets Manager through your approved secret-management process. Never paste real tokens into chat, source control, command arguments, or report files:

```json
{
  "base_url": "https://jira-example.atlassian.net",
  "email": "<dedicated Jira service account>",
  "api_token": "<service account API token>",
  "identity_key": "<independent cryptographically random secret of at least 32 characters>"
}
```

The exact base URL must equal JiraOrigin. HTTP redirects, proxy forwarding and cross-origin credentials are not accepted. Restrict the service account and Secrets Manager read permission. Rotate the Jira API token without changing the independent identity key. Routine identity-key rotation needs a controlled re-signing migration; do not change it blindly or signed ticket recovery will fail. If compromised, revoke access and review state/Jira identities before enabling writes again.

## Approve configuration and storage

Review `config/policy.example.json`; it is an empty, safe starting point, not approved production routing. Rules match source/repository exactly. Unknown owners are routed to security triage and marked needs-owner, not assigned to a guessed developer.

Example owner rule, once the real Jira account and SLA are approved:

```json
{
  "source": "snyk",
  "repository": "organization/service-repo",
  "account_id": "<real assignable Jira accountId>",
  "priority": "Major",
  "sla_hours": 48
}
```

An adoption rule identifies an existing destination issue explicitly. Omit finding_id for a repository campaign; include it for a child:

```json
{
  "source": "snyk",
  "repository": "organization/service-repo",
  "finding_id": "SNYK-<actual stable finding ID>",
  "jira_key": "<approved project key>-<existing numeric issue number>"
}
```

Do not use source-project keys in a destination adoption map. Migrating issues between projects changes keys and workflow compatibility; this application does not perform that migration. Review the actual migrated destination keys and relationships first. Reusing a label or matching repository text is not sufficient authorization to adopt a ticket.

Validate the JSON locally, upload it to the protected configuration folder, and set PolicyKey plus the exact file SHA-256 returned by validation:

```bash
python3.12 scripts/security_operator.py validate-policy --file approved-policy.json
```

Only trusted administrators should write configuration or verification evidence. Report uploaders must not be able to read secrets, invoke Lambda, send arbitrary continuation messages, edit DynamoDB, or write audit history. Separate the attachment scanner from evidence uploaders and the enrichment producer from report uploaders.

Managed input/audit buckets are encrypted, versioned, public-access blocked, and TLS-only. Managed evidence tags can only be changed by EvidenceScannerRoleArn; enrichment can only be written by EvidenceProducerRoleArn. Unconfigured trusted roles intentionally deny those writes. The template does not create a malware scanner or enrichment producer. Never let ordinary uploaders self-tag files CLEAN.

For an existing bucket, independently verify equivalent policy, encryption, versioning, region, lifecycle and role separation. The stack does not alter those settings. Customer-managed KMS keys for an existing bucket or secret require narrowly scoped role/key-policy permissions; the template does not grant broad decrypt access.

Retention defaults are 90 days for managed reports/evidence/audit objects and operational state, and 30 days for logs. Configuration is excluded from automatic input expiration so an active policy does not disappear. Approve these before deployment. The audit bucket and state table are retained on stack deletion, but their lifecycle/TTL rules still apply. Identity mappings intentionally have no TTL to prevent accidental duplicate Jira creation.

## Deploy with all writes disabled

Use AWS SAM in an approved account and region. Review the change set; preserve the existing table when upgrading and assess the new index, audit bucket, and IAM changes:

```bash
sam build
sam deploy --guided
```

Initial parameters:

```text
JiraSecretArn=<approved secret ARN>
JiraOrigin=https://jira-example.atlassian.net
JiraProjectKey=<approved project key>
CampaignIssueType=Epic
FindingIssueType=Bug
JiraPriorityName=Major
ActivationApproved=false
DryRun=true
UploadTriggerState=DISABLED
ScheduleState=DISABLED
MonitorState=DISABLED
PolicyKey=<approved key or empty for initial checks>
PolicySha256=<approved exact file SHA-256 or empty>
ProductProfilesJson={}
```

For an existing bucket, preview EventBridge notification configuration first. Applying requires an exclusive backup file, rereads for concurrent changes, and checks the saved result:

```bash
python3.12 scripts/configure_bucket_events.py --bucket <bucket> --region <region>
python3.12 scripts/configure_bucket_events.py --bucket <bucket> --region <region> \
  --apply --backup-file bucket-notifications.backup.json
```

S3 does not offer atomic compare-and-swap for notification settings. Coordinate configuration changes; retain the backup. Managed buckets already enable EventBridge delivery.

## Run setup and staged dry runs

Install the pinned runtime dependencies locally or use the validated package. Operator commands authenticate to Lambda with the normal AWS SDK credential chain:

```bash
python3.12 scripts/security_operator.py invoke --function <function> \
  --region <region> --event events/check.json
python3.12 scripts/security_operator.py invoke --function <function> \
  --region <region> --event events/dry-run.json
```

Check verifies project permissions, issue types, create-screen requirements, attachment settings, signing-key readiness and audit bucket versioning. A dry run reads Jira but does not create/update issues, persist jobs, upload files or notify. For large complete previews, use the offline preview command; cloud work is bounded by the Lambda time budget.

Before activation, test in a nonproduction Jira project/account:

1. Matching current reports produce the expected repository campaigns and independent child findings.
2. Either upload order works; missing companions expire visibly rather than falling back.
3. Duplicate delivery and an interrupted import reuse known Jira keys and restore relationships.
4. Developer notes, labels and manually changed routing survive refresh; managed-section conflicts stop for review.
5. A count mismatch, stale/overwritten report, unsupported profile and unknown status cause no Jira writes.
6. Explicit clean, version-pinned attachments can be added without fresh CSVs; duplicates reuse the checksum filename.
7. Positive scan evidence covers every target; partial, stale and pre-deployment evidence is rejected.
8. Exceptions expire visibly, notifications recover independently, and alarms reach the confirmed operations subscription.

Activate only after these checks and policy approvals: set ActivationApproved=true, retain dry run while testing the upload trigger, then set DryRun=false after reviewing previews. UploadTriggerState controls event routing and the queue consumer. MonitorState independently controls operational monitoring and must be enabled deliberately. ScheduleState controls optional Snyk reconciliation; its expression and timezone are configurable, with 8 AM UTC as the generic default. Set the intended local timezone explicitly in the private deployment file. All three start disabled.

## Routine imports and checkpoints

Upload one immutable, versioned Snyk pair per filename date into its two folders. Default maximum age is 36 hours, each CSV is at most 20 MiB, and an import supports at most 5,000 groups. New-ticket volume defaults to a conservative upper bound of 50, including campaigns. A reviewed operator can approve a larger bound up to 10,000 for a specific import.

Each CSV is capped at 50,000 rows, 100 headers and 20,000 characters per cell. Header-only Snyk details require a paired zero-Critical aggregate and do not resolve existing tickets. Parser/profile changes invalidate continuation; inspect the old job and start a new reviewed import.

Validation and apply each checkpoint at most 20 groups per invocation by default. No ticket is created until the entire batch's payload/schema validation completes. Jira permissions, relationships, legacy identity and API failures can still occur during apply; earlier successful work remains mapped and recoverable. There is no distributed transaction spanning Jira, S3 and DynamoDB.

Results include status, job_id, validation_cursor, cursor and total_groups. COMPLETE means the import finished, not that vulnerabilities were fixed. PENDING means a saved checkpoint awaits continuation. Counters in a continuation result describe that invocation; the paginated action history gives the full job outcome.

Inspect or resume an exact job ID using the JSON templates. `resume` changes state and requires --apply. A volume review requires approved_new_ticket_limit. For other review reasons, resolve the problem and start a new reviewed ingest with force=true; the old review record is retained. Policy/destination changes invalidate a saved job and require a new reviewed import. `force` does not bypass identity checks or permit duplicate creation.

For mismatched counts, prefer a consistent export pair. If security approves a known difference, add a reconciliation containing exact risk_sha256/issues_sha256, risk_count/detail_count, approved_by, reason and a timezone-aware expires_at within 72 hours. Expired or different-file approvals do not apply. Do not disable reconciliation. Historical reports must not be made “current” by renaming them.

## Source facts and additional products

Prefer real source-provided installed/fixed versions and paths in the rich CSV fields. If unavailable, a trusted producer may create a sidecar named `enrichment/<detail CSV basename>.json`. It must have schema=1, source, report_sha256, and occurrences matched exactly by repository/finding_id/target. See `config/enrichment.example.json`. Reported fixes and no-supported-fix assertions require a provenance URL; the sidecar is version-pinned and included in the job identity.

No source API is queried automatically. Do not invent upgrade versions from a CVE or Snyk ID. The original supplied detail reports require remediation triage because exact fix data is absent.

Generate the enrichment sidecar before the pair is processed. A later sidecar upload does not itself trigger a report job; invoke a reviewed ingest against the unchanged immutable reports to incorporate the new enrichment version. Do not overwrite the original CSV to force another upload event.

Onboard Alert Logic with `profile-preview` against a real export. Approve schema_version, actual header/status/severity semantics, stable IDs, grouping field, remediation evidence and sample SHA-256, then supply certification.approved_by and certification.sample_sha256 in ProductProfilesJson. The example remains unverified and cannot write live Jira. CSV formats needing multiple files or non-CSV data require an additional adapter, not an approximate mapping.

`operation=bundles` proposes exact shared-fix candidates only when multiple finding IDs share source-backed package/version/path/environment scope. It does not create, merge, close or delete issues.

## Optional attachments through the API

Upload evidence to the attachment folder. The trusted scanner must tag the exact object version malware-scan-status=CLEAN after scanning. Then review `events/with-attachment.json`, supplying an explicit destination issue key or an exact mapped repository/finding target, plus s3_key and preferably version_id.

```bash
python3.12 scripts/security_operator.py invoke --function <function> \
  --region <region> --event events/with-attachment.json
python3.12 scripts/security_operator.py invoke --function <function> \
  --region <region> --event events/with-attachment.json --apply
```

The operation does not need new/current reports. It prevalidates every target and file before uploading, pins scan tags and download to the same version, checks Jira's limit, and accepts at most 20 files of 10 MiB each with a 25 MiB combined limit. Attachment filenames include a 32-hex-character content-digest suffix for repeat-request reuse; older short-suffix filenames are not automatically recognized. A partially completed attachment request can be explicitly retried; it has no dedicated continuation job. Jira attachments are not cryptographically re-downloaded to confirm existing bytes, so filename/size reuse assumes trusted Jira editors.

`jira_attachment_smoke.py` is a separate deliberate local-file smoke tool, dry-run by default and --upload to mutate. It requires an explicit --project, --origin and --secret-id; it has no default customer project or tenant. It bypasses S3 scanning because the operator supplies a trusted local file. Use the protected S3 path for routine evidence handling.

## Positive verification and exceptions

Upload reviewed JSON under verification/, record its S3 version and exact SHA-256, then review the verify/exception event template. Both require --apply, existing authoritative mappings, all affected targets, owner and approver.

Verification requires resolved disposition, a sha256 artifact identity, deployment and scan HTTPS references, and a timezone-aware scan no older than 36 hours. It must follow deployment and the most recent Open observation. Exceptions require reason, controls, migration plan, approval link and future expiry at most 90 days away.

Approved facts become visible in the managed Jira description and labels, preserving developer notes. Optional policy transition IDs must be confirmed against the actual Jira workflow; without them, verified status is recorded without an automatic Jira transition. A newer Open observation flags source-still-open and can use an approved reopen transition. CSV absence never closes tickets or campaigns.

These are trusted, reviewed assertions, not independently authenticated responses from a scanner API. IAM is the approver authorization boundary; free-text approved_by alone is not an identity proof. Enable fully automatic closure only after adding an authenticated verification provider and validating target/deployment semantics.

## Failure and recovery

Inspect protected job/audit history and error types before retrying. Permanent report errors produce QUARANTINED records and a rejection alarm; fix the source and submit a new reviewed, immutable pair. Never blindly redrive malformed input. Temporary delivery/API failures retry and can enter the upload failure queue; redrive after the underlying problem is fixed.

An uncertain Jira create response leaves a PENDING identity claim rather than risking another POST. Review Jira using the creation intent/nonce and adopt the exact issue, or approve a repair only after confirming no issue was created. Missing/inaccessible mapped tickets and ambiguous/copied identities also require review; do not interpret 403 as deletion.

`operation=repair` resets a specific v2 mapping after destination validation and an audited approved_reason. It preserves identity metadata, does not delete Jira issues, and does not itself authorize adopting an unrelated issue. The next import still validates signed identity and legacy candidates. This is a privileged action, not a routine retry.

The monitor expires pair waits, marks expired exceptions for review in Jira, and retries failed notifications. An import's completed state is independent of SNS delivery. Confirm the SNS email subscription and CloudWatch alarm route; protected summaries and logs can contain repository names and finding context.

For lost target state, use `events/restore.json` with a reviewed exact mapping audit reference and --apply. Restore checks the destination, issue-bound signed property, scope hash, managed-section hash and observation/lifecycle metadata before reinstating the full record. It does not silently adopt or replace an unrelated known issue. If a signed recovery lacks full scope and a new export has only a subset, ingestion stops for this recovery rather than dropping earlier targets. Targets absent from a Critical-only export remain unresolved until positive evidence covers the full retained scope.

## Export and retire

Export a stable job and its complete paginated actions without changing AWS or Jira. Including --audit-bucket follows version-pinned artifact references, verifies hashes, and exports reachable snapshot, mapping, intent, approval and history artifacts. The local output is exclusively created with mode 0600; treat it as sensitive security data.

```bash
python3.12 scripts/security_operator.py export --function <function> \
  --region <region> --job-id <exact job ID> --product snyk \
  --audit-bucket <audit bucket> --output reviewed-job-export.json
```

Omit --audit-bucket for a compact manifest. Full exports fetch only the approved audit bucket; original CSV/enrichment object references remain provenance in the manifest rather than authorizing reads of other buckets. Exports are bounded to 10,000 artifacts and 128 MiB; for larger history retain the manifest and retrieve protected versions separately. Independent attachment operations have their own audit IDs and must be retained/exported separately. Exports are not backups of every Jira comment, human edit or external scanner record.

To retire a source, add it to retired_sources in an approved policy, stop its delivery/trigger, drain or review pending work, export needed evidence, and apply the retention policy. Retirement blocks new Jira mutations for that source without deleting Jira issues or identity mappings. Hard deletion and legal-hold policy are separate approved administrative operations, intentionally not an automatic button.

## Release constraints still requiring verification

Live AWS/Jira integration, SAM/arm64 deployment, real owner/SLA/adoption values, source API enrichment, actual Alert Logic schema, trustworthy malware scanning, notification delivery and retention approval remain external gates. Versioned audit objects are append-only for the Lambda role, not S3 Object Lock/WORM against administrators. Jira description and S3 notification updates lack atomic CAS; coordinate external writers. No web dashboard, hour-precision SLA escalation engine, bulk Jira migration or automatic campaign closure is provided.
