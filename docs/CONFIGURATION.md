# Private environment configuration

Keep environment-specific values out of GitHub. The tracked `config/environment.example.json` and `config/deployment.example.json` contain key names and blank values only. Create private copies under ignored `config/local/`; never populate the tracked examples. The configuration tool does not source a shell file, execute expressions or print settings values.

For prerequisites, account preparation, exact deployment steps and activation checkpoints, start with the [complete setup guide](SETUP.md). This document is the settings reference, not a substitute for live staging acceptance.

## Create and validate local settings

Run from the repository root with Python 3.12:

```bash
python3.12 scripts/environment_config.py init
```

This creates `config/local/environment.json` and `config/local/deployment.json` with mode 0600. It never overwrites existing files. Edit these private files in your local editor. Blank optional values use the documented safe defaults; blank required values stop validation.

For an initial SAM deployment, set `JIRA_ORIGIN` to the approved exact Jira Cloud HTTPS origin, `JIRA_PROJECT_KEY` to the explicitly approved destination project, and `JIRA_SECRET_ARN` to the approved Secrets Manager ARN. There is no default tenant or project. Set deployment `stack_name` and `region`; set `profile` only if using a named AWS SDK/SSO profile. `INPUT_BUCKET` may remain blank to create a managed bucket, or identify a reviewed existing same-region bucket. Set `ScheduleTimezone` explicitly when local time rather than the generic UTC default is required.

Leave `STATE_TABLE_NAME`, `AUDIT_BUCKET`, `SUMMARY_TOPIC_ARN` and `UPLOAD_QUEUE_URL` blank for SAM. The stack generates them and keeps IAM aligned. Those variables are still available in the environment template for a separately reviewed direct-runtime configuration; the SAM renderer refuses unmanaged overrides. Do not substitute arbitrary external state/audit resources without updating IAM and recovery design.

```bash
python3.12 scripts/environment_config.py validate
python3.12 scripts/environment_config.py render \
  --output config/local/samconfig.staging.toml
```

The renderer writes a private, exclusive SAM file. Choose a new output filename when regenerating; it does not overwrite a previous artifact. Enabled triggers, monitoring, schedules, disabled dry run or activation approval require an explicit `--allow-active` acknowledgement. Rendering is local only and does not deploy or authorize a Jira mutation.

Deploy only after the staging checklist in the operating guide. Resolve the private configuration path in the context of the built template; the example uses an absolute path to avoid referring to the wrong folder. [SAM configuration guidance](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-config.html)

```bash
sam build --template-file template.yaml
sam deploy --template-file .aws-sam/build/template.yaml \
  --config-file /absolute/path/to/config/local/samconfig.staging.toml
```

Review the change set; never add a production token to command arguments. The renderer checks format and safety constraints, not IAM privileges, actual Jira permissions, scanner role behavior or the existence of cloud resources. Schedule grammar and final generated resource-name sizes must also pass SAM/AWS validation.

## Secrets and AWS credentials

Do not add `JIRA_API_TOKEN`, `JIRA_EMAIL`, `AWS_ACCESS_KEY_ID`, signing keys or passwords to these files. Unknown keys are rejected. Store Jira account information and the independent signing key in Secrets Manager; use AWS IAM roles/SSO and the normal SDK credential chain. A private settings file is still sensitive infrastructure metadata, not a secret vault.

The Jira client currently supports a regular automation account's email/API-token Basic authentication at the exact tenant origin. It does not support OAuth, scoped-token gateway URLs or native managed Atlassian Service accounts. Review the [authentication gate](SETUP.md#step-7-choose-compatible-jira-authentication) before choosing credentials. The deployment `profile` selects SAM only; operator Python commands need the intended AWS SDK profile/default independently.

AWS recommends Secrets Manager for API credentials, and Lambda limits the combined environment to 4 KiB. The renderer applies a conservative budget including room for SAM-generated names. Mappings that do not fit need a separately designed external configuration mechanism rather than bypassing the limit. [AWS environment guidance](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)

## Configuration precedence and safeguards

The private JSON is read by the local configuration tool. Nonblank values override generic defaults; the renderer writes explicit parameter overrides. SAM converts those parameters and generated resources into Lambda environment variables. The Lambda does not load workstation files or bundle `config/local/`.

Prefix settings are relative to `INGESTION_PREFIX`, must end in `/`, cannot overlap each other and cannot overlap protected configuration/enrichment/verification folders. Their SAM parameters update application reads, bucket policies, IAM paths and lifecycle scopes together. Review custom prefixes against certified product profiles and uploader permissions before activation.

Use INFO logging normally. Application DEBUG is isolated from SDK transport logs, but developers must still avoid adding source bodies or secret values to application messages. Live operations reject disabling clean-attachment verification. Snyk live imports also reject disabled count/date reconciliation.

## Deployment settings

`deployment.json` contains stack name, region, optional SDK profile and the following non-runtime parameters:

| Parameter | Generic default | Purpose |
| --- | --- | --- |
| UploadTriggerState | DISABLED | Event routing and queue consumer |
| ScheduleState | DISABLED | Optional Snyk reconciliation |
| MonitorState | DISABLED | Independent operational monitoring |
| DailyScheduleExpression | cron(0 8 * * ? *) | Default daily reconciliation time |
| ScheduleTimezone | UTC | IANA timezone; set the approved local timezone explicitly |
| MonitorScheduleExpression | rate(1 hour) | Operational check frequency |
| EvidenceScannerRoleArn | Blank | Trusted version-aware malware scanner |
| EvidenceProducerRoleArn | Blank | Trusted enrichment writer |
| NotificationEmail | Blank | Optional confirmed SNS email subscription |
| InputRetentionDays | 90 | Managed input and audit lifecycle settings |
| LogRetentionDays | 30 | CloudWatch log retention |

`STATE_RETENTION_DAYS` independently controls operational DynamoDB TTL. Identity mappings do not expire and retain sensitive facts. S3 current-version expiration and noncurrent-version deletion are different events, so the configured days are not an exact end-to-end deletion deadline. [AWS lifecycle behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html)

## Environment variable reference

The table below is the application-owned variable inventory. AWS-reserved runtime variables are intentionally excluded. The tracked template has blank values even when a generic default exists.

| Variable | Generic default | SAM parameter | Notes |
| --- | --- | --- | --- |
| `INPUT_BUCKET` | Blank | `ExistingInputBucketName` | Blank creates managed input; otherwise existing bucket |
| `INGESTION_PREFIX` | Blank | `IngestionPrefix` | Validated application setting |
| `RISK_REPORT_PREFIX` | `snyk/risk-exposure/` | `RiskReportPrefix` | Validated application setting |
| `ISSUES_REPORT_PREFIX` | `snyk/issues-detail/` | `IssuesReportPrefix` | Validated application setting |
| `ATTACHMENT_PREFIX` | `snyk/attachments/` | `AttachmentPrefix` | Validated application setting |
| `PRODUCTS_REPORT_PREFIX` | `products/` | `ProductsReportPrefix` | Validated application setting |
| `PRODUCT_PROFILES_JSON` | `{}` | `ProductProfilesJson` | Explicit additional-product schema/certification JSON |
| `JIRA_SECRET_ARN` | Required | `JiraSecretArn` | Required Secrets Manager reference; never the token |
| `JIRA_PROJECT_KEY` | Required | `JiraProjectKey` | Explicit approved project; no customer default |
| `JIRA_EPIC_ISSUE_TYPE` | `Epic` | `CampaignIssueType` | Validated application setting |
| `JIRA_CHILD_ISSUE_TYPE` | `Bug` | `FindingIssueType` | Validated application setting |
| `JIRA_PRIORITY_NAME` | `Major` | `JiraPriorityName` | Validated application setting |
| `JIRA_ALLOWED_HOST_SUFFIX` | `atlassian.net` | `JiraAllowedHostSuffix` | Validated application setting |
| `JIRA_ORIGIN` | Required | `JiraOrigin` | Required exact approved HTTPS Jira Cloud origin |
| `STATE_TABLE_NAME` | SAM-generated | Generated resource | SAM-generated state table; direct-runtime override only |
| `AUDIT_BUCKET` | SAM-generated | Generated resource | SAM-generated audit bucket; direct-runtime override only |
| `SUMMARY_TOPIC_ARN` | SAM-generated | Generated resource | SAM-generated notification topic; direct-runtime override only |
| `UPLOAD_QUEUE_URL` | SAM-generated | Generated resource | SAM-generated continuation queue; direct-runtime override only |
| `POLICY_KEY` | Blank | `PolicyKey` | Protected S3 policy key, paired with SHA-256 |
| `POLICY_SHA256` | Blank | `PolicySha256` | Exact approved policy-file SHA-256 |
| `MAX_INPUT_AGE_HOURS` | `36` | `MaxInputAgeHours` | Validated application setting |
| `MAX_INPUT_BYTES` | `20971520` | `MaxInputBytes` | Validated application setting |
| `MAX_ATTACHMENT_BYTES` | `10485760` | `MaxAttachmentBytes` | Validated application setting |
| `MAX_ATTACHMENTS_PER_RUN` | `20` | `MaxAttachmentsPerRun` | Validated application setting |
| `ALLOWED_ATTACHMENT_TYPES` | `text/csv,text/plain,application/json,application/pdf,image/png,image/jpeg` | `AllowedAttachmentTypes` | Validated application setting |
| `REQUIRE_CLEAN_ATTACHMENT_TAG` | `true` | `RequireCleanAttachmentTag` | Validated application setting |
| `ENFORCE_COUNT_MATCH` | `true` | `EnforceCountMatch` | Validated application setting |
| `REQUIRE_SAME_REPORT_DATE` | `true` | `RequireSameReportDate` | Validated application setting |
| `UPDATE_EXISTING_TITLES` | `true` | `UpdateExistingTitles` | Validated application setting |
| `DRY_RUN` | `true` | `DryRun` | Automatic-import default; privileged manual applies and monitoring are separate |
| `ACTIVATION_APPROVED` | `false` | `ActivationApproved` | Separate approval gate for live mutations |
| `MAX_GROUPS_PER_RUN` | `5000` | `MaxGroupsPerRun` | Validated application setting |
| `MAX_GROUPS_PER_INVOCATION` | `20` | `MaxGroupsPerInvocation` | Validation/apply checkpoint chunk |
| `MAX_NEW_TICKETS` | `50` | `MaxNewTickets` | New-ticket guardrail including campaigns |
| `WORK_SECONDS` | `240` | `WorkSeconds` | Work budget; cannot exceed 240 seconds |
| `PAIR_WAIT_HOURS` | `4` | `PairWaitHours` | Validated application setting |
| `STATE_RETENTION_DAYS` | `90` | `StateRetentionDays` | Operational state TTL; identity mappings do not expire |
| `LOG_LEVEL` | `INFO` | `LogLevel` | Application logger only; SDK logs remain restricted |

## Publication checks

Before committing, run `python3.12 scripts/check_repository.py --staged`. It scans the actual index, rejects private tracked paths and populated JSON templates, and reports recognizable secrets without displaying values. CI repeats it. `.gitignore` does not remove an already-tracked file; audit the index and history separately. [GitHub ignore guidance](https://docs.github.com/en/get-started/git-basics/ignoring-files)

Enable GitHub secret scanning/push protection when available and use an approved independent full-history scanner. Availability depends on repository ownership and plan. The local preflight cannot guarantee that every secret pattern, private source value or earlier commit has been detected. [GitHub secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning)
