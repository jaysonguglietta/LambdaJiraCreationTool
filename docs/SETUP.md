# Complete setup guide for security CSV Jira automation

Use this guide to install the tools, prepare Jira and AWS, configure a private staging environment, test a report pair, and deliberately enable automated processing. It is written for security operators, Jira administrators and AWS platform administrators. No web application or browser session is required for runtime processing; account administration and initial credential creation may still require your organization's approved sign-in process.

Start in staging. The repository's initial settings disable upload processing, schedules, monitoring and live Jira writes. A successful unit test or dry run is not approval to activate production. The steps below describe actions for an authorized administrator; publishing this guide does not execute them.

Documentation checked against the repository and linked provider documentation on October 5, 2026. Local tests and GitHub CI have run; SAM deployment, the actual arm64 Lambda runtime, live Jira permissions and end-to-end cloud processing remain unverified.

## What you are setting up

Two Snyk CSV exports are uploaded to separate folders in one versioned S3 bucket. EventBridge sends report-upload events to an SQS FIFO queue. A Python 3.12 Lambda validates the reports, compares counts and creates or updates Jira work in one explicitly configured project. DynamoDB stores identities and checkpoints; a separate versioned S3 bucket stores audit history. SNS and CloudWatch provide notifications and alarms.

Ticket grouping is one repository campaign per source/repository, with one child per source/repository/stable finding ID. Multiple affected targets for the same finding are retained in that child. New campaigns default to Epic and children to Bug. Only Open Critical Snyk findings become remediation work. This is not one large ticket containing every issue in a repository.

The optional 8 AM schedule reconciles reports already uploaded. It does not log in to Snyk, export CSVs, fetch source APIs or generate attachments. Someone or a separately managed upstream process must supply fresh reports. There is no installation wizard or web dashboard; setup results, previews and job records are JSON, and developers work in Jira.

## Guide navigation

- [Prerequisites and responsibilities](#prerequisites-and-responsibilities)
- [Install and verify the local tools](#install-and-verify-the-local-tools)
- [Prepare AWS access](#prepare-aws-access)
- [Prepare the Jira project and authentication](#prepare-the-jira-project-and-authentication)
- [Create the Jira secret](#create-the-jira-secret)
- [Create private configuration files](#create-private-configuration-files)
- [Prepare ownership and existing issue adoption](#prepare-ownership-and-existing-issue-adoption)
- [Deploy the disabled staging stack](#deploy-the-disabled-staging-stack)
- [Verify storage and publish the approved policy](#verify-storage-and-publish-the-approved-policy)
- [Prepare and upload the first report pair](#prepare-and-upload-the-first-report-pair)
- [Validate the cloud setup and dry run](#validate-the-cloud-setup-and-dry-run)
- [Run a controlled live staging import](#run-a-controlled-live-staging-import)
- [Enable automatic uploads and optional schedules](#enable-automatic-uploads-and-optional-schedules)
- [Prepare a separate production environment](#prepare-a-separate-production-environment)
- [Enable optional capabilities](#enable-optional-capabilities)
- [Operate and maintain the deployment](#operate-and-maintain-the-deployment)
- [Troubleshooting](#troubleshooting)
- [Completion checklist](#completion-checklist)

## Prerequisites and responsibilities

### Required before cloud setup

| Requirement | What must be available | Who confirms it |
| --- | --- | --- |
| Source access | Permission to export Snyk Risk Exposure by Introduction Category and Issues Detail for identical organization/project filters and report date | Security operator |
| AWS account and Region | Approved account, billing, Region, resource naming, retention and staging isolation | AWS administrator |
| Deployment identity | Approved IAM/SSO role that can deploy the resources and IAM policies in `template.yaml` | AWS administrator |
| Operator identity | Approved AWS identity for explicit Lambda invocation and relevant protected evidence/audit reads | AWS administrator and security owner |
| Upload identity | Separate, narrowly scoped role for report-object uploads, without approval or secret access | AWS administrator |
| Jira destination | Jira Cloud project key, administrator access to its types/screens/permissions, and an approved staging destination | Jira administrator |
| Jira authentication | Dedicated automation account using the supported authentication described below | Jira administrator |
| Routing decisions | Repository owner account IDs, priority names, SLA dates, triage owner and existing issue adoption review | Engineering/security owners |
| Network | Local access to GitHub/Python package sources and AWS; Lambda HTTPS access to the Jira origin and AWS endpoints | Platform/network owner |
| Operational owner | Named people responsible for alerts, token expiry, failed imports, exceptions, recovery and dependency updates | Service owner |
| Retention and privacy | Approval for vulnerability facts in Jira, S3, DynamoDB, logs and notifications | Security/privacy owner |
| Activation approval | A documented decision authorizing the destination and the first live import | Security/service owner |

Jira administrators and AWS administrators may be different people. Obtain their approvals before the dependent step; installation does not create your organization's operator/uploader identities or approve their access.

### Local software

Required for the full deployment path:

- Git and access to this GitHub repository. A private fork requires its own repository access.
- Python **3.12** with `venv` and `pip`. Match the Lambda runtime rather than relying on whichever `python` appears first on your path.
- AWS CLI **v2**, including support for `s3api put-object --if-none-match`.
- AWS SAM CLI compatible with Python 3.12 and arm64 builds.
- Docker or an approved compatible container runtime for the `sam build --use-container` procedure in this guide. Ensure the daemon is running and can build for Linux arm64. On x86 hosts, use an approved arm64-capable build environment or administrator-approved emulation.
- A local editor for JSON files and your organization's password manager/secret-management process.

Docker, AWS CLI and SAM are not required for the offline unit tests or CSV preview. GitHub CLI is optional for publishing changes and is not a runtime dependency. There is no Node.js, SQL server, Jira browser plug-in or always-open browser prerequisite.

Install tools using their supported platform instructions: [AWS CLI installation](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), [SAM installation](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html), [SAM container prerequisites](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-docker.html) and [Python virtual environments](https://docs.python.org/3.12/library/venv.html). Windows users should use an approved shell/build environment and adapt `.venv/bin/` to their environment; the commands here target macOS/Linux shells.

### AWS permissions and deployment constraints

Have the administrator review `template.yaml`, the deployment role, permission boundaries and organization SCPs. Deployment involves CloudFormation/SAM artifacts, S3, Lambda, IAM role creation and scoped `iam:PassRole`, DynamoDB, SQS, EventBridge rules, EventBridge Scheduler, SNS, KMS, CloudWatch/Logs and X-Ray permissions. Do not solve a missing permission by giving routine uploaders AdministratorAccess.

The template sets Lambda reserved concurrency to **1** to serialize writers. AWS requires capacity to remain available for unreserved functions; verify enough account concurrency headroom before deploying. Low-quota/new accounts may require a quota increase. Do not remove the serialization control to get past a deployment error. [AWS reserved concurrency guidance](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html)

Use a same-account, same-Region input bucket and secret for the baseline deployment. A managed new input bucket is the simplest first staging setup. Cross-account inputs, VPC networking, mandatory permission boundaries and custom KMS keys require additional reviewed infrastructure configuration; they are not enabled simply by filling in a JSON value.

The function is not attached to a VPC by this template. If your organization requires a VPC, arrange AWS endpoint access and approved egress to Jira, then review the IaC changes. The Jira client intentionally ignores environment HTTP proxy settings and rejects redirects; an enterprise proxy requirement needs a supported design, not an ad hoc bypass.

Budget for storage, DynamoDB/PITR, queues, schedules, logs, monitoring, SNS and the notification KMS key as well as Lambda. Low invocation volume does not mean the entire stack is free.

### Optional feature prerequisites

| Capability | Additional prerequisite | Default behavior without it |
| --- | --- | --- |
| Email notifications | Approved recipient and confirmed SNS subscription | No email recipient is configured |
| Attachments | Jira attachment permission/settings and an external version-aware malware scanner with an approved role | No automatic attachment upload; unscanned evidence is rejected |
| Rich remediation sidecars | Trusted enrichment producer, provenance and exact report hash/occurrence mapping | Missing facts remain remediation triage, not invented fixes |
| Jira status transitions | Approved transition IDs available in the actual issue workflow | Evidence is recorded without an automatic transition |
| Alert Logic/other CSVs | Real representative sample, explicit mapping, stable IDs and sample-bound certification | The supplied example cannot create live tickets |
| Automatic scan-based closure | Independently authenticated source/deployment verification integration | Not implemented; reviewed operator evidence is required |

Do not enable all optional capabilities merely to complete initial setup. First prove a small Snyk import end to end.

## Install and verify the local tools

### Step 1 Clone the published repository

Choose an approved working directory, then run:

```bash
git clone https://github.com/jaysonguglietta/LambdaJiraCreationTool.git
cd LambdaJiraCreationTool
git status --short --branch
git rev-parse HEAD
```

Record the approved commit in your private deployment/change record. Do not upload private customer CSVs or populated configuration to the public repository. Check out the reviewed release/commit if your organization requires release approval; the latest branch is not automatically an approved production release.

### Step 2 Confirm tool versions

```bash
git --version
python3.12 --version
aws --version
sam --version
docker version
```

**Checkpoint:** Python reports 3.12; AWS CLI reports v2; SAM is installed; Docker shows both client and running server. A missing Docker server is a deployment-build issue, not a reason to skip dependency/runtime validation.

### Step 3 Create an isolated Python environment

Run from the repository root:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --only-binary=:all: -r src/requirements.txt
```

The second installation supplies the pinned, hash-checked runtime SDK needed by cloud operator commands. Explicit `.venv/bin/` commands avoid accidentally using another Python installation. Development tools are version-pinned, but their transitive dependency set is not fully hash-locked. Do not commit `.venv/`.

### Step 4 Run the offline checks

```bash
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/cfn-lint template.yaml
.venv/bin/python scripts/check_repository.py --staged
.venv/bin/python scripts/security_operator.py preview \
  --risk tests/fixtures/risk.csv --issues tests/fixtures/issues.csv
```

**Checkpoint:** this revision has 134 unit tests. Checks should exit successfully; the synthetic preview reports `OFFLINE_PREVIEW`, two finding tickets and two campaigns. These are proposed objects, not actual Jira creations. Test count may change in later revisions; investigate failures rather than relying solely on the number.

Fixtures are deliberately synthetic and historically dated. Do not upload them unchanged for a cloud freshness test. `cfn-lint` checks template structure; it does not prove account permissions, quotas, successful deployment or Jira compatibility.

For release packaging, also run the dependency audit and deterministic build instructions in the [README](../README.md#build-and-validate). Neither building a zip nor passing CI deploys the application.

## Prepare AWS access

### Step 5 Configure an approved AWS identity

Prefer an IAM Identity Center/SSO profile or your organization's assumed-role flow. Do not put AWS access keys in application JSON, Jira events or GitHub. With an SSO profile:

```bash
aws configure sso --profile REPLACE_WITH_STAGING_PROFILE
aws sso login --profile REPLACE_WITH_STAGING_PROFILE
aws sts get-caller-identity --profile REPLACE_WITH_STAGING_PROFILE
```

Use the [AWS SSO setup instructions](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html) for your organization-specific start URL, account and role selection. **Checkpoint:** the returned account and assumed role are the approved staging destination. Stop if they are not.

Check Lambda account settings and have the administrator confirm concurrency availability:

```bash
aws lambda get-account-settings \
  --profile REPLACE_WITH_STAGING_PROFILE --region REPLACE_WITH_REGION
```

AWS SDK commands in `security_operator.py` use the ordinary SDK credential chain. The `profile` in `deployment.json` is written into SAM configuration; it does **not** automatically select the profile for separate Python operator commands. This guide sets `AWS_PROFILE` for each such invocation. Passing `--region` explicitly avoids another common source of wrong-environment calls.

All `REPLACE_WITH_...` values in commands are placeholders. Substitute your approved values locally. ARNs, account IDs, object paths and profile names are infrastructure metadata and should still be kept out of public issue comments and screenshots.

## Prepare the Jira project and authentication

### Step 6 Approve and configure the destination project

Use the requested destination only after its project administrator approves it. A separate staging project is recommended. The application does not create projects, configure boards or migrate issues between projects.

A new project is useful if the existing project cannot safely provide the required issue types, screens, permission scope and workflow. It is not universally required: an existing compatible project works. Prefer a company-managed Jira Cloud software project for predictable Epic/Bug hierarchy, then verify the actual scheme rather than assuming its defaults.

Have the Jira administrator confirm:

1. The exact project key and automation account access.
2. Campaign and child issue types. Defaults are `Epic` and `Bug`; change private settings if your approved scheme differs.
3. The child `parent` field can refer to the campaign Epic. An explicitly adopted non-Epic campaign uses a Relates issue link instead.
4. A valid priority name. The application's generic default is `Major`, which may not exist in your project's priority scheme. Configure an actual approved name.
5. Create/edit screens support summary, description, labels, priority and parent, plus assignee/due date if routing uses them.
6. Required custom fields have approved values and valid Jira payload shapes. Required system fields not supported by this application's payload need a project default, a screen/workflow change or an application extension.
7. Unknown repositories can enter a clearly owned triage queue; they are not silently assigned to guessed developers.
8. Board filters and initial workflow status include the new tickets. The application does not guarantee that an issue appears in a particular backlog or sprint.
9. Optional transition IDs and attachment settings are available if those capabilities will be enabled.

Grant least privilege within this project. The setup check tests Browse Projects, Create Issues, Edit Issues and Link Issues. Assignment/due-date routing may require Assign Issues/Schedule Issues; attachments require Create Attachments; transitions require the appropriate workflow permissions. These conditional permissions must also be checked by the administrator and staging tests.

### Step 7 Choose compatible Jira authentication

**Important compatibility limit:** the current client uses Basic authentication with an Atlassian account email and an API token, sent directly to one exact origin such as `https://jira-example.atlassian.net`. It supports neither OAuth nor the scoped-token gateway `https://api.atlassian.com/ex/jira/{cloudId}`.

Use an organization-approved **dedicated automation account that is a regular licensed Atlassian account**, with a compatible API token without scopes and tightly limited project permissions. This is not the native managed Atlassian **Service accounts** feature: Atlassian requires scopes for those service-account tokens, so they are not compatible with this client. Atlassian recommends scoped tokens; if your policy requires scoped tokens, native service accounts or OAuth, **stop before deployment activation and extend the authentication adapter**. Do not weaken your organization's policy to fit the current code. [Atlassian API token guidance](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/), [Jira REST Basic authentication](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/)

For the supported path, create the token through the approved account-management interface, choose an approved expiry, store it in the approved secret process and assign a rotation owner. Atlassian tokens expire; this application does not independently notify you of token expiry. Do not use an account password or a browser cookie as an API token. Do not paste the token into chat, the shell, a CSV or a Git-tracked file.

This deployment is an internal single-organization integration. Do not repurpose this credential pattern into a publicly distributed, multi-customer integration without reviewing Atlassian's integration requirements and redesigning authorization.

## Create the Jira secret

### Step 8 Store credentials in AWS Secrets Manager

Use the approved AWS console/secret-management workflow in the staging account and Region. Create an **Other type of secret** containing these four string fields:

| Field | Value to enter privately |
| --- | --- |
| `base_url` | Exact Jira HTTPS origin, with no path, trailing slash, port, query or embedded credentials |
| `email` | Dedicated automation account's Atlassian email |
| `api_token` | Compatible account API token |
| `identity_key` | Independent cryptographically random signing secret; generate at least 32 random bytes with an approved password manager, for example encoded as 64 hex characters |

The independent identity key authenticates managed issue identities; it is not the Jira token and must not be derived from it. The application accepts a minimum of 32 characters, but a long string is not a substitute for cryptographic randomness.

Use the service's default managed encryption for the baseline secret. A customer-managed secret KMS key requires an explicit scoped decrypt grant and matching key policy; those are not added automatically by this template. Assign secret administration and runtime read access separately. [AWS secret creation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/create_secret.html)

Copy only the secret ARN into private configuration. Do not copy its JSON value into the repository. An ARN can be checked without retrieving the secret body:

```bash
aws secretsmanager describe-secret \
  --secret-id REPLACE_WITH_SECRET_ARN \
  --query ARN --output text \
  --profile REPLACE_WITH_STAGING_PROFILE --region REPLACE_WITH_REGION
```

**Checkpoint:** the secret is in the intended account/Region, has exactly the intended keys, and `base_url` will match `JIRA_ORIGIN`. Do not print `get-secret-value` results to a shared terminal or deployment log.

Rotate the Jira token without changing `identity_key`. Identity-key rotation requires a controlled re-signing/recovery migration; changing it casually can make previously managed issues fail identity validation. Maintain an approved recovery record for the secret and key.

## Create private configuration files

### Step 9 Create the blank private copies

```bash
.venv/bin/python scripts/environment_config.py init
git check-ignore config/local/environment.json config/local/deployment.json
```

The tool creates `config/local/environment.json` and `config/local/deployment.json` with mode 0600 and refuses to overwrite existing files. If copies already exist, inspect and edit them; do not delete them just to rerun initialization. Both files should be ignored by Git.

**Never populate** `config/environment.example.json` or `config/deployment.example.json`. They remain blank public templates. Private copies are not a secret vault: they contain deployment metadata and secret references, not raw Jira/AWS credentials.

### Step 10 Fill in the environment copy

Open `config/local/environment.json` in your editor. All values are strings, including booleans and numbers. Set:

| Key | Initial staging value or decision |
| --- | --- |
| `JIRA_ORIGIN` | Approved exact Jira Cloud HTTPS origin |
| `JIRA_PROJECT_KEY` | Approved staging project key |
| `JIRA_SECRET_ARN` | ARN from Step 8 |
| `JIRA_PRIORITY_NAME` | Approved priority that actually exists in Jira |
| `JIRA_EPIC_ISSUE_TYPE` | `Epic`, or the approved existing campaign type |
| `JIRA_CHILD_ISSUE_TYPE` | `Bug`, or the approved existing finding type |
| `INPUT_BUCKET` | Leave blank to create a managed bucket; otherwise an approved existing bucket |
| `INGESTION_PREFIX` | Optional root such as `incoming/security/`; choose once before setting upload permissions |
| `DRY_RUN` | `true` |
| `ACTIVATION_APPROVED` | `false` |
| `REQUIRE_CLEAN_ATTACHMENT_TAG` | `true` |
| `ENFORCE_COUNT_MATCH` | `true` |
| `REQUIRE_SAME_REPORT_DATE` | `true` |
| `POLICY_KEY`, `POLICY_SHA256` | Initially blank; bind the approved S3 policy later |

Leave `STATE_TABLE_NAME`, `AUDIT_BUCKET`, `SUMMARY_TOPIC_ARN` and `UPLOAD_QUEUE_URL` blank: SAM generates these resources and aligns IAM. Other blank optional values use the generic defaults documented in the [complete 38-key reference](CONFIGURATION.md#environment-variable-reference).

Do not add `JIRA_API_TOKEN`, `JIRA_EMAIL`, AWS keys or signing keys. Unknown keys are rejected. Prefixes are relative to `INGESTION_PREFIX`, end in `/` and must not overlap each other or protected configuration/evidence folders. Do not customize all limits for the first test.

### Step 11 Fill in the deployment copy

Open `config/local/deployment.json`. Preserve its structure: `stack_name`, `region`, `profile` and a `parameters` object. Use a distinct staging stack name, the approved Region and the named SSO profile if applicable. Within `parameters`, explicitly set:

| Parameter | Initial value |
| --- | --- |
| `UploadTriggerState` | `DISABLED` |
| `ScheduleState` | `DISABLED` |
| `MonitorState` | `DISABLED` |
| `DailyScheduleExpression` | `cron(0 8 * * ? *)` if the optional daily reconciliation is wanted |
| `ScheduleTimezone` | Approved IANA timezone; generic default is `UTC` |
| `NotificationEmail` | Approved alert recipient, or blank until arranged |
| `EvidenceScannerRoleArn` | Blank unless the external scanner is ready and approved |
| `EvidenceProducerRoleArn` | Blank unless the trusted enrichment producer is ready |
| `InputRetentionDays` | Approved value; default `90` |
| `LogRetentionDays` | Approved value; default `30` |

If 8 AM means local time, set the intended IANA timezone explicitly, for example `America/New_York` only when that is your approved choice. This is not a machine-local-time setting.

The Lambda does not read these workstation files. The configuration tool renders SAM parameter overrides; SAM puts the relevant values into Lambda environment variables. Raw local configuration is not bundled into the deployment.

### Step 12 Validate the private configuration

```bash
.venv/bin/python scripts/environment_config.py validate
```

**Checkpoint:** `status` is `VALID`, the inventory has 38 environment keys, and the initial configuration is not active. Validation checks syntax, key inventory, prefixes and configuration budgets; it does not verify IAM, real Jira objects or live scanner behavior.

The renderer budgets for Lambda's 4 KiB environment limit and SAM-generated values. Additional-product profile JSON has a separate conservative size bound. If configuration does not fit, design external configuration support rather than disabling the checks.

## Prepare ownership and existing issue adoption

### Step 13 Create a private policy

```bash
umask 077
cp config/policy.example.json config/local/policy.staging-v1.json
```

Edit the private copy. The starting schema contains empty `owners`, `adoptions`, `custom_fields`, `transitions`, `retired_sources` and `reconciliations`, plus a triage name/account ID. It is a safe format example, not approved routing.

An owner entry uses the exact source/repository and an assignable Jira **account ID**, not a guessed email or display name:

```json
{
  "source": "snyk",
  "repository": "organization/service-repo",
  "account_id": "REPLACE_WITH_ASSIGNABLE_ACCOUNT_ID",
  "priority": "REPLACE_WITH_APPROVED_PRIORITY_NAME",
  "sla_hours": 48
}
```

Put this object inside `owners`; use real approved values only in the private file. SLAs produce a Jira calendar due date, not an hour-precision escalation system. Configure `triage_account_id` if your organization requires a fallback assignee. Unknown repositories retain `needs-owner` for explicit review.

Required custom fields go under `custom_fields.campaign` and/or `custom_fields.finding`, keyed by actual `customfield_<number>` IDs with the exact Jira value shape. This mechanism does not supply arbitrary required system fields such as every possible component/security configuration; resolve those through approved project defaults or an application change. Confirm with cloud dry-run payload validation.

### Step 14 Review existing tickets before creating new ones

If work already exists, inspect the destination project and add exact adoption entries. Campaign entries omit `finding_id`; child entries include the stable finding ID. Use **current destination keys** only.

Changing `JIRA_PROJECT_KEY` does not move tickets from the former project. Complete any approved Jira migration outside this application, review resulting keys/hierarchy, then adopt them. A label or title resemblance is not proof that a ticket may be adopted. Do not create a second stack writing the same destination without coordinating state and ownership.

Optional verified/reopen transitions use transition IDs from the actual workflow, not status IDs. They must be available from the relevant current status; have the Jira administrator confirm them. Leave them absent for the initial import if not needed.

Validate the finished policy, keeping its output private because it includes policy contents and account IDs:

```bash
.venv/bin/python scripts/security_operator.py validate-policy \
  --file config/local/policy.staging-v1.json \
  > config/local/policy-validation.staging-v1.json
```

**Checkpoint:** validation succeeds. Record the exact policy SHA-256 for Step 20. Do not add a count-reconciliation exception as a routine workaround; obtain matching reports first.

## Deploy the disabled staging stack

### Step 15 Build for Lambda

```bash
sam build --template-file template.yaml --use-container
```

SAM uses the application's `src/` code and dependency requirements. Review build output and dependency installation; retain hashes/commit provenance in the deployment record. A host-side zip import test does not replace this arm64 build or a live smoke test. [SAM build guidance](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-using-build.html)

### Step 16 Render and deploy the private SAM configuration

```bash
.venv/bin/python scripts/environment_config.py render \
  --output config/local/samconfig.staging-v1.toml
sam deploy --template-file .aws-sam/build/template.yaml \
  --config-file /absolute/path/to/LambdaJiraCreationTool/config/local/samconfig.staging-v1.toml \
  --config-env default
```

Replace the absolute configuration path with your actual checkout path. The renderer refuses to overwrite an existing output; use a new revision filename whenever regenerating. Review the change set before confirming. It acknowledges IAM creation through `CAPABILITY_IAM` and retains change-set confirmation. Do not use `--no-confirm-changeset` for this first setup. [SAM configuration](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-config.html), [SAM deploy options](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-deploy.html)

**Checkpoint:** CloudFormation finishes successfully, the intended Region/account was used, and all initial switches remain disabled. Investigate rollback/failure events before retrying. Do not delete retained state/audit resources as a shortcut.

### Step 17 Record the stack outputs

```bash
aws cloudformation describe-stacks \
  --stack-name REPLACE_WITH_STAGING_STACK \
  --query 'Stacks[0].Outputs' --output table \
  --profile REPLACE_WITH_STAGING_PROFILE --region REPLACE_WITH_REGION
```

Record outputs privately:

| Output | Used for |
| --- | --- |
| `InputBucketName`, `ReportRootPrefix` | Report, policy and evidence locations |
| `FunctionName` | Explicit operator invocations and logs |
| `StateTableName` | Restricted state inspection/recovery |
| `AuditBucketName` | Audit export and recovery evidence |
| `SummaryTopicArn`, `NotificationKeyArn` | Notification delivery and encryption review |
| `UploadRuleName` | Report-upload event routing |
| `UploadQueueUrl`, `UploadDeadLetterQueueUrl` | Import/continuation delivery and failure handling |
| `DeadLetterQueueUrl` | Scheduler/EventBridge delivery-failure queue |
| `ScheduleName` | Optional daily reconciliation schedule |

The operational monitor has logical resource ID `OperationalMonitor`, not its own named output. Use CloudFormation resource details to locate it when checking the schedule.

## Verify storage and publish the approved policy

### Step 18 Check the input bucket

For either managed or existing input, verify versioning and public-access blocking:

```bash
aws s3api get-bucket-versioning --bucket REPLACE_WITH_INPUT_BUCKET \
  --profile REPLACE_WITH_STAGING_PROFILE --region REPLACE_WITH_REGION
aws s3api get-public-access-block --bucket REPLACE_WITH_INPUT_BUCKET \
  --profile REPLACE_WITH_STAGING_PROFILE --region REPLACE_WITH_REGION
```

**Checkpoint:** versioning is `Enabled`, the bucket is private, and administrators have reviewed encryption, TLS enforcement, lifecycle, notification settings and role separation. The managed bucket supplies these controls in the template. An existing bucket's policy, encryption, versioning and lifecycle are **not** configured by this stack; its administrator must verify equivalent controls. External customer-managed S3 encryption keys also need scoped role/key permissions. [S3 versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)

For an existing bucket only, preview the EventBridge notification change:

```bash
AWS_PROFILE=REPLACE_WITH_STAGING_PROFILE .venv/bin/python scripts/configure_bucket_events.py \
  --bucket REPLACE_WITH_INPUT_BUCKET --region REPLACE_WITH_REGION
```

Coordinate with its administrator, then apply with a new private backup filename:

```bash
umask 077
AWS_PROFILE=REPLACE_WITH_STAGING_PROFILE .venv/bin/python scripts/configure_bucket_events.py \
  --bucket REPLACE_WITH_INPUT_BUCKET --region REPLACE_WITH_REGION \
  --apply --backup-file config/local/bucket-notifications.staging-v1.json
```

The script preserves existing notification entries and checks for changes, but S3 notification updates are not atomic compare-and-swap. Do not run competing notification changes. Managed input already enables EventBridge. AWS notes that enabling delivery can take about five minutes; allow for propagation before testing new events. [S3 EventBridge configuration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications-eventbridge.html)

### Step 19 Establish role separation

Have administrators provision the identities they approved earlier:

- Report uploader: write only approved report prefixes; no Secrets Manager reads, arbitrary Lambda invocation, queue injection, DynamoDB editing or protected policy/evidence writes.
- Operator: narrowly authorized Lambda invocation and protected evidence/audit access. Direct invocation can authorize powerful actions, not just harmless imports.
- Policy administrator: write approved configuration revisions and approve their hashes.
- Optional scanner: read/tag the exact evidence versions it scans, under its approved attachment prefix.
- Optional enrichment producer: write approved enrichment sidecars, separate from ordinary report uploaders.

The template creates runtime/scheduler infrastructure roles; it does not create these organizational identities or an external scanner. Setting a trusted role ARN allows that role in managed-bucket restrictions; it does not itself create the role, grant all required permissions or run a scanning service.

### Step 20 Upload and bind the approved policy

Use the administrator identity allowed to write the protected configuration folder. In this example, substitute the actual ingestion root, including its trailing slash; if the root is blank, omit it from the key:

```bash
aws s3api put-object --bucket REPLACE_WITH_INPUT_BUCKET \
  --key REPLACE_WITH_ROOT/configuration/policy-staging-v1.json \
  --body config/local/policy.staging-v1.json --content-type application/json \
  --if-none-match '*' \
  --profile REPLACE_WITH_POLICY_ADMIN_PROFILE --region REPLACE_WITH_REGION
```

For a root of `incoming/security/`, the key is `incoming/security/configuration/policy-staging-v1.json`, not a double-slash path. Save the returned VersionId. Conditional creation rejects an existing key rather than silently replacing it. [S3 conditional upload option](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-object.html)

In private `environment.json`, set `POLICY_KEY` to that exact full S3 key and `POLICY_SHA256` to the exact hash returned by policy validation. Validate, render a **new** SAM filename and redeploy with the same disabled switches. A policy upload alone does not update the configured hash. Never edit a bound policy in place; publish a new reviewed revision and update both values together.

### Step 21 Confirm notification delivery

If you set `NotificationEmail`, ask the recipient to confirm the SNS subscription email. Confirm the topic/subscription in AWS and, with approved publish permissions, send a benign setup test:

```bash
aws sns publish --topic-arn REPLACE_WITH_SUMMARY_TOPIC_ARN \
  --message 'Security automation notification setup test' \
  --profile REPLACE_WITH_STAGING_PROFILE --region REPLACE_WITH_REGION
```

Verify actual receipt. Check CloudWatch alarm actions reference the intended encrypted topic. Do not distribute repository/finding summaries to an unapproved mailing list. SNS subscription confirmation is required for email delivery. [SNS email setup](https://docs.aws.amazon.com/sns/latest/dg/sns-email-notifications.html)

## Prepare and upload the first report pair

### Step 22 Export compatible Snyk reports

Export these two report types using identical scope/filter selections:

1. Risk Exposure by Introduction Category.
2. Issues Detail.

Use the original CSV exports, not spreadsheets resaved with altered headers or encodings. Both filenames must encode the same `_MM_DD_YYYY_` date, or end in `_MM_DD_YYYY.csv`. The default maximum filename-date age is 36 hours. Use genuinely fresh reports; do not rename historical reports to make them appear fresh.

Exactly one write-once CSV per type/date is allowed within each report prefix. Do not upload a second export for the same date or overwrite/delete-and-recreate an earlier key. Versioning preserves history but does not make an overwritten input acceptable: the application rejects multiple versions/delete markers for input reports. Arrange a reviewed source-correction workflow if a report for an already-used date is wrong.

Required risk headers:

```text
INTRODUCTION_CATEGORY,CRITICAL,HIGH,MEDIUM,LOW,IMPACTED_ASSETS,ASSET_IDS
```

Required detail headers:

```text
ISSUE_SEVERITY,SCORE,PROBLEM_TITLE,CVE,CVE_URL,CWE,PROJECT_NAME,PROJECT_URL,EXPLOIT_MATURITY,COMPUTED_FIXABILITY,FIRST_INTRODUCED,PRODUCT_NAME,ISSUE_URL,ISSUE_STATUS_INDICATOR,ISSUE_TYPE
```

The strict parser accepts UTF-8, including a BOM. Accepted detail severity values are Critical/High/Medium/Low/Info/Informational and accepted source statuses are Open/Closed/Resolved/Ignored, case-insensitively. Unknown values reject the report rather than being guessed. Only Open Critical rows produce work.

`PROJECT_NAME` must identify repository and target consistently; the repository portion before the first colon is used for exact routing/grouping. `ISSUE_URL` must supply a recognized stable Snyk issue ID. Changing these identities casually can change grouping. Inspect an actual preview rather than inferring owner rules from a display label.

For developer-ready remediation, supply actual source-backed optional columns when available: `PACKAGE_NAME`, `INSTALLED_VERSION`, `FIXED_VERSION`, `DEPENDENCY_PATH`, `LOCATION`, `ENVIRONMENT`, `REMEDIATION`, `SCAN_COMPLETED_AT` and `EVIDENCE_URL`. Missing exact fix data is explicitly marked as needing triage; a CVE by itself does not establish a safe upgrade version.

Default bounds are 20 MiB per CSV, 50,000 data rows, 100 headers, 20,000 characters per cell and 5,000 finding groups. The new-ticket guardrail is 50 **including campaigns**. A full import validates all payloads before creating tickets, but Jira/S3/state failures during apply can still leave partial successful work requiring recovery.

### Step 23 Preview the real files locally

```bash
umask 077
.venv/bin/python scripts/security_operator.py preview \
  --risk /absolute/private/path/REPLACE_WITH_RISK_CSV \
  --issues /absolute/private/path/REPLACE_WITH_DETAIL_CSV \
  > config/local/report-preview.staging-v1.json
```

Review counts, repositories, stable IDs, proposed titles, every target, source links and remediation facts. The JSON includes complete proposed Jira ADF descriptions and can contain sensitive vulnerability information. Keep it private.

**Checkpoint:** no unexplained count mismatch, correct Critical-only scope and acceptable developer content. `REVIEW_REQUIRED` is not approval to proceed. The offline preview does not contact Jira, apply the deployed ownership policy or verify current destination state. Header-only details paired with zero Critical risk count are permitted, but never close earlier issues.

If counts disagree, regenerate a consistent pair. A discrepancy can only be overridden through an explicit short-lived policy reconciliation tied to both exact report hashes/counts and a reviewer/reason; see [OPERATIONS](../OPERATIONS.md#routine-imports-and-checkpoints). Do not disable count/date safeguards.

### Step 24 Upload each report once

With upload processing still disabled, use the approved report uploader:

```bash
aws s3api put-object --bucket REPLACE_WITH_INPUT_BUCKET \
  --key REPLACE_WITH_ROOT/snyk/risk-exposure/REPLACE_WITH_RISK_CSV_FILENAME \
  --body /absolute/private/path/REPLACE_WITH_RISK_CSV --content-type text/csv \
  --if-none-match '*' \
  --profile REPLACE_WITH_UPLOADER_PROFILE --region REPLACE_WITH_REGION
aws s3api put-object --bucket REPLACE_WITH_INPUT_BUCKET \
  --key REPLACE_WITH_ROOT/snyk/issues-detail/REPLACE_WITH_DETAIL_CSV_FILENAME \
  --body /absolute/private/path/REPLACE_WITH_DETAIL_CSV --content-type text/csv \
  --if-none-match '*' \
  --profile REPLACE_WITH_UPLOADER_PROFILE --region REPLACE_WITH_REGION
```

Omit the root segment when blank, or substitute your approved root without creating a double slash. Custom report prefixes must replace the generic ones shown here. Save both exact keys and VersionIds in the private test record. A `412` response means the key exists: inspect it, do not retry without the conditional guard.

Disabled rules do not replay historical object events when enabled later. The first staged import therefore uses an explicit operator invocation. Routine automatic processing is tested with a genuinely new report pair after activation.

## Validate the cloud setup and dry run

### Step 25 Run the read-only setup check

```bash
AWS_PROFILE=REPLACE_WITH_STAGING_PROFILE .venv/bin/python scripts/security_operator.py invoke \
  --function REPLACE_WITH_FUNCTION_NAME --region REPLACE_WITH_REGION \
  --event events/check.json
```

**Checkpoint:** result is `SETUP_VALIDATED`, the returned project/origin is correct, and `identity_key_ready` is true. Inspect its audit/policy fields and actual account permissions. Issue-type/create-screen validation happens inside the check. This is not proof that attachment upload, all workflow transitions or notification delivery work.

If a check fails, fix the reported permission/metadata issue before proceeding. Use protected CloudWatch logs and `OPERATIONS.md`; do not paste raw secret values or report bodies into a public troubleshooting issue.

### Step 26 Run the cloud dry run

```bash
umask 077
AWS_PROFILE=REPLACE_WITH_STAGING_PROFILE .venv/bin/python scripts/security_operator.py invoke \
  --function REPLACE_WITH_FUNCTION_NAME --region REPLACE_WITH_REGION \
  --event events/dry-run.json \
  > config/local/cloud-preview.staging-v1.json
```

There is no `--apply` in this command. The operator CLI explicitly sets `dryRun=true` for ingest/attachment invocations without it. The deployed function reads S3, Secrets Manager, approved policy, state and Jira metadata. It validates destination payloads without creating/updating Jira tickets.

Review the full result, counts, routing, new-ticket estimates and any identity/adoption conflict. A successful full preview returns `DRY_RUN`. A review/failure result requires resolution, not an automatic retry with writes enabled. Large dry runs are also bounded; start with a genuinely small representative staging report pair.

### Understand the controls before adding apply

| Control | What it actually controls |
| --- | --- |
| `DRY_RUN=true` | Default for automatic upload/daily reconciliation imports |
| `ACTIVATION_APPROVED=false` | Blocks live Jira mutation paths |
| `UploadTriggerState=DISABLED` | Disables both the upload rule and queue consumer, including queued continuations |
| `ScheduleState=DISABLED` | Disables the optional daily reconciliation schedule |
| `MonitorState=DISABLED` | Disables independent monitoring; monitoring can update exception/state information |
| Operator `--apply` | Explicit ingest/attachment write selection; required for other mutating operator operations |
| Renderer `--allow-active` | Local acknowledgement of an active configuration, not a deployment or approval record |

**Manual `--apply` can write while global `DRY_RUN=true` once `ACTIVATION_APPROVED=true`.** Do not treat the global dry-run flag as protection against every privileged operator command. Monitoring is independent of import dry run and may change operational/Jira exception state. Restrict direct Lambda invocation with IAM and review every mutating event.

## Run a controlled live staging import

### Step 27 Approve the specific staging test

Before approval, confirm the exact Jira destination, report keys/hashes, policy revision, ownership, adoption review, expected issue count and operator identity. Use a small report set that fits the normal guardrails. Approval must come from the authorized human/change process; a CSV row or free-text label cannot authorize it.

In private configuration, change only `ACTIVATION_APPROVED` to `true`. Keep `DRY_RUN=true`, upload processing disabled, daily schedule disabled and monitor disabled. Validate, then render a new revision with acknowledgement:

```bash
.venv/bin/python scripts/environment_config.py validate
.venv/bin/python scripts/environment_config.py render \
  --allow-active --output config/local/samconfig.staging-approved-v1.toml
sam deploy --template-file .aws-sam/build/template.yaml \
  --config-file /absolute/path/to/LambdaJiraCreationTool/config/local/samconfig.staging-approved-v1.toml \
  --config-env default
```

Review the change set. If source/template changed since the previous build, rebuild before deployment. Confirm the deployed parameters, then rerun the setup check. Rendering alone changes nothing in AWS.

### Step 28 Apply the reviewed import

**This command can create/update Jira issues and persistent operational state:**

```bash
umask 077
AWS_PROFILE=REPLACE_WITH_STAGING_PROFILE .venv/bin/python scripts/security_operator.py invoke \
  --function REPLACE_WITH_FUNCTION_NAME --region REPLACE_WITH_REGION \
  --event events/dry-run.json --apply \
  > config/local/first-live-import.staging-v1.json
```

Despite the event filename, `--apply` makes ingest live; the CLI overrides its `dryRun` field. Record the result/job ID. `COMPLETE` means import processing finished, not that vulnerabilities were remediated. `PENDING` means validation/apply is checkpointed and not yet finished. Review status before any further action.

### Step 29 Inspect and finish a checkpointed job

Copy `events/inspect.json` to a private event file and substitute the returned exact job ID. Invoke it without `--apply`:

```bash
cp events/inspect.json config/local/inspect.staging-v1.json
AWS_PROFILE=REPLACE_WITH_STAGING_PROFILE .venv/bin/python scripts/security_operator.py invoke \
  --function REPLACE_WITH_FUNCTION_NAME --region REPLACE_WITH_REGION \
  --event config/local/inspect.staging-v1.json
```

With the queue consumer disabled, continuations will not run automatically. For a reviewed resumable job, copy `events/resume.json`, fill the exact job ID, inspect its reason and explicitly resume:

```bash
cp events/resume.json config/local/resume.staging-v1.json
AWS_PROFILE=REPLACE_WITH_STAGING_PROFILE .venv/bin/python scripts/security_operator.py invoke \
  --function REPLACE_WITH_FUNCTION_NAME --region REPLACE_WITH_REGION \
  --event config/local/resume.staging-v1.json --apply
```

Repeat only as justified by the saved status. A volume review additionally requires `approved_new_ticket_limit`. Policy/parser/destination changes can invalidate continuation and require a new reviewed import. Do not alter a saved job's inputs or assume a transient error proves no Jira work occurred.

### Step 30 Review developer usability and repeat safety

Open the created/adopted tickets and verify:

- Titles visibly identify the repository, problem/package and CVE/finding.
- Campaigns and children are linked correctly; targets for one finding are not scattered into duplicate tickets.
- Owners, priorities and due dates match the approved policy.
- Source links work and installed/fixed versions, paths and environments reflect evidence.
- Missing remediation facts are clearly identified, with an actionable triage checklist.
- Human notes can be entered separately from managed facts.
- Initial status and board placement match the project's actual workflow.

In a reviewed repeat test, the supplied `events/dry-run.json` has `force=true`, so it re-evaluates the same immutable reports. Preview first; another explicit approved `--apply` should reuse existing issue identities, not create duplicates. Check actual Jira keys and full action history. Verify that developer notes survive a refresh and that edited managed content causes review instead of silent replacement.

Test positive verification separately. Omitting a finding from a Critical-only export must never be used as evidence that it is fixed.

## Enable automatic uploads and optional schedules

### Step 31 Enable the upload path in staging

Keep daily reconciliation and monitoring disabled initially. Before enabling the queue consumer, review pending upload/continuation messages from manual tests; queued live continuations retain their job semantics and are not converted to harmless previews by changing the default dry-run flag.

With no unreviewed pending live work, set private `UploadTriggerState=ENABLED`, leave `DRY_RUN=true`, render a new configuration with `--allow-active` and deploy it after change-set review. Confirm:

1. S3 EventBridge delivery is enabled.
2. The stack's EventBridge upload rule is enabled.
3. Its SQS FIFO queue receives matching report events.
4. The Lambda event-source mapping is enabled.
5. CloudWatch shows a controlled result for a new, fresh report pair.

The first file may yield `WAITING_FOR_REPORT_PAIR`; once both reports are available a dry-run preview can complete. Dry-run pair waits are not durably monitored like live waits. If the pair has already been processed, a skip can be appropriate; inspect the status. Do not overwrite existing CSVs to manufacture an event test.

### Step 32 Enable live automatic processing

After the upload-path preview and staging acceptance pass, obtain activation approval and set `DRY_RUN=false`, leaving `ACTIVATION_APPROVED=true` and `UploadTriggerState=ENABLED`. Keep safety flags for clean attachments, same-date reports and count matching enabled. Render a new acknowledged revision and review/deploy it.

Submit the next genuinely new, matching report pair through the scoped uploader. Inspect the completed job, Jira identities, audit artifacts and notifications. The first file does not authorize incomplete-pair ticket creation. If the second file arrives later, processing waits for the pair rather than falling back to an older date.

Automatic mode keeps only 20 groups per invocation by default, a 240-second work budget and one concurrent writer. Let saved continuations finish; monitor queue age and limits. Do not raise the new-ticket guardrail simply because an unexpectedly large count is inconvenient.

### Step 33 Enable monitoring and optional 8 AM reconciliation

Once exception handling, notifications and pending-job recovery are tested, explicitly enable `MonitorState`. The default monitor schedule is hourly. It handles pair expiry, exception expiry and notification retries; it is not a guarantee that every external failure is independently isolated at maximum scale. Review the remaining [monitoring hardening gap](DEEP_REVIEW.md).

If the daily safety-net reconciliation is wanted, enable `ScheduleState` with the approved expression and timezone. `cron(0 8 * * ? *)` means 8 AM in `ScheduleTimezone`, whose generic default is UTC. Scheduler has minute-level precision and timezone/DST behavior; it is not an exact 8:00:00 deadline. [AWS Scheduler timing](https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html)

The daily schedule does not produce new CSVs or automatically refresh authentication. Arrange the upstream export/upload before it runs. A newer incomplete date blocks fallback to an older complete pair; that is intentional.

## Prepare a separate production environment

### Step 34 Repeat setup with production isolation

Use a separate approved production stack, input/audit resources, state table, secret and IAM roles. Prefer separate AWS accounts and a staging Jira project where organizational policy permits. Do not merely point a tested staging state table at another destination.

Create private production environment/deployment copies without putting them in tracked examples. The tool supports selecting copies explicitly:

```bash
.venv/bin/python scripts/environment_config.py validate \
  --environment-file config/local/environment.production.json \
  --deployment-file config/local/deployment.production.json
.venv/bin/python scripts/environment_config.py render \
  --environment-file config/local/environment.production.json \
  --deployment-file config/local/deployment.production.json \
  --output config/local/samconfig.production-disabled-v1.toml
```

Create/edit those private JSON copies with the same schema first. Protect them with mode 0600; use `umask 077` when copying. Explicit filenames help prevent accidentally deploying production settings as staging. Operator commands still require the correct `AWS_PROFILE`, function name and Region; they do not read those deployment files.

Repeat disabled deployment, permissions checks, storage verification, approved policy binding, actual-production dry run and notification validation. Reconcile existing destination tickets/adoptions before the first creation. Approve production retention/recovery and all remaining external gates. Then perform a small, explicitly approved live import before enabling automatic processing. Do not merge staging identity history into production by copying arbitrary DynamoDB rows.

## Enable optional capabilities

### Attachments to existing tickets

Attachments are opt-in per operator request, independent of report imports. Uploading an evidence file alone does not attach it to every ticket.

1. Confirm Jira attachments are enabled, its size limit is sufficient and the automation account has Create Attachments.
2. Integrate an **actual external malware scanner**. This repository does not provide one.
3. Configure `EvidenceScannerRoleArn` and have the IAM administrator grant the scanner scoped access to read/tag exact S3 evidence versions. The managed bucket denies scanner-tag writes to ordinary uploaders.
4. Upload evidence to the approved attachment prefix and record VersionId.
5. Have the trusted scanner inspect that version and set `malware-scan-status=CLEAN` on that same version only after a clean result. Preserve unrelated tags. Do not self-tag a file CLEAN as a substitute for scanning.
6. Copy `events/with-attachment.json` to `config/local/`, fill the exact destination key, full `s3_key`, scanned `version_id` and useful display name. Include your ingestion root in the key.
7. Preview using `security_operator.py invoke` without `--apply`; review destination, file and limits.
8. Run the same approved request with `--apply`, then verify the attachment in Jira and its audit record.

Default limits are 20 files, 10 MiB each and 25 MiB combined. Supported types are CSV, plain text, JSON, PDF, PNG and JPEG; file validation and Jira limits still apply. Every target/file is prevalidated before upload. Repeat requests recognize the content-digest filename convention, but Jira editors remain trusted; the client does not re-download an existing attachment to cryptographically compare its bytes.

Use [OPERATIONS attachment instructions](../OPERATIONS.md#optional-attachments-through-the-api) for the command shape. The separate local `jira_attachment_smoke.py` tool bypasses S3 scanning because it accepts a trusted operator file; it is not the routine untrusted-evidence path.

### Source backed remediation enrichment

If the export lacks exact fix facts, prefer a richer source export. Otherwise provision a trusted enrichment producer, configure its approved role and publish a reviewed sidecar using `config/enrichment.example.json`:

- Full key is `<root>enrichment/<detail CSV basename>.json`.
- Schema/source and `report_sha256` bind it to the exact detail report.
- Every occurrence matches the exact repository, finding ID and target.
- Fix assertions have provenance URLs; unknown versions remain unknown.
- Publish before report processing, and preserve versions for audit.

A later sidecar does not itself trigger a new import. Incorporate it through a reviewed ingest against the unchanged write-once CSVs; do not overwrite CSVs to force processing. No automatic Snyk/CVE API enrichment is implemented.

### Positive verification and time limited exceptions

1. Copy `config/verification.example.json` or `config/exception.example.json` into a private file.
2. Provide all retained target identities, owner, actual reviewer and required evidence. A fresh export missing an issue is insufficient.
3. For verification, supply the deployed artifact SHA-256, HTTPS deployment/scan references and timezone-aware times. The scan must follow deployment and the latest Open observation, and be no older than 36 hours.
4. For an exception, supply justification, implemented compensating controls, migration plan, approval reference and future expiry within 90 days.
5. Upload through the protected verification prefix, record the exact object version/hash and populate the corresponding private `events/verify.json` or `events/exception.json` copy.
6. Review the JSON and invoke with `--apply`. These operations mutate state/tickets; they do not have an ingest-style dry-run mode.
7. Inspect the ticket, retained scope and audit record. Without configured workflow transition IDs, verified facts can be recorded without moving the Jira status.

These are trusted operator assertions authorized by IAM, not independently authenticated scanner responses. A typed `approved_by` string is not identity proof. Do not represent this workflow as fully automatic remediation validation or enable automatic closure without the additional authenticated integration.

### Alert Logic and other products

Do not send a different vendor's arbitrary CSV into a Snyk folder. Start with the mapped-product example:

```bash
.venv/bin/python scripts/security_operator.py profile-preview \
  --profiles config/alertlogic-profile.example.json \
  --sample tests/fixtures/alertlogic-normalized-example.csv --product alertlogic
```

The result is `REVIEW_REQUIRED`; the example is intentionally not live-certified. To onboard a real product:

1. Obtain a representative real export and document its scope/privacy controls.
2. Create a private profile mapping actual columns, severity/status semantics, grouping field, stable IDs, URLs and remediation facts.
3. Preview the real sample, including malformed/empty/repeated-ID cases, and confirm developer content/grouping.
4. Approve the exact schema version, reviewer and sample SHA-256 certification.
5. Configure the reviewed profile JSON within the environment-size budget and approved product prefix; deploy initially in dry run.
6. Repeat cloud validation, live staging tests and source-specific approval before activation.

The supplied Alert Logic sample is not proof that a native vendor export matches. Multi-file or non-CSV products require additional adapters. A profile cannot manufacture missing fix evidence or fetch vendor data automatically.

## Operate and maintain the deployment

### Daily routine

Export fresh reports with consistent filters, preview suspicious changes, upload the immutable pair and verify completion. Review `needs-owner`, missing-fix triage, rejected reports, incomplete pairs, expired exceptions, queue age/DLQs and failed notification delivery. `COMPLETE` means tickets were processed, not that developers resolved the vulnerabilities.

Useful filter, with the approved key substituted:

```jql
project = YOUR_PROJECT_KEY AND labels = security-remediation
ORDER BY priority DESC, created ASC
```

For Snyk Critical children rather than campaigns:

```jql
project = YOUR_PROJECT_KEY AND labels = snyk AND labels = severity-critical
AND labels != repo-security-epic ORDER BY priority DESC, created ASC
```

Verify board filters/workflow status separately. The application does not place tickets into a selected sprint or guarantee backlog visibility.

### Recover safely and retain evidence

Use read-only `inspect` first and export the exact job when needed:

```bash
AWS_PROFILE=REPLACE_WITH_OPERATOR_PROFILE .venv/bin/python scripts/security_operator.py export \
  --function REPLACE_WITH_FUNCTION_NAME --region REPLACE_WITH_REGION \
  --job-id REPLACE_WITH_EXACT_JOB_ID --product snyk \
  --audit-bucket REPLACE_WITH_AUDIT_BUCKET \
  --output config/local/REPLACE_WITH_NEW_EXPORT_FILENAME.json
```

Exports are exclusively created with mode 0600. A full job export follows version-pinned audit references and checks hashes; it is not a full backup of every Jira comment or every external scanner record. Attachment operations have separate audit records.

The upload FIFO queue retains messages for four days; its failure queue retains them for fourteen. The scheduler/delivery-failure queue is separate. Fix the cause and review whether work already succeeded before redriving. Permanent input errors are quarantined and must not be blindly redriven. An uncertain Jira create stops for identity review rather than repeating POST; verify the exact issue or approve recovery, not a speculative retry.

Read [OPERATIONS recovery guidance](../OPERATIONS.md#failure-and-recovery) before `repair`, `restore` or volume approval. These are privileged actions, not routine buttons. Policy/destination/parser changes may require a new reviewed import.

### Stop writes and investigate an incident

Use the approved incident process. Disable upload processing, daily reconciliation and monitoring, set activation approval false, and deploy the reviewed change. This stops future automated invocations but does not undo Jira edits or prove an already-running invocation stopped. Queued messages need review before re-enabling; disabling the upload consumer also halts continuations.

For urgent containment, the AWS administrator can suspend function execution with reserved concurrency zero and/or restrict invocation; if credential compromise is suspected, revoke the Jira token and restrict secret access. Treat these as incident actions with availability consequences, not routine configuration. Preserve logs, state and audit versions; do not delete resources to clear an alarm.

After resolving the cause, revalidate credentials, identities, pending jobs, destination and policy before restoration. Returning `DRY_RUN=true` alone is not containment for privileged manual applies or saved live continuations.

### Periodic maintenance

- Rotate the Jira API token before expiry while preserving the independent signing key.
- Review least-privilege access, approver identities and trusted scanner/enrichment behavior.
- Run tests, dependency advisory checks and reviewed updates; CI does not deploy automatically.
- Test failure handling, notification delivery and recovery after infrastructure/authentication changes.
- Review actual costs, queue growth, Lambda duration/throttles and maximum-scale assumptions.
- Reassess retention and restore procedures. Managed S3 defaults are 90 days, logs 30 and operational state TTL 90; identity mappings have no TTL and retain sensitive facts.
- Remember that current/noncurrent object expiration happens separately. Retained stack resources still have lifecycle/TTL behavior. The audit bucket is not administrator-proof Object Lock/WORM storage.

## Troubleshooting

| Symptom | Likely check and safe next action |
| --- | --- |
| `python3.12` or `venv` is missing | Install supported Python 3.12; do not replace the runtime version casually |
| `ModuleNotFoundError: boto3` in operator command | Install hash-locked `src/requirements.txt` into the same `.venv` used for the command |
| AWS token expired or wrong account | Refresh the approved SSO session and recheck caller identity; explicitly select `AWS_PROFILE` |
| SAM cannot find configuration | Use the actual absolute private config path with the built template |
| Renderer refuses an existing output | Choose a new revision filename; it intentionally refuses overwrite |
| Renderer rejects active settings | Confirm approval, then use `--allow-active`; the flag does not itself deploy |
| SAM IAM/PassRole/SCP failure | Have the administrator examine CloudFormation events and narrow role/boundary constraints |
| Reserved concurrency deployment failure | Check account quota/headroom and request an approved increase; retain serialization |
| Jira 401 | Check compatible token/email, expiry and exact secret origin; scoped-gateway/native service-account tokens are unsupported |
| Jira 403 | Check project/workflow/conditional permissions; do not interpret forbidden access as deleted issues |
| Jira type/priority/required-field error | Verify actual schemes and screen values; `Major` is not guaranteed to exist |
| Setup works but creates fail | Review dry-run payload metadata, conditional permissions, parent support and the particular Jira error |
| Missing matching report | Check both prefixes, matching filename dates and scope; do not fall back to older data |
| Stale filename date | Export truly fresh reports; do not rename historical data |
| Duplicate key/date or overwritten report rejection | Inspect original input versions; stop blind retries and review source correction |
| Aggregate/detail counts differ | Regenerate consistent reports or obtain exact hash/count-bound reconciliation approval |
| Policy hash mismatch | Validate the exact uploaded bytes and redeploy a reviewed matching key/hash revision |
| Event never arrives | Check bucket EventBridge setting, propagation, rule prefix, Region, queue delivery and event-source mapping |
| `PENDING` job does not progress | Inspect reason; a disabled queue consumer also disables continuation, so resume only through approved recovery |
| Guardrail/review result | Verify new-ticket count including campaigns; do not automatically increase the bound |
| Legacy/copied/missing identity conflict | Review exact destination issue and signed mapping; use approved adoption/repair/restore |
| Jira create outcome unknown | Search/reconcile the specific creation intent before any new create attempt |
| Attachment rejected as unscanned | Confirm the trusted scanner's CLEAN tag belongs to the exact requested version; do not self-tag |
| SNS email absent | Confirm subscription, topic/KMS permissions and notification retries separately from import success |
| Alert Logic live import rejected | Validate/certify a real mapped sample; the normalized example is deliberately not approved |
| Scan evidence rejected | Check all retained targets, artifact identity, timing and exact evidence version/hash |
| Ticket is not in backlog | Check Jira board filter and initial workflow status; application setup does not configure a board |

When filing a public repository bug, redact credentials, origins, account IDs, private repository names, report bodies, evidence URLs and populated configuration. Preserve error category, version and a synthetic reproducer. Use the private reporting route in [SECURITY.md](../SECURITY.md) for sensitive issues.

## Completion checklist

Installation and staging are complete only when all relevant items below have evidence in the private change record:

- [ ] Approved account/Region/project and supported Jira authentication are recorded.
- [ ] Local tool versions, tests, lint, template lint and publication checks pass.
- [ ] Tracked settings templates are still blank; private configuration is ignored and protected.
- [ ] Secret and signing-key storage/rotation/recovery are approved.
- [ ] SAM build and actual arm64 deployment succeed in the intended environment.
- [ ] Initial stack has disabled triggers/schedules/monitoring and no live write approval.
- [ ] Bucket controls, IAM role separation, policy hash binding and retention are verified.
- [ ] Jira setup check passes, including independently reviewed conditional permissions.
- [ ] A genuinely fresh consistent report pair passes local and cloud previews.
- [ ] The first explicitly approved live staging import completes and developer content is reviewed.
- [ ] Repeat import preserves identities and human notes without duplicate creation.
- [ ] Upload events, continuations, failure queues and notifications work as expected.
- [ ] Positive verification/exception behavior is tested if enabled; absence never closes work.
- [ ] Optional scanner, enrichment and product adapters have separate acceptance evidence.
- [ ] Incident stop, recovery and retained-data handling have named owners and a tested procedure.
- [ ] Production repeats these checks with isolated resources and explicit activation approval.

Passing this checklist requires actual cloud/Jira observations. The repository's local checks and CI cover only their stated scope. Remaining design and integration limitations are recorded in [the deep review](DEEP_REVIEW.md) and [implementation status](../IMPLEMENTATION_STATUS.md).
