# Security CSV automation for Jira

This headless application turns uploaded security reports into actionable Critical-remediation work in an explicitly configured Jira project. It uses AWS IAM and a Jira service-account API token; no browser session is needed. Version 2 adds safer identities, source reconciliation, managed ticket updates, resumable imports, positive verification, independent attachments, and protected audit history.

Start with the [documentation index](docs/README.md), [private configuration guide](docs/CONFIGURATION.md) and [deep review](docs/DEEP_REVIEW.md). Environment-specific values belong in ignored `config/local/`; the tracked environment/deployment JSON templates contain blank values only. Jira origin and project key are explicitly required, not embedded as tenant defaults. Test keys such as `SEC-123` and tenant URLs such as `jira-example.atlassian.net` are synthetic examples, not destinations or credentials.

The local implementation is tested. **AWS deployment, live Jira permissions, and activation are not verified.** Upload processing and the optional schedule remain disabled, `DryRun=true`, and `ActivationApproved=false`. The generic schedule is 8 AM UTC; set the approved timezone in the private deployment file. See [the operating guide](OPERATIONS.md) before enabling writes and [implementation status](IMPLEMENTATION_STATUS.md) for tested scope and remaining gates.

## Product purpose and boundaries

Security operators upload reports, review previews and approvals, and recover interrupted work. Developers receive repository-scoped tickets with affected targets, source links, reported fixes, tests, and closure criteria. Platform administrators manage IAM, secrets, retention, scanning, and deployment.

The core workflow is upload → validate and reconcile → preview or approve → create/update repository campaigns and finding tickets → deploy fixes → submit positive verification or an expiring exception. Operator views are JSON setup results, import checkpoints, audit exports, and notifications; developer views are Jira campaigns and finding tickets. A separate web dashboard is intentionally outside this release.

The main records are source observations, per-target findings, destination-scoped identities, repository campaigns, owned ticket sections, resumable jobs, approvals, and versioned audit artifacts. CSV contents are data, never executable instructions or permission to change policy.

## Architecture

```text
S3 versioned report folders
    → EventBridge object-created rule
    → SQS FIFO upload queue
    → Python 3.12 Lambda
        → strict source parsers and approved policy
        → immutable job snapshot and bounded validation/apply checkpoints
        → Jira Cloud REST API in the configured project
        → DynamoDB mappings and operational state
        → versioned S3 audit artifacts and SNS notifications

Optional daily reconciliation in the configured timezone → same Lambda
Hourly operational monitor → pair expiry, exception expiry, notification retries
```

One Lambda writer and a destination lock serialize application mutations. Continuations reference the saved job ID, not a fresh copy of a mutable CSV. Permanent invalid inputs are quarantined with an audit record; transient failures retry through SQS. A notification failure does not turn completed Jira work into a failed import.

## Ticket organization and developer content

One campaign per **source + repository/asset group**, and one child per **source + repository/asset group + stable finding ID**. Multiple targets for the same finding stay in the child with their own facts. New campaigns default to Epic and children to Bug; configurable issue types are checked against Jira. Explicitly adopted campaign Tasks use a Relates link; Epic campaigns use the child parent field.

Each child starts with `[Critical] <repository> — <reported package or problem> (<CVE or finding ID>)`. The description contains:

- Repository, owner, campaign, source status, automation first-seen time and last observation.
- Every occurrence's target, location, environment, package, installed/fixed versions, dependency path, fixability, remediation, and source links when supplied.
- A product-specific implementation checklist, test/deployment guidance, and positive verification criteria.
- An owned “Security source facts” section and a preserved “Developer notes” section for PRs, decisions, and deployment evidence.

Missing fix versions are marked for remediation triage, not guessed. “No supported fix” requires explicit source evidence; it is different from missing data. Approved routing supplies assignee, priority, and a Jira calendar due date. Unknown owners receive `needs-owner` and a configurable triage fallback. Due dates are not an hour-precision SLA engine.

Unverified targets remain in the ticket even if a later Critical-only report omits them; retained historical facts are marked explicitly. Closing a remaining target alone cannot silently drop the earlier scope. Lost target state can be restored from a reviewed, signed-state-consistent audit artifact through the privileged restore operation.

Managed facts refresh only if their prior hash still matches. Human descriptions, labels, titles, assignments and due dates are preserved where they differ from automation-owned values. A conflicting edit requires review. Jira has no atomic description compare-and-swap; the read-before-write check reduces, but cannot eliminate, concurrent human-edit races.

The application does not configure Jira boards, migrate issues between projects, or change project workflows. New issues enter the project's configured initial status; “backlog” placement depends on that board and workflow.

Useful JQL (replace `YOUR_PROJECT_KEY` with the approved destination):

```jql
project = YOUR_PROJECT_KEY AND labels = security-remediation ORDER BY priority DESC, created ASC
```

For Snyk children only:

```jql
project = YOUR_PROJECT_KEY AND labels = snyk AND labels = severity-critical
AND labels != repo-security-epic ORDER BY priority DESC, created ASC
```

## Input contracts

With an optional `IngestionPrefix=incoming/security/`, all folders below sit under that root:

```text
snyk/risk-exposure/<dated risk CSV>
snyk/issues-detail/<dated detail CSV>
snyk/attachments/<explicit evidence file>
products/<certified-source>/<single mapped CSV>
configuration/<approved policy JSON>
enrichment/<detail CSV basename>.json
verification/<reviewed scan or exception JSON>
```

Snyk needs one Risk Exposure and one Issues Detail export with matching `_MM_DD_YYYY_` filename dates. Each object must be write-once and versioned. Multiple keys for the same day, overwritten versions, stale files, malformed rows, and unknown severity/status values are rejected. Default freshness is 36 hours; default input limit is 20 MiB. A missing companion is durably tracked and alerts after four hours. A newer incomplete date never falls back to an older complete pair.

Parsing is bounded to 50,000 data rows, 100 headers and 20,000 characters per cell. A header-only detail report is accepted only with a paired zero-Critical aggregate; it never closes earlier findings. Saved jobs bind the parser/profile policy as well as input versions, so profile changes require a new reviewed import instead of changing a continuation's meaning.

Only Open Critical detail rows become work. Aggregate counts are compared before writes. A mismatch blocks live ingestion unless a reviewer approves the exact two SHA-256 hashes, both counts, a reason, and a short expiry. That approval retains every detail occurrence; it never silently drops rows to match the aggregate.

An aggregate/detail count mismatch blocks live writes until the exact report hashes and discrepancy are reviewed. The offline preview exposes count warnings and missing remediation facts. Private report contents, repository inventories, and historical customer counts are not included in this repository.

Other sources require explicit column mappings, stable IDs, severity/status semantics, and a certification tied to a reviewed real sample. The Alert Logic example is a normalized example, not a certified native export. Shared-remediation bundle suggestions are review-only and never merge tickets automatically.

## Run locally

There is no UI server to start. From this directory, Python 3.12 can run tests and a fully offline preview without credentials:

```bash
python3.12 -m unittest discover -s tests -q
python3.12 scripts/security_operator.py preview \
  --risk tests/fixtures/risk.csv --issues tests/fixtures/issues.csv
python3.12 scripts/security_operator.py validate-policy --file config/policy.example.json
python3.12 scripts/environment_config.py init
python3.12 scripts/security_operator.py profile-preview \
  --profiles config/alertlogic-profile.example.json \
  --sample tests/fixtures/alertlogic-normalized-example.csv --product alertlogic
```

For a real offline preview, replace the two fixture paths with your CSV paths. This reads the files locally and does not contact AWS or Jira. The result includes complete proposed ADF descriptions and count warnings.

For cloud operator commands and evidence schemas, use [OPERATIONS.md](OPERATIONS.md). Cloud commands use the AWS SDK credential chain. Mutating operator commands require `--apply`; ingest/attachment invocations default to dry run. Direct Lambda access is privileged and must be restricted with IAM.

## Build and validate

Runtime wheels are pinned by version and SHA-256 in `src/requirements.txt`; the release includes its own SDK instead of depending on Lambda's bundled SDK version.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --only-binary=:all: \
  -r src/requirements.txt --target build/package
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/cfn-lint template.yaml
.venv/bin/python scripts/check_repository.py --staged
.venv/bin/pip-audit -r src/requirements.txt --no-deps --disable-pip
.venv/bin/python scripts/build_release.py \
  --package-dir build/package --output build/security-jira.zip
```

The release zip uses sorted paths and fixed archive metadata. Its manifest records archive, lock-file, and template hashes. Build twice from the same dependency staging directory to compare hashes. The CI workflow uses pinned official action commits and checks/tests/builds without deploying or writing Jira.

AWS SAM remains the deployment route: `sam build`, then review `sam deploy --guided` with triggers and writes disabled. The deterministic zip is also available for a reviewed release pipeline. SAM build/deployment and the actual arm64 Lambda environment were not exercised locally.

## Main implementation files

- `src/reports.py`, `src/products.py`: strict Snyk and mapped-source parsing, certification, snapshots and enrichment.
- `src/policy.py`, `src/lifecycle.py`: exact ownership/adoption, reconciliation approvals and evidence rules.
- `src/service.py`, `src/ticketing.py`: idempotent jobs, lifecycle, relationships, owned sections and attachments.
- `src/jira_client.py`, `src/identity.py`: bounded REST transport and signed destination-scoped identities.
- `src/state_store.py`, `src/audit.py`, `src/handler.py`: durable state, complete artifacts, queues and monitoring.
- `template.yaml`: infrastructure, IAM, encryption, schedules, retention and alarms.
- `scripts/security_operator.py`: offline preview, setup, inspection, explicit actions and read-only export.
- `scripts/build_release.py`, `.github/workflows/ci.yml`: reproducible packaging and validation.
- `scripts/environment_config.py`, blank `config/*.example.json` settings templates: validated private-file configuration and SAM generation.
- `scripts/check_repository.py`, `.gitignore`, `.github/dependabot.yml`: publication boundaries and maintenance checks.
- `docs/`, `SECURITY.md`: architecture, configuration, developer workflow, GitHub publication and remaining risk review.

## Assumptions and activation requirements

This version targets one approved Jira Cloud origin/project and a same-account, same-region input bucket per stack. IAM-authenticated operators are trusted approvers; this is not a multi-tenant portal or an application-level RBAC system. Existing cross-project migrations require a separate reviewed Jira migration and explicit adoption map for the destination keys.

Before activation, approve repository ownership/SLA rules, required Jira custom fields, legacy adoption, retention, scanning and trusted enrichment roles. Verify permissions and dry-run outputs in staging. Real source-API enrichment and independently authenticated scan ingestion are not implemented: rich CSVs or protected, reviewed sidecars supply facts, and a trusted operator submits verification evidence.

No deployment, ticket migration, attachment upload, live ticket creation, or automatic schedule activation was performed during this local implementation.
