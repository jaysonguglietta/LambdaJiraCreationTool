# Security automation architecture

The application converts validated security observations into repository-owned Jira work. It is a headless AWS application, not a web portal. SQS serializes uploads and continuations; DynamoDB and versioned S3 audit artifacts preserve progress across short Lambda invocations. Jira remains the developer work surface.

## Data flow and boundaries

```text
Report uploader → versioned input S3 → EventBridge → FIFO SQS → Lambda
                                                              ├→ strict source parser
Trusted producer → protected enrichment                        ├→ policy and identity checks
Trusted approver → protected verification                       ├→ DynamoDB checkpoints
Secrets Manager → dedicated Jira credentials                    ├→ versioned audit S3
                                                              └→ exact-origin Jira REST
Operator via AWS IAM → preview, check, inspect, recovery               ↓
Scheduler → optional reconciliation and operational monitoring    developers
SNS and CloudWatch → operations alerts
```

Report contents, event bodies and source URLs are untrusted data. They cannot select another Jira destination, execute code, enable writes, choose attachment targets or authorize an exception. Source URLs are rendered as links, not fetched for instructions. IAM-authenticated configuration and verification writers are trusted authorities, so their compromise is within the threat model.

## Component ownership

| Component | Responsibility |
| --- | --- |
| `config.py` and `environment_config.py` | Safe defaults, private-file validation and deployment parameter generation |
| `aws_adapters.py` and `upload_events.py` | Version-pinned object reads, freshness, report pairing and event decoding |
| `products.py` and `reports.py` | Source schemas, certified mappings, enrichment and full observation snapshots |
| `identity.py` and `policy.py` | Signed destination-scoped ownership, explicit adoption, routing and approvals |
| `service.py` and `ticketing.py` | Bounded jobs, owned Jira sections, relationships, lifecycle and attachments |
| `state_store.py` and `audit.py` | Claims, checkpoints, recovery metadata and versioned complete artifacts |
| `handler.py` | Upload/manual dispatch, continuation, monitoring and structured application logs |
| `template.yaml` | IAM, encryption, storage, queues, schedules, retention and alarms |

## Data model and identity

A finding is one source occurrence with a stable finding ID, repository or asset group, target, reported severity/status, source links and optional remediation facts. A child groups occurrences by source, repository and finding ID. A repository campaign provides the ownership umbrella; shared CVEs or package names do not establish ticket identity.

An identity includes the exact Jira origin, real Jira project ID, source, repository, finding ID and schema version. A campaign has no finding ID. The signed Jira property binds the identity to the actual Jira key. Labels support discovery only; they are not proof of ownership. Separate API credentials and identity-signing secrets allow routine API-token rotation without invalidating identities.

A job binds input versions/hashes, parser/profile policy, destination and approved routing policy. Its snapshot freezes parsed facts. Validation and apply have separate cursors. A continuation references a job ID; it cannot substitute a new CSV or silently change the profile semantics.

## Invariants and recovery

- Live mutations require activation approval, audit storage and applicable source safeguards.
- Every batch is parsed and its proposed payloads validated before the first issue create. External failures can still leave partial progress; there is no cross-service transaction.
- A known create key is saved before secondary property, audit or relationship operations. Uncertain create responses stop for review instead of blind replay.
- Description refresh changes only an unchanged owned section. Developer notes and manual routing overrides are preserved.
- Missing targets remain unresolved. An absent Critical finding is not proof of remediation.
- Positive verification covers the exact retained scope and records a post-deployment scan. It is currently a trusted approver assertion, not an authenticated scanner connection.
- Mapping identities do not expire. Full facts may still require reviewed restoration when state is lost; retention policy must preserve needed recovery artifacts.

The default stack has one reserved Lambda writer plus a destination lease. Do not deploy multiple independent writers with separate state tables against the same destination. Jira descriptions and S3 notification settings lack the atomic compare-and-swap used in DynamoDB, so coordinate human edits and infrastructure changes.

## Deployment and confidentiality

All application-owned environment settings have a blank tracked JSON template. Populated copies and generated SAM files stay in ignored `config/local/` with private permissions. AWS manages reserved runtime variables and role credentials; these are not settings-file inputs. SAM derives the table, audit bucket, notification topic and queue, keeping IAM aligned with the actual resources.

Jira tokens and the signing key live in Secrets Manager, not JSON environment settings. Application logging uses a dedicated logger; application DEBUG does not enable SDK transport debugging. Source bodies and credential values must never be added to logs.

Audit artifacts are append-only under the application role, but this is not WORM storage or protection against a compromised AWS administrator. S3 versioning and lifecycle settings are not backups of every Jira comment, source scanner record or human change. See the deep review before approving production retention.
