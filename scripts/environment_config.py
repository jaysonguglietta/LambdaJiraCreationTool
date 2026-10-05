"""Validate private JSON settings and render SAM configuration without revealing values."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from config import ENVIRONMENT_DEFAULTS, Config, ConfigurationError  # noqa: E402
from products import load_profiles  # noqa: E402

ENV_TO_PARAMETER = {
    "INPUT_BUCKET": "ExistingInputBucketName",
    "INGESTION_PREFIX": "IngestionPrefix",
    "RISK_REPORT_PREFIX": "RiskReportPrefix",
    "ISSUES_REPORT_PREFIX": "IssuesReportPrefix",
    "ATTACHMENT_PREFIX": "AttachmentPrefix",
    "PRODUCTS_REPORT_PREFIX": "ProductsReportPrefix",
    "PRODUCT_PROFILES_JSON": "ProductProfilesJson",
    "JIRA_SECRET_ARN": "JiraSecretArn",
    "JIRA_PROJECT_KEY": "JiraProjectKey",
    "JIRA_EPIC_ISSUE_TYPE": "CampaignIssueType",
    "JIRA_CHILD_ISSUE_TYPE": "FindingIssueType",
    "JIRA_PRIORITY_NAME": "JiraPriorityName",
    "JIRA_ALLOWED_HOST_SUFFIX": "JiraAllowedHostSuffix",
    "JIRA_ORIGIN": "JiraOrigin",
    "POLICY_KEY": "PolicyKey",
    "POLICY_SHA256": "PolicySha256",
    "MAX_INPUT_AGE_HOURS": "MaxInputAgeHours",
    "MAX_INPUT_BYTES": "MaxInputBytes",
    "MAX_ATTACHMENT_BYTES": "MaxAttachmentBytes",
    "MAX_ATTACHMENTS_PER_RUN": "MaxAttachmentsPerRun",
    "ALLOWED_ATTACHMENT_TYPES": "AllowedAttachmentTypes",
    "REQUIRE_CLEAN_ATTACHMENT_TAG": "RequireCleanAttachmentTag",
    "ENFORCE_COUNT_MATCH": "EnforceCountMatch",
    "REQUIRE_SAME_REPORT_DATE": "RequireSameReportDate",
    "UPDATE_EXISTING_TITLES": "UpdateExistingTitles",
    "DRY_RUN": "DryRun",
    "ACTIVATION_APPROVED": "ActivationApproved",
    "MAX_GROUPS_PER_RUN": "MaxGroupsPerRun",
    "MAX_GROUPS_PER_INVOCATION": "MaxGroupsPerInvocation",
    "MAX_NEW_TICKETS": "MaxNewTickets",
    "WORK_SECONDS": "WorkSeconds",
    "PAIR_WAIT_HOURS": "PairWaitHours",
    "STATE_RETENTION_DAYS": "StateRetentionDays",
    "LOG_LEVEL": "LogLevel",
}
GENERATED_RESOURCES = frozenset(
    {"STATE_TABLE_NAME", "AUDIT_BUCKET", "SUMMARY_TOPIC_ARN", "UPLOAD_QUEUE_URL"}
)
DEPLOYMENT_DEFAULTS = {
    "UploadTriggerState": "DISABLED",
    "ScheduleState": "DISABLED",
    "MonitorState": "DISABLED",
    "DailyScheduleExpression": "cron(0 8 * * ? *)",
    "ScheduleTimezone": "UTC",
    "MonitorScheduleExpression": "rate(1 hour)",
    "EvidenceScannerRoleArn": "",
    "EvidenceProducerRoleArn": "",
    "NotificationEmail": "",
    "InputRetentionDays": "90",
    "LogRetentionDays": "30",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("Configuration contains a duplicate key")
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError("Settings must be a regular non-symlink file")
    with path.open("rb") as handle:
        body = handle.read(65537)
    if len(body) > 65536:
        raise ConfigurationError("Settings exceed the 64 KiB limit")
    try:
        value = json.loads(body, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigurationError("Settings must contain valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("Settings must be a JSON object")
    return value


def strings(value: dict, allowed: set | dict) -> dict[str, str]:
    if set(value) - set(allowed):
        raise ConfigurationError("Unknown settings key; credentials are not accepted here")
    if any(
        not isinstance(v, str) or any(ord(c) < 32 for c in v) or len(v) > 4096
        for v in value.values()
    ):
        raise ConfigurationError(
            "Setting values must be bounded strings without control characters"
        )
    return {k: v.strip() for k, v in value.items()}


def deployment_template():
    return {
        "stack_name": "",
        "region": "",
        "profile": "",
        "parameters": dict.fromkeys(DEPLOYMENT_DEFAULTS, ""),
    }


def prepare(environment: dict, deployment: dict, *, runtime: bool = False):
    values = strings(environment, ENVIRONMENT_DEFAULTS)
    if set(deployment) != {"stack_name", "region", "profile", "parameters"}:
        raise ConfigurationError("Deployment settings have missing or unknown keys")
    base = strings({k: deployment[k] for k in ("stack_name", "region", "profile")}, deployment)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,100}", base["stack_name"]):
        raise ConfigurationError("Set a valid deployment stack_name")
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", base["region"]):
        raise ConfigurationError("Set a valid deployment region")
    if base["profile"] and not re.fullmatch(r"[A-Za-z0-9_.@-]+", base["profile"]):
        raise ConfigurationError("Deployment profile contains unsupported characters")
    if not isinstance(deployment["parameters"], dict):
        raise ConfigurationError("Deployment parameters must be an object")
    settings = strings(deployment["parameters"], DEPLOYMENT_DEFAULTS)
    params = {k: settings.get(k) or v for k, v in DEPLOYMENT_DEFAULTS.items()}
    for name in ("UploadTriggerState", "ScheduleState", "MonitorState"):
        if params[name] not in {"DISABLED", "ENABLED"}:
            raise ConfigurationError("Trigger/monitor states must be DISABLED or ENABLED")
    for name in ("DailyScheduleExpression", "MonitorScheduleExpression"):
        if not re.fullmatch(r"(?:cron|rate)\([A-Za-z0-9*?/,# -]+\)", params[name]):
            raise ConfigurationError("Schedule expression must use cron(...) or rate(...)")
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        ZoneInfo(params["ScheduleTimezone"])
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigurationError("ScheduleTimezone must be an IANA timezone") from exc
    for name in ("EvidenceScannerRoleArn", "EvidenceProducerRoleArn"):
        if params[name] and not re.fullmatch(
            r"arn:[a-z-]+:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", params[name]
        ):
            raise ConfigurationError("Evidence role setting must be an IAM role ARN")
    try:
        retention = int(params["InputRetentionDays"])
        log_retention = int(params["LogRetentionDays"])
    except ValueError as exc:
        raise ConfigurationError("Retention settings must be integers") from exc
    if not 30 <= retention <= 2555 or log_retention not in {
        7,
        14,
        30,
        60,
        90,
        120,
        150,
        180,
        365,
        400,
        545,
        731,
        1096,
        1827,
        2192,
        2557,
        2922,
        3288,
        3653,
    }:
        raise ConfigurationError("Retention settings are outside supported ranges")
    if params["NotificationEmail"] and not re.fullmatch(
        r"[^\s@]+@[^\s@]+[.][^\s@]+", params["NotificationEmail"]
    ):
        raise ConfigurationError("NotificationEmail is not a valid email shape")
    env = {k: values.get(k) or v for k, v in ENVIRONMENT_DEFAULTS.items()}
    if not runtime and any(values.get(k) for k in GENERATED_RESOURCES):
        raise ConfigurationError("SAM owns table/audit/topic/queue settings; leave them blank")
    validation = dict(env)
    if not runtime:
        validation.update(
            INPUT_BUCKET=env["INPUT_BUCKET"] or "stack-generated-input",
            STATE_TABLE_NAME="stack-generated-state",
        )
    config = Config.from_mapping(validation)
    if not re.fullmatch(
        r"arn:[a-z-]+:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+",
        env["JIRA_SECRET_ARN"],
    ):
        raise ConfigurationError("Set JIRA_SECRET_ARN to an approved Secrets Manager ARN")
    if env["INPUT_BUCKET"] and not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", env["INPUT_BUCKET"]
    ):
        raise ConfigurationError("INPUT_BUCKET must be an S3 bucket name")
    if bool(config.policy_key) != bool(config.policy_sha256):
        raise ConfigurationError("POLICY_KEY and POLICY_SHA256 must be set together")
    if config.policy_key and (
        not config.policy_key.startswith(config.configuration_prefix)
        or not re.fullmatch(r"[a-f0-9]{64}", config.policy_sha256)
        or ".." in config.policy_key
    ):
        raise ConfigurationError("Policy reference must use the protected prefix and SHA-256")
    if len(env["PRODUCT_PROFILES_JSON"].encode()) > 2200:
        raise ConfigurationError("Product mappings exceed the deployment parameter limit")
    load_profiles(config)
    booleans = {
        "REQUIRE_CLEAN_ATTACHMENT_TAG",
        "ENFORCE_COUNT_MATCH",
        "REQUIRE_SAME_REPORT_DATE",
        "UPDATE_EXISTING_TITLES",
        "DRY_RUN",
        "ACTIVATION_APPROVED",
    }
    for name in booleans:
        env[name] = "true" if env[name].lower() in {"1", "true", "yes", "on"} else "false"
    env["JIRA_PROJECT_KEY"] = config.jira_project_key
    if config.activation_approved and not all(
        env[k] == "true"
        for k in ("REQUIRE_CLEAN_ATTACHMENT_TAG", "ENFORCE_COUNT_MATCH", "REQUIRE_SAME_REPORT_DATE")
    ):
        raise ConfigurationError("Activation cannot disable scan/count/date safeguards")
    # Reserve room for the actual SAM-generated physical resource names/ARNs.
    size = sum(len(k.encode()) + len(v.encode()) for k, v in env.items()) + (0 if runtime else 700)
    if size > 4096:
        raise ConfigurationError("Settings exceed the Lambda environment budget")
    params.update({param: env[name] for name, param in ENV_TO_PARAMETER.items()})
    active = (
        config.activation_approved
        or not config.dry_run_default
        or any(
            params[k] == "ENABLED" for k in ("UploadTriggerState", "ScheduleState", "MonitorState")
        )
    )
    return base, params, env, active, size


def write_private(path: Path, content: str, *, local_root: Path | None = None):
    permitted = (local_root or ROOT / "config/local").resolve()
    if not path.resolve().is_relative_to(permitted):
        raise ConfigurationError("Generated settings must remain under config/local/")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(content)


def sam_config(base: dict, parameters: dict) -> str:
    lines = [
        "version = 0.1",
        "",
        "[default.deploy.parameters]",
        f"stack_name = {json.dumps(base['stack_name'])}",
        f"region = {json.dumps(base['region'])}",
        "resolve_s3 = true",
        'capabilities = "CAPABILITY_IAM"',
        "confirm_changeset = true",
        "fail_on_empty_changeset = false",
    ]
    if base["profile"]:
        lines.append(f"profile = {json.dumps(base['profile'])}")
    # Each override is a separate TOML array entry; JSON escaping handles quotes
    # in embedded profile mappings without shell evaluation or argument expansion.
    overrides = [
        f"ParameterKey={key},ParameterValue={json.dumps(value)}"
        for key, value in sorted(parameters.items())
    ]
    lines.append("parameter_overrides = " + json.dumps(overrides))
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create blank, private local settings without overwriting")
    for command in ("validate", "render"):
        part = commands.add_parser(command)
        part.add_argument(
            "--environment-file", type=Path, default=ROOT / "config/local/environment.json"
        )
        part.add_argument(
            "--deployment-file", type=Path, default=ROOT / "config/local/deployment.json"
        )
        if command == "render":
            part.add_argument("--output", type=Path, default=ROOT / "config/local/samconfig.toml")
            part.add_argument(
                "--allow-active",
                action="store_true",
                help="Acknowledge enabled triggers/writes; does not deploy",
            )
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            paths = [ROOT / "config/local/environment.json", ROOT / "config/local/deployment.json"]
            if any(path.exists() for path in paths):
                raise ConfigurationError(
                    "Local settings already exist; initialization never overwrites"
                )
            for path, value in zip(
                paths, (dict.fromkeys(ENVIRONMENT_DEFAULTS, ""), deployment_template()), strict=True
            ):
                write_private(path, json.dumps(value, indent=2) + "\n")
            result = {"status": "BLANK_LOCAL_SETTINGS_CREATED"}
        else:
            base, params, _env, active, size = prepare(
                read_json(args.environment_file), read_json(args.deployment_file)
            )
            if args.command == "render":
                if active and not args.allow_active:
                    raise ConfigurationError(
                        "Enabled settings require an explicit --allow-active acknowledgement"
                    )
                write_private(args.output, sam_config(base, params))
            result = {
                "status": "RENDERED" if args.command == "render" else "VALID",
                "environment_keys": len(ENVIRONMENT_DEFAULTS),
                "estimated_environment_bytes": size,
                "active_settings": active,
            }
        print(json.dumps(result))
        return 0
    except (ConfigurationError, FileExistsError):
        # Detailed values and paths are not printed; validation exceptions name only settings.
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConfigurationError, FileExistsError) as error:
        print(f"Configuration rejected: {error}", file=sys.stderr)
        raise SystemExit(2) from None
