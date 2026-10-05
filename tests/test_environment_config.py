from __future__ import annotations

import copy
import io
import json
import logging
import re
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import environment_config as settings  # noqa: E402
import test_service as fixtures  # noqa: E402
from check_repository import blank_values, private_path, scan_content  # noqa: E402

import handler  # noqa: E402
from config import ENVIRONMENT_DEFAULTS, Config, ConfigurationError  # noqa: E402
from service import ReviewRequired  # noqa: E402


class EnvironmentFileTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            "JIRA_ORIGIN": "https://jira-example.atlassian.net",
            "JIRA_PROJECT_KEY": "SEC",
            "JIRA_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
        }
        self.deploy = settings.deployment_template()
        self.deploy.update(stack_name="security-test", region="us-east-1")

    def test_all_environment_settings_have_blank_template_and_cloud_mapping(self):
        template = json.loads((ROOT / "config/environment.example.json").read_text())
        self.assertEqual(set(ENVIRONMENT_DEFAULTS), set(template))
        self.assertTrue(blank_values(template))
        self.assertEqual(
            set(ENVIRONMENT_DEFAULTS),
            set(settings.ENV_TO_PARAMETER) | set(settings.GENERATED_RESOURCES),
        )
        cloud = (ROOT / "template.yaml").read_text()
        block = cloud.split("        Variables:\n", 1)[1].split("      Policies:", 1)[0]
        cloud_env = set(re.findall(r"^          ([A-Z0-9_]+):", block, flags=re.MULTILINE))
        self.assertEqual(set(ENVIRONMENT_DEFAULTS), cloud_env)
        for parameter in settings.ENV_TO_PARAMETER.values():
            self.assertRegex(cloud, rf"(?m)^  {parameter}:$")
        deployment = json.loads((ROOT / "config/deployment.example.json").read_text())
        self.assertTrue(blank_values(deployment))
        self.assertEqual(settings.deployment_template(), deployment)
        project_parameter = cloud.split("  JiraProjectKey:\n", 1)[1].split(
            "  JiraPriorityName:\n", 1
        )[0]
        self.assertNotIn("Default:", project_parameter)
        self.assertEqual("", ENVIRONMENT_DEFAULTS["JIRA_PROJECT_KEY"])
        declared = set(
            re.findall(r"^  ([A-Za-z][A-Za-z0-9]+):$", cloud.split("Conditions:")[0], re.MULTILINE)
        )
        self.assertEqual(
            declared, set(settings.ENV_TO_PARAMETER.values()) | set(settings.DEPLOYMENT_DEFAULTS)
        )

    def test_safe_deployment_can_use_generated_bucket_and_managed_resources(self):
        _, params, env, active, size = settings.prepare(self.env, self.deploy)
        self.assertEqual("", params["ExistingInputBucketName"])
        self.assertEqual("false", params["ActivationApproved"])
        self.assertEqual("true", params["DryRun"])
        self.assertEqual("DISABLED", params["MonitorState"])
        self.assertFalse(active)
        self.assertLessEqual(size, 4096)
        self.assertNotIn("STATE_TABLE_NAME", params)
        self.assertEqual("", env["STATE_TABLE_NAME"])
        self.assertEqual("UTC", params["ScheduleTimezone"])

    def test_runtime_mapping_uses_file_values_without_mutating_process_environment(self):
        environment = {
            **self.env,
            "INPUT_BUCKET": "test-bucket",
            "STATE_TABLE_NAME": "test-state",
            "MAX_NEW_TICKETS": "12",
        }
        config = Config.from_mapping(environment)
        self.assertEqual(12, config.max_new_tickets)
        self.assertTrue(config.dry_run_default)
        settings.prepare(environment, self.deploy, runtime=True)

    def test_credentials_unknown_keys_and_nonstring_values_are_rejected(self):
        for bad in (
            {**self.env, "JIRA_API_TOKEN": "must-never-be-stored-here"},
            {**self.env, "MAX_NEW_TICKETS": 50},
            {**self.env, "JIRA_ORIGIN": "https://jira-example.atlassian.net\nsecret"},
        ):
            with self.subTest(keys=list(bad)), self.assertRaises(ConfigurationError):
                settings.prepare(bad, self.deploy)

    def test_required_origin_and_resource_safety_are_checked(self):
        for override in (
            {"JIRA_PROJECT_KEY": ""},
            {"JIRA_ORIGIN": ""},
            {"JIRA_ORIGIN": "https://jira-example.atlassian.net/path"},
            {"MAX_NEW_TICKETS": "10001"},
            {"AUDIT_BUCKET": "not-owned-by-stack"},
            {"RISK_REPORT_PREFIX": "configuration/"},
            {"PRODUCTS_REPORT_PREFIX": "enrichment/"},
            {"POLICY_KEY": "configuration/policy.json"},
            {"ACTIVATION_APPROVED": "true", "REQUIRE_CLEAN_ATTACHMENT_TAG": "false"},
        ):
            with self.subTest(override=override), self.assertRaises(ConfigurationError):
                settings.prepare({**self.env, **override}, self.deploy)

    def test_environment_size_and_schedule_validation(self):
        for name, value in (
            ("ScheduleTimezone", "not/a-timezone"),
            ("MonitorState", "YES"),
            ("InputRetentionDays", "29"),
        ):
            deployment = copy.deepcopy(self.deploy)
            deployment["parameters"][name] = value
            with self.assertRaises(ConfigurationError):
                settings.prepare(self.env, deployment)
        with self.assertRaisesRegex(ConfigurationError, "environment budget"):
            settings.prepare({**self.env, "JIRA_PRIORITY_NAME": "x" * 4096}, self.deploy)

    def test_quoted_sam_parameters_round_trip_empty_spaces_and_profile_json(self):
        params = {
            "Empty": "",
            "Priority": "Highest Critical",
            "Profile": '{"product":{"name":"Vendor \\"quoted\\" name"}}',
        }
        rendered = settings.sam_config(
            {"stack_name": "test", "region": "us-east-1", "profile": ""}, params
        )
        parsed = tomllib.loads(rendered)["default"]["deploy"]["parameters"]
        recovered = {}
        for override in parsed["parameter_overrides"]:
            key, value = override.split(",ParameterValue=", 1)
            recovered[key.removeprefix("ParameterKey=")] = json.loads(value)
        self.assertEqual(params, recovered)

    def test_private_output_permissions_and_no_overwrite_or_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "settings.json"
            settings.write_private(output, "{}", local_root=root)
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                settings.write_private(output, "new", local_root=root)
            with self.assertRaises(ConfigurationError):
                settings.write_private(root.parent / "escape.json", "{}", local_root=root)

    def test_cli_active_render_requires_acknowledgement_and_never_prints_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / "config/local"
            local.mkdir(parents=True)
            environment = {**self.env, "ACTIVATION_APPROVED": "true"}
            (local / "environment.json").write_text(json.dumps(environment))
            (local / "deployment.json").write_text(json.dumps(self.deploy))
            output = io.StringIO()
            with patch.object(settings, "ROOT", root), redirect_stdout(output):
                with self.assertRaisesRegex(ConfigurationError, "allow-active"):
                    settings.main(["render"])
                self.assertFalse((local / "samconfig.toml").exists())
                self.assertEqual(0, settings.main(["render", "--allow-active"]))
            receipt = json.loads(output.getvalue())
            self.assertEqual("RENDERED", receipt["status"])
            self.assertNotIn(environment["JIRA_SECRET_ARN"], output.getvalue())
            self.assertNotIn(environment["JIRA_ORIGIN"], output.getvalue())

    def test_duplicate_json_keys_and_symlink_input_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text('{"JIRA_ORIGIN":"one","JIRA_ORIGIN":"two"}')
            with self.assertRaisesRegex(ConfigurationError, "duplicate"):
                settings.read_json(path)
            link = Path(directory) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ConfigurationError):
                settings.read_json(link)

    def test_application_debug_does_not_enable_sdk_secret_logging(self):
        self.assertEqual("security_automation", handler.LOGGER.name)
        self.assertGreaterEqual(logging.getLogger("botocore").getEffectiveLevel(), logging.WARNING)
        self.assertGreaterEqual(logging.getLogger("boto3").getEffectiveLevel(), logging.WARNING)

    def test_publication_rejects_populated_templates_private_paths_and_tokens(self):
        self.assertEqual([], scan_content("config/environment.example.json", b'{"JIRA_ORIGIN":""}'))
        self.assertTrue(
            scan_content("config/environment.example.json", b'{"JIRA_ORIGIN":"populated"}')
        )
        for name in (
            "config/local/environment.json",
            ".env.production",
            "exports/private.json",
            "reports/issues.csv",
            "samconfig.toml",
        ):
            self.assertTrue(private_path(name))
        token = "ghp_" + "a" * 36
        result = scan_content("src/example.py", token.encode())
        self.assertEqual("github-token", result[0]["rule"])
        self.assertNotIn(token, json.dumps(result))

    def test_live_scan_bypass_is_rejected_even_without_file_generator(self):
        # Use the existing service fixture without inheriting its entire test suite.
        fixture = fixtures.ServiceTests(methodName="test_dry_run_never_creates_or_writes_state")
        fixture.setUp()
        fixture.service.config = replace(fixture.service.config, require_clean_attachment_tag=False)
        with self.assertRaisesRegex(ReviewRequired, "scan verification"):
            fixture.service.run(dry_run=False)
        self.assertEqual([], fixture.jira.created_fields)
