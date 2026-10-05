import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from config import Config, ConfigurationError  # noqa: E402


class ConfigTests(unittest.TestCase):
    required = {
        "INPUT_BUCKET": "reports-bucket",
        "JIRA_SECRET_ARN": "test-arn",
        "STATE_TABLE_NAME": "state",
        "JIRA_ORIGIN": "https://jira-example.atlassian.net",
        "JIRA_PROJECT_KEY": "SEC",
    }

    def test_default_paths_and_explicit_project_are_preserved(self):
        with patch.dict(os.environ, self.required, clear=True):
            config = Config.from_env()
        self.assertEqual("snyk/risk-exposure/", config.risk_prefix)
        self.assertEqual("SEC", config.jira_project_key)
        self.assertTrue(config.dry_run_default)
        self.assertEqual("{}", config.product_profiles_json)

    def test_destination_project_has_no_environment_specific_default(self):
        for project in (None, "", "   "):
            environment = dict(self.required)
            if project is None:
                del environment["JIRA_PROJECT_KEY"]
            else:
                environment["JIRA_PROJECT_KEY"] = project
            with (
                self.subTest(project=project),
                self.assertRaisesRegex(
                    ConfigurationError, "Missing required environment variable: JIRA_PROJECT_KEY"
                ),
            ):
                Config.from_mapping(environment)

    def test_selected_root_applies_to_every_allowed_folder(self):
        with patch.dict(
            os.environ, {**self.required, "INGESTION_PREFIX": "incoming/security/"}, clear=True
        ):
            config = Config.from_env()
        self.assertEqual("incoming/security/snyk/issues-detail/", config.issues_prefix)
        self.assertEqual("incoming/security/products/", config.products_prefix)
        self.assertEqual("incoming/security/snyk/attachments/", config.attachment_prefix)

    def test_ambiguous_prefixes_are_rejected(self):
        for override in (
            {"INGESTION_PREFIX": "/incoming/"},
            {"INGESTION_PREFIX": "incoming"},
            {"PRODUCTS_REPORT_PREFIX": "snyk/"},
            {"ISSUES_REPORT_PREFIX": "snyk/risk-exposure/"},
        ):
            with (
                self.subTest(override=override),
                patch.dict(os.environ, {**self.required, **override}, clear=True),
            ):
                with self.assertRaises(ConfigurationError):
                    Config.from_env()

    def test_resource_limits_cannot_exceed_supported_bounds(self):
        for key, value in (
            ("WORK_SECONDS", "300"),
            ("MAX_INPUT_BYTES", "999999999"),
            ("MAX_ATTACHMENTS_PER_RUN", "21"),
        ):
            with patch.dict(os.environ, {**self.required, key: value}, clear=True):
                with self.assertRaisesRegex(ConfigurationError, "safety limit"):
                    Config.from_env()
