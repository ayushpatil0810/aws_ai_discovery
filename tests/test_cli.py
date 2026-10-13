"""End-to-end integration tests for CLI commands."""

import os
from click.testing import CliRunner
import pytest

from src.cli import cli


def test_cli_init_db():
    runner = CliRunner()
    result = runner.invoke(cli, ["init-db"])
    assert result.exit_code == 0
    assert "Database initialized" in result.output


def test_cli_mock_scan():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--mode", "mock"])
    assert result.exit_code == 0
    assert "Scan Run" in result.output
    assert "COMPLETED" in result.output


def test_cli_inventory_list():
    runner = CliRunner()
    # First scan
    runner.invoke(cli, ["scan", "--mode", "mock"])
    result = runner.invoke(cli, ["inventory", "list", "--format", "table"])
    assert result.exit_code == 0
    assert "Total Discovered Assets:" in result.output


def test_cli_shadow_ai():
    runner = CliRunner()
    runner.invoke(cli, ["scan", "--mode", "mock"])
    result = runner.invoke(cli, ["shadow-ai"])
    assert result.exit_code == 0
    assert "Potential Shadow AI & Governance Findings" in result.output


def test_cli_allowlist_workflow():
    runner = CliRunner()
    add_result = runner.invoke(
        cli,
        [
            "allowlist", "add",
            "--key", "aws:123:us-east-1:sagemaker:endpoint:cli-test-endpoint",
            "--name", "cli-test-endpoint",
            "--owner", "security-lead",
            "--reference", "SEC-001"
        ]
    )
    assert add_result.exit_code == 0
    assert "registered as APPROVED" in add_result.output

    list_result = runner.invoke(cli, ["allowlist", "list"])
    assert list_result.exit_code == 0
    assert "cli-test-endpoint" in list_result.output


def test_cli_generate_policy():
    runner = CliRunner()
    test_policy_path = "test_iam_policy.json"
    try:
        result = runner.invoke(cli, ["generate-policy", "--output", test_policy_path])
        assert result.exit_code == 0
        assert os.path.exists(test_policy_path)
    finally:
        if os.path.exists(test_policy_path):
            os.remove(test_policy_path)
