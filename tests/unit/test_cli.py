"""Tests for the command-line interface."""

from pathlib import Path
from typing import Never

import pytest
from typer.testing import CliRunner

from banglasecure_baseline import cli
from banglasecure_baseline.cli import app
from banglasecure_baseline.dependency_audit import ScannerExecutionError
from banglasecure_baseline.findings import Finding, Severity

runner = CliRunner()


def test_help_displays_project_description() -> None:
    """The CLI help page should explain the tool's purpose."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Affordable security checks" in result.output


def test_version_command_succeeds() -> None:
    """The version command should return the installed package version."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "BanglaSecure Baseline" in result.output


def test_dependency_audit_help_explains_network_consent() -> None:
    result = runner.invoke(app, ["dependency-audit", "--help"])

    assert result.exit_code == 0
    assert "--allow-advisory-network" in result.output
    assert "Package names and versions" in result.output


def test_dependency_audit_requires_network_consent(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "sample-project"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["dependency-audit", str(project)])

    assert result.exit_code == 2
    assert "Dependency auditing requires external" in result.output


def test_dependency_audit_success_reports_clean_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "audit_dependencies", lambda *args, **kwargs: ())

    result = runner.invoke(
        app,
        ["dependency-audit", str(tmp_path), "--allow-advisory-network"],
    )

    assert result.exit_code == 0
    assert "no known vulnerabilities were reported" in result.output


def test_dependency_audit_findings_return_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    finding = Finding(
        finding_id="DEP-0123456789abcdef",
        title="Vulnerable dependency: sample-package 1.2.3 (CVE-2024-12345)",
        severity=Severity.UNASSESSED,
        category="dependency",
        summary_en="The dependency is listed in an advisory.",
        summary_bn="নির্ভরতাটি একটি নিরাপত্তা পরামর্শে উল্লেখ করা হয়েছে।",
        safe_evidence="Package: sample-package==1.2.3; advisory: CVE-2024-12345.",
        impact_en="The affected dependency may expose applications to risk.",
        impact_bn="দুর্বল নির্ভরতা অ্যাপ্লিকেশনের জন্য ঝুঁকি তৈরি করতে পারে।",
        remediation_en="Review the advisory and update the dependency.",
        remediation_bn="পরামর্শটি পর্যালোচনা করে নির্ভরতাটি আপডেট করুন।",
    )
    monkeypatch.setattr(cli, "audit_dependencies", lambda *args, **kwargs: (finding,))

    result = runner.invoke(
        app,
        ["dependency-audit", ".", "--allow-advisory-network"],
    )

    assert result.exit_code == 1
    assert "CVE-2024-12345" in result.output
    assert "unassessed" in result.output


def test_dependency_audit_failure_does_not_claim_clean_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail_audit(*args: object, **kwargs: object) -> Never:
        raise ScannerExecutionError("pip-audit could not be started.")

    monkeypatch.setattr(cli, "audit_dependencies", fail_audit)

    result = runner.invoke(
        app,
        ["dependency-audit", str(tmp_path), "--allow-advisory-network"],
    )

    assert result.exit_code == 2
    assert "Dependency audit failed" in result.output
    assert "no known vulnerabilities" not in result.output
