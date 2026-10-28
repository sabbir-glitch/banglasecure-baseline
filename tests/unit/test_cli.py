"""Tests for the command-line interface."""

import json
import secrets
import string
import subprocess
from pathlib import Path
from typing import Never
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from banglasecure_baseline import cli, secret_scan
from banglasecure_baseline.cli import app
from banglasecure_baseline.dependency_audit import ScannerExecutionError
from banglasecure_baseline.findings import Finding, Severity
from banglasecure_baseline.secret_scan import ScannerUnavailableError
from banglasecure_baseline.web_check import (
    NetworkConsentError,
    VerificationError,
)

runner = CliRunner()


def _assert_secret_not_disclosed(value: str, secret: str) -> None:
    if secret in value:
        pytest.fail("The synthetic secret was exposed.")


def _synthetic_github_token() -> str:
    return "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


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


def test_secret_scan_help_explains_history_option() -> None:
    result = runner.invoke(app, ["secret-scan", "--help"])

    assert result.exit_code == 0
    assert "--include-git-history" in result.output
    assert "authorised" in result.output


def test_secret_scan_success_reports_no_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "scan_secrets", lambda *args, **kwargs: ())

    result = runner.invoke(app, ["secret-scan", "."])

    assert result.exit_code == 0
    assert "no potential secrets" in result.output


def test_secret_scan_findings_return_nonzero_without_secret_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = _synthetic_github_token()
    finding = Finding(
        finding_id="SECRET-0123456789abcdef0123",
        title="Potential secret detected (synthetic-rule)",
        severity=Severity.UNASSESSED,
        category="secret",
        summary_en="Potential secret detected; value withheld.",
        summary_bn="সম্ভাব্য গোপন তথ্য শনাক্ত; মান প্রকাশ করা হয়নি।",
        safe_evidence="Potential secret detected; value withheld.",
        impact_en="A genuine credential may allow unauthorised access.",
        impact_bn="প্রকৃত পরিচয়-তথ্য অননুমোদিত প্রবেশের সুযোগ দিতে পারে।",
        remediation_en="Revoke or rotate any genuine exposed credential.",
        remediation_bn="প্রকৃত উন্মুক্ত পরিচয়-তথ্য বাতিল বা পরিবর্তন করুন।",
        location="app.py:3",
    )
    monkeypatch.setattr(cli, "scan_secrets", lambda *args, **kwargs: (finding,))

    result = runner.invoke(app, ["secret-scan", "."])

    assert result.exit_code == 1
    assert finding.title in result.output
    _assert_secret_not_disclosed(result.output, sentinel)


def test_secret_scan_failure_is_distinct_from_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_scan(*args: object, **kwargs: object) -> Never:
        raise ScannerUnavailableError("Gitleaks was not found on PATH. Install it separately.")

    monkeypatch.setattr(cli, "scan_secrets", fail_scan)
    result = runner.invoke(app, ["secret-scan", "."])

    assert result.exit_code == 2
    assert "Secret scan failed" in result.output
    assert "Install it separately" in result.output


def test_secret_scan_cli_never_displays_raw_report_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sentinel = _synthetic_github_token()
    monkeypatch.setattr(secret_scan, "_scanner_path", lambda: "gitleaks")

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, "8.24.0", "")
        report_path = Path(
            next(arg.split("=", 1)[1] for arg in command if arg.startswith("--report-path="))
        )
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "File": "app.py",
                        "StartLine": 3,
                        "Secret": sentinel,
                        "Match": f"token={sentinel}",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 1, sentinel, sentinel)

    monkeypatch.setattr(secret_scan.subprocess, "run", run)
    result = runner.invoke(app, ["secret-scan", str(tmp_path)])

    assert result.exit_code == 1
    assert "Potential secret detected" in result.output
    _assert_secret_not_disclosed(result.output, sentinel)


def test_secret_scan_cli_sanitizes_unexpected_scanner_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sentinel = _synthetic_github_token()
    monkeypatch.setattr(secret_scan, "_scanner_path", lambda: "gitleaks")

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, "8.24.0", "")
        return subprocess.CompletedProcess(command, 2, sentinel, sentinel)

    monkeypatch.setattr(secret_scan.subprocess, "run", run)
    result = runner.invoke(app, ["secret-scan", str(tmp_path)])

    assert result.exit_code == 2
    assert "Secret scan failed" in result.output
    _assert_secret_not_disclosed(result.output, sentinel)


def test_web_verification_token_command_outputs_dns_record_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record_name = "_banglasecure-verification.example.org"
    token = "z" * 43
    generate = Mock(return_value=(record_name, token))
    monkeypatch.setattr(cli, "generate_verification_token", generate)

    result = runner.invoke(app, ["web-verification-token", "Example.org"])

    assert result.exit_code == 0
    assert record_name in result.output
    assert token in result.output
    assert "verification has not occurred" in result.output
    generate.assert_called_once_with("Example.org")


def test_web_check_requires_token_and_allow_network_options() -> None:
    result = runner.invoke(app, ["web-check", "example.org"])

    assert result.exit_code != 0


def test_web_check_missing_network_consent_returns_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = Mock(side_effect=NetworkConsentError("Explicit network consent is required."))
    monkeypatch.setattr(cli, "check_web_configuration", check)

    result = runner.invoke(
        app,
        ["web-check", "example.org", "--verification-token", "z" * 43],
    )

    assert result.exit_code == 2
    check.assert_called_once()


@pytest.mark.parametrize(
    ("findings", "expected_code", "message"),
    [
        ((), 0, "without reportable findings"),
        (
            (
                Finding(
                    finding_id="WEB-0123456789abcdef",
                    title="SPF record is absent",
                    severity=Severity.UNASSESSED,
                    category="web-configuration",
                    summary_en="No SPF record was found.",
                    summary_bn="SPF রেকর্ড পাওয়া যায়নি।",
                    safe_evidence="No SPF TXT record was found.",
                    impact_en="Mail spoofing may be harder to identify.",
                    impact_bn="জাল ইমেইল শনাক্ত করা কঠিন হতে পারে।",
                    remediation_en="Publish an SPF policy.",
                    remediation_bn="SPF নীতি প্রকাশ করুন।",
                    location="dns://example.org/TXT",
                ),
            ),
            1,
            "finding(s)",
        ),
    ],
)
def test_web_check_exit_code_for_completed_assessment(
    monkeypatch: pytest.MonkeyPatch,
    findings: tuple[Finding, ...],
    expected_code: int,
    message: str,
) -> None:
    monkeypatch.setattr(cli, "check_web_configuration", lambda *args, **kwargs: findings)

    result = runner.invoke(
        app,
        [
            "web-check",
            "example.org",
            "--verification-token",
            "z" * 43,
            "--allow-network",
        ],
    )

    assert result.exit_code == expected_code
    assert message in result.output


def test_web_check_verification_failure_returns_distinct_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = Mock(side_effect=VerificationError("The DNS verification token does not match."))
    monkeypatch.setattr(cli, "check_web_configuration", check)

    result = runner.invoke(
        app,
        [
            "web-check",
            "example.org",
            "--verification-token",
            "z" * 43,
            "--allow-network",
        ],
    )

    assert result.exit_code == 2
    assert "Web assessment failed" in result.output
