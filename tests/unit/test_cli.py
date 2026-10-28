"""Tests for the command-line interface."""

import json
import re
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
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _normalized_cli_output(output: str) -> str:
    return " ".join(_ANSI_ESCAPE.sub("", output).split())


def test_cli_output_normalization_removes_ansi_and_collapses_wrapping() -> None:
    output = "\x1b[1m--allow-advisory-network\x1b[0m Package names\n and versions"

    assert _normalized_cli_output(output) == ("--allow-advisory-network Package names and versions")


def _assert_secret_not_disclosed(value: str, secret: str) -> None:
    if secret in value:
        pytest.fail("The synthetic secret was exposed.")


def _synthetic_github_token() -> str:
    return "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


def _policy_finding(severity: Severity, finding_id: str = "POLICY-001") -> Finding:
    return Finding(
        finding_id=finding_id,
        title=f"Synthetic {severity.value} finding",
        severity=severity,
        category="synthetic",
        summary_en="Synthetic finding for severity-policy testing.",
        summary_bn="সিভিয়ারিটি নীতির পরীক্ষার জন্য কৃত্রিম ফলাফল।",
        safe_evidence="Synthetic evidence only.",
        impact_en="Synthetic impact.",
        impact_bn="কৃত্রিম প্রভাব।",
        remediation_en="Review the synthetic finding.",
        remediation_bn="কৃত্রিম ফলাফলটি পর্যালোচনা করুন।",
        location="synthetic.txt:1",
    )


def _scan_args(scan_name: str) -> list[str]:
    if scan_name == "dependency-audit":
        return ["dependency-audit", ".", "--allow-advisory-network"]
    if scan_name == "secret-scan":
        return ["secret-scan", "."]
    return [
        "web-check",
        "example.org",
        "--verification-token",
        "synthetic-token",
        "--allow-network",
    ]


def _mock_scan_result(
    monkeypatch: pytest.MonkeyPatch,
    scan_name: str,
    result: object,
) -> Mock:
    scan = Mock(return_value=result)
    if scan_name == "dependency-audit":
        monkeypatch.setattr(cli, "audit_dependencies", scan)
    elif scan_name == "secret-scan":
        monkeypatch.setattr(cli, "scan_secrets", scan)
    else:
        monkeypatch.setattr(cli, "check_web_configuration", scan)
    return scan


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
    result = runner.invoke(
        app,
        ["dependency-audit", "--help"],
        color=False,
        terminal_width=120,
    )
    output = _normalized_cli_output(result.output)

    assert result.exit_code == 0
    assert "--allow-advisory-network" in output
    assert "Package names and versions" in output


@pytest.mark.parametrize("scan_name", ["dependency-audit", "secret-scan", "web-check"])
def test_scan_help_exposes_minimum_severity_option(scan_name: str) -> None:
    result = runner.invoke(app, [scan_name, "--help"], color=False, terminal_width=120)

    assert result.exit_code == 0
    assert "--minimum-severity" in _normalized_cli_output(result.output)


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


def test_dependency_audit_json_stdout_has_only_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "audit_dependencies", lambda *args, **kwargs: ())
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(
        app,
        [
            "dependency-audit",
            str(project),
            "--allow-advisory-network",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"] == []
    assert "completed" not in result.stdout.lower()


def test_dependency_audit_json_still_requires_network_consent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit = Mock(side_effect=cli.DependencyAuditError("Consent required."))
    monkeypatch.setattr(cli, "audit_dependencies", audit)
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(
        app,
        ["dependency-audit", str(project), "--format", "json"],
    )

    assert result.exit_code == 2
    audit.assert_called_once_with(str(project), allow_advisory_network=False)
    assert "Consent required" in result.output


def test_dependency_audit_sarif_does_not_bypass_network_consent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit = Mock(side_effect=cli.DependencyAuditError("Consent required."))
    monkeypatch.setattr(cli, "audit_dependencies", audit)
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(
        app,
        ["dependency-audit", str(project), "--format", "sarif"],
    )

    assert result.exit_code == 2
    audit.assert_called_once_with(str(project), allow_advisory_network=False)
    assert not result.stdout.startswith("{")


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


def test_dependency_audit_json_scanner_failure_is_not_a_clean_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit = Mock(side_effect=ScannerExecutionError("pip-audit could not be started."))
    monkeypatch.setattr(cli, "audit_dependencies", audit)
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(
        app,
        [
            "dependency-audit",
            str(project),
            "--allow-advisory-network",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    assert "Dependency audit failed" in result.output
    assert not result.stdout.startswith("{")


def test_secret_scan_help_explains_history_option() -> None:
    result = runner.invoke(
        app,
        ["secret-scan", "--help"],
        color=False,
        terminal_width=120,
    )
    output = _normalized_cli_output(result.output)

    assert result.exit_code == 0
    assert "--include-git-history" in output
    assert "authorised" in output


@pytest.mark.parametrize("scan_name", ["dependency-audit", "secret-scan", "web-check"])
@pytest.mark.parametrize(
    ("severity", "minimum_severity", "expected_exit"),
    [
        (Severity.LOW, Severity.HIGH, 0),
        (Severity.HIGH, Severity.HIGH, 1),
        (Severity.CRITICAL, Severity.HIGH, 1),
    ],
)
def test_minimum_severity_gate_across_scan_commands(
    monkeypatch: pytest.MonkeyPatch,
    scan_name: str,
    severity: Severity,
    minimum_severity: Severity,
    expected_exit: int,
) -> None:
    finding = _policy_finding(severity)
    _mock_scan_result(monkeypatch, scan_name, (finding,))

    result = runner.invoke(
        app,
        [*_scan_args(scan_name), "--minimum-severity", minimum_severity.value],
    )

    assert result.exit_code == expected_exit
    assert finding.title in result.output
    if expected_exit:
        assert "Severity policy failed" in result.output
    else:
        assert "Severity policy failed" not in result.output


@pytest.mark.parametrize("scan_name", ["dependency-audit", "secret-scan", "web-check"])
def test_minimum_severity_gate_allows_no_findings(
    monkeypatch: pytest.MonkeyPatch,
    scan_name: str,
) -> None:
    _mock_scan_result(monkeypatch, scan_name, ())

    result = runner.invoke(
        app,
        [*_scan_args(scan_name), "--minimum-severity", "critical"],
    )

    assert result.exit_code == 0
    assert "Severity policy failed" not in result.output


def test_unassessed_finding_fails_any_explicit_minimum_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _policy_finding(Severity.UNASSESSED)
    _mock_scan_result(monkeypatch, "secret-scan", (finding,))

    result = runner.invoke(
        app,
        ["secret-scan", ".", "--minimum-severity", "critical"],
    )

    assert result.exit_code == 1
    assert finding.title in result.output
    assert "or are unassessed" in result.output


def test_invalid_finding_severity_is_an_assessment_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _policy_finding(Severity.HIGH)
    object.__setattr__(finding, "severity", None)
    _mock_scan_result(monkeypatch, "secret-scan", (finding,))

    result = runner.invoke(
        app,
        ["secret-scan", ".", "--minimum-severity", "high"],
    )

    assert result.exit_code == 2
    assert "missing or unsupported severity" in result.output
    assert "Severity policy failed" not in result.output


@pytest.mark.parametrize("report_format", ["json", "sarif"])
@pytest.mark.parametrize("write_to_file", [False, True])
def test_threshold_failure_still_generates_requested_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    report_format: str,
    write_to_file: bool,
) -> None:
    finding = _policy_finding(Severity.HIGH)
    _mock_scan_result(monkeypatch, "secret-scan", (finding,))
    project = tmp_path / "project"
    project.mkdir()
    args = [
        "secret-scan",
        str(project),
        "--minimum-severity",
        "high",
        "--format",
        report_format,
    ]
    output_path = tmp_path / ("report." + ("sarif" if report_format == "sarif" else "json"))
    if write_to_file:
        args.extend(["--output", str(output_path)])

    result = runner.invoke(app, args)

    assert result.exit_code == 1
    assert "Severity policy failed" in result.output
    if write_to_file:
        report_text = output_path.read_text(encoding="utf-8")
    else:
        report_text = result.stdout
    report = json.loads(report_text)
    if report_format == "json":
        assert report["findings"][0]["finding_id"] == finding.finding_id
    else:
        assert report["runs"][0]["results"][0]["ruleId"] == finding.finding_id


@pytest.mark.parametrize(
    ("scan_name", "error", "expected_message"),
    [
        (
            "dependency-audit",
            ScannerExecutionError("pip-audit could not be started."),
            "Dependency audit failed",
        ),
        ("secret-scan", ScannerUnavailableError("Gitleaks is unavailable."), "Secret scan failed"),
        ("web-check", NetworkConsentError("Consent is required."), "Web assessment failed"),
    ],
)
def test_scanner_errors_remain_distinct_from_threshold_failures(
    monkeypatch: pytest.MonkeyPatch,
    scan_name: str,
    error: Exception,
    expected_message: str,
) -> None:
    _mock_scan_result(monkeypatch, scan_name, error)
    scan = (
        cli.audit_dependencies
        if scan_name == "dependency-audit"
        else cli.scan_secrets
        if scan_name == "secret-scan"
        else cli.check_web_configuration
    )
    scan.side_effect = error
    scan.return_value = None

    result = runner.invoke(
        app,
        [*_scan_args(scan_name), "--minimum-severity", "high"],
    )

    assert result.exit_code == 2
    assert expected_message in result.output
    assert "Severity policy failed" not in result.output


def test_invalid_minimum_severity_is_rejected_before_scanning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = Mock()
    monkeypatch.setattr(cli, "scan_secrets", scan)

    result = runner.invoke(
        app,
        ["secret-scan", ".", "--minimum-severity", "urgent"],
    )

    assert result.exit_code == 2
    scan.assert_not_called()
    assert "Invalid value" in result.output


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


def test_secret_scan_json_report_omits_raw_synthetic_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
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
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(
        app,
        ["secret-scan", str(project), "--format", "json"],
    )

    assert result.exit_code == 1
    parsed = json.loads(result.stdout)
    assert parsed["findings"][0]["finding_id"] == finding.finding_id
    _assert_secret_not_disclosed(result.stdout, sentinel)


def test_secret_scan_sarif_output_keeps_raw_secret_out_and_returns_finding_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sentinel = _synthetic_github_token()
    finding = Finding(
        finding_id="SECRET-synthetic",
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
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(
        app,
        ["secret-scan", str(project), "--format", "sarif"],
    )

    assert result.exit_code == 1
    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == finding.finding_id
    _assert_secret_not_disclosed(result.stdout, sentinel)


def test_sarif_output_file_is_separate_from_completion_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "scan_secrets", lambda *args, **kwargs: ())
    project = tmp_path / "project"
    project.mkdir()
    output = tmp_path / "report.sarif"

    result = runner.invoke(
        app,
        ["secret-scan", str(project), "--format", "sarif", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert result.stdout.startswith("SARIF report written to")
    assert json.loads(output.read_text(encoding="utf-8"))["runs"][0]["results"] == []


def test_sarif_stdout_contains_only_the_empty_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "scan_secrets", lambda *args, **kwargs: ())
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(app, ["secret-scan", str(project), "--format", "sarif"])

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"] == []


def test_secret_scan_json_file_output_is_separate_from_completion_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "scan_secrets", lambda *args, **kwargs: ())
    project = tmp_path / "project"
    project.mkdir()
    output = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["secret-scan", str(project), "--format", "json", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert "JSON report written to" in result.stdout
    assert json.loads(output.read_text(encoding="utf-8"))["findings"] == []


def test_text_format_rejects_output_file_before_running_scanner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scan = Mock()
    monkeypatch.setattr(cli, "scan_secrets", scan)
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(
        app,
        ["secret-scan", str(project), "--output", str(tmp_path / "report.json")],
    )

    assert result.exit_code == 2
    scan.assert_not_called()
    assert "only with --format json" in result.output


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


def test_secret_scan_json_scanner_failure_is_not_a_clean_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scan = Mock(side_effect=ScannerUnavailableError("Gitleaks unavailable."))
    monkeypatch.setattr(cli, "scan_secrets", scan)
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(
        app,
        ["secret-scan", str(project), "--format", "json"],
    )

    assert result.exit_code == 2
    assert "Secret scan failed" in result.output
    assert not result.stdout.startswith("{")


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


def test_web_check_json_report_uses_mocked_verified_scan_and_preserves_finding_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = Finding(
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
    )
    check = Mock(return_value=(finding,))
    monkeypatch.setattr(cli, "check_web_configuration", check)

    result = runner.invoke(
        app,
        [
            "web-check",
            "example.org",
            "--verification-token",
            "z" * 43,
            "--allow-network",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["findings"][0]["title"] == finding.title
    check.assert_called_once_with(
        "example.org",
        verification_token="z" * 43,
        allow_network=True,
    )


def test_web_check_sarif_report_uses_completed_assessment_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = Finding(
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
    )
    check = Mock(return_value=(finding,))
    monkeypatch.setattr(cli, "check_web_configuration", check)

    result = runner.invoke(
        app,
        [
            "web-check",
            "example.org",
            "--verification-token",
            "z" * 43,
            "--allow-network",
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 1
    result_entry = json.loads(result.stdout)["runs"][0]["results"][0]
    assert result_entry["ruleId"] == finding.finding_id
    assert "locations" not in result_entry


def test_web_check_json_does_not_bypass_network_consent_or_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = Mock(side_effect=NetworkConsentError("Explicit network consent is required."))
    monkeypatch.setattr(cli, "check_web_configuration", check)

    result = runner.invoke(
        app,
        [
            "web-check",
            "example.org",
            "--verification-token",
            "z" * 43,
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    check.assert_called_once_with(
        "example.org",
        verification_token="z" * 43,
        allow_network=False,
    )
    assert not result.stdout.startswith("{")


def test_web_check_sarif_does_not_bypass_verification_or_network_consent(
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
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 2
    check.assert_called_once_with(
        "example.org",
        verification_token="z" * 43,
        allow_network=False,
    )
    assert not result.stdout.startswith("{")


def test_web_check_sarif_with_consent_still_requires_matching_verification(
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
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 2
    check.assert_called_once_with(
        "example.org",
        verification_token="z" * 43,
        allow_network=True,
    )
    assert not result.stdout.startswith("{")


def test_web_check_json_scanner_failure_is_not_a_clean_report(
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
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    assert "Web assessment failed" in result.output
    assert not result.stdout.startswith("{")


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
