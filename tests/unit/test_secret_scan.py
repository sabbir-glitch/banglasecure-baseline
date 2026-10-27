"""Tests for safe Gitleaks invocation, parsing, and cleanup."""

import json
import secrets
import string
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from banglasecure_baseline import secret_scan
from banglasecure_baseline.findings import Severity
from banglasecure_baseline.secret_scan import (
    InvalidScanReportError,
    InvalidTargetError,
    ScannerExecutionError,
    ScannerTimeoutError,
    ScannerUnavailableError,
    UnsupportedScannerError,
    scan_secrets,
)

SENTINEL = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


def _assert_secret_not_disclosed(value: str, secret: str) -> None:
    if secret in value:
        pytest.fail("The synthetic secret was exposed.")


def test_synthetic_github_token_fixture_has_high_entropy_shape() -> None:
    token = SENTINEL

    assert token.startswith("ghp_")
    assert len(token) == 40
    assert len(set(token[4:])) >= 20


def _target(tmp_path: Path, *, git: bool = False) -> Path:
    target = tmp_path / "source"
    target.mkdir()
    (target / "app.py").write_text("print('synthetic')\n", encoding="utf-8")
    if git:
        (target / ".git").mkdir()
    return target


def _entry(
    *,
    file: str = "app.py",
    rule_id: str = "generic-api-key",
    line: int = 4,
    commit: str = "abcdef0123456789",
    secret: str = SENTINEL,
) -> dict[str, object]:
    return {
        "RuleID": rule_id,
        "Description": "Synthetic credential rule",
        "File": file,
        "StartLine": line,
        "StartColumn": 3,
        "Commit": commit,
        "Secret": secret,
        "Match": f"token={secret}",
    }


def _report_argument(command: list[str]) -> Path:
    report_arg = next(arg for arg in command if arg.startswith("--report-path="))
    return Path(report_arg.split("=", 1)[1])


def _mock_scanner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    report: list[dict[str, object]] | None = None,
    exit_code: int = 0,
    create_report: bool = True,
    scan_stderr: str = "",
    scan_stdout: str = "",
    scan_exception: Exception | None = None,
    version_text: str = "8.24.0",
) -> tuple[Mock, list[Path], list[list[str]]]:
    commands: list[list[str]] = []
    temporary_paths: list[Path] = []
    scanner = r"C:\tools\gitleaks.exe"
    monkeypatch.setattr(secret_scan, "_scanner_path", lambda: scanner)

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, version_text, "")
        report_path = _report_argument(command)
        temporary_paths.append(report_path)
        config_path = Path(
            next(arg.split("=", 1)[1] for arg in command if arg.startswith("--config="))
        )
        temporary_paths.append(config_path)
        assert "useDefault = true" in config_path.read_text(encoding="utf-8")
        if scan_exception is not None:
            raise scan_exception
        if create_report:
            report_path.write_text(
                json.dumps(report if report is not None else []), encoding="utf-8"
            )
        return subprocess.CompletedProcess(command, exit_code, scan_stdout, scan_stderr)

    mock = Mock(side_effect=run)
    monkeypatch.setattr(secret_scan.subprocess, "run", mock)
    return mock, temporary_paths, commands


def test_valid_directory_uses_dir_mode_and_safe_gitleaks_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = _target(tmp_path)
    mock, temporary_paths, commands = _mock_scanner(monkeypatch)

    assert scan_secrets(target) == ()

    command = commands[1]
    assert command[1] == "dir"
    assert str(target) in command
    assert "--redact=100" in command
    assert any(arg.startswith("--report-path=") for arg in command)
    assert any(arg.startswith("--config=") for arg in command)
    assert "--fix" not in command
    assert mock.call_count == 2
    assert temporary_paths
    assert all(not path.exists() for path in temporary_paths)
    assert all(not path.is_relative_to(target) for path in temporary_paths)


def test_invalid_target_is_rejected_without_starting_scanner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mock = Mock()
    monkeypatch.setattr(secret_scan.subprocess, "run", mock)
    monkeypatch.setattr(secret_scan, "_scanner_path", lambda: "gitleaks")

    with pytest.raises(InvalidTargetError):
        scan_secrets(tmp_path / "missing")

    mock.assert_not_called()


def test_missing_gitleaks_has_install_guidance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(secret_scan.shutil, "which", lambda _: None)

    with pytest.raises(ScannerUnavailableError, match="Install it separately"):
        scan_secrets(_target(tmp_path))


@pytest.mark.parametrize("version_text", ["8.18.9", "9.0.0", "version unknown"])
def test_unsupported_gitleaks_versions_fail_safely(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, version_text: str
) -> None:
    _mock_scanner(monkeypatch, version_text=version_text)

    with pytest.raises(UnsupportedScannerError):
        scan_secrets(_target(tmp_path))


def test_clean_scan_requires_a_valid_empty_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_scanner(monkeypatch, report=[])

    assert scan_secrets(_target(tmp_path)) == ()


def test_one_finding_uses_safe_metadata_and_relative_location(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = _target(tmp_path)
    _mock_scanner(monkeypatch, report=[_entry()], exit_code=1)

    findings = scan_secrets(target)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_id.startswith("SECRET-")
    assert finding.title == "Potential secret detected (generic-api-key)"
    assert finding.severity is Severity.UNASSESSED
    assert finding.category == "secret"
    assert finding.location == "app.py:4"
    assert "potential secret" in finding.summary_en.lower()
    assert finding.remediation_en and finding.remediation_bn
    _assert_secret_not_disclosed(repr(finding), SENTINEL)
    assert target.as_posix() not in repr(finding)


def test_multiple_findings_are_preserved(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _mock_scanner(
        monkeypatch,
        report=[
            _entry(file="app.py", rule_id="rule-one", line=4),
            _entry(file="config/settings.py", rule_id="rule-two", line=12),
        ],
        exit_code=1,
    )

    findings = scan_secrets(_target(tmp_path))

    assert len(findings) == 2
    assert {finding.location for finding in findings} == {"app.py:4", "config/settings.py:12"}
    assert findings[0].finding_id != findings[1].finding_id


def test_valid_exit_one_report_is_returned_as_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_scanner(monkeypatch, report=[_entry()], exit_code=1)

    assert len(scan_secrets(_target(tmp_path))) == 1


@pytest.mark.parametrize("exit_code", [2, 3, 127])
def test_unexpected_exit_code_is_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exit_code: int
) -> None:
    _mock_scanner(
        monkeypatch,
        exit_code=exit_code,
        scan_stdout=f"contains {SENTINEL}",
        scan_stderr=f"error {SENTINEL}",
    )

    with pytest.raises(ScannerExecutionError) as error:
        scan_secrets(_target(tmp_path))

    _assert_secret_not_disclosed(str(error.value), SENTINEL)


def test_missing_report_is_a_failure_and_cleans_temporary_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_scanner(monkeypatch, create_report=False)

    with pytest.raises(InvalidScanReportError, match="did not create"):
        scan_secrets(_target(tmp_path))


def test_malformed_json_is_reported_without_disclosing_report_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, temporary_paths, commands = _mock_scanner(monkeypatch)

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, "8.24.0", "")
        report_path = _report_argument(command)
        temporary_paths.append(report_path)
        config_path = Path(
            next(arg.split("=", 1)[1] for arg in command if arg.startswith("--config="))
        )
        temporary_paths.append(config_path)
        report_path.write_text(f'{{"Secret": "{SENTINEL}"', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", f"Match={SENTINEL}")

    monkeypatch.setattr(secret_scan.subprocess, "run", Mock(side_effect=run))

    with pytest.raises(InvalidScanReportError) as error:
        scan_secrets(_target(tmp_path))

    _assert_secret_not_disclosed(str(error.value), SENTINEL)
    assert all(not path.exists() for path in temporary_paths)


@pytest.mark.parametrize(
    "report",
    [
        {},
        [None],
        [{"File": "app.py", "RuleID": "bad id"}],
        [{"RuleID": "rule", "File": "../outside"}],
        [{"RuleID": "rule", "File": "app.py", "StartLine": "4"}],
    ],
)
def test_malformed_finding_structures_are_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, report: object
) -> None:
    mock = Mock()
    scanner = r"C:\tools\gitleaks.exe"
    monkeypatch.setattr(secret_scan, "_scanner_path", lambda: scanner)

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, "8.24.0", "")
        _report_argument(command).write_text(json.dumps(report), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    mock.side_effect = run
    monkeypatch.setattr(secret_scan.subprocess, "run", mock)
    with pytest.raises(InvalidScanReportError):
        scan_secrets(_target(tmp_path))


def test_timeout_cleans_temporary_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _, temporary_paths, commands = _mock_scanner(monkeypatch)

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, "8.24.0", "")
        temporary_paths.append(_report_argument(command))
        raise subprocess.TimeoutExpired(command, timeout=1, stderr=f"Secret={SENTINEL}")

    monkeypatch.setattr(secret_scan.subprocess, "run", Mock(side_effect=run))

    with pytest.raises(ScannerTimeoutError) as error:
        scan_secrets(_target(tmp_path))

    _assert_secret_not_disclosed(str(error.value), SENTINEL)
    assert all(not path.exists() for path in temporary_paths)


def test_history_mode_uses_git_command_and_requires_repository(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = _target(tmp_path, git=True)
    _, _, commands = _mock_scanner(monkeypatch)

    assert scan_secrets(target, include_git_history=True) == ()
    assert commands[1][1] == "git"


def test_history_mode_rejects_non_repository(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mock = Mock()
    monkeypatch.setattr(secret_scan, "_scanner_path", lambda: "gitleaks")
    monkeypatch.setattr(secret_scan.subprocess, "run", mock)

    with pytest.raises(InvalidTargetError, match="Git repository"):
        scan_secrets(_target(tmp_path), include_git_history=True)

    mock.assert_not_called()


def test_absolute_in_target_paths_are_normalized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = _target(tmp_path)
    absolute_file = target / "app.py"
    _mock_scanner(monkeypatch, report=[_entry(file=str(absolute_file))], exit_code=1)

    findings = scan_secrets(target)

    assert findings[0].location == "app.py:4"


def test_secret_and_match_sentinel_never_enter_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_scanner(
        monkeypatch,
        report=[_entry(secret=SENTINEL)],
        exit_code=1,
    )

    findings = scan_secrets(_target(tmp_path))

    _assert_secret_not_disclosed(repr(findings), SENTINEL)
