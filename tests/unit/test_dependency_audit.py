"""Tests for dependency-audit validation and scanner handling."""

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from banglasecure_baseline import dependency_audit
from banglasecure_baseline.dependency_audit import (
    InvalidAuditReportError,
    InvalidTargetError,
    NetworkConsentError,
    ScannerExecutionError,
    ScannerTimeoutError,
    ScannerUnavailableError,
    audit_dependencies,
)
from banglasecure_baseline.findings import Severity


def _scanner_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    scanner = tmp_path / "Scripts" / "pip-audit.exe"
    scanner.parent.mkdir()
    scanner.touch()
    monkeypatch.setattr(dependency_audit, "_scanner_path", lambda: scanner)
    return scanner


def _project_path(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "sample-project"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    return project


def _report(*dependencies: dict[str, Any]) -> str:
    return json.dumps({"dependencies": list(dependencies)})


def _clean_dependency() -> dict[str, Any]:
    return {"name": "sample-package", "version": "1.2.3", "vulns": []}


def _vulnerable_dependency() -> dict[str, Any]:
    return {
        "name": "sample-package",
        "version": "1.2.3",
        "vulns": [
            {
                "id": "PYSEC-2024-123",
                "aliases": ["CVE-2024-12345", "GHSA-2345-2345-2345"],
                "fix_versions": ["1.2.4"],
            }
        ],
    }


def _mock_result(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: str,
    returncode: int = 0,
    stderr: str = "",
) -> Mock:
    run = Mock(
        return_value=subprocess.CompletedProcess(
            args=["pip-audit"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )
    )
    monkeypatch.setattr(dependency_audit.subprocess, "run", run)
    return run


def test_valid_project_input_invokes_scanner_without_modification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = _project_path(tmp_path)
    scanner = _scanner_path(monkeypatch, tmp_path)
    run = _mock_result(monkeypatch, stdout=_report(_clean_dependency()))

    findings = audit_dependencies(project, allow_advisory_network=True)

    assert findings == ()
    args = run.call_args.args[0]
    assert args[0] == str(scanner)
    assert str(project) in args
    assert "--format=json" in args
    assert "--fix" not in args
    assert run.call_args.kwargs["timeout"] == dependency_audit.EXECUTION_TIMEOUT_SECONDS


def test_valid_requirements_input_uses_explicit_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    requirements = tmp_path / "requirements-dev.txt"
    requirements.write_text("sample-package==1.2.3\n", encoding="utf-8")
    _scanner_path(monkeypatch, tmp_path)
    run = _mock_result(monkeypatch, stdout=_report())

    assert audit_dependencies(requirements, allow_advisory_network=True) == ()
    assert run.call_args.args[0][-2:] == ["--requirement", str(requirements)]


def test_invalid_project_input_is_rejected_before_scanner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = tmp_path / "without-manifest"
    project.mkdir()
    run = Mock()
    monkeypatch.setattr(dependency_audit.subprocess, "run", run)

    with pytest.raises(InvalidTargetError):
        audit_dependencies(project, allow_advisory_network=True)

    run.assert_not_called()


def test_invalid_pyproject_toml_is_rejected(tmp_path: Path) -> None:
    project = tmp_path / "invalid-project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[broken", encoding="utf-8")

    with pytest.raises(InvalidTargetError, match="not valid TOML"):
        audit_dependencies(project, allow_advisory_network=True)


@pytest.mark.parametrize(
    "pyproject_content",
    [
        "[tool.ruff]\nline-length = 100\n",
        ('[project]\nname = "sample-project"\nversion = "1.0.0"\ndynamic = ["dependencies"]\n'),
        ('[project]\nname = "sample-project"\nversion = "1.0.0"\ndependencies = "not-a-list"\n'),
    ],
)
def test_unsupported_project_metadata_is_rejected_before_scanner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pyproject_content: str
) -> None:
    project = tmp_path / "unsupported-project"
    project.mkdir()
    (project / "pyproject.toml").write_text(pyproject_content, encoding="utf-8")
    run = Mock()
    monkeypatch.setattr(dependency_audit.subprocess, "run", run)

    with pytest.raises(InvalidTargetError):
        audit_dependencies(project, allow_advisory_network=True)

    run.assert_not_called()


def test_network_consent_is_required_before_scanner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run = Mock()
    monkeypatch.setattr(dependency_audit.subprocess, "run", run)

    with pytest.raises(NetworkConsentError, match="external"):
        audit_dependencies(_project_path(tmp_path))

    run.assert_not_called()


def test_valid_report_without_vulnerabilities_returns_no_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scanner_path(monkeypatch, tmp_path)
    _mock_result(monkeypatch, stdout=_report(_clean_dependency()))

    assert audit_dependencies(_project_path(tmp_path), allow_advisory_network=True) == ()


def test_exit_one_preserves_advisory_and_safe_finding_details(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scanner_path(monkeypatch, tmp_path)
    _mock_result(
        monkeypatch,
        stdout=_report(_vulnerable_dependency()),
        returncode=1,
    )

    findings = audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.UNASSESSED
    assert "sample-package 1.2.3" in finding.title
    assert "PYSEC-2024-123" in finding.safe_evidence
    assert "CVE-2024-12345" in finding.safe_evidence
    assert "1.2.4" in finding.safe_evidence
    assert finding.location == "pyproject.toml"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-12345" in finding.references
    assert "https://github.com/advisories/GHSA-2345-2345-2345" in finding.references
    assert finding.remediation_en and finding.remediation_bn


@pytest.mark.parametrize(
    "stdout",
    [
        "not-json",
        "[]",
        '{"dependencies": {}}',
        '{"dependencies": [null]}',
        '{"dependencies": [{"name": "pkg", "version": "1.0", "vulns": [{}]}]}',
        ('{"dependencies": [{"name": "pkg", "version": "1.0", "vulns": [{"id": "BAD ID"}]}]}'),
    ],
)
def test_malformed_reports_are_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stdout: str
) -> None:
    _scanner_path(monkeypatch, tmp_path)
    _mock_result(monkeypatch, stdout=stdout)

    with pytest.raises(InvalidAuditReportError):
        audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)


def test_exit_one_without_vulnerabilities_is_not_reported_as_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scanner_path(monkeypatch, tmp_path)
    _mock_result(monkeypatch, stdout=_report(), returncode=1)

    with pytest.raises(InvalidAuditReportError, match="exit status"):
        audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)


def test_unexpected_scanner_exit_is_a_safe_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scanner_path(monkeypatch, tmp_path)
    _mock_result(
        monkeypatch,
        stdout="sensitive-output",
        stderr="token=do-not-disclose",
        returncode=2,
    )

    with pytest.raises(ScannerExecutionError) as error:
        audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)

    assert "token=do-not-disclose" not in str(error.value)
    assert "sensitive-output" not in str(error.value)


def test_scanner_timeout_is_reported_without_subprocess_diagnostics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scanner_path(monkeypatch, tmp_path)
    run = Mock(
        side_effect=subprocess.TimeoutExpired(
            cmd="pip-audit", timeout=1, stderr="token=do-not-disclose"
        )
    )
    monkeypatch.setattr(dependency_audit.subprocess, "run", run)

    with pytest.raises(ScannerTimeoutError) as error:
        audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)

    assert "token=do-not-disclose" not in str(error.value)


def test_missing_scanner_is_reported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    missing_scanner = tmp_path / "missing" / "pip-audit.exe"
    monkeypatch.setattr(dependency_audit, "_scanner_path", lambda: missing_scanner)

    with pytest.raises(ScannerUnavailableError):
        audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)


def test_scanner_start_error_is_sanitised(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _scanner_path(monkeypatch, tmp_path)
    run = Mock(side_effect=OSError("secret path C:\\private\\credential"))
    monkeypatch.setattr(dependency_audit.subprocess, "run", run)

    with pytest.raises(ScannerExecutionError) as error:
        audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)

    assert "credential" not in str(error.value)


def test_malformed_scanner_output_does_not_leak_report_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scanner_path(monkeypatch, tmp_path)
    _mock_result(
        monkeypatch,
        stdout='{"credentials": "token=do-not-disclose"',
        stderr="password=do-not-disclose",
    )

    with pytest.raises(InvalidAuditReportError) as error:
        audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)

    assert "do-not-disclose" not in str(error.value)


def test_bad_vulnerability_fields_are_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _scanner_path(monkeypatch, tmp_path)
    malformed = {
        "name": "sample-package",
        "version": "1.2.3",
        "vulns": [{"id": "CVE-2024-12345", "aliases": "not-a-list"}],
    }
    _mock_result(monkeypatch, stdout=_report(malformed))

    with pytest.raises(InvalidAuditReportError):
        audit_dependencies(_project_path(tmp_path), allow_advisory_network=True)


def test_requirements_path_is_manifest_relative_in_finding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("sample-package==1.2.3\n", encoding="utf-8")
    _scanner_path(monkeypatch, tmp_path)
    _mock_result(monkeypatch, stdout=_report(_vulnerable_dependency()), returncode=1)

    findings = audit_dependencies(requirements, allow_advisory_network=True)

    assert findings[0].location == "requirements.txt"
