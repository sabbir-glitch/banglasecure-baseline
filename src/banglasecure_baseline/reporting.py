"""Deterministic JSON reporting for BanglaSecure Baseline findings."""

import json
import os
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path, PureWindowsPath

from banglasecure_baseline.findings import Finding, Severity

SCHEMA_VERSION = "1.0"
TOOL_NAME = "BanglaSecure Baseline"
REPORT_FORMAT = "banglasecure-json"


class ReportError(Exception):
    """A JSON report could not be validated or written safely."""


def serialize_json_report(findings: Iterable[Finding]) -> str:
    """Serialize Finding objects using the stable BanglaSecure JSON schema."""
    report_findings: list[dict[str, object]] = []
    try:
        for finding in findings:
            if not isinstance(finding, Finding):
                raise ReportError("JSON reports can contain only Finding objects.")
            if not isinstance(finding.severity, Severity):
                raise ReportError("A finding contains an unsupported severity.")
            if not isinstance(finding.references, tuple) or any(
                not isinstance(reference, str) for reference in finding.references
            ):
                raise ReportError("A finding contains invalid references.")
            if finding.location is not None and not isinstance(finding.location, str):
                raise ReportError("A finding contains an invalid location.")

            finding_data: dict[str, object] = {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "category": finding.category,
                "summary_en": finding.summary_en,
                "summary_bn": finding.summary_bn,
                "safe_evidence": finding.safe_evidence,
                "impact_en": finding.impact_en,
                "impact_bn": finding.impact_bn,
                "remediation_en": finding.remediation_en,
                "remediation_bn": finding.remediation_bn,
                "references": finding.references,
                "location": finding.location,
            }
            if any(
                not isinstance(value, str)
                for key, value in finding_data.items()
                if key not in {"references", "location"}
            ):
                raise ReportError("A finding contains an invalid field value.")
            try:
                for value in finding_data.values():
                    if isinstance(value, str):
                        value.encode("utf-8")
                    elif isinstance(value, tuple):
                        for reference in value:
                            reference.encode("utf-8")
            except UnicodeEncodeError:
                raise ReportError("A finding contains text that is not valid UTF-8.") from None
            report_findings.append(finding_data)

        report: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "tool": TOOL_NAME,
            "format": REPORT_FORMAT,
            "findings": report_findings,
        }
        return json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except ReportError:
        raise
    except (TypeError, ValueError):
        raise ReportError("The findings could not be serialized as a JSON report.") from None


def validate_report_destination(
    destination: str | Path,
    *,
    protected_target: str | Path | None = None,
) -> Path:
    """Resolve and validate a local report path without following output symlinks."""
    try:
        windows_path = PureWindowsPath(str(destination))
        if windows_path.drive.startswith("\\\\"):
            raise ReportError("The report destination must be a local path, not a network share.")
        path = Path(destination).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        if path.name in {"", ".", ".."}:
            raise ReportError("The report destination must be a file path.")
        if path.is_symlink():
            raise ReportError("The report destination must not be a symbolic link.")
        parent = path.parent
        if not parent.is_dir():
            raise ReportError("The report destination's parent directory must already exist.")
        if any(
            component.is_symlink() or component.is_junction()
            for component in (parent, *parent.parents)
        ):
            raise ReportError(
                "The report destination must not pass through a symbolic link or junction."
            )
        resolved_parent = parent.resolve(strict=True)
        resolved_path = resolved_parent / path.name
        if resolved_path.exists():
            if resolved_path.is_dir():
                raise ReportError("The report destination must not be a directory.")
            if not stat.S_ISREG(resolved_path.stat().st_mode):
                raise ReportError("The report destination must be a regular file.")

        if protected_target is not None:
            target = Path(protected_target).expanduser().resolve(strict=False)
            if target.is_dir():
                if resolved_path == target or target in resolved_path.parents:
                    raise ReportError("The report must be written outside the assessed directory.")
            elif resolved_path == target:
                raise ReportError("The report must not overwrite the assessed input file.")
        return resolved_path
    except ReportError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ReportError("The report destination could not be validated.") from None


def write_json_report(
    findings: Iterable[Finding],
    destination: str | Path,
    *,
    protected_target: str | Path | None = None,
) -> Path:
    """Atomically write a UTF-8 JSON report to a validated local regular file."""
    path = validate_report_destination(destination, protected_target=protected_target)
    serialized = serialize_json_report(findings)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as report_file:
            report_file.write(serialized)
            report_file.flush()
            os.fsync(report_file.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        return path
    except (OSError, UnicodeError):
        raise ReportError("The JSON report could not be written to the selected path.") from None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                raise ReportError("A temporary JSON report file could not be removed.") from None
