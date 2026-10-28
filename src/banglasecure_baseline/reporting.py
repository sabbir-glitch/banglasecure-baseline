"""Deterministic JSON reporting for BanglaSecure Baseline findings."""

import ctypes
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote, urlsplit

from banglasecure_baseline.findings import Finding, Severity

SCHEMA_VERSION = "1.0"
TOOL_NAME = "BanglaSecure Baseline"
REPORT_FORMAT = "banglasecure-json"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_LINE_SUFFIX = re.compile(r"^(.*):([1-9][0-9]*)$")
_DRIVE_UNKNOWN = 0
_DRIVE_NO_ROOT_DIR = 1
_DRIVE_REMOTE = 4


class ReportError(Exception):
    """A JSON report could not be validated or written safely."""


def _is_windows() -> bool:
    return os.name == "nt"


def _windows_drive_type(drive_root: str) -> int:
    try:
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint
        return int(get_drive_type(drive_root))
    except (AttributeError, OSError):
        raise ReportError("The report destination drive could not be verified.") from None


def _is_mapped_network_drive(drive: str) -> bool:
    if not _is_windows():
        return False

    drive_type = _windows_drive_type(f"{drive}\\")
    if drive_type in {_DRIVE_UNKNOWN, _DRIVE_NO_ROOT_DIR}:
        raise ReportError("The report destination drive could not be verified.")
    return drive_type == _DRIVE_REMOTE


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


def _sarif_level(severity: str) -> str:
    if severity in {Severity.CRITICAL.value, Severity.HIGH.value}:
        return "error"
    if severity == Severity.MEDIUM.value:
        return "warning"
    return "note"


def _sarif_property_location(location: str | None) -> str | None:
    if location is None:
        return None
    try:
        parsed = urlsplit(location)
    except ValueError:
        raise ReportError("A finding contains an invalid SARIF location.") from None
    if parsed.scheme and "://" in location:
        return location if parsed.scheme in {"http", "https", "dns"} else None

    relative_path = location
    line_match = _LINE_SUFFIX.fullmatch(location)
    if line_match is not None:
        relative_path = line_match.group(1)
        try:
            parsed = urlsplit(relative_path)
        except ValueError:
            raise ReportError("A finding contains an invalid SARIF location.") from None
    windows_path = PureWindowsPath(relative_path)
    posix_path = PurePosixPath(relative_path)
    if windows_path.is_absolute() or windows_path.drive or posix_path.is_absolute():
        return None
    if parsed.scheme or parsed.netloc:
        return None
    return location


def _sarif_file_location(location: str | None, category: str) -> dict[str, object] | None:
    if location is None or category == "web-configuration":
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in location):
        return None
    relative_path = location
    start_line: int | None = None
    line_match = _LINE_SUFFIX.fullmatch(location)
    if line_match is not None:
        relative_path, line_text = line_match.groups()
        start_line = int(line_text)

    try:
        parsed = urlsplit(relative_path)
    except ValueError:
        raise ReportError("A finding contains an invalid SARIF location.") from None
    if parsed.scheme or parsed.netloc:
        return None

    windows_path = PureWindowsPath(relative_path)
    posix_path = PurePosixPath(relative_path)
    if (
        not relative_path
        or windows_path.is_absolute()
        or windows_path.drive
        or posix_path.is_absolute()
        or any(part in {"", ".", ".."} for part in posix_path.parts)
    ):
        return None

    physical_location: dict[str, object] = {
        "artifactLocation": {"uri": quote(posix_path.as_posix(), safe="/-._~")}
    }
    if start_line is not None:
        physical_location["region"] = {"startLine": start_line}
    return {"physicalLocation": physical_location}


def serialize_sarif_report(findings: Iterable[Finding]) -> str:
    """Serialize Finding objects as deterministic SARIF 2.1.0."""
    validated = json.loads(serialize_json_report(findings))
    finding_data = validated["findings"]
    finding_data.sort(
        key=lambda finding: (
            finding["finding_id"],
            finding["location"] or "",
            finding["title"],
            json.dumps(finding, ensure_ascii=False, sort_keys=True),
        )
    )
    rules_by_id: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in finding_data:
        finding_id = finding["finding_id"]
        category = finding["category"]
        severity = finding["severity"]
        references = finding["references"]
        property_location = _sarif_property_location(finding["location"])
        rule: dict[str, object] = {
            "id": finding_id,
            "name": category,
            "shortDescription": {"text": finding["title"]},
            "fullDescription": {"text": finding["summary_en"]},
            "help": {
                "text": finding["remediation_en"],
                "markdown": f"{finding['remediation_en']}\n\n{finding['remediation_bn']}",
            },
            "properties": {
                "category": category,
                "severity": severity,
                "summary_bn": finding["summary_bn"],
                "impact_en": finding["impact_en"],
                "impact_bn": finding["impact_bn"],
                "remediation_bn": finding["remediation_bn"],
                "references": references,
            },
        }
        if references:
            rule["helpUri"] = references[0]
        existing_rule = rules_by_id.get(finding_id)
        if existing_rule is not None and existing_rule != rule:
            raise ReportError(
                "Findings with the same identifier contain conflicting SARIF metadata."
            )
        rules_by_id[finding_id] = rule

        result: dict[str, object] = {
            "ruleId": finding_id,
            "level": _sarif_level(severity),
            "message": {"text": finding["summary_en"]},
            "properties": {
                "finding_id": finding_id,
                "title": finding["title"],
                "severity": severity,
                "category": category,
                "summary_en": finding["summary_en"],
                "summary_bn": finding["summary_bn"],
                "safe_evidence": finding["safe_evidence"],
                "impact_en": finding["impact_en"],
                "impact_bn": finding["impact_bn"],
                "remediation_en": finding["remediation_en"],
                "remediation_bn": finding["remediation_bn"],
                "references": references,
                "location": property_location,
            },
        }
        result_location = _sarif_file_location(property_location, category)
        if result_location is not None:
            result["locations"] = [result_location]
        results.append(result)

    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "rules": [rules_by_id[rule_id] for rule_id in sorted(rules_by_id)],
            }
        },
        "results": results,
    }
    sarif: dict[str, object] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
    try:
        return json.dumps(sarif, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except (TypeError, ValueError):
        raise ReportError("The findings could not be serialized as SARIF.") from None


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
        if windows_path.drive and _is_mapped_network_drive(windows_path.drive):
            raise ReportError("The report destination must be a local path, not a network drive.")
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


def _write_report_content(
    content: str,
    destination: str | Path,
    *,
    protected_target: str | Path | None = None,
) -> Path:
    path = validate_report_destination(destination, protected_target=protected_target)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as report_file:
            report_file.write(content)
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


def write_json_report(
    findings: Iterable[Finding],
    destination: str | Path,
    *,
    protected_target: str | Path | None = None,
) -> Path:
    """Atomically write a UTF-8 JSON report to a validated local regular file."""
    serialized = serialize_json_report(findings)
    return _write_report_content(serialized, destination, protected_target=protected_target)


def write_sarif_report(
    findings: Iterable[Finding],
    destination: str | Path,
    *,
    protected_target: str | Path | None = None,
) -> Path:
    """Atomically write a UTF-8 SARIF report to a validated local regular file."""
    serialized = serialize_sarif_report(findings)
    return _write_report_content(serialized, destination, protected_target=protected_target)
