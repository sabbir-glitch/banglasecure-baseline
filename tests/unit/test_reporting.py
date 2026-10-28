"""Tests for deterministic JSON report serialization and safe file handling."""

import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from banglasecure_baseline import reporting
from banglasecure_baseline.findings import Finding, Severity
from banglasecure_baseline.reporting import (
    REPORT_FORMAT,
    SCHEMA_VERSION,
    TOOL_NAME,
    ReportError,
    serialize_json_report,
    validate_report_destination,
    write_json_report,
)


def _finding(
    severity: Severity = Severity.UNASSESSED,
    *,
    location: str | None = "requirements.txt:1",
    references: tuple[str, ...] = ("https://example.org/advisory",),
) -> Finding:
    return Finding(
        finding_id=f"TEST-{severity.value}",
        title='Test "finding" — পরীক্ষা',
        severity=severity,
        category="test",
        summary_en="English summary with \n a newline.",
        summary_bn="বাংলা সারাংশ।",
        safe_evidence="Synthetic, redacted evidence.",
        impact_en="English impact.",
        impact_bn="বাংলা প্রভাব।",
        remediation_en="English remediation.",
        remediation_bn="বাংলা প্রতিকার।",
        references=references,
        location=location,
    )


def test_empty_findings_serialize_to_versioned_report() -> None:
    serialized = serialize_json_report(())

    assert json.loads(serialized) == {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "format": REPORT_FORMAT,
        "findings": [],
    }


@pytest.mark.parametrize("severity", list(Severity))
def test_one_finding_preserves_fields_and_severity(severity: Severity) -> None:
    finding = _finding(severity, references=("https://one.example", "https://two.example"))

    report = json.loads(serialize_json_report((finding,)))
    result = report["findings"][0]

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["tool"] == TOOL_NAME
    assert report["format"] == REPORT_FORMAT
    assert result == {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": severity.value,
        "category": finding.category,
        "summary_en": finding.summary_en,
        "summary_bn": finding.summary_bn,
        "safe_evidence": finding.safe_evidence,
        "impact_en": finding.impact_en,
        "impact_bn": finding.impact_bn,
        "remediation_en": finding.remediation_en,
        "remediation_bn": finding.remediation_bn,
        "references": ["https://one.example", "https://two.example"],
        "location": finding.location,
    }


def test_multiple_findings_keep_input_order() -> None:
    findings = (_finding(Severity.LOW), _finding(Severity.HIGH))

    report = json.loads(serialize_json_report(findings))

    assert [finding["severity"] for finding in report["findings"]] == ["low", "high"]


def test_json_round_trip_preserves_bangla_and_punctuation() -> None:
    finding = _finding()
    parsed = json.loads(serialize_json_report((finding,)))

    assert "বাংলা সারাংশ।" in parsed["findings"][0]["summary_bn"]
    assert parsed["findings"][0]["title"] == finding.title
    assert "\\u09" not in serialize_json_report((finding,))
    assert "\\n" in serialize_json_report((finding,))


def test_missing_location_is_serialized_as_null() -> None:
    report = json.loads(serialize_json_report((_finding(location=None),)))

    assert report["findings"][0]["location"] is None


def test_invalid_or_nonserializable_finding_values_are_rejected() -> None:
    finding = _finding()
    object.__setattr__(finding, "title", object())

    with pytest.raises(ReportError, match="invalid field value"):
        serialize_json_report((finding,))


def test_invalid_utf8_surrogate_text_is_rejected_before_output() -> None:
    finding = _finding()
    object.__setattr__(finding, "title", "invalid-\ud800")

    with pytest.raises(ReportError, match="not valid UTF-8"):
        serialize_json_report((finding,))


def test_non_finding_items_are_rejected() -> None:
    with pytest.raises(ReportError, match="only Finding"):
        serialize_json_report((object(),))  # type: ignore[arg-type]


def test_write_report_uses_utf8_and_preserves_bangla(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"

    result = write_json_report((_finding(),), destination)
    content = destination.read_bytes()

    assert result == destination
    assert "বাংলা".encode() in content
    assert json.loads(content.decode("utf-8"))["findings"][0]["summary_bn"] == "বাংলা সারাংশ।"


def test_atomic_replace_keeps_existing_report_until_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = tmp_path / "report.json"
    destination.write_text("old report", encoding="utf-8")
    real_replace = os.replace
    replace = Mock(
        side_effect=lambda source, target: (
            pytest.fail("Existing report changed before atomic replace.")
            if destination.read_text(encoding="utf-8") != "old report"
            else real_replace(source, target)
        )
    )
    monkeypatch.setattr("banglasecure_baseline.reporting.os.replace", replace)

    write_json_report((_finding(),), destination)

    replace.assert_called_once()
    assert json.loads(destination.read_text(encoding="utf-8"))["findings"]


def test_failed_atomic_replace_cleans_temporary_file_and_preserves_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = tmp_path / "report.json"
    destination.write_text("existing", encoding="utf-8")
    monkeypatch.setattr(
        "banglasecure_baseline.reporting.os.replace",
        Mock(side_effect=OSError("private operating system detail")),
    )

    with pytest.raises(ReportError, match="could not be written"):
        write_json_report((_finding(),), destination)

    assert destination.read_text(encoding="utf-8") == "existing"
    assert list(tmp_path.iterdir()) == [destination]


def test_mapped_windows_network_drive_is_rejected_without_accessing_the_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drive_type = Mock(return_value=4)
    monkeypatch.setattr("banglasecure_baseline.reporting._is_windows", lambda: True)
    monkeypatch.setattr("banglasecure_baseline.reporting._windows_drive_type", drive_type)

    with pytest.raises(ReportError, match="local path, not a network drive"):
        validate_report_destination(r"R:\reports\report.json")

    drive_type.assert_called_once_with("R:\\")


def test_missing_windows_api_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(reporting.ctypes, "windll", raising=False)

    with pytest.raises(ReportError, match="drive could not be verified"):
        reporting._windows_drive_type("R:\\")


@pytest.mark.parametrize("drive_type", [2, 3, 5, 6])
def test_local_windows_drive_types_are_not_classified_as_network_drives(
    monkeypatch: pytest.MonkeyPatch,
    drive_type: int,
) -> None:
    get_drive_type = Mock(return_value=drive_type)
    monkeypatch.setattr("banglasecure_baseline.reporting._is_windows", lambda: True)
    monkeypatch.setattr(
        "banglasecure_baseline.reporting._windows_drive_type",
        get_drive_type,
    )

    assert not reporting._is_mapped_network_drive("C:")
    get_drive_type.assert_called_once_with("C:\\")


@pytest.mark.parametrize("drive_type", [0, 1])
def test_unknown_windows_drive_type_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    drive_type: int,
) -> None:
    monkeypatch.setattr("banglasecure_baseline.reporting._is_windows", lambda: True)
    monkeypatch.setattr(
        "banglasecure_baseline.reporting._windows_drive_type",
        Mock(return_value=drive_type),
    )

    with pytest.raises(ReportError, match="drive could not be verified"):
        validate_report_destination(r"R:\reports\report.json")


@pytest.mark.parametrize(
    "destination_kind",
    ["directory", "missing-parent", "symlink", "junction", "network-share"],
)
def test_invalid_report_destinations_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    destination_kind: str,
) -> None:
    if destination_kind == "directory":
        destination = tmp_path
    elif destination_kind == "missing-parent":
        destination = tmp_path / "missing" / "report.json"
    elif destination_kind == "junction":
        junction_directory = tmp_path / "junction"
        junction_directory.mkdir()
        destination = junction_directory / "report.json"

        def is_junction(path: Path) -> bool:
            return path == junction_directory

        monkeypatch.setattr(Path, "is_junction", is_junction)
    else:
        if destination_kind == "symlink":
            target = tmp_path / "target.json"
            target.write_text("do not replace", encoding="utf-8")
            destination = tmp_path / "link.json"
            try:
                destination.symlink_to(target)
            except (OSError, NotImplementedError):
                pytest.skip("Symbolic links are unavailable in this environment.")
        else:
            destination = r"\\example-share\reports\report.json"

    with pytest.raises(ReportError):
        validate_report_destination(destination)


def test_report_cannot_overwrite_assessed_input_or_enter_assessed_directory(
    tmp_path: Path,
) -> None:
    assessed = tmp_path / "assessed"
    assessed.mkdir()
    source = assessed / "requirements.txt"
    source.write_text("example==1.0", encoding="utf-8")

    with pytest.raises(ReportError, match="outside the assessed directory"):
        validate_report_destination(assessed / "report.json", protected_target=assessed)
    with pytest.raises(ReportError, match="must not overwrite"):
        validate_report_destination(source, protected_target=source)


def test_report_writing_does_not_modify_unrelated_source_file(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("unchanged", encoding="utf-8")
    before = source.read_bytes()

    write_json_report((_finding(),), tmp_path / "report.json", protected_target=source)

    assert source.read_bytes() == before
