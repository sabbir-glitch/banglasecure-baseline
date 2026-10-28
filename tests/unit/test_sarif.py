"""Tests for safe, deterministic SARIF 2.1.0 reporting."""

import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from banglasecure_baseline import secret_scan
from banglasecure_baseline.findings import Finding, Severity
from banglasecure_baseline.reporting import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    ReportError,
    serialize_sarif_report,
    validate_report_destination,
    write_sarif_report,
)


def _finding(
    finding_id: str = "WEB-header-policy",
    *,
    severity: Severity = Severity.UNASSESSED,
    category: str = "web-configuration",
    location: str | None = "https://example.org/",
    references: tuple[str, ...] = ("https://one.example/ref", "https://two.example/ref"),
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title='Security configuration "finding" — পরীক্ষা',
        severity=severity,
        category=category,
        summary_en="Configuration needs review.\nValue stays safely escaped.",
        summary_bn="নিরাপত্তা কনফিগারেশন পর্যালোচনা করুন।",
        safe_evidence="Only safe, synthetic evidence.",
        impact_en="The configuration may expose users to risk.",
        impact_bn="কনফিগারেশন ব্যবহারকারীদের ঝুঁকিতে ফেলতে পারে।",
        remediation_en="Apply a suitable configuration.",
        remediation_bn="উপযুক্ত কনফিগারেশন প্রয়োগ করুন।",
        references=references,
        location=location,
    )


def _document(*findings: Finding) -> dict[str, object]:
    return json.loads(serialize_sarif_report(findings))


def test_empty_sarif_document_has_required_version_and_empty_arrays() -> None:
    document = _document()

    assert document["$schema"] == SARIF_SCHEMA
    assert document["version"] == SARIF_VERSION
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "BanglaSecure Baseline"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_single_result_maps_finding_and_rule_metadata() -> None:
    finding = _finding()

    document = _document(finding)
    run = document["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    result = run["results"][0]

    assert rule["id"] == finding.finding_id
    assert rule["name"] == finding.category
    assert rule["shortDescription"]["text"] == finding.title
    assert rule["fullDescription"]["text"] == finding.summary_en
    assert rule["help"]["text"] == finding.remediation_en
    assert finding.remediation_bn in rule["help"]["markdown"]
    assert rule["helpUri"] == finding.references[0]
    assert result["ruleId"] == finding.finding_id
    assert result["level"] == "note"
    assert result["message"]["text"] == finding.summary_en
    assert result["properties"]["safe_evidence"] == finding.safe_evidence
    assert result["properties"]["summary_bn"] == finding.summary_bn
    assert result["properties"]["impact_bn"] == finding.impact_bn
    assert result["properties"]["remediation_bn"] == finding.remediation_bn
    assert result["properties"]["references"] == list(finding.references)


def test_multiple_results_and_rules_are_sorted_deterministically() -> None:
    findings = (
        _finding("Z-FINDING", category="secret", location="src/z.py:9"),
        _finding("A-FINDING", category="dependency", location="requirements.txt"),
    )

    first = serialize_sarif_report(findings)
    second = serialize_sarif_report(findings)
    document = json.loads(first)

    assert first == second
    assert [rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]] == [
        "A-FINDING",
        "Z-FINDING",
    ]
    assert [result["ruleId"] for result in document["runs"][0]["results"]] == [
        "A-FINDING",
        "Z-FINDING",
    ]


def test_result_sort_order_is_stable_when_primary_keys_match() -> None:
    first = _finding("DUPLICATE", category="secret", location="src/app.py:3")
    second = Finding(
        finding_id="DUPLICATE",
        title=first.title,
        severity=first.severity,
        category=first.category,
        summary_en=first.summary_en,
        summary_bn=first.summary_bn,
        safe_evidence="Alternate safe evidence.",
        impact_en=first.impact_en,
        impact_bn=first.impact_bn,
        remediation_en=first.remediation_en,
        remediation_bn=first.remediation_bn,
        references=first.references,
        location=first.location,
    )

    assert serialize_sarif_report((first, second)) == serialize_sarif_report((second, first))


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
        (Severity.UNASSESSED, "note"),
    ],
)
def test_severity_maps_conservatively(severity: Severity, expected_level: str) -> None:
    result = _document(_finding(severity=severity))["runs"][0]["results"][0]

    assert result["level"] == expected_level
    assert result["properties"]["severity"] == severity.value


@pytest.mark.parametrize(
    ("location", "expected_uri", "expected_line"),
    [
        ("requirements.txt", "requirements.txt", None),
        ("app.py:3", "app.py", 3),
        ("src/app.py:12", "src/app.py", 12),
        ("src/unsafe name.py", "src/unsafe%20name.py", None),
    ],
)
def test_relative_file_locations_are_encoded_without_absolute_paths(
    location: str,
    expected_uri: str,
    expected_line: int | None,
) -> None:
    result = _document(_finding(category="secret", location=location))["runs"][0]["results"][0]
    physical_location = result["locations"][0]["physicalLocation"]

    assert physical_location["artifactLocation"]["uri"] == expected_uri
    assert not Path(physical_location["artifactLocation"]["uri"]).is_absolute()
    if expected_line is not None:
        assert physical_location["region"]["startLine"] == expected_line


def test_web_location_is_preserved_without_fabricated_file_location() -> None:
    finding = _finding(location="https://example.org/")

    result = _document(finding)["runs"][0]["results"][0]

    assert "locations" not in result
    assert result["properties"]["location"] == finding.location


@pytest.mark.parametrize("location", ["/private/home/project/app.py:5", r"C:\private\app.py:5"])
def test_absolute_local_locations_are_not_embedded_in_sarif(location: str) -> None:
    result = _document(_finding(category="secret", location=location))["runs"][0]["results"][0]

    assert "locations" not in result
    assert result["properties"]["location"] is None


@pytest.mark.parametrize("location", [None, "dns://example.org/TXT"])
def test_missing_or_dns_locations_do_not_fabricate_file_artifacts(location: str | None) -> None:
    result = _document(_finding(category="dependency", location=location))["runs"][0]["results"][0]

    assert "locations" not in result
    assert result["properties"]["location"] == location


def test_multiple_references_and_bangla_survive_sarif_json_round_trip() -> None:
    finding = _finding()
    serialized = serialize_sarif_report((finding,))
    result = json.loads(serialized)["runs"][0]["results"][0]

    assert result["properties"]["references"] == list(finding.references)
    assert finding.summary_bn in serialized
    assert "\\u09" not in serialized
    assert "\\n" in serialized


def test_duplicate_finding_identifier_with_conflicting_rule_data_is_rejected() -> None:
    first = _finding(finding_id="DUPLICATE")
    second = Finding(
        finding_id="DUPLICATE",
        title="Different rule title",
        severity=Severity.LOW,
        category="secret",
        summary_en="Different summary.",
        summary_bn="ভিন্ন সারাংশ।",
        safe_evidence="Safe evidence.",
        impact_en="Impact.",
        impact_bn="প্রভাব।",
        remediation_en="Fix.",
        remediation_bn="সমাধান।",
    )

    with pytest.raises(ReportError, match="conflicting SARIF metadata"):
        serialize_sarif_report((first, second))


def test_sarif_report_does_not_copy_synthetic_secret_or_scanner_fields() -> None:
    synthetic_secret = "ghp_synthetic_high_entropy_not_a_credential"
    finding = secret_scan._finding(
        {
            "RuleID": "github-pat",
            "File": "src/settings.py",
            "StartLine": 8,
            "Secret": synthetic_secret,
            "Match": f"token={synthetic_secret}",
        },
        Path("assessment"),
    )
    report = serialize_sarif_report((finding,))

    assert synthetic_secret not in report
    assert '"Secret"' not in report
    assert '"Match"' not in report
    assert "Secret values and matching source text are withheld." in report


def test_sarif_rejects_malformed_finding_values() -> None:
    finding = _finding()
    object.__setattr__(finding, "severity", "urgent")

    with pytest.raises(ReportError, match="unsupported severity"):
        serialize_sarif_report((finding,))


def test_malformed_location_is_rejected_without_traceback_details() -> None:
    finding = _finding(category="secret", location="//[malformed")

    with pytest.raises(ReportError, match="invalid SARIF location"):
        serialize_sarif_report((finding,))


def test_sarif_file_write_reuses_validation_atomic_replace_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = tmp_path / "report.sarif"
    destination.write_text("previous report", encoding="utf-8")
    real_replace = os.replace
    replace = Mock(
        side_effect=lambda source, target: (
            pytest.fail("Destination was changed before replacement.")
            if destination.read_text(encoding="utf-8") != "previous report"
            else real_replace(source, target)
        )
    )
    monkeypatch.setattr("banglasecure_baseline.reporting.os.replace", replace)

    result = write_sarif_report((_finding(),), destination)

    assert result == destination
    replace.assert_called_once()
    assert json.loads(destination.read_text(encoding="utf-8"))["version"] == SARIF_VERSION
    assert len(list(tmp_path.iterdir())) == 1


def test_sarif_file_error_cleans_temporary_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = tmp_path / "report.sarif"
    monkeypatch.setattr(
        "banglasecure_baseline.reporting.os.replace",
        Mock(side_effect=OSError("private file error")),
    )

    with pytest.raises(ReportError, match="could not be written"):
        write_sarif_report((_finding(),), destination)

    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_sarif_uses_shared_report_destination_validation(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="outside the assessed directory"):
        validate_report_destination(tmp_path / "report.sarif", protected_target=tmp_path)
