"""Tests for the shared security finding model."""

from dataclasses import FrozenInstanceError, replace

import pytest

from banglasecure_baseline.findings import (
    Finding,
    InvalidFindingSeverityError,
    Severity,
    findings_fail_severity_gate,
)


def sample_finding() -> Finding:
    """Create a safe example finding for unit tests."""
    return Finding(
        finding_id="DEPENDENCY-001",
        title="Potentially vulnerable dependency",
        severity=Severity.HIGH,
        category="dependency",
        summary_en="A dependency requires security review.",
        summary_bn="একটি সফটওয়্যার নির্ভরতার নিরাপত্তা পর্যালোচনা প্রয়োজন।",
        safe_evidence="Dependency identified; no credentials exposed.",
        impact_en="An affected dependency may expose the application to risk.",
        impact_bn="দুর্বল নির্ভরতা অ্যাপ্লিকেশনের জন্য ঝুঁকি তৈরি করতে পারে।",
        remediation_en="Review the advisory and update to a supported version.",
        remediation_bn="পরামর্শটি পর্যালোচনা করুন এবং সমর্থিত সংস্করণে আপডেট করুন।",
        references=("https://example.com/security-guidance",),
        location="requirements.txt",
    )


def test_finding_contains_expected_information() -> None:
    """A finding should retain its structured security information."""
    finding = sample_finding()

    assert finding.finding_id == "DEPENDENCY-001"
    assert finding.severity == Severity.HIGH
    assert finding.safe_evidence == "Dependency identified; no credentials exposed."
    assert finding.remediation_bn
    assert finding.references


def test_empty_finding_id_is_rejected() -> None:
    """A finding must have a non-empty identifier."""
    with pytest.raises(ValueError, match="finding_id must not be empty"):
        replace(sample_finding(), finding_id=" ")


def test_empty_reference_is_rejected() -> None:
    """A finding must not contain empty reference entries."""
    with pytest.raises(ValueError, match="References must not contain empty"):
        replace(sample_finding(), references=("",))


def test_finding_is_immutable() -> None:
    """A finding cannot be modified after construction."""
    finding = sample_finding()

    with pytest.raises(FrozenInstanceError):
        finding.title = "Changed title"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("severity", "minimum_severity", "expected"),
    [
        (Severity.CRITICAL, Severity.HIGH, True),
        (Severity.HIGH, Severity.HIGH, True),
        (Severity.MEDIUM, Severity.HIGH, False),
        (Severity.LOW, Severity.MEDIUM, False),
        (Severity.INFO, Severity.INFO, True),
        (Severity.UNASSESSED, Severity.CRITICAL, True),
    ],
)
def test_severity_gate_uses_explicit_order_and_fails_closed_for_unassessed(
    severity: Severity,
    minimum_severity: Severity,
    expected: bool,
) -> None:
    finding = replace(sample_finding(), severity=severity)

    assert findings_fail_severity_gate((finding,), minimum_severity) is expected


def test_severity_gate_preserves_fail_on_any_finding_by_default() -> None:
    assert findings_fail_severity_gate((), None) is False
    assert findings_fail_severity_gate((sample_finding(),), None) is True


def test_severity_gate_handles_multiple_findings() -> None:
    findings = (
        replace(sample_finding(), severity=Severity.INFO),
        replace(sample_finding(), finding_id="DEPENDENCY-002", severity=Severity.HIGH),
    )

    assert findings_fail_severity_gate(findings, Severity.MEDIUM) is True


@pytest.mark.parametrize("severity", [None, "high", object()])
def test_severity_gate_rejects_missing_or_unsupported_severity(severity: object) -> None:
    finding = sample_finding()
    object.__setattr__(finding, "severity", severity)

    with pytest.raises(InvalidFindingSeverityError, match="missing or unsupported"):
        findings_fail_severity_gate((finding,), Severity.HIGH)


def test_severity_gate_rejects_unsupported_threshold() -> None:
    with pytest.raises(InvalidFindingSeverityError, match="minimum severity"):
        findings_fail_severity_gate((sample_finding(),), "high")  # type: ignore[arg-type]
