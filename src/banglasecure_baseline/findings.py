"""Shared data models for BanglaSecure Baseline findings."""

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    """Supported severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNASSESSED = "unassessed"


@dataclass(frozen=True, slots=True)
class Finding:
    """Represent one security finding with bilingual remediation guidance.

    The safe_evidence field must contain redacted evidence.
    Raw credentials, tokens, passwords, and private keys must never
    be placed in this field.
    """

    finding_id: str
    title: str
    severity: Severity
    category: str
    summary_en: str
    summary_bn: str
    safe_evidence: str
    impact_en: str
    impact_bn: str
    remediation_en: str
    remediation_bn: str
    references: tuple[str, ...] = ()
    location: str | None = None

    def __post_init__(self) -> None:
        """Reject missing required text and empty reference entries."""
        required_text = {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "summary_en": self.summary_en,
            "summary_bn": self.summary_bn,
            "safe_evidence": self.safe_evidence,
            "impact_en": self.impact_en,
            "impact_bn": self.impact_bn,
            "remediation_en": self.remediation_en,
            "remediation_bn": self.remediation_bn,
        }

        for field_name, value in required_text.items():
            if not value.strip():
                raise ValueError(f"{field_name} must not be empty.")

        for reference in self.references:
            if not reference.strip():
                raise ValueError("References must not contain empty entries.")

        if self.location is not None and not self.location.strip():
            raise ValueError("Location must be None or non-empty.")
