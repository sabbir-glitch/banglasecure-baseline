"""Dependency vulnerability auditing through the installed pip-audit scanner."""

import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from banglasecure_baseline.findings import Finding, Severity

EXECUTION_TIMEOUT_SECONDS = 300
_PACKAGE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z")
_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}\Z")
_ADVISORY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}\Z")
_GHSA_PATTERN = re.compile(
    r"GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}\Z"
)
_PYSEC_PATTERN = re.compile(r"PYSEC-\d{4}-\d+\Z")


class DependencyAuditError(Exception):
    """Base class for safe, user-facing dependency-audit failures."""


class InvalidTargetError(DependencyAuditError):
    """The selected target is not a supported dependency manifest."""


class NetworkConsentError(DependencyAuditError):
    """The operator did not permit external advisory and package-index queries."""


class ScannerUnavailableError(DependencyAuditError):
    """The pip-audit executable for the current Python environment is missing."""


class ScannerTimeoutError(DependencyAuditError):
    """The dependency audit exceeded its maximum execution time."""


class InvalidAuditReportError(DependencyAuditError):
    """The scanner returned malformed or inconsistent JSON output."""


class ScannerExecutionError(DependencyAuditError):
    """The scanner could not complete the audit successfully."""


def _scanner_path() -> Path:
    executable = "pip-audit.exe" if os.name == "nt" else "pip-audit"
    return Path(sys.executable).parent / executable


def _validated_target(target: Path | str) -> tuple[Path, str, bool]:
    try:
        path = Path(target).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise InvalidTargetError(
            "Target must be a readable project directory or requirements*.txt file."
        ) from None

    if path.is_dir():
        manifest = path / "pyproject.toml"
        if not manifest.is_file():
            raise InvalidTargetError("Project directories must contain a supported pyproject.toml.")
        try:
            with manifest.open("rb") as project_file:
                project_data = tomllib.load(project_file)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            raise InvalidTargetError("The project's pyproject.toml is not valid TOML.") from None
        if not isinstance(project_data, dict):
            raise InvalidTargetError("The project's pyproject.toml has an invalid structure.")
        project = project_data.get("project")
        if not isinstance(project, dict):
            raise InvalidTargetError(
                "The project's pyproject.toml must define a supported PEP 621 [project] table."
            )
        dependencies = project.get("dependencies")
        dynamic = project.get("dynamic", [])
        if (
            not isinstance(dynamic, list)
            or any(not isinstance(field, str) for field in dynamic)
            or "dependencies" in dynamic
        ):
            raise InvalidTargetError(
                "Dependencies must be statically declared in pyproject.toml; "
                "use an explicit requirements*.txt file otherwise."
            )
        if dependencies is not None and (
            not isinstance(dependencies, list)
            or any(
                not isinstance(dependency, str) or not dependency.strip()
                for dependency in dependencies
            )
        ):
            raise InvalidTargetError("The project's dependency declarations are invalid.")
        return path, "pyproject.toml", True

    if (
        path.is_file()
        and path.name.lower().startswith("requirements")
        and path.name.lower().endswith(".txt")
    ):
        return path, path.name, False

    raise InvalidTargetError(
        "Target must be a project directory with pyproject.toml or a requirements*.txt file."
    )


def _safe_string(value: object, pattern: re.Pattern[str]) -> str | None:
    if isinstance(value, str) and pattern.fullmatch(value):
        return value
    return None


def _references(identifiers: tuple[str, ...]) -> tuple[str, ...]:
    references: list[str] = []
    for identifier in identifiers:
        if _CVE_PATTERN.fullmatch(identifier):
            reference = f"https://nvd.nist.gov/vuln/detail/{identifier}"
        elif _GHSA_PATTERN.fullmatch(identifier):
            reference = f"https://github.com/advisories/{identifier}"
        elif _PYSEC_PATTERN.fullmatch(identifier):
            reference = f"https://osv.dev/vulnerability/{identifier}"
        else:
            continue
        if reference not in references:
            references.append(reference)
    return tuple(references)


def _finding(
    dependency_name: str,
    version: str,
    advisory_id: str,
    aliases: tuple[str, ...],
    fix_versions: tuple[str, ...],
    location: str,
) -> Finding:
    identity = f"{dependency_name.casefold()}|{version}|{advisory_id}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    alias_text = f"; aliases: {', '.join(aliases)}" if aliases else ""
    fix_text = f"; fixed versions: {', '.join(fix_versions)}" if fix_versions else ""
    fix_guidance_en = (
        f" Upgrade to one of these fixed versions: {', '.join(fix_versions)}."
        if fix_versions
        else " Check the advisory for a maintained, non-affected version."
    )
    fix_guidance_bn = (
        f" সমাধানকৃত সংস্করণগুলোর একটিতে আপডেট করুন: {', '.join(fix_versions)}।"
        if fix_versions
        else " পরামর্শটি দেখে রক্ষণাবেক্ষণাধীন নিরাপদ সংস্করণ নির্বাচন করুন।"
    )

    return Finding(
        finding_id=f"DEP-{digest}",
        title=f"Vulnerable dependency: {dependency_name} {version} ({advisory_id})",
        severity=Severity.UNASSESSED,
        category="dependency",
        summary_en=(f"{dependency_name} {version} is listed in advisory {advisory_id}."),
        summary_bn=(
            f"{dependency_name} {version} সংস্করণটি {advisory_id} নিরাপত্তা পরামর্শে উল্লেখ করা হয়েছে।"
        ),
        safe_evidence=(
            f"Package: {dependency_name}=={version}; advisory: {advisory_id}{alias_text}{fix_text}."
        ),
        impact_en="The affected dependency may expose applications using it to a known risk.",
        impact_bn="এই দুর্বল নির্ভরতা ব্যবহারকারী অ্যাপ্লিকেশন পরিচিত ঝুঁকিতে পড়তে পারে।",
        remediation_en="Review the advisory and update the dependency." + fix_guidance_en,
        remediation_bn="নিরাপত্তা পরামর্শটি পর্যালোচনা করে নির্ভরতাটি আপডেট করুন।" + fix_guidance_bn,
        references=_references((advisory_id, *aliases)),
        location=location,
    )


def _parse_report(stdout: str, location: str) -> tuple[Finding, ...]:
    try:
        report = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        raise InvalidAuditReportError("pip-audit returned invalid JSON.") from None

    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise InvalidAuditReportError("pip-audit returned an invalid report structure.")

    findings: list[Finding] = []
    for dependency in report["dependencies"]:
        if not isinstance(dependency, dict):
            raise InvalidAuditReportError("pip-audit returned an invalid dependency entry.")
        name = _safe_string(dependency.get("name"), _PACKAGE_NAME_PATTERN)
        version = _safe_string(dependency.get("version"), _VERSION_PATTERN)
        vulnerabilities = dependency.get("vulns")
        if name is None or version is None or not isinstance(vulnerabilities, list):
            raise InvalidAuditReportError("pip-audit returned invalid dependency fields.")

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise InvalidAuditReportError("pip-audit returned an invalid advisory entry.")
            advisory_id = _safe_string(vulnerability.get("id"), _ADVISORY_PATTERN)
            aliases_data = vulnerability.get("aliases", [])
            fix_versions_data = vulnerability.get("fix_versions", [])
            if (
                advisory_id is None
                or not isinstance(aliases_data, list)
                or not isinstance(fix_versions_data, list)
            ):
                raise InvalidAuditReportError("pip-audit returned invalid advisory fields.")

            aliases = tuple(_safe_string(alias, _ADVISORY_PATTERN) or "" for alias in aliases_data)
            fix_versions = tuple(
                _safe_string(fix_version, _VERSION_PATTERN) or ""
                for fix_version in fix_versions_data
            )
            if any(not value for value in (*aliases, *fix_versions)):
                raise InvalidAuditReportError("pip-audit returned invalid advisory details.")
            findings.append(_finding(name, version, advisory_id, aliases, fix_versions, location))

    return tuple(findings)


def audit_dependencies(
    target: Path | str, *, allow_advisory_network: bool = False
) -> tuple[Finding, ...]:
    """Audit a supported dependency manifest without changing the assessed project.

    External advisory and package-index queries are made by pip-audit only after
    explicit operator consent. Subprocess output is parsed internally and never
    included in error messages.
    """
    manifest_path, location, is_project = _validated_target(target)
    if not allow_advisory_network:
        raise NetworkConsentError(
            "Dependency auditing requires external advisory and package-index queries. "
            "Re-run with --allow-advisory-network only if you consent."
        )

    scanner = _scanner_path()
    if not scanner.is_file():
        raise ScannerUnavailableError(
            "pip-audit is not installed in the current Python environment."
        )

    command = [
        str(scanner),
        "--format=json",
        "--strict",
        "--desc=off",
        "--aliases=on",
        "--progress-spinner=off",
        "--timeout=30",
    ]
    command.extend([str(manifest_path)] if is_project else ["--requirement", str(manifest_path)])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=EXECUTION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise ScannerTimeoutError(
            f"pip-audit exceeded the {EXECUTION_TIMEOUT_SECONDS}-second execution limit."
        ) from None
    except OSError:
        raise ScannerExecutionError("pip-audit could not be started.") from None

    if result.returncode not in (0, 1):
        raise ScannerExecutionError(
            f"pip-audit failed with unexpected exit status {result.returncode}."
        )

    findings = _parse_report(result.stdout, location)
    if (result.returncode == 0 and findings) or (result.returncode == 1 and not findings):
        raise InvalidAuditReportError(
            "pip-audit's exit status did not match its reported vulnerability results."
        )
    return findings
