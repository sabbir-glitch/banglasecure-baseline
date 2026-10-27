"""Local secret scanning through the separately installed Gitleaks executable."""

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from banglasecure_baseline.findings import Finding, Severity

EXECUTION_TIMEOUT_SECONDS = 300
VERSION_TIMEOUT_SECONDS = 10
MINIMUM_GITLEAKS_VERSION = (8, 19, 0)
_VERSION_PATTERN = re.compile(r"(?:^|[^0-9])v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?")
_RULE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_COMMIT_PATTERN = re.compile(r"[a-fA-F0-9]{7,64}\Z")
_MAX_REPORT_BYTES = 50_000_000


class SecretScanError(Exception):
    """Base class for safe, user-facing Gitleaks scan failures."""


class InvalidTargetError(SecretScanError):
    """The selected target is not a supported local directory."""


class ScannerUnavailableError(SecretScanError):
    """Gitleaks is not installed or is not available on PATH."""


class UnsupportedScannerError(SecretScanError):
    """The installed Gitleaks version does not support the required commands."""


class ScannerTimeoutError(SecretScanError):
    """The Gitleaks scan exceeded its maximum execution time."""


class InvalidScanReportError(SecretScanError):
    """Gitleaks returned a missing, malformed, or inconsistent report."""


class ScannerExecutionError(SecretScanError):
    """Gitleaks could not complete the scan."""


def _validated_target(target: Path | str, *, include_git_history: bool) -> Path:
    try:
        path = Path(target).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise InvalidTargetError("Target must be an existing local directory.") from None

    if not path.is_dir():
        raise InvalidTargetError("Target must be an existing local directory.")
    if include_git_history and not (path / ".git").exists():
        raise InvalidTargetError("Git-history scanning requires the target to be a Git repository.")
    return path


def _scanner_path() -> str:
    scanner = shutil.which("gitleaks")
    if scanner is None:
        raise ScannerUnavailableError(
            "Gitleaks was not found on PATH. Install it separately, then retry; "
            "BanglaSecure will not install or download it."
        )
    return scanner


def _check_scanner_version(scanner: str) -> None:
    try:
        result = subprocess.run(
            [scanner, "version"],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=VERSION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise ScannerTimeoutError("Gitleaks version check timed out.") from None
    except OSError:
        raise ScannerExecutionError("Gitleaks could not be started.") from None

    if result.returncode != 0:
        raise ScannerExecutionError("Gitleaks version check failed.")

    version_text = f"{result.stdout}\n{result.stderr}"
    match = _VERSION_PATTERN.search(version_text)
    if match is None:
        raise UnsupportedScannerError(
            "Gitleaks version could not be identified; install a supported Gitleaks 8.x release."
        )
    version = tuple(int(part) for part in match.groups())
    if version < MINIMUM_GITLEAKS_VERSION or version[0] != 8:
        raise UnsupportedScannerError(
            "This command requires Gitleaks 8.19.0 or newer, before version 9."
        )


def _relative_location(value: object, target: Path) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise InvalidScanReportError("Gitleaks returned an invalid file location.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InvalidScanReportError("Gitleaks returned an invalid file location.")

    portable_value = value.replace("\\", "/")
    windows_path = PureWindowsPath(value)
    if windows_path.is_absolute() or windows_path.drive:
        try:
            absolute_path = Path(value).resolve(strict=False)
            relative = absolute_path.relative_to(target).as_posix()
        except (OSError, RuntimeError, ValueError):
            raise InvalidScanReportError(
                "Gitleaks returned an out-of-scope file location."
            ) from None
    else:
        relative = portable_value.removeprefix("./")

    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise InvalidScanReportError("Gitleaks returned an invalid file location.")
    return path.as_posix()


def _line_number(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    raise InvalidScanReportError(f"Gitleaks returned an invalid {field}.")


def _finding_id(
    rule_id: str,
    location: str,
    start_line: int | None,
    start_column: int | None,
    commit: str | None,
) -> str:
    identity = f"{rule_id}|{location}|{start_line}|{start_column}|{commit or ''}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return f"SECRET-{digest}"


def _finding(report_entry: object, target: Path) -> Finding:
    if not isinstance(report_entry, dict):
        raise InvalidScanReportError("Gitleaks returned an invalid finding entry.")

    rule_id = report_entry.get("RuleID")
    if not isinstance(rule_id, str) or _RULE_ID_PATTERN.fullmatch(rule_id) is None:
        raise InvalidScanReportError("Gitleaks returned an invalid rule identifier.")

    location = _relative_location(report_entry.get("File"), target)
    start_line = _line_number(report_entry.get("StartLine"), "start line")
    start_column = _line_number(report_entry.get("StartColumn"), "start column")
    commit_value = report_entry.get("Commit")
    commit = (
        commit_value
        if isinstance(commit_value, str) and _COMMIT_PATTERN.fullmatch(commit_value)
        else None
    )

    line_location = f"{location}:{start_line}" if start_line is not None else location
    return Finding(
        finding_id=_finding_id(rule_id, location, start_line, start_column, commit),
        title=f"Potential secret detected ({rule_id})",
        severity=Severity.UNASSESSED,
        category="secret",
        summary_en="Gitleaks detected a potential secret; the secret value was withheld.",
        summary_bn="Gitleaks সম্ভাব্য গোপন তথ্য শনাক্ত করেছে; গোপন মানটি প্রকাশ করা হয়নি।",
        safe_evidence=(
            f"Gitleaks rule {rule_id} matched this location. Secret values and matching "
            "source text are withheld."
        ),
        impact_en=(
            "If this is a genuine credential, it may allow unauthorised access to a system or data."
        ),
        impact_bn=("এটি প্রকৃত পরিচয়-তথ্য হলে কোনো সিস্টেম বা তথ্যে অননুমোদিত প্রবেশের সুযোগ হতে পারে।"),
        remediation_en=(
            "Verify the finding without sharing the secret. Revoke or rotate any genuine exposed "
            "credential, then remove it from the source and securely address its history."
        ),
        remediation_bn=(
            "গোপন মান প্রকাশ না করে ফলাফলটি যাচাই করুন। প্রকৃত উন্মুক্ত পরিচয়-তথ্য বাতিল বা "
            "পরিবর্তন করুন, তারপর সোর্স থেকে সরিয়ে ইতিহাসও নিরাপদভাবে সংশোধন করুন।"
        ),
        location=line_location,
    )


def _load_report(report_path: Path, target: Path) -> tuple[Finding, ...]:
    try:
        if not report_path.is_file():
            raise InvalidScanReportError("Gitleaks did not create a JSON report.")
        if report_path.stat().st_size > _MAX_REPORT_BYTES:
            raise InvalidScanReportError("Gitleaks JSON report exceeds the supported size.")
        report_text = report_path.read_text(encoding="utf-8")
        report = json.loads(report_text)
    except InvalidScanReportError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidScanReportError(
            "Gitleaks returned an unreadable or invalid JSON report."
        ) from None

    if not isinstance(report, list):
        raise InvalidScanReportError("Gitleaks returned an invalid JSON report structure.")
    return tuple(_finding(entry, target) for entry in report)


def scan_secrets(target: Path | str, *, include_git_history: bool = False) -> tuple[Finding, ...]:
    """Scan a local directory with Gitleaks without disclosing any secret values."""
    directory = _validated_target(target, include_git_history=include_git_history)
    scanner = _scanner_path()
    _check_scanner_version(scanner)

    mode = "git" if include_git_history else "dir"
    try:
        with tempfile.TemporaryDirectory(
            prefix="banglasecure-gitleaks-", dir=directory.parent
        ) as temp:
            temporary_directory = Path(temp)
            report_path = temporary_directory / "gitleaks-report.json"
            config_path = temporary_directory / "gitleaks-defaults.toml"
            config_path.write_text(
                'title = "BanglaSecure Gitleaks defaults"\n\n[extend]\nuseDefault = true\n',
                encoding="utf-8",
            )
            command = [
                scanner,
                mode,
                "--report-format=json",
                f"--report-path={report_path}",
                "--redact=100",
                f"--config={config_path}",
                "--no-banner",
                str(directory),
            ]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    check=False,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=EXECUTION_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                raise ScannerTimeoutError(
                    f"Gitleaks scan exceeded the {EXECUTION_TIMEOUT_SECONDS}-second timeout."
                ) from None
            except OSError:
                raise ScannerExecutionError("Gitleaks could not be started.") from None

            if result.returncode not in (0, 1):
                raise ScannerExecutionError(
                    f"Gitleaks failed with unexpected exit status {result.returncode}."
                )

            findings = _load_report(report_path, directory)
            if (result.returncode == 0 and findings) or (result.returncode == 1 and not findings):
                raise InvalidScanReportError(
                    "Gitleaks exit status did not match its reported findings."
                )
            return findings
    except OSError:
        raise ScannerExecutionError(
            "Temporary scan files could not be created or removed."
        ) from None
