"""Command-line interface for BanglaSecure Baseline."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path

import typer

from banglasecure_baseline.dependency_audit import DependencyAuditError, audit_dependencies
from banglasecure_baseline.findings import Finding
from banglasecure_baseline.reporting import (
    ReportError,
    serialize_json_report,
    validate_report_destination,
    write_json_report,
)
from banglasecure_baseline.secret_scan import SecretScanError, scan_secrets
from banglasecure_baseline.web_check import (
    WebCheckError,
    check_web_configuration,
    generate_verification_token,
)

app = typer.Typer(
    help="Affordable security checks. Clear fixes. Safer systems.",
    no_args_is_help=True,
)


def _prepare_report_output(
    report_format: str,
    output: str | None,
    protected_target: str | None,
) -> tuple[str, Path | None]:
    if report_format not in {"text", "json"}:
        raise ReportError("Report format must be either 'text' or 'json'.")
    if output is None:
        return report_format, None
    if report_format != "json":
        raise ReportError("--output can be used only with --format json.")
    return report_format, validate_report_destination(output, protected_target=protected_target)


def _emit_json_report(
    findings: tuple[Finding, ...],
    output: Path | None,
    protected_target: str | None,
) -> None:
    if output is None:
        typer.echo(serialize_json_report(findings), nl=False)
        return
    report_path = write_json_report(findings, output, protected_target=protected_target)
    typer.echo(f"JSON report written to {report_path}.")


@app.callback()
def main() -> None:
    """Run non-invasive, authorised security baseline checks."""


@app.command()
def version() -> None:
    """Display the installed BanglaSecure Baseline version."""
    try:
        installed_version = package_version("banglasecure-baseline")
    except PackageNotFoundError:
        installed_version = "unknown"

    typer.echo(f"BanglaSecure Baseline {installed_version}")


@app.command("dependency-audit")
def dependency_audit(
    target: str = typer.Argument(
        ...,
        help="Project directory with pyproject.toml or an explicit requirements*.txt file.",
    ),
    allow_advisory_network: bool = typer.Option(
        False,
        "--allow-advisory-network",
        help=(
            "Package names and versions may be sent to external advisory and package-index "
            "services; explicit consent is required."
        ),
    ),
    report_format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text (default) or json.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        help="Write a JSON report to this local file; requires --format json.",
    ),
) -> None:
    """Audit dependencies; this check does not prove that an application is secure."""
    try:
        report_format, output_path = _prepare_report_output(report_format, output, target)
    except ReportError as error:
        typer.echo(f"Dependency audit failed: {error}", err=True)
        raise typer.Exit(code=2) from None
    try:
        findings = audit_dependencies(target, allow_advisory_network=allow_advisory_network)
    except DependencyAuditError as error:
        typer.echo(f"Dependency audit failed: {error}", err=True)
        raise typer.Exit(code=2) from None

    if report_format == "json":
        try:
            _emit_json_report(findings, output_path, target)
        except ReportError as error:
            typer.echo(f"Dependency audit report failed: {error}", err=True)
            raise typer.Exit(code=2) from None
        if findings:
            raise typer.Exit(code=1)
        return

    if not findings:
        typer.echo("Dependency audit completed: no known vulnerabilities were reported.")
        return

    typer.echo(f"Dependency audit found {len(findings)} vulnerability advisory(s):")
    for finding in findings:
        typer.echo(f"- {finding.title}")
        typer.echo(f"  Severity: {finding.severity.value}")
        typer.echo(f"  Evidence: {finding.safe_evidence}")
        if finding.references:
            typer.echo(f"  References: {', '.join(finding.references)}")
    raise typer.Exit(code=1)


@app.command("secret-scan")
def secret_scan(
    target: str = typer.Argument(
        ...,
        help=(
            "Explicit local directory to scan; assess only directories you are authorised to scan."
        ),
    ),
    include_git_history: bool = typer.Option(
        False,
        "--include-git-history",
        help="Also scan the target Git repository's commit history.",
    ),
    report_format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text (default) or json.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        help="Write a JSON report to this local file; requires --format json.",
    ),
) -> None:
    """Scan local files for potential secrets without displaying secret values."""
    try:
        report_format, output_path = _prepare_report_output(report_format, output, target)
    except ReportError as error:
        typer.echo(f"Secret scan failed: {error}", err=True)
        raise typer.Exit(code=2) from None
    try:
        findings = scan_secrets(target, include_git_history=include_git_history)
    except SecretScanError as error:
        typer.echo(f"Secret scan failed: {error}", err=True)
        raise typer.Exit(code=2) from None

    if report_format == "json":
        try:
            _emit_json_report(findings, output_path, target)
        except ReportError as error:
            typer.echo(f"Secret scan report failed: {error}", err=True)
            raise typer.Exit(code=2) from None
        if findings:
            raise typer.Exit(code=1)
        return

    if not findings:
        typer.echo("Secret scan completed: Gitleaks reported no potential secrets.")
        return

    typer.echo(f"Secret scan found {len(findings)} potential finding(s):")
    for finding in findings:
        typer.echo(f"- {finding.title}")
        typer.echo(f"  Severity: {finding.severity.value}")
        typer.echo(f"  Location: {finding.location}")
        typer.echo(f"  Evidence: {finding.safe_evidence}")
    raise typer.Exit(code=1)


@app.command("web-verification-token")
def web_verification_token(
    domain: str = typer.Argument(..., help="Public domain name to verify ownership of."),
) -> None:
    """Generate a local DNS TXT challenge; no DNS lookup or change is performed."""
    try:
        record_name, token = generate_verification_token(domain)
    except WebCheckError as error:
        typer.echo(f"Verification token generation failed: {error}", err=True)
        raise typer.Exit(code=2) from None

    typer.echo("Publish this DNS TXT record to prove control of the domain:")
    typer.echo(f"Name: {record_name}")
    typer.echo(f"Value: {token}")
    typer.echo("This command generated a challenge; DNS verification has not occurred.")


@app.command("web-check")
def web_check(
    domain: str = typer.Argument(..., help="Public domain you are authorised to assess."),
    verification_token: str = typer.Option(
        ...,
        "--verification-token",
        help="Token from the matching _banglasecure-verification DNS TXT record.",
        prompt=False,
        hide_input=True,
    ),
    allow_network: bool = typer.Option(
        False,
        "--allow-network",
        help="Consent to DNS and HTTPS requests to the verified target domain.",
    ),
    report_format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text (default) or json.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        help="Write a JSON report to this local file; requires --format json.",
    ),
) -> None:
    """Check selected DNS and HTTPS configuration for a verified public domain."""
    try:
        report_format, output_path = _prepare_report_output(report_format, output, None)
    except ReportError as error:
        typer.echo(f"Web assessment failed: {error}", err=True)
        raise typer.Exit(code=2) from None
    try:
        findings = check_web_configuration(
            domain,
            verification_token=verification_token,
            allow_network=allow_network,
        )
    except WebCheckError as error:
        typer.echo(f"Web assessment failed: {error}", err=True)
        raise typer.Exit(code=2) from None

    if report_format == "json":
        try:
            _emit_json_report(findings, output_path, None)
        except ReportError as error:
            typer.echo(f"Web assessment report failed: {error}", err=True)
            raise typer.Exit(code=2) from None
        if findings:
            raise typer.Exit(code=1)
        return

    if not findings:
        typer.echo("Web configuration checks completed without reportable findings.")
        return

    typer.echo(f"Web configuration checks reported {len(findings)} finding(s):")
    for finding in findings:
        typer.echo(f"- {finding.title}")
        typer.echo(f"  Severity: {finding.severity.value}")
        typer.echo(f"  Location: {finding.location}")
        typer.echo(f"  Evidence: {finding.safe_evidence}")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
