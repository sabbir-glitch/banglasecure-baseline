"""Command-line interface for BanglaSecure Baseline."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version

import typer

from banglasecure_baseline.dependency_audit import DependencyAuditError, audit_dependencies

app = typer.Typer(
    help="Affordable security checks. Clear fixes. Safer systems.",
    no_args_is_help=True,
)


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
            "Consent to external vulnerability-advisory and package-index queries. "
            "Package names and versions may be sent to those services."
        ),
    ),
) -> None:
    """Audit dependencies; this check does not prove that an application is secure."""
    try:
        findings = audit_dependencies(target, allow_advisory_network=allow_advisory_network)
    except DependencyAuditError as error:
        typer.echo(f"Dependency audit failed: {error}", err=True)
        raise typer.Exit(code=2) from None

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


if __name__ == "__main__":
    app()
