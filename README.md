# BanglaSecure Baseline

**Affordable security checks. Clear fixes. Safer systems.**

BanglaSecure Baseline is an open-source cybersecurity assessment toolkit
designed to make selected defensive security checks more accessible to
small organisations in Bangladesh.

## Project status

Early development. The dependency-audit command is implemented; the other
capabilities listed below are planned and are not currently available.

## Implemented: dependency auditing

- Install the project and its optional scanner:

  ```powershell
  python -m pip install -e ".[security]"
  ```

- Audit a local Python project with a supported `pyproject.toml`:

  ```powershell
  banglasecure dependency-audit . --allow-advisory-network
  ```

- Or audit an explicitly selected `requirements*.txt` file:

  ```powershell
  banglasecure dependency-audit .\requirements.txt --allow-advisory-network
  ```

Dependency auditing requires the explicit `--allow-advisory-network` consent
flag. `pip-audit` queries external vulnerability-advisory services and may
query package-index services to resolve dependencies. Package names and
versions may therefore be sent to those services. Dependency resolution may
also download packages or invoke project build backends.

For `pyproject.toml`, the scanner audits the static PEP 621
`project.dependencies` list. Dynamically declared dependencies are rejected,
and optional dependency groups are not included; use a requirements file that
captures the intended dependency set when those are in scope.

BanglaSecure does not upload source files, repository archives, discovered
credentials, environment variables, or complete scan reports. Scanner output
is processed locally into findings. The assessment does not modify the
selected project or automatically update dependencies. A vulnerability result
causes a non-zero exit status, and scanner failures are reported as failures,
not clean scans. An audit reporting no known vulnerabilities does not prove
that an application or its dependencies are secure.

Only assess projects that you own or are explicitly authorised to assess.
Because dependency resolution can execute project build tooling, only audit
projects you trust sufficiently for that resolution process.

## Planned capabilities

- Secret detection using Gitleaks.
- Non-invasive HTTPS, TLS, HTTP security-header, and selected DNS checks.
- JSON and SARIF reports.
- GitHub Actions integration.

## Security and privacy

The tool is intended for repositories and infrastructure that the operator
owns or is explicitly authorised to assess. The dependency audit is the only
implemented assessment command at this stage.

The design prioritises local processing, redacted findings, explicit scope,
and reproducible checks.

Scan results and repository contents are not uploaded to a central BanglaSecure
service. Dependency auditing is an exception to fully offline operation:
after consent, pip-audit can send dependency names and versions to external
advisory and package-index services as part of auditing and dependency
resolution. BanglaSecure itself does not send source files, archives,
credentials, environment variables, or complete reports.

BanglaSecure Baseline cannot prove that a system is secure and does not
replace a comprehensive security assessment.

## Development requirements

- Python 3.12 or newer.
- Git.
- Windows, Linux, or macOS.

## License

MIT License. See LICENSE.
