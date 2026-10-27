# BanglaSecure Baseline

**Affordable security checks. Clear fixes. Safer systems.**

BanglaSecure Baseline is an open-source cybersecurity assessment toolkit
designed to make selected defensive security checks more accessible to
small organisations in Bangladesh.

## Project status

Early development. Dependency auditing and local secret scanning are
implemented; the other capabilities listed below are planned and are not
currently available.

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

## Implemented: secret scanning

Gitleaks is a separate executable and is not installed by BanglaSecure. On
Windows, download a supported Gitleaks 8.x release from the
[official Gitleaks releases](https://github.com/gitleaks/gitleaks/releases),
verify it using the release's published checksums, and add the directory
containing `gitleaks.exe` to `PATH`. Confirm that `gitleaks version` works in
the terminal used to run BanglaSecure. BanglaSecure requires Gitleaks 8.19.0
or newer, before version 9, and reports a clear error if it is unavailable or
unsupported; it never downloads or installs the scanner.

Scan current files in an explicitly selected local directory:

```powershell
banglasecure secret-scan .\path\to\project
```

Add `--include-git-history` to also inspect Git history:

```powershell
banglasecure secret-scan .\path\to\repository --include-git-history
```

File scanning checks the current directory tree; it does not inspect old
commits. Git-history scanning requires a Git repository and checks historical
content as well. Scans have a five-minute timeout. Missing executables,
unsupported scanner versions, malformed reports, timeouts, and scanner
failures return a distinct non-zero status and are not reported as clean
scans. Findings also return a non-zero status for CI.

BanglaSecure asks Gitleaks to redact reports completely and writes the JSON
report and an explicit default-rules configuration to a temporary directory
outside the target. It captures scanner output, parses only safe metadata,
never displays raw `Secret` or `Match` fields, and removes temporary files
after success or failure. Repository-provided Gitleaks configuration is not
used: the scanner is explicitly given its default rules so a repository
configuration cannot silently disable checks. Source files, credentials,
repository archives, and scan reports are not uploaded or saved as BanglaSecure
reports. The scan does not modify the assessed repository.

A finding indicates a possible secret, not that a credential is genuine or
still valid. Verify it without copying or sharing the value. If it is a
genuine exposed credential, revoke or rotate it; deleting the source line
alone does not invalidate the credential or remove it from Git history.
Only scan directories and repositories you own or are explicitly authorised
to assess. Gitleaks applies detector-specific matching and entropy thresholds;
low-entropy placeholders or synthetic strings may not match a default rule.
A clean result is not proof that no secrets are present.

## Planned capabilities

- Non-invasive HTTPS, TLS, HTTP security-header, and selected DNS checks.
- JSON and SARIF reports.
- GitHub Actions integration.

## Security and privacy

The tool is intended for repositories and infrastructure that the operator
owns or is explicitly authorised to assess.

The design prioritises local processing, redacted findings, explicit scope,
and reproducible checks.

Scan results and repository contents are not uploaded to a central BanglaSecure
service. Dependency auditing is an exception to fully offline operation:
after consent, pip-audit can send dependency names and versions to external
advisory and package-index services as part of auditing and dependency
resolution. Secret scanning is local; BanglaSecure captures Gitleaks output
and temporarily writes a report outside the assessed directory, then deletes
the temporary files. BanglaSecure does not send source files, archives,
credentials, environment variables, or complete reports.

BanglaSecure Baseline cannot prove that a system is secure and does not
replace a comprehensive security assessment.

## Development requirements

- Python 3.12 or newer.
- Git.
- Windows, Linux, or macOS.

## License

MIT License. See LICENSE.
