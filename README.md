# BanglaSecure Baseline

**Affordable security checks. Clear fixes. Safer systems.**

BanglaSecure Baseline is an open-source cybersecurity assessment toolkit
designed to make selected defensive security checks more accessible to
small organisations in Bangladesh.
The installed console command is `banglasecure`.

## Project status

Project version 0.1.0. Dependency auditing, local secret scanning, and
authorised web configuration checks are implemented; the other capabilities
listed below are planned and are not currently available.

## Implemented: dependency auditing

- Install the project and its optional scanner:

  ```powershell
  # Run from the project checkout root.
  python -m pip install ".[security]"
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
repository archives, and scan reports are not uploaded. JSON reports are only
persisted as user-facing output when explicitly requested with `--format json`;
Gitleaks still creates a temporary internal JSON report during scanning, which
is removed after success or failure. See the reporting section below. The scan
does not modify the assessed repository.

A finding indicates a possible secret, not that a credential is genuine or
still valid. Verify it without copying or sharing the value. If it is a
genuine exposed credential, revoke or rotate it; deleting the source line
alone does not invalidate the credential or remove it from Git history.
Only scan directories and repositories you own or are explicitly authorised
to assess. Gitleaks applies detector-specific matching and entropy thresholds;
low-entropy placeholders or synthetic strings may not match a default rule.
A clean result is not proof that no secrets are present.

## Implemented: authorised web configuration checks

Only assess public domains for which you have explicit legal authorisation.
The DNS challenge below establishes control over a DNS record, but does not
establish the legal scope or permission for an assessment.

Generate a challenge locally:

```powershell
banglasecure web-verification-token example.org
```

This command makes no network request and does not change DNS. Publish the
exact TXT record name and token value it prints:

```text
_banglasecure-verification.example.org TXT "<generated-token>"
```

After the record is visible in DNS, run the explicitly consented assessment:

```powershell
banglasecure web-check example.org --verification-token "<generated-token>" --allow-network
```

The assessment refuses to start without a valid hostname, a matching
verification TXT record, and `--allow-network`. It checks A and AAAA
resolution, validated HTTPS/TLS, selected security headers (HSTS, CSP,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and framing
protection), and SPF/DMARC TXT records. It does not enumerate DKIM selectors,
follow redirects, crawl pages, submit forms, authenticate, modify the site,
or use a central scanning service.

DNS lookups have bounded per-query timeouts and the assessment has a finite
overall timeout. HTTPS connects to a previously resolved, globally routable
IP address while retaining the domain for SNI, certificate hostname
verification, and the HTTP Host header. Private, reserved, and other
non-global addresses are rejected. Redirects are not followed. TLS
certificate validation remains enabled. Response bodies and sensitive
response headers are not retained or displayed; findings contain check
metadata only. A certificate expiring within 30 days is reported as a
configuration finding. DNS verification, record lookups, and HTTPS/TLS checks
contact the target's DNS infrastructure or HTTPS endpoint.

The checks are a limited configuration baseline, not a penetration test and
not proof that a website is secure. Findings use unassessed severity unless a
specific observation supports a more precise classification. A failed check
is reported as an assessment failure rather than a clean result. Certificate
metadata is reported only when normal TLS certificate validation succeeds;
on validation failure, the scanner reports the failure without trusting or
retrieving unverified certificate metadata.

## Implemented: JSON reporting

All three scan commands retain human-readable text output by default. Select
`--format json` to write a UTF-8 JSON report to stdout:

```powershell
banglasecure dependency-audit . --allow-advisory-network --format json
banglasecure secret-scan .\path\to\project --format json
banglasecure web-check example.org --verification-token "<token>" --allow-network --format json
```

Use `--output PATH` with JSON or SARIF format to atomically write a local report file.
The parent directory must already exist; the destination must be a regular
file and must not be a network share, symbolic link, or a path through a
symbolic link or Windows junction. Existing regular files at the destination
are replaced atomically. BanglaSecure does not claim restrictive Windows file
permissions; protect report files according to your operating-system policy.

```powershell
banglasecure dependency-audit . --allow-advisory-network --format json --output .\audit.json
banglasecure secret-scan .\path\to\project --format json --output .\secrets.json
banglasecure web-check example.org --verification-token "<token>" --allow-network --format json --output .\web.json
```

Select `--format sarif` for a SARIF 2.1.0 report, written to stdout or to a
local file using `--output`:

```powershell
banglasecure secret-scan .\path\to\project --format sarif
banglasecure dependency-audit . --allow-advisory-network --format sarif --output .\audit.sarif
banglasecure web-check example.org --verification-token "<token>" --allow-network --format sarif --output .\web.sarif
```

SARIF maps finding identifiers to rule identifiers, preserves bilingual
remediation and references in result properties, and adds file locations only
when the finding contains a safe relative file path. Web and DNS findings do
not receive fabricated file locations. Severity maps conservatively to SARIF
levels; the original severity remains in the properties.

The JSON document uses schema version `1.0`, format identifier
`banglasecure-json`, and the tool name `BanglaSecure Baseline`. Its top-level
fields are `schema_version`, `tool`, `format`, and `findings`. Each finding
preserves the shared model fields: ID, title, severity, category, English and
Bangla summaries, safe evidence, English and Bangla impact and remediation,
references, and location. Field order is stable, and Bangla text is emitted
as UTF-8 without ASCII escaping. This versioned schema may evolve in a future
version.

JSON on stdout contains only the report document. File output prints a short
completion message separately. Exit status is `0` when the assessment
completed without findings, `1` when findings were reported, and `2` when
the assessment or report generation failed. JSON output does not bypass
`--allow-advisory-network`, DNS verification, or `--allow-network`.

Reports are local and are not uploaded by BanglaSecure. They can contain
dependency names and versions, secret finding locations, domain names, and
other sensitive infrastructure information. Review and protect them; do not
commit them to public repositories without reviewing their contents. Report
output must be outside an assessed scan directory and cannot overwrite the
selected manifest. Text mode does not create persistent, user-facing report
files. Secret scanning does create a temporary internal Gitleaks report during
execution and removes it afterward.

## Implemented: GitHub Actions quality workflow

The `.github/workflows/ci.yml` workflow runs on pushes and pull requests using
GitHub-hosted Linux runners and Python 3.12 and 3.13. It installs the project
and development dependencies, then runs Ruff linting, Ruff formatting checks,
pytest, and mypy. It builds both distribution formats, installs the wheel in a
fresh temporary virtual environment, and smoke-tests the installed
`banglasecure` command outside the source checkout. It uses read-only
repository permissions, does not persist checkout credentials, and does not
run remote security assessments, dependency advisory scans, or Gitleaks. The
workflow does not upload SARIF or create GitHub Code Scanning alerts.

## Planned capabilities

- SARIF upload to GitHub Code Scanning.

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
