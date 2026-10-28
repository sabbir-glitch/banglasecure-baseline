# Changelog

## 0.1.0

### Added

- Python dependency vulnerability auditing through `pip-audit`, with explicit
  `--allow-advisory-network` consent before advisory and package-index queries.
- Local Gitleaks-based secret scanning with redacted findings and optional
  Git-history scanning.
- Authorized web configuration checks for HTTPS/TLS, selected security
  headers, and SPF/DMARC DNS records, protected by DNS ownership verification
  and explicit network consent.
- Structured findings with text, versioned JSON, and SARIF 2.1.0 reporting.
- English and Bangla summaries, impact descriptions, and remediation guidance
  where provided by the implemented findings.
- GitHub Actions quality checks on Python 3.12 and 3.13, including building
  distribution artifacts and smoke-testing the installed wheel and CLI in an
  isolated environment.

BanglaSecure Baseline is a limited security baseline, not a comprehensive
security assessment, and does not prove that an application or system is
secure.
