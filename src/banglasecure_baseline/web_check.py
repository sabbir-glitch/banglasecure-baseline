"""Authorised, non-invasive DNS and HTTPS configuration checks."""

import email.parser
import email.policy
import hashlib
import ipaddress
import secrets
import socket
import ssl
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

import dns.exception
import dns.resolver
import idna

from banglasecure_baseline.findings import Finding, Severity

DNS_QUERY_TIMEOUT_SECONDS = 2.0
DNS_LIFETIME_SECONDS = 4.0
CONNECT_TIMEOUT_SECONDS = 5.0
OVERALL_TIMEOUT_SECONDS = 20.0
CERTIFICATE_WARNING_DAYS = 30
_TOKEN_LENGTH = 43
_TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
_INTERNAL_SUFFIXES = frozenset(
    {
        "arpa",
        "example",
        "home",
        "internal",
        "invalid",
        "lan",
        "local",
        "localhost",
        "onion",
        "test",
    }
)
_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Frame-Options",
)


class WebCheckError(Exception):
    """Base class for safe, user-facing web-check failures."""


class InvalidDomainError(WebCheckError):
    """The supplied target is not a public DNS hostname."""


class VerificationError(WebCheckError):
    """The DNS ownership challenge could not be established."""


class NetworkConsentError(WebCheckError):
    """Explicit network consent was not supplied."""


class DNSCheckError(WebCheckError):
    """A DNS operation failed or returned malformed data."""


class UnsafeAddressError(WebCheckError):
    """The target resolves to an address that is not globally routable."""


class HTTPSCheckError(WebCheckError):
    """The pinned HTTPS check could not be completed safely."""


class TLSCertificateError(Exception):
    """The pinned TLS endpoint rejected certificate validation."""

    def __init__(self, verify_code: int | None) -> None:
        self.verify_code = verify_code
        super().__init__("TLS certificate validation failed.")


class Resolver(Protocol):
    """Small resolver interface to keep DNS behavior deterministic in tests."""

    timeout: float
    lifetime: float

    def resolve(self, qname: str, rdtype: str, *, lifetime: float) -> object:
        """Resolve one DNS record type."""


@runtime_checkable
class TXTRecord(Protocol):
    """TXT record interface exposed by dnspython."""

    strings: Sequence[bytes]


@runtime_checkable
class AddressRecord(Protocol):
    """A/AAAA record interface exposed by dnspython."""

    address: str


@dataclass(frozen=True, slots=True)
class HTTPSResponse:
    """Safe metadata read from one HTTPS response."""

    status: int
    headers: tuple[str, ...]
    has_csp_frame_ancestors: bool
    certificate_not_after: str


def normalize_domain(domain: str) -> str:
    """Validate and IDNA-normalize a public DNS hostname without network access."""
    if not isinstance(domain, str) or not domain or domain != domain.strip():
        raise InvalidDomainError("Supply a hostname only, without a URL or surrounding spaces.")
    if any(character in domain for character in "/\\@:#?[]%") or "*" in domain:
        raise InvalidDomainError(
            "Supply a hostname only; URLs, ports, IP literals, and wildcards are not allowed."
        )
    if any(ord(character) < 33 or ord(character) == 127 for character in domain):
        raise InvalidDomainError("The hostname contains invalid characters.")

    candidate = domain[:-1] if domain.endswith(".") else domain
    if not candidate or candidate.endswith("."):
        raise InvalidDomainError("The hostname is malformed.")
    try:
        normalized = idna.encode(candidate, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError:
        raise InvalidDomainError("The hostname is malformed.") from None

    labels = normalized.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise InvalidDomainError("Supply a fully qualified public domain name.")
    if len(normalized) > 253:
        raise InvalidDomainError("The hostname is too long.")
    if labels[-1] in _INTERNAL_SUFFIXES or all(label.isdecimal() for label in labels):
        raise InvalidDomainError("Local and special-use hostnames are not allowed.")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise InvalidDomainError("IP-literal targets are not allowed.")
    return normalized


def generate_verification_token(domain: str) -> tuple[str, str]:
    """Generate a high-entropy DNS token locally, without performing DNS."""
    normalized = normalize_domain(domain)
    return f"_banglasecure-verification.{normalized}", secrets.token_urlsafe(32)


def _new_resolver() -> Resolver:
    try:
        resolver = dns.resolver.Resolver(configure=True)
    except (OSError, dns.exception.DNSException):
        raise DNSCheckError("The system DNS resolver could not be configured.") from None
    resolver.timeout = DNS_QUERY_TIMEOUT_SECONDS
    resolver.lifetime = DNS_LIFETIME_SECONDS
    nameservers = resolver.nameservers
    if not nameservers:
        raise DNSCheckError("No DNS nameserver is configured for this assessment.")
    resolver.nameservers = nameservers[:1]
    resolver.retry_servfail = False
    return resolver


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DNSCheckError("The web assessment exceeded its overall time limit.")
    return remaining


def _resolve(
    resolver: Resolver,
    qname: str,
    rdtype: str,
    deadline: float,
    *,
    allow_no_answer: bool = False,
) -> object | None:
    lifetime = min(DNS_LIFETIME_SECONDS, _remaining(deadline))
    try:
        absolute_qname = qname if qname.endswith(".") else f"{qname}."
        return resolver.resolve(absolute_qname, rdtype, lifetime=lifetime)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        if allow_no_answer:
            return None
        raise VerificationError("The DNS verification record was not found.") from None
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        raise DNSCheckError("A DNS query timed out or could not be completed.") from None
    except dns.exception.DNSException:
        raise DNSCheckError("A DNS query failed.") from None


def _txt_records(answer: object | None) -> tuple[str, ...]:
    if answer is None:
        return ()
    records: list[str] = []
    try:
        for record in _iter_records(answer):
            if not isinstance(record, TXTRecord):
                raise DNSCheckError("DNS returned a malformed TXT record.")
            chunks = record.strings
            if not chunks:
                raise DNSCheckError("DNS returned a malformed TXT record.")
            if any(not isinstance(chunk, bytes) for chunk in chunks):
                raise DNSCheckError("DNS returned a malformed TXT record.")
            records.append(b"".join(chunks).decode("utf-8"))
    except (AttributeError, TypeError, UnicodeDecodeError):
        raise DNSCheckError("DNS returned a malformed TXT answer.") from None
    return tuple(records)


def _iter_records(answer: object) -> Iterator[object]:
    if not isinstance(answer, Iterable):
        raise DNSCheckError("DNS returned a malformed answer.")
    return iter(answer)


def _verify_challenge(resolver: Resolver, domain: str, token: str, deadline: float) -> None:
    if len(token) != _TOKEN_LENGTH or any(character not in _TOKEN_ALPHABET for character in token):
        raise VerificationError("The verification token is malformed.")
    answers = _resolve(
        resolver,
        f"_banglasecure-verification.{domain}",
        "TXT",
        deadline,
    )
    if not any(secrets.compare_digest(record, token) for record in _txt_records(answers)):
        raise VerificationError("The DNS verification token does not match.")


def _address_value(record: object, version: int) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        if not isinstance(record, AddressRecord):
            raise AttributeError
        value = ipaddress.ip_address(record.address)
    except (AttributeError, ValueError):
        raise DNSCheckError("DNS returned a malformed address record.") from None
    expected_version = 4 if version == 4 else 6
    if value.version != expected_version:
        raise DNSCheckError("DNS returned an address in the wrong record family.")
    return value


def _resolved_addresses(
    resolver: Resolver, domain: str, deadline: float
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for record_type, version in (("A", 4), ("AAAA", 6)):
        answer = _resolve(
            resolver,
            domain,
            record_type,
            deadline,
            allow_no_answer=True,
        )
        if answer is None:
            continue
        try:
            for record in _iter_records(answer):
                address = _address_value(record, version)
                checked_address = (
                    address.ipv4_mapped
                    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
                    else address
                )
                routable = (
                    checked_address.is_global
                    and not checked_address.is_private
                    and not checked_address.is_loopback
                    and not checked_address.is_link_local
                    and not checked_address.is_multicast
                    and not checked_address.is_reserved
                    and not checked_address.is_unspecified
                )
                if not routable:
                    raise UnsafeAddressError(
                        "The domain resolves to a non-public IP address; assessment was refused."
                    )
                addresses.append(address)
        except TypeError:
            raise DNSCheckError("DNS returned a malformed address answer.") from None

    if not addresses:
        raise DNSCheckError("The domain has no usable A or AAAA address records.")
    return tuple(addresses)


def _has_frame_ancestors_directive(policy: str) -> bool:
    for directive in policy.split(";"):
        parts = directive.strip().split(None, 1)
        if parts and parts[0].casefold() == "frame-ancestors":
            return True
    return False


def _pinned_https_get(
    domain: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    deadline: float,
) -> HTTPSResponse:
    raw_socket: socket.socket | None = None
    tls_socket: ssl.SSLSocket | None = None
    try:
        raw_socket = socket.create_connection(
            (str(address), 443),
            timeout=min(CONNECT_TIMEOUT_SECONDS, _remaining(deadline)),
        )
        raw_socket.settimeout(min(CONNECT_TIMEOUT_SECONDS, _remaining(deadline)))
        context = ssl.create_default_context()
        tls_socket = context.wrap_socket(raw_socket, server_hostname=domain)
        certificate = tls_socket.getpeercert()
        if not isinstance(certificate, dict):
            raise HTTPSCheckError("The TLS certificate expiry could not be read.")
        not_after = certificate.get("notAfter")
        if not isinstance(not_after, str):
            raise HTTPSCheckError("The TLS certificate expiry could not be read.")

        request = (
            f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: BanglaSecureBaseline/0.1\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        tls_socket.settimeout(min(CONNECT_TIMEOUT_SECONDS, _remaining(deadline)))
        tls_socket.sendall(request.encode("ascii"))
        raw_headers = bytearray()
        while b"\r\n\r\n" not in raw_headers:
            tls_socket.settimeout(min(CONNECT_TIMEOUT_SECONDS, _remaining(deadline)))
            chunk = tls_socket.recv(4096)
            if not chunk:
                raise HTTPSCheckError("The HTTPS endpoint closed before sending response headers.")
            raw_headers.extend(chunk)
            if len(raw_headers) > 65_536:
                raise HTTPSCheckError("The HTTPS response headers exceeded the supported size.")

        header_bytes, _, _body_prefix = raw_headers.partition(b"\r\n\r\n")
        status_line, separator, header_lines = header_bytes.partition(b"\r\n")
        if not separator:
            raise HTTPSCheckError("The HTTPS endpoint returned malformed response headers.")
        try:
            status_parts = status_line.decode("ascii").split(" ", 2)
            if (
                len(status_parts) < 2
                or not status_parts[0].startswith("HTTP/")
                or len(status_parts[1]) != 3
                or not status_parts[1].isdigit()
            ):
                raise ValueError
            status = int(status_parts[1])
            parsed_headers = email.parser.BytesHeaderParser(policy=email.policy.HTTP).parsebytes(
                header_lines + b"\r\n\r\n"
            )
        except (UnicodeDecodeError, ValueError):
            raise HTTPSCheckError(
                "The HTTPS endpoint returned malformed response headers."
            ) from None
        if parsed_headers.defects:
            raise HTTPSCheckError("The HTTPS endpoint returned malformed response headers.")
        safe_headers: list[str] = []
        security_header_names = {header.casefold() for header in _SECURITY_HEADERS}
        has_csp_frame_ancestors = False
        for name, value in parsed_headers.items():
            header_name = name.casefold()
            if header_name in security_header_names:
                safe_headers.append(name)
            if header_name == "content-security-policy" and _has_frame_ancestors_directive(value):
                has_csp_frame_ancestors = True
        return HTTPSResponse(
            status=status,
            headers=tuple(safe_headers),
            has_csp_frame_ancestors=has_csp_frame_ancestors,
            certificate_not_after=not_after,
        )
    except ssl.SSLCertVerificationError as error:
        raise TLSCertificateError(error.verify_code) from None
    except HTTPSCheckError:
        raise
    except (OSError, ssl.SSLError, ValueError, DNSCheckError):
        raise HTTPSCheckError("The pinned HTTPS request could not be completed.") from None
    finally:
        if tls_socket is not None:
            tls_socket.close()
        elif raw_socket is not None:
            raw_socket.close()


def _finding(
    check_id: str,
    title: str,
    summary_en: str,
    summary_bn: str,
    evidence: str,
    impact_en: str,
    impact_bn: str,
    remediation_en: str,
    remediation_bn: str,
    location: str,
    reference: str,
) -> Finding:
    digest = hashlib.sha256(f"{check_id}|{location}".encode()).hexdigest()[:16]
    return Finding(
        finding_id=f"WEB-{digest}",
        title=title,
        severity=Severity.UNASSESSED,
        category="web-configuration",
        summary_en=summary_en,
        summary_bn=summary_bn,
        safe_evidence=evidence,
        impact_en=impact_en,
        impact_bn=impact_bn,
        remediation_en=remediation_en,
        remediation_bn=remediation_bn,
        references=(reference,),
        location=location,
    )


def _missing_header_finding(domain: str, header: str) -> Finding:
    guidance = {
        "Strict-Transport-Security": (
            "Use HSTS to instruct browsers to use HTTPS for this domain.",
            "এই ডোমেইনে HTTPS ব্যবহারে ব্রাউজারকে নির্দেশ দিতে HSTS ব্যবহার করুন।",
        ),
        "Content-Security-Policy": (
            "Define a Content Security Policy appropriate for the application.",
            "অ্যাপ্লিকেশনের উপযোগী Content Security Policy নির্ধারণ করুন।",
        ),
        "X-Content-Type-Options": (
            "Set X-Content-Type-Options to nosniff where compatible.",
            "সামঞ্জস্যপূর্ণ হলে X-Content-Type-Options-এ nosniff সেট করুন।",
        ),
        "Referrer-Policy": (
            "Set a Referrer-Policy that limits unnecessary referrer disclosure.",
            "অপ্রয়োজনীয় রেফারার তথ্য প্রকাশ সীমিত করতে Referrer-Policy সেট করুন।",
        ),
        "Permissions-Policy": (
            "Restrict browser features that the application does not need.",
            "অ্যাপ্লিকেশনের অপ্রয়োজনীয় ব্রাউজার ফিচার সীমিত করুন।",
        ),
        "X-Frame-Options": (
            "Use X-Frame-Options or CSP frame-ancestors to control framing.",
            "ফ্রেমে প্রদর্শন নিয়ন্ত্রণে X-Frame-Options অথবা CSP frame-ancestors ব্যবহার করুন।",
        ),
    }
    remediation_en, remediation_bn = guidance[header]
    return _finding(
        f"header-{header.casefold()}",
        f"HTTP security header is absent: {header}",
        f"The HTTPS response does not include {header}.",
        f"HTTPS প্রতিক্রিয়ায় {header} হেডারটি নেই।",
        f"Response header absent: {header}. Header values and response content were not retained.",
        "Browser protections associated with this header may not be applied.",
        "এই হেডারের সঙ্গে সম্পর্কিত ব্রাউজার সুরক্ষা কার্যকর নাও হতে পারে।",
        remediation_en,
        remediation_bn,
        f"https://{domain}/",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    )


def _tls_finding(domain: str, *, expired: bool) -> Finding:
    if expired:
        title = "TLS certificate is expired"
        evidence = (
            "TLS validation rejected an expired certificate. HTTP security-header checks "
            "were not performed because the connection was not trusted."
        )
        summary_en = f"The HTTPS endpoint for {domain} presented an expired TLS certificate."
        summary_bn = f"{domain} HTTPS এন্ডপয়েন্টে মেয়াদোত্তীর্ণ TLS সার্টিফিকেট পাওয়া গেছে।"
        impact_en = "Browsers cannot establish a trusted HTTPS connection to the domain."
        impact_bn = "ব্রাউজার ডোমেইনটির সঙ্গে বিশ্বস্ত HTTPS সংযোগ স্থাপন করতে পারে না।"
        remediation_en = "Renew and deploy a valid certificate for the domain."
        remediation_bn = "ডোমেইনের জন্য বৈধ সার্টিফিকেট নবায়ন করে স্থাপন করুন।"
    else:
        title = "TLS certificate validation failed"
        evidence = (
            "TLS certificate validation failed; certificate details were not trusted. "
            "HTTP security-header checks were not performed because the connection was not trusted."
        )
        summary_en = f"The HTTPS endpoint for {domain} did not pass TLS certificate validation."
        summary_bn = f"{domain} HTTPS এন্ডপয়েন্ট TLS সার্টিফিকেট যাচাইয়ে উত্তীর্ণ হয়নি।"
        impact_en = "Clients may be unable to verify the identity of the HTTPS endpoint."
        impact_bn = "ক্লায়েন্ট HTTPS এন্ডপয়েন্টের পরিচয় যাচাই করতে ব্যর্থ হতে পারে।"
        remediation_en = "Correct the certificate chain, validity, and hostname coverage."
        remediation_bn = "সার্টিফিকেট চেইন, মেয়াদ এবং হোস্টনেম কভারেজ ঠিক করুন।"
    return _finding(
        "tls-certificate",
        title,
        summary_en,
        summary_bn,
        evidence,
        impact_en,
        impact_bn,
        remediation_en,
        remediation_bn,
        f"https://{domain}/",
        "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
    )


def _certificate_expiry_finding(domain: str, not_after: str) -> Finding | None:
    try:
        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=UTC)
    except (OverflowError, OSError, ValueError):
        raise HTTPSCheckError("The TLS certificate expiry metadata was malformed.") from None
    now = datetime.now(UTC)
    if expires_at <= now or expires_at - now > timedelta(days=CERTIFICATE_WARNING_DAYS):
        return None
    date_text = expires_at.date().isoformat()
    return _finding(
        "tls-certificate-expiry",
        "TLS certificate expires soon",
        f"The validated TLS certificate expires on {date_text}.",
        f"যাচাইকৃত TLS সার্টিফিকেটটির মেয়াদ {date_text} তারিখে শেষ হবে।",
        f"Certificate expiry date: {date_text}.",
        "An expired certificate will prevent clients from establishing trusted HTTPS.",
        "সার্টিফিকেটের মেয়াদ শেষ হলে ক্লায়েন্ট বিশ্বস্ত HTTPS সংযোগ করতে পারবে না।",
        "Renew the certificate before its expiry date.",
        "মেয়াদ শেষ হওয়ার আগে সার্টিফিকেট নবায়ন করুন।",
        f"https://{domain}/",
        "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
    )


def _header_findings(domain: str, response: HTTPSResponse) -> tuple[Finding, ...]:
    headers = {name.casefold() for name in response.headers}
    missing: list[str] = []
    for header in _SECURITY_HEADERS:
        if header.casefold() not in headers:
            if header != "X-Frame-Options":
                missing.append(header)
            elif not response.has_csp_frame_ancestors:
                missing.append(header)
    return tuple(_missing_header_finding(domain, header) for header in missing)


def _dns_record_finding(domain: str, *, record_name: str, record_type: str) -> Finding:
    is_spf = record_type == "SPF"
    title = "SPF record is absent" if is_spf else "DMARC record is absent"
    summary_en = f"No {record_type} TXT record was found for {record_name}."
    summary_bn = f"{record_name}-এ কোনো {record_type} TXT রেকর্ড পাওয়া যায়নি।"
    if is_spf:
        evidence = f"No TXT record beginning v=spf1 was found for {record_name}."
        remediation_en = "Publish an SPF policy listing authorised mail senders."
        remediation_bn = "অনুমোদিত মেইল প্রেরকদের উল্লেখ করে SPF নীতি প্রকাশ করুন।"
    else:
        evidence = f"No TXT record beginning v=DMARC1 was found for {record_name}."
        remediation_en = "Publish a DMARC policy after reviewing SPF and DKIM alignment."
        remediation_bn = "SPF ও DKIM সামঞ্জস্য পর্যালোচনা করে DMARC নীতি প্রকাশ করুন।"
    return _finding(
        f"dns-{record_type.casefold()}",
        title,
        summary_en,
        summary_bn,
        evidence,
        "Mail receivers may have less information for detecting spoofed mail.",
        "জাল ইমেইল শনাক্ত করতে মেইল গ্রহণকারীদের কাছে কম তথ্য থাকতে পারে।",
        remediation_en,
        remediation_bn,
        f"dns://{record_name}/TXT",
        "https://www.rfc-editor.org/rfc/rfc7208"
        if is_spf
        else "https://www.rfc-editor.org/rfc/rfc7489",
    )


def _mail_dns_findings(resolver: Resolver, domain: str, deadline: float) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    records = (
        (domain, "SPF", "v=spf1"),
        (f"_dmarc.{domain}", "DMARC", "v=DMARC1"),
    )
    for record_name, record_type, prefix in records:
        answer = _resolve(
            resolver,
            record_name,
            "TXT",
            deadline,
            allow_no_answer=True,
        )
        txt_records = _txt_records(answer)
        if not any(record.casefold().startswith(prefix.casefold()) for record in txt_records):
            findings.append(
                _dns_record_finding(
                    domain,
                    record_name=record_name,
                    record_type=record_type,
                )
            )
    return tuple(findings)


def _validate_token_argument(token: str | None) -> str:
    if token is None:
        raise VerificationError("A DNS verification token is required.")
    if len(token) != _TOKEN_LENGTH or any(character not in _TOKEN_ALPHABET for character in token):
        raise VerificationError("The verification token is malformed.")
    return token


def check_web_configuration(
    domain: str,
    *,
    verification_token: str | None,
    allow_network: bool,
) -> tuple[Finding, ...]:
    """Run bounded, verified DNS and HTTPS checks for a verified public domain."""
    normalized_domain = normalize_domain(domain)
    token = _validate_token_argument(verification_token)
    if not allow_network:
        raise NetworkConsentError(
            "Remote DNS and HTTPS checks require the explicit --allow-network option."
        )

    deadline = time.monotonic() + OVERALL_TIMEOUT_SECONDS
    resolver = _new_resolver()
    _verify_challenge(resolver, normalized_domain, token, deadline)
    addresses = _resolved_addresses(resolver, normalized_domain, deadline)

    findings: list[Finding] = []
    try:
        response = _pinned_https_get(
            normalized_domain,
            addresses[0],
            deadline,
        )
    except TLSCertificateError as error:
        findings.append(_tls_finding(normalized_domain, expired=error.verify_code == 10))
    except HTTPSCheckError:
        raise
    else:
        if 300 <= response.status < 400:
            raise HTTPSCheckError(
                "The HTTPS endpoint returned a redirect; redirects are not followed."
            )
        expiry_finding = _certificate_expiry_finding(
            normalized_domain,
            response.certificate_not_after,
        )
        if expiry_finding is not None:
            findings.append(expiry_finding)
        findings.extend(_header_findings(normalized_domain, response))

    findings.extend(_mail_dns_findings(resolver, normalized_domain, deadline))
    return tuple(findings)
