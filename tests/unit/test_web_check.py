"""Tests for domain verification and safe web-configuration checks."""

import ipaddress
import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from banglasecure_baseline import web_check
from banglasecure_baseline.findings import Finding, Severity
from banglasecure_baseline.web_check import (
    DNSCheckError,
    HTTPSCheckError,
    InvalidDomainError,
    NetworkConsentError,
    TLSCertificateError,
    UnsafeAddressError,
    VerificationError,
    check_web_configuration,
    generate_verification_token,
    normalize_domain,
)

DOMAIN = "example.org"
TOKEN = "a" * 43


class TXTRecord:
    def __init__(self, *chunks: bytes) -> None:
        self.strings = list(chunks)


class AddressRecord:
    def __init__(self, address: str) -> None:
        self.address = address


class FakeResolver:
    def __init__(self, records: dict[tuple[str, str], object]) -> None:
        self.records = records
        self.calls: list[tuple[str, str, float]] = []
        self.timeout = 0.0
        self.lifetime = 0.0
        self.attempts = 0
        self.nameservers: list[str] = []
        self.retry_servfail = True

    def resolve(self, qname: str, rdtype: str, *, lifetime: float) -> object:
        self.calls.append((qname, rdtype, lifetime))
        value = self.records.get((qname.rstrip("."), rdtype), dns.resolver.NoAnswer())
        if isinstance(value, BaseException):
            raise value
        return value


class FakeTLSSocket:
    def __init__(self, response: bytes = b"HTTP/1.1 200 OK\r\n\r\n") -> None:
        self.response = response
        self.sent = b""
        self.timeouts: list[float] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def getpeercert(self) -> dict[str, str]:
        expiry = datetime.now(UTC) + timedelta(days=60)
        return {"notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")}

    def sendall(self, data: bytes) -> None:
        self.sent = data

    def recv(self, size: int) -> bytes:
        chunk = self.response[:size]
        self.response = self.response[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


def _records(
    *,
    addresses: tuple[str, ...] = ("93.184.216.34",),
    ipv6: tuple[str, ...] = (),
    challenge: str = TOKEN,
    spf: tuple[bytes, ...] | None = (b"v=spf1 -all",),
    dmarc: tuple[bytes, ...] | None = (b"v=DMARC1; p=reject",),
) -> dict[tuple[str, str], object]:
    records: dict[tuple[str, str], object] = {
        (f"_banglasecure-verification.{DOMAIN}", "TXT"): [TXTRecord(challenge.encode())],
    }
    address_records = [AddressRecord(address) for address in addresses if ":" not in address]
    ipv6_records = [AddressRecord(address) for address in (*addresses, *ipv6) if ":" in address]
    if address_records:
        records[(DOMAIN, "A")] = address_records
    if ipv6_records:
        records[(DOMAIN, "AAAA")] = ipv6_records
    if spf is not None:
        records[(DOMAIN, "TXT")] = [TXTRecord(*spf)]
    if dmarc is not None:
        records[(f"_dmarc.{DOMAIN}", "TXT")] = [TXTRecord(*dmarc)]
    return records


def _present_headers() -> tuple[tuple[str, str], ...]:
    return (
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=()"),
    )


def _response(
    *,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] | None = None,
    expiry: datetime | None = None,
) -> web_check.HTTPSResponse:
    cert_expiry = expiry or (datetime.now(UTC) + timedelta(days=60))
    return web_check.HTTPSResponse(
        status=status,
        headers=tuple(name for name, _ in (headers if headers is not None else _present_headers())),
        has_csp_frame_ancestors=any(
            name.casefold() == "content-security-policy" and "frame-ancestors" in value.casefold()
            for name, value in (headers if headers is not None else _present_headers())
        ),
        certificate_not_after=cert_expiry.strftime("%b %d %H:%M:%S %Y GMT"),
    )


def _install_mocks(
    monkeypatch: pytest.MonkeyPatch,
    *,
    records: dict[tuple[str, str], object] | None = None,
    response: web_check.HTTPSResponse | None = None,
) -> FakeResolver:
    resolver = FakeResolver(records if records is not None else _records())
    monkeypatch.setattr(web_check, "_new_resolver", lambda: resolver)
    monkeypatch.setattr(
        web_check,
        "_pinned_https_get",
        lambda domain, address, deadline: response or _response(),
    )
    return resolver


def _check() -> tuple[Finding, ...]:
    return check_web_configuration(
        DOMAIN,
        verification_token=TOKEN,
        allow_network=True,
    )


def test_domain_normalizes_case_and_idna() -> None:
    assert normalize_domain("ExAmPlE.Org.") == DOMAIN
    assert normalize_domain("bücher.org") == "xn--bcher-kva.org"


@pytest.mark.parametrize(
    "domain",
    [
        "https://example.org",
        "user@example.org",
        "example.org/path",
        "example.org?x=1",
        "example.org#fragment",
        "example.org:443",
        "*.example.org",
        "127.0.0.1",
        "0127.0.0.1",
        "localhost",
        "printer.local",
        "host.internal",
        "service.test",
        "host.example",
        "bad_label.example",
        "two..labels",
    ],
)
def test_unsafe_or_malformed_domains_are_rejected(domain: str) -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(domain)


def test_verification_token_generation_is_local_and_high_entropy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Mock(side_effect=AssertionError("Token generation must not use the network"))
    monkeypatch.setattr(web_check.dns.resolver, "Resolver", network)

    record_name, token = generate_verification_token("ExAmPlE.org")

    assert record_name == "_banglasecure-verification.example.org"
    assert len(token) == 43
    assert len(set(token)) > 20
    network.assert_not_called()


def test_missing_token_refuses_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = Mock(side_effect=AssertionError("DNS must not run"))
    monkeypatch.setattr(web_check, "_new_resolver", resolver)

    with pytest.raises(VerificationError, match="required"):
        check_web_configuration(DOMAIN, verification_token=None, allow_network=True)

    resolver.assert_not_called()


def test_missing_network_consent_refuses_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = Mock(side_effect=AssertionError("DNS must not run"))
    monkeypatch.setattr(web_check, "_new_resolver", resolver)

    with pytest.raises(NetworkConsentError):
        check_web_configuration(DOMAIN, verification_token=TOKEN, allow_network=False)

    resolver.assert_not_called()


def test_verification_token_mismatch_stops_before_other_queries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = _install_mocks(monkeypatch, records=_records(challenge="b" * 43))

    with pytest.raises(VerificationError, match="does not match"):
        _check()

    assert len(resolver.calls) == 1


def test_verification_dns_timeout_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = _install_mocks(
        monkeypatch,
        records={
            (f"_banglasecure-verification.{DOMAIN}", "TXT"): dns.exception.Timeout(),
        },
    )

    with pytest.raises(DNSCheckError, match="timed out"):
        _check()

    assert len(resolver.calls) == 1


def test_system_resolver_has_explicit_timeout_and_bounded_nameservers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = FakeResolver({})
    resolver.nameservers = ["192.0.2.53", "192.0.2.54"]
    monkeypatch.setattr(web_check.dns.resolver, "Resolver", lambda **kwargs: resolver)

    configured = web_check._new_resolver()

    assert configured.timeout == web_check.DNS_QUERY_TIMEOUT_SECONDS
    assert configured.lifetime == web_check.DNS_LIFETIME_SECONDS
    assert configured.nameservers == ["192.0.2.53"]
    assert configured.retry_servfail is False


def test_a_and_aaaa_are_resolved_with_bounded_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = _install_mocks(
        monkeypatch,
        records=_records(ipv6=("2606:2800:220:1:248:1893:25c8:1946",)),
    )

    _check()

    address_queries = [
        (name, kind, timeout) for name, kind, timeout in resolver.calls if kind in {"A", "AAAA"}
    ]
    assert [(name, kind) for name, kind, _ in address_queries] == [
        (f"{DOMAIN}.", "A"),
        (f"{DOMAIN}.", "AAAA"),
    ]
    assert all(0 < timeout <= web_check.DNS_LIFETIME_SECONDS for _, _, timeout in resolver.calls)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "192.168.1.1",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:192.168.1.1",
    ],
)
def test_non_global_addresses_are_rejected_before_connection(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    resolver = _install_mocks(monkeypatch, records=_records(addresses=(address,)))
    connect = Mock(side_effect=AssertionError("Unsafe target must never connect"))
    monkeypatch.setattr(web_check, "_pinned_https_get", connect)

    with pytest.raises(UnsafeAddressError):
        _check()

    connect.assert_not_called()
    assert all(kind in {"TXT", "A", "AAAA"} for _, kind, _ in resolver.calls)


def test_mixed_public_and_private_answers_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect = Mock(side_effect=AssertionError("Unsafe target must never connect"))
    _install_mocks(
        monkeypatch,
        records=_records(addresses=("93.184.216.34", "10.0.0.1")),
    )
    monkeypatch.setattr(web_check, "_pinned_https_get", connect)

    with pytest.raises(UnsafeAddressError):
        _check()

    connect.assert_not_called()


def test_pinned_connection_uses_validated_ip_but_domain_for_tls_and_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tls = FakeTLSSocket(b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1\r\n\r\nbody")
    raw_socket = Mock()
    context = Mock()
    context.wrap_socket.return_value = tls
    create_connection = Mock(return_value=raw_socket)
    monkeypatch.setattr(web_check.socket, "create_connection", create_connection)
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    deadline = web_check.time.monotonic() + 10

    response = web_check._pinned_https_get(
        DOMAIN,
        ipaddress.ip_address("93.184.216.34"),
        deadline,
    )

    assert create_connection.call_args.args[0] == ("93.184.216.34", 443)
    context.wrap_socket.assert_called_once_with(raw_socket, server_hostname=DOMAIN)
    assert f"Host: {DOMAIN}\r\n".encode() in tls.sent
    assert response.status == 200
    assert response.headers[0] == "Strict-Transport-Security"
    assert tls.closed


def test_pinned_response_discards_cookie_headers_and_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tls = FakeTLSSocket(
        b"HTTP/1.1 200 OK\r\n"
        b"Set-Cookie: synthetic-cookie-secret\r\n"
        b"Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
        b"\r\nresponse-body-sentinel"
    )
    raw_socket = Mock()
    context = Mock()
    context.wrap_socket.return_value = tls
    monkeypatch.setattr(web_check.socket, "create_connection", lambda *args, **kwargs: raw_socket)
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)

    response = web_check._pinned_https_get(
        DOMAIN,
        ipaddress.ip_address("93.184.216.34"),
        web_check.time.monotonic() + 10,
    )

    assert response.headers == ("Content-Security-Policy",)
    assert response.has_csp_frame_ancestors
    assert "synthetic-cookie-secret" not in repr(response)
    assert "response-body-sentinel" not in repr(response)


def test_tls_certificate_validation_failure_is_reported_as_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(monkeypatch)
    monkeypatch.setattr(
        web_check,
        "_pinned_https_get",
        Mock(side_effect=TLSCertificateError(10)),
    )

    findings = _check()

    assert any("expired" in finding.title.lower() for finding in findings)
    assert all(finding.severity is Severity.UNASSESSED for finding in findings)


def test_tls_certificate_warning_uses_safe_expiry_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(
        monkeypatch,
        response=_response(expiry=datetime.now(UTC) + timedelta(days=5)),
    )

    findings = _check()

    expiry = next(finding for finding in findings if "expires soon" in finding.title)
    assert "Certificate expiry date:" in expiry.safe_evidence
    assert expiry.location == f"https://{DOMAIN}/"


def test_tls_connection_timeout_fails_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = Mock()
    monkeypatch.setattr(
        web_check.socket,
        "create_connection",
        Mock(side_effect=TimeoutError("private timeout detail")),
    )

    with pytest.raises(HTTPSCheckError) as error:
        web_check._pinned_https_get(
            DOMAIN,
            ipaddress.ip_address("93.184.216.34"),
            web_check.time.monotonic() + 10,
        )

    assert "private timeout detail" not in str(error.value)
    raw_socket.close.assert_not_called()


def test_https_request_failure_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_mocks(monkeypatch)
    monkeypatch.setattr(
        web_check,
        "_pinned_https_get",
        Mock(side_effect=HTTPSCheckError("The pinned HTTPS request could not be completed.")),
    )

    with pytest.raises(HTTPSCheckError):
        _check()


def test_missing_security_headers_create_bilingual_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(monkeypatch, response=_response(headers=()))

    findings = _check()

    missing_headers = {finding.title.rsplit(": ", 1)[-1] for finding in findings}
    assert missing_headers == set(web_check._SECURITY_HEADERS)
    assert all(finding.summary_bn and finding.remediation_bn for finding in findings)


def test_present_security_headers_produce_no_header_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = (*_present_headers(), ("X-Frame-Options", "DENY"))
    _install_mocks(monkeypatch, response=_response(headers=headers))

    findings = _check()

    assert not any(
        finding.category == "web-configuration" and "header" in finding.title.lower()
        for finding in findings
    )


def test_csp_frame_ancestors_satisfies_framing_check_without_xfo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(monkeypatch)

    findings = _check()

    assert not any("X-Frame-Options" in finding.title for finding in findings)


def test_csp_value_mention_does_not_count_as_frame_ancestors_directive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = "img-src https://frame-ancestors.example"
    tls = FakeTLSSocket(
        (
            "HTTP/1.1 200 OK\r\n"
            "Strict-Transport-Security: max-age=31536000\r\n"
            f"Content-Security-Policy: {policy}\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Referrer-Policy: no-referrer\r\n"
            "Permissions-Policy: camera=()\r\n"
            "\r\n"
        ).encode()
    )
    raw_socket = Mock()
    context = Mock()
    context.wrap_socket.return_value = tls
    monkeypatch.setattr(web_check.socket, "create_connection", lambda *args, **kwargs: raw_socket)
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    response = web_check._pinned_https_get(
        DOMAIN,
        ipaddress.ip_address("93.184.216.34"),
        web_check.time.monotonic() + 10,
    )

    findings = web_check._header_findings(DOMAIN, response)

    assert not response.has_csp_frame_ancestors
    assert any("X-Frame-Options" in finding.title for finding in findings)


@pytest.mark.parametrize(
    ("records", "missing"),
    [
        (_records(spf=None), "SPF"),
        (_records(dmarc=None), "DMARC"),
    ],
)
def test_missing_mail_dns_records_create_findings(
    monkeypatch: pytest.MonkeyPatch,
    records: dict[tuple[str, str], object],
    missing: str,
) -> None:
    _install_mocks(monkeypatch, records=records)

    findings = _check()

    assert any(missing in finding.title for finding in findings)


def test_spf_and_dmarc_records_are_matched_case_insensitively_and_joined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(
        monkeypatch,
        records=_records(
            spf=(b"v=spf", b"1 -all"),
            dmarc=(b"v=DMARC1; p=none",),
        ),
    )

    findings = _check()

    assert not any("SPF" in finding.title or "DMARC" in finding.title for finding in findings)


def test_dns_malformed_txt_answer_fails_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(
        monkeypatch,
        records={
            (f"_banglasecure-verification.{DOMAIN}", "TXT"): [object()],
        },
    )

    with pytest.raises(DNSCheckError, match="malformed"):
        _check()


def test_dns_malformed_address_fails_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(
        monkeypatch,
        records={
            (f"_banglasecure-verification.{DOMAIN}", "TXT"): [TXTRecord(TOKEN.encode())],
            (DOMAIN, "A"): [AddressRecord("not-an-ip")],
        },
    )

    with pytest.raises(DNSCheckError, match="malformed"):
        _check()


def test_redirect_is_not_followed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(monkeypatch, response=_response(status=302))
    pinned_request = Mock(return_value=_response(status=302))
    monkeypatch.setattr(web_check, "_pinned_https_get", pinned_request)

    with pytest.raises(HTTPSCheckError, match="redirect"):
        _check()

    assert pinned_request.call_count == 1


def test_finding_uses_existing_model_and_supported_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_mocks(monkeypatch, response=_response(headers=()))

    finding = check_web_configuration(
        DOMAIN,
        verification_token=TOKEN,
        allow_network=True,
    )[0]

    assert isinstance(finding, Finding)
    assert finding.finding_id.startswith("WEB-")
    assert finding.severity is Severity.UNASSESSED
    assert finding.summary_en and finding.summary_bn
    assert finding.impact_en and finding.impact_bn
    assert finding.remediation_en and finding.remediation_bn
    assert finding.references


def test_response_sensitive_headers_and_body_are_not_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_value = "synthetic-cookie-value-do-not-disclose"
    response = web_check.HTTPSResponse(
        status=200,
        headers=("Set-Cookie",),
        has_csp_frame_ancestors=False,
        certificate_not_after=(datetime.now(UTC) + timedelta(days=60)).strftime(
            "%b %d %H:%M:%S %Y GMT"
        ),
    )
    _install_mocks(monkeypatch, response=response)

    findings = _check()

    assert secret_value not in repr(findings)
