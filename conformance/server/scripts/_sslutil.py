"""Shared SSL-context helper for the CI-style conformance driver
scripts in this directory (retry-flaky-modules.py,
unblock-implicit-callback.py) — both talk to the same CONFORMANCE_SERVER
over the same self-signed-cert local suite setup, so this exists in one
place rather than being copy-pasted into each script.
"""
import ipaddress
import socket
import ssl


def local_only_ssl_context(host):
    """An unverified SSL context only when host resolves entirely to
    loopback addresses — localhost.emobix.co.uk (both scripts' own
    default CONFORMANCE_SERVER) included: the OIDF conformance suite's
    own docs use that hostname specifically because it always resolves
    to 127.0.0.1, giving a local suite a real-looking hostname under an
    actual TLS handshake without needing a trusted CA. Any other host
    gets ordinary certificate and hostname verification: this is a
    local-testing accommodation for the suite's self-signed cert, not a
    blanket exemption, so pointing CONFORMANCE_SERVER at a non-local
    instance doesn't silently lose TLS protection. Either way, the
    minimum protocol version is pinned to TLS 1.2 explicitly — matching
    fapihttp's own tls.Config{MinVersion: tls.VersionTLS12} — rather
    than relying on whatever a given Python version's own default
    happens to allow.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return _context(verify=True)
    if infos and all(ipaddress.ip_address(info[4][0]).is_loopback for info in infos):
        return _context(verify=False)
    return _context(verify=True)


def _context(verify):
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
