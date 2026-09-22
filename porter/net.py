"""
porter/net.py — SSRF-hardened remote fetcher for Porter.
Zero-dependency: uses Python standard library only.

Defences:
- http/https only; only globally routable unicast destinations (`ip.is_global`), which also
  rejects CGNAT 100.64.0.0/10, 6to4 relay, site-local fec0::/10 and IPv4-mapped loopback.
- DNS pinning: the address that is validated is the address that is connected to, so a
  DNS answer that changes between check and use (rebinding) cannot reach an internal host.
  TLS still verifies the certificate for the original hostname (SNI + hostname check).
- Every redirect hop is re-validated and connected through the same pinned path.
- Environment proxies are ignored (a proxy would bypass the destination checks).
- Bounded response size and timeouts.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.parse
import urllib.request
from typing import List, Tuple

MAX_REDIRECTS = 5

# Ranges some Python versions still report as global, plus IPv6 transition prefixes that can
# embed an internal IPv4 address.
_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "192.88.99.0/24",   # deprecated 6to4 relay anycast
    "fec0::/10",        # deprecated IPv6 site-local
    "2002::/16",        # 6to4 (embeds IPv4)
    "64:ff9b::/96",     # NAT64 well-known prefix (embeds IPv4)
    "64:ff9b:1::/48",   # local-use NAT64
)]


def _address_allowed(ip) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if any(ip.version == net.version and ip in net for net in _EXTRA_BLOCKED):
        return False
    return bool(ip.is_global) and not ip.is_multicast


def resolve_safe_addresses(hostname: str, port: int) -> List[Tuple[int, Tuple]]:
    """Resolves hostname and returns (family, sockaddr) pairs, raising if ANY answer is not global."""
    if hostname.lower() in ("localhost", "localhost.localdomain", "ip6-localhost"):
        raise ValueError(f"SSRF Protection: Access to localhost ('{hostname}') is blocked.")
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve hostname '{hostname}': {e}")
    results: List[Tuple[int, Tuple]] = []
    for family, _, _, _, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        except ValueError:
            raise ValueError(f"SSRF Protection: unparseable address '{sockaddr[0]}' for '{hostname}'.")
        if not _address_allowed(ip):
            raise ValueError(
                f"SSRF Protection: Access to non-public address '{ip}' ({hostname}) is strictly prohibited."
            )
        results.append((family, sockaddr))
    if not results:
        raise ValueError(f"Could not resolve hostname '{hostname}'.")
    return results


def validate_safe_url(url: str) -> None:
    """Validates scheme, hostname and every resolved address of `url` (pre-flight check)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed.")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid URL: missing hostname in '{url}'.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolve_safe_addresses(hostname, port)


def _pinned_socket(host: str, port: int, timeout: float) -> socket.socket:
    last_error: Exception = OSError("no address")
    for family, sockaddr in resolve_safe_addresses(host, port):
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as e:
            sock.close()
            last_error = e
    raise last_error


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = _pinned_socket(self.host, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        self._agy_context = kwargs.get("context") or ssl.create_default_context()
        kwargs["context"] = self._agy_context
        super().__init__(*args, **kwargs)

    def connect(self):
        raw = _pinned_socket(self.host, self.port, self.timeout)
        self.sock = self._agy_context.wrap_socket(raw, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates each redirect target (scheme + addresses) and caps the chain length."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_safe_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_safe_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _PinnedHTTPHandler(),
        _PinnedHTTPSHandler(),
        SafeRedirectHandler(),
    )


def safe_fetch_url(
    url: str,
    user_agent: str = "",
    timeout: float = 10.0,
    max_bytes: int = 10_000_000,
) -> str:
    """Retrieves remote text via HTTP(S) with SSRF validation, DNS pinning and size bounds."""
    if not user_agent:
        from porter import __version__

        user_agent = f"Antigravity-Porter/{__version__}"
    validate_safe_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with build_safe_opener().open(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"Remote content exceeds maximum allowed size ({max_bytes} bytes).")
        return data.decode("utf-8", errors="replace")
