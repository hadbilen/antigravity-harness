"""
porter/net.py — SSRF-hardened remote fetcher for Porter.
Zero-dependency: uses Python standard library only.

Defences:
- http/https only; only globally routable unicast destinations (`ip.is_global`), which also
  rejects CGNAT 100.64.0.0/10, 6to4 relay, site-local fec0::/10 and IPv4-mapped loopback.
  IPv6 forms that embed an IPv4 address (IPv4-compatible ::a.b.c.d, IPv4-translated
  ::ffff:0:a.b.c.d, 6to4, NAT64) are rejected outright.
- DNS pinning: the address that is validated is the address that is connected to, so a
  DNS answer that changes between check and use (rebinding) cannot reach an internal host.
  TLS still verifies the certificate for the original hostname (SNI + hostname check).
- Every redirect hop is re-validated and connected through the same pinned path.
- The opener is built explicitly: no proxy, file:, ftp: or data: handlers are registered,
  so only the pinned http/https handlers can open anything.
- Bounded response size, a per-operation socket timeout AND an overall wall-clock deadline
  for the whole fetch (redirects included), so a server trickling bytes cannot hold it open.
"""

from __future__ import annotations

import functools
import http.client
import ipaddress
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

MAX_REDIRECTS = 5
# Default overall deadline of safe_fetch_url() = timeout * DEADLINE_FACTOR seconds.
DEADLINE_FACTOR = 3.0

# Ranges some Python versions still report as global, plus IPv6 transition prefixes that can
# embed an internal IPv4 address.
_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "192.88.99.0/24",   # deprecated 6to4 relay anycast
    "fec0::/10",        # deprecated IPv6 site-local
    "::/96",            # deprecated IPv4-compatible IPv6 (::a.b.c.d), includes :: and ::1
    "::ffff:0:0:0/96",  # IPv4-translated (SIIT, ::ffff:0:a.b.c.d)
    "2002::/16",        # 6to4 (embeds IPv4)
    "64:ff9b::/96",     # NAT64 well-known prefix (embeds IPv4)
    "64:ff9b:1::/48",   # local-use NAT64
)]


class FetchDeadlineExceeded(TimeoutError):
    """Raised when a fetch exceeds its overall wall-clock deadline."""


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


def _per_op_timeout(timeout) -> Optional[float]:
    if timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
        return socket.getdefaulttimeout()
    return timeout


class _DeadlineMixin:
    """Re-arms the socket timeout before every I/O call so no call can outlive the deadline."""

    _agy_deadline: Optional[float] = None
    _agy_per_op: Optional[float] = None

    def _agy_arm(self) -> bool:
        """Sets the socket timeout; True when the overall deadline (not the per-op timeout) bounds it."""
        per_op = self._agy_per_op
        capped = False
        if self._agy_deadline is not None:
            remaining = self._agy_deadline - time.monotonic()
            if remaining <= 0:
                raise FetchDeadlineExceeded("Remote fetch exceeded its overall deadline.")
            capped = per_op is None or remaining <= per_op
            per_op = remaining if per_op is None else min(per_op, remaining)
        self.settimeout(per_op)
        return capped

    def _agy_io(self, call, *args, **kwargs):
        capped = self._agy_arm()
        try:
            return call(*args, **kwargs)
        except socket.timeout as e:
            # When the deadline set this call's timeout, running out of it IS the deadline being
            # exceeded (the exact moment depends on the platform's timer resolution).
            if capped:
                raise FetchDeadlineExceeded("Remote fetch exceeded its overall deadline.") from e
            raise

    def recv_into(self, *args, **kwargs):
        return self._agy_io(super().recv_into, *args, **kwargs)

    def recv(self, *args, **kwargs):
        return self._agy_io(super().recv, *args, **kwargs)

    def send(self, *args, **kwargs):
        return self._agy_io(super().send, *args, **kwargs)

    def sendall(self, *args, **kwargs):
        return self._agy_io(super().sendall, *args, **kwargs)


class _DeadlineSocket(_DeadlineMixin, socket.socket):
    pass


class _DeadlineSSLSocket(_DeadlineMixin, ssl.SSLSocket):
    pass


def _pinned_socket(host: str, port: int, timeout, deadline: Optional[float] = None) -> socket.socket:
    per_op = _per_op_timeout(timeout)
    last_error: Exception = OSError("no address")
    for family, sockaddr in resolve_safe_addresses(host, port):
        sock = _DeadlineSocket(family, socket.SOCK_STREAM)
        sock._agy_deadline = deadline
        sock._agy_per_op = per_op
        try:
            sock._agy_arm()
            sock.connect(sockaddr)
            return sock
        except FetchDeadlineExceeded:
            sock.close()
            raise
        except OSError as e:
            sock.close()
            last_error = e
    raise last_error


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, agy_deadline: Optional[float] = None, **kwargs):
        self._agy_deadline = agy_deadline
        super().__init__(*args, **kwargs)

    def connect(self):
        self.sock = _pinned_socket(self.host, self.port, self.timeout, self._agy_deadline)


def _deadline_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.sslsocket_class = _DeadlineSSLSocket
    return context


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, agy_deadline: Optional[float] = None, **kwargs):
        self._agy_deadline = agy_deadline
        self._agy_context = kwargs.get("context") or _deadline_context()
        kwargs["context"] = self._agy_context
        super().__init__(*args, **kwargs)

    def connect(self):
        raw = _pinned_socket(self.host, self.port, self.timeout, self._agy_deadline)
        sock = self._agy_context.wrap_socket(raw, server_hostname=self.host)
        if isinstance(sock, _DeadlineMixin):
            sock._agy_deadline = self._agy_deadline
            sock._agy_per_op = raw._agy_per_op
        self.sock = sock


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, deadline: Optional[float] = None):
        super().__init__()
        self._agy_deadline = deadline

    def http_open(self, req):
        return self.do_open(functools.partial(_PinnedHTTPConnection, agy_deadline=self._agy_deadline), req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, deadline: Optional[float] = None):
        super().__init__(context=_deadline_context())
        self._agy_deadline = deadline

    def https_open(self, req):
        return self.do_open(functools.partial(_PinnedHTTPSConnection, agy_deadline=self._agy_deadline), req,
                            context=self._context)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates each redirect target (scheme + addresses) and caps the chain length."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_safe_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_safe_opener(deadline: Optional[float] = None) -> urllib.request.OpenerDirector:
    """
    An opener that can only fetch http/https through the pinned handlers. `deadline` is an
    absolute time.monotonic() value after which every socket operation of this opener fails.
    Built explicitly (not via build_opener) so no file:, ftp: or data: handler is registered.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler({}),
        urllib.request.UnknownHandler(),
        _PinnedHTTPHandler(deadline),
        _PinnedHTTPSHandler(deadline),
        urllib.request.HTTPDefaultErrorHandler(),
        SafeRedirectHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


def safe_fetch_url(
    url: str,
    user_agent: str = "",
    timeout: float = 10.0,
    max_bytes: int = 10_000_000,
    deadline: Optional[float] = None,
) -> str:
    """
    Retrieves remote text via HTTP(S) with SSRF validation, DNS pinning and size bounds.
    `timeout` bounds each socket operation; `deadline` (seconds, default timeout * DEADLINE_FACTOR)
    bounds the whole fetch including redirects. Exceeding it raises FetchDeadlineExceeded.
    """
    if not user_agent:
        from porter import __version__

        user_agent = f"Antigravity-Porter/{__version__}"
    total = float(deadline) if deadline is not None else float(timeout) * DEADLINE_FACTOR
    if total <= 0:
        raise ValueError("deadline must be positive")
    deadline_at = time.monotonic() + total
    validate_safe_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with build_safe_opener(deadline_at).open(req, timeout=timeout) as resp:
            data = resp.read(max_bytes + 1)
    except (OSError, http.client.HTTPException) as e:
        reason = getattr(e, "reason", None)
        if isinstance(reason, FetchDeadlineExceeded):
            raise FetchDeadlineExceeded(f"Remote fetch exceeded its {total:g}s deadline.") from e
        if time.monotonic() >= deadline_at and not isinstance(e, urllib.error.HTTPError):
            raise FetchDeadlineExceeded(f"Remote fetch exceeded its {total:g}s deadline.") from e
        raise
    if time.monotonic() > deadline_at:
        raise FetchDeadlineExceeded(f"Remote fetch exceeded its {total:g}s deadline.")
    if len(data) > max_bytes:
        raise ValueError(f"Remote content exceeds maximum allowed size ({max_bytes} bytes).")
    return data.decode("utf-8", errors="replace")
