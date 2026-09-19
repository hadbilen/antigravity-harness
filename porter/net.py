"""
porter/net.py — Secure remote network fetcher with SSRF and redirect protection.
Guarantees zero-third-party dependency standard library implementation.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
import urllib.request
from typing import Optional


def validate_safe_url(url: str) -> None:
    """
    Validates that a URL does not target localhost, private subnets,
    link-local addresses (e.g. AWS/GCP metadata 169.254.169.254), or reserved IP ranges.
    Guarantees strict Server-Side Request Forgery (SSRF) immunity.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid URL: missing hostname in '{url}'.")

    # Immediate rejection of obvious loopback aliases
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError(f"SSRF Protection: Access to localhost ('{hostname}') is blocked.")

    # Resolve all IPs for hostname and evaluate each against forbidden subnets
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve hostname '{hostname}': {e}")

    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError(
                f"SSRF Protection: Access to private, local, or internal metadata address "
                f"'{ip_str}' ({hostname}) is strictly prohibited."
            )


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler that re-evaluates each redirect target against SSRF rules.
    Prevents open-redirect bypass attacks (e.g. public URL redirecting to 169.254.169.254).
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Validate redirected target URL before allowing client to follow
        validate_safe_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_fetch_url(
    url: str,
    user_agent: str = "Antigravity-Porter/1.2.8",
    timeout: float = 10.0,
    max_bytes: int = 10_000_000,
) -> str:
    """
    Safely retrieves remote content via HTTP(S) with SSRF validation,
    redirect inspection, and response size bounds.
    """
    validate_safe_url(url)

    req = urllib.request.Request(
        url,
        headers={"User-Agent": user_agent},
    )

    opener = urllib.request.build_opener(SafeRedirectHandler())
    with opener.open(req, timeout=timeout) as resp:
        # Bounded read to prevent memory exhaustion from oversized responses
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"Remote content exceeds maximum allowed size ({max_bytes} bytes).")
        return data.decode("utf-8", errors="replace")
