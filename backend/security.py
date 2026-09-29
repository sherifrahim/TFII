"""
Security helpers shared by main.py and intel_api.py.

TFII fetches and displays attacker-influenced data (URLs, domains, feed items,
NVD references), so the primitives live in one place and are unit-tested:

* GuardedBackend / safe_client  — outbound HTTP that refuses to connect to
  non-public addresses. The check happens at *connect time*, on the address the
  socket actually uses, so DNS rebinding (public on the first lookup, private on
  the second) and redirects to internal hosts cannot bypass it. Validating the
  URL string and then letting the HTTP client resolve the name again is the
  classic SSRF hole this closes.
* safe_http_url — only http(s) links may reach an <a href>. Feed items and
  references are third-party data; a `javascript:` URL in one must never become
  a clickable link.
* is_valid_domain / is_valid_ip — strict target validation before a value is
  interpolated into an upstream request.
* install_security_headers — baseline response headers for the API.
"""
import asyncio
import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urlparse

import httpcore
import httpx


# ── Address policy ────────────────────────────────────────────────────────────
def is_public_ip(value) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        a = ipaddress.ip_address(value)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:      # ::ffff:127.0.0.1 is loopback
        a = a.ipv4_mapped
    return bool(a.is_global and not a.is_multicast)


class BlockedAddress(httpcore.ConnectError):
    """Raised when a request would connect to a non-public address."""


async def _resolve(host: str, port: int):
    infos = await asyncio.to_thread(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM)
    seen, out = set(), []
    for i in infos:
        ip = i[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """Resolve, vet, then connect to the vetted IP (SNI/Host still use the name)."""

    def __init__(self, resolver=None):
        self._inner = httpcore.AnyIOBackend()
        self._resolver = resolver or _resolve

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            ips = await self._resolver(host, port)
        except OSError as e:
            raise httpcore.ConnectError(f"DNS resolution failed for {host}: {e}")
        if not ips:
            raise httpcore.ConnectError(f"{host} did not resolve")
        bad = [ip for ip in ips if not is_public_ip(ip)]
        if bad:
            # Any non-public answer poisons the whole name: an attacker can
            # return one public and one private record and hope we pick the
            # private one.
            raise BlockedAddress(f"blocked: {host} resolves to non-public address {bad[0]}")
        last = None
        for ip in ips:
            try:
                return await self._inner.connect_tcp(ip, port, timeout=timeout,
                                                     local_address=local_address,
                                                     socket_options=socket_options)
            except httpcore.ConnectError as e:
                last = e
        raise last or httpcore.ConnectError(f"could not connect to {host}")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise BlockedAddress("blocked: unix sockets are not allowed")

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


def guarded_transport(verify=True, backend: Optional[GuardedBackend] = None, **limits) -> httpx.AsyncHTTPTransport:
    """An httpx transport whose connection pool uses GuardedBackend.

    httpx does not expose the network backend, so the pool is rebuilt. The
    unit tests fail loudly if a future httpx renames the attribute.
    """
    t = httpx.AsyncHTTPTransport(verify=verify, trust_env=False)
    ctx = httpx.create_ssl_context(verify=verify)
    t._pool = httpcore.AsyncConnectionPool(
        ssl_context=ctx,
        max_connections=limits.get("max_connections", 20),
        max_keepalive_connections=limits.get("max_keepalive_connections", 5),
        keepalive_expiry=5.0,
        network_backend=backend or GuardedBackend(),
    )
    return t


def safe_client(timeout=15.0, verify=True, follow_redirects=False, headers=None) -> httpx.AsyncClient:
    """AsyncClient for URLs an analyst or attacker typed. Never proxies from env."""
    return httpx.AsyncClient(transport=guarded_transport(verify=verify), timeout=timeout,
                             follow_redirects=follow_redirects, headers=headers)


# ── Link / value validation ───────────────────────────────────────────────────
def safe_http_url(u, max_len=2048) -> Optional[str]:
    """Return u only if it is a plain http(s) URL with a host, else None."""
    if not isinstance(u, str):
        return None
    u = u.strip()
    if not u or len(u) > max_len or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in u):
        return None
    try:
        p = urlparse(u)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc or not p.hostname:
        return None
    return u


_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,63}}$", re.I)


def is_valid_domain(v: str) -> bool:
    return bool(v) and len(v) <= 253 and bool(_DOMAIN_RE.match(v))


def is_valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


# ── Response headers ──────────────────────────────────────────────────────────
API_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def install_security_headers(app):
    @app.middleware("http")
    async def _headers(request, call_next):
        resp = await call_next(request)
        for k, v in API_HEADERS.items():
            resp.headers.setdefault(k, v)
        # Behind nginx/Caddy TLS terminates upstream; honour the forwarded scheme.
        if request.headers.get("x-forwarded-proto") == "https" or request.url.scheme == "https":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        p = request.url.path
        # Authenticated JSON must never be cached by a shared proxy or the browser.
        if not p.startswith(("/f/", "/health")):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp
