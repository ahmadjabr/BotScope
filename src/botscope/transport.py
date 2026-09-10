"""Bounded, DNS-pinned HTTP requests. No automatic redirects or environment proxies."""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .model import origin


class FetchError(Exception):
    pass


class BudgetExceeded(FetchError):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def resolve_public(host: str, port: int, allow_private: bool) -> list:
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise FetchError("dns_no_addresses")
    for _, _, _, _, addr in addresses:
        ip = ipaddress.ip_address(addr[0].split("%")[0])
        mapped = getattr(ip, "ipv4_mapped", None)
        ip = mapped or ip
        # Metadata/link-local/multicast/unspecified targets stay blocked even on intranets.
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or str(ip) == "100.100.100.200" or (not allow_private and not ip.is_global):
            raise FetchError("blocked_network_address")
    return addresses


def read_headers(path: str | None, scope) -> dict[str, dict[str, str]]:
    if not path:
        return {}
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError("headers_file must map exact origins to header dictionaries")
    for site, headers in data.items():
        if site not in scope.origins or not isinstance(headers, dict):
            raise ValueError("Every headers_file origin must be explicitly in scan scope")
        for key, value in headers.items():
            if not isinstance(value, str) or any(c in key + value for c in "\r\n"):
                raise ValueError("Invalid request header")
            if key.lower() in {"host", "connection", "content-length", "transfer-encoding", "proxy-authorization"}:
                raise ValueError("Transport headers cannot be overridden")
    return data


class Fetcher:
    def __init__(self, config, scope):
        self.config, self.scope = config, scope
        self.headers = read_headers(config.headers_file, scope)
        self.count = 0
        self.started = time.monotonic()
        self.next_request = 0.0
        self.lock = threading.Lock()
        self.ssl_context = ssl.create_default_context(cafile=config.ca_bundle)

    @property
    def exhausted(self) -> bool:
        return self.count >= self.config.max_requests or time.monotonic() - self.started >= self.config.max_seconds

    def get(self, url: str, *, extra_headers=None) -> Response:
        with self.lock:
            reason = self.scope.fetch_reason(url)
            if reason:
                raise FetchError(reason)
            if self.exhausted:
                raise BudgetExceeded("request_or_time_budget")
            wait = self.next_request - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            if self.exhausted:
                raise BudgetExceeded("request_or_time_budget")
            self.count += 1
            self.next_request = time.monotonic() + 1 / self.config.requests_per_second
            return self._get(url, extra_headers or {})

    def _get(self, url, extra_headers):
        p = urlsplit(url)
        port = p.port or (443 if p.scheme == "https" else 80)
        conn = None
        sock = None
        deadline = min(time.monotonic() + self.config.timeout, self.started + self.config.max_seconds)
        try:
            addresses = resolve_public(p.hostname, port, self.config.allow_private)
            last_error = None
            # Connect to the validated numeric address, never resolve the host a second time.
            for family, kind, proto, _, address in addresses:
                try:
                    sock = socket.socket(family, kind, proto)
                    sock.settimeout(max(0.01, deadline - time.monotonic()))
                    sock.connect(address)
                    break
                except OSError as exc:
                    last_error = exc
                    sock.close()
                    sock = None
            if sock is None:
                raise last_error or FetchError("connection_failed")
            if p.scheme == "https":
                sock = self.ssl_context.wrap_socket(sock, server_hostname=p.hostname)
            conn = http.client.HTTPConnection(p.hostname, port, timeout=self.config.timeout)
            conn.sock = sock
            headers = {"User-Agent": "BotScope/0.1 (+authorized bot exposure assessment)",
                       "Accept": "text/html,application/json,application/xml,text/plain,*/*;q=0.5",
                       "Accept-Encoding": "gzip", "Connection": "close"}
            # Browser-originated request headers belong only to this exact intercepted request.
            headers.update({k: v for k, v in extra_headers.items() if k.lower() in {"authorization", "cookie", "accept", "content-type", "x-api-key"}})
            headers.update(self.headers.get(origin(url), {}))
            conn.request("GET", (p.path or "/") + ("?" + p.query if p.query else ""), headers=headers)
            response = conn.getresponse()
            rh = {k.lower(): v for k, v in response.getheaders()}
            limit = self.config.max_response_bytes
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if rh.get("content-encoding", "").lower() == "gzip" else None
            output = bytearray()
            raw_total = 0
            truncated = False
            while True:
                if response.isclosed():
                    break
                if time.monotonic() >= deadline:
                    raise FetchError("response_deadline")
                sock.settimeout(max(0.01, deadline - time.monotonic()))
                chunk = response.read1(min(65536, limit + 1 - raw_total))
                if not chunk:
                    break
                raw_total += len(chunk)
                output.extend(decoder.decompress(chunk, max(1, limit + 1 - len(output))) if decoder else chunk)
                if len(output) > limit or raw_total > limit or (decoder and decoder.unconsumed_tail):
                    truncated = True
                    break
            if response.status in {429, 503}:
                # Do not hammer a throttled site. No retry loops.
                try:
                    backoff = min(60, max(5, int(rh.get("retry-after", "5"))))
                except ValueError:
                    backoff = 5
                self.next_request = max(self.next_request, time.monotonic() + backoff)
            return Response(url, response.status, rh, bytes(output[:limit]), truncated)
        except FetchError:
            raise
        except (OSError, http.client.HTTPException, zlib.error, ValueError) as exc:
            # Exception strings may contain a credential-bearing URL; expose only the type.
            raise FetchError(type(exc).__name__) from None
        finally:
            if conn:
                conn.close()
            elif sock:
                sock.close()
