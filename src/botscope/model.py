from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit, urlunsplit

METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "UNKNOWN"}
SECRET = re.compile(r"(?i)(token|password|passwd|secret|session|cookie|authorization|api.?key|signature|jwt|code)")
STATIC = re.compile(r"(?i)\.(?:css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp[34]|zip|map)$")
SIDE_EFFECT = re.compile(r"(?i)(?:^|[/_.?=&-])(logout|signout|logoff|delete|remove|destroy|unsubscribe|confirm|activate|redeem|checkout|purchase|transfer|withdraw|send|resend|reset|revoke|cancel|approve|accept|reject|execute|trigger|submit)(?:$|[/_.?=&-])")


def canonical_url(value: str, base: str = "") -> str | None:
    """Keep path case and query values in memory; never collapse trailing slashes."""
    if not isinstance(value, str) or len(value) > 8192 or re.search(r"[\x00-\x20\\]", value):
        return None
    try:
        p = urlsplit(urljoin(base, value))
        if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
            return None
        host = p.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = p.port
        host = f"[{host}]" if ":" in host else host
        netloc = host if port in {None, 80 if p.scheme == "http" else 443} else f"{host}:{port}"
        return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))
    except (ValueError, UnicodeError):
        return None


def origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def safe_path(path: str) -> str:
    parts = path.split("/")
    semantic = {"reset", "forgot", "recovery", "recover", "change", "verify", "validate", "refresh", "revoke", "exchange", "create", "delete", "status", "login", "logout", "send", "resend", "request", "check"}
    for i, part in enumerate(parts):
        decoded = unquote(part)
        if ("@" in decoded or len(decoded) > 64 or
                re.fullmatch(r"[A-Za-z0-9_-]{24,}", decoded) or
                (i and re.search(r"(?i)(token|session|secret|reset|verify|password|api.?key)", parts[i - 1]) and decoded.lower() not in semantic and not part.startswith("{"))):
            parts[i] = "{redacted}"
    return "/".join(parts)


def display_url(url: str) -> str:
    p = urlsplit(url)
    keys = sorted(parameter_names(url))
    return urlunsplit((p.scheme, p.netloc, safe_path(p.path), "&".join(f"{quote(k)}=[redacted]" for k in keys), ""))


def safe_label(value: object, limit: int = 180) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value))
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[redacted-email]", text)
    text = re.sub(r"\b[A-Za-z0-9_-]{32,}(?:\.[A-Za-z0-9_-]+){0,2}\b", "[redacted]", text)
    return text[:limit]


def parameter_names(url: str) -> set[str]:
    try:
        return {safe_label(k, 100) for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True, max_num_fields=1000)}
    except ValueError:
        return set()


def route_shape(path: str) -> str:
    return re.sub(r"\{[^/]+\}|(?<=/)[0-9]+(?=/|$)|(?<=/)[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}(?=/|$)", "{id}", path)


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    operation: str = ""
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)
    auth: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    observed: bool = False
    declared: bool = False
    fetch_state: str = "discovered_only"
    observations: int = 0
    client_type: str = "unknown"
    classifications: list[str] = field(default_factory=list)
    threats: list[dict] = field(default_factory=list)
    priority: str = "Review"
    score: int = 0
    confidence: str = "low"
    suitability: str = "Review"
    recommendation: str = ""
    validation: list[str] = field(default_factory=list)
    inventory_status: str = "Unreconciled"

    @property
    def key(self) -> str:
        p = urlsplit(self.url)
        return f"{self.method} {origin(self.url)}{p.path}?{'&'.join(sorted(parameter_names(self.url)))} {self.operation}"

    def export(self) -> dict:
        data = asdict(self)
        data["url"] = display_url(self.url)
        data["path"] = safe_path(urlsplit(self.url).path)
        data["route_shape"] = route_shape(data["path"])
        data["origin"] = origin(self.url)
        data["id"] = hashlib.sha256(self.key.encode()).hexdigest()[:16]
        return data


class Inventory:
    def __init__(self, scope, max_endpoints: int = 20000):
        self.scope = scope
        self.max_endpoints = max_endpoints
        self.endpoints: dict[str, Endpoint] = {}
        self.issues: list[str] = []
        self.rejected = 0
        self.imports: list[dict] = []

    def issue(self, message: str) -> None:
        if message not in self.issues and len(self.issues) < 500:
            self.issues.append(message)

    def add(self, url: str, method: str = "GET", source: str = "manual", *,
            base: str = "", operation: str = "", evidence: str = "", parameters=(),
            contexts=(), auth: str = "", controls=(), status: int = 0,
            content_type: str = "", observed=False, declared=False,
            client_type="unknown") -> Endpoint | None:
        url = canonical_url(url, base)
        method = str(method).upper()
        if not url or method not in METHODS or not self.scope.contains(url):
            self.rejected += 1
            return None
        candidate = Endpoint(url=url, method=method, operation=safe_label(operation))
        key = candidate.key
        if key not in self.endpoints and len(self.endpoints) >= self.max_endpoints:
            self.issue("Endpoint inventory limit reached; increase max_endpoints or split the assessment.")
            return None
        ep = self.endpoints.setdefault(key, candidate)
        for attr, values in {
            "sources": [source], "evidence": [evidence],
            "parameters": list(parameters) + list(parameter_names(url)),
            "contexts": list(contexts), "auth": [auth], "controls": list(controls),
            "statuses": [int(status)] if status else [], "content_types": [content_type.split(";")[0]],
        }.items():
            items = getattr(ep, attr)
            for val in values:
                val = safe_label(val) if isinstance(val, str) else val
                if val and val not in items and len(items) < 100:
                    items.append(val)
        ep.observed |= observed
        ep.declared |= declared
        ep.observations += int(observed)
        if client_type != "unknown":
            ep.client_type = client_type if ep.client_type in {"unknown", client_type} else "mixed"
        return ep
