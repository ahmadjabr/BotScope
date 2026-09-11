from __future__ import annotations

import fnmatch
import math
import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .model import SIDE_EFFECT, canonical_url, origin


@dataclass
class Config:
    target: str
    allowed_origins: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    max_requests: int = 1000
    max_endpoints: int = 20000
    max_depth: int = 8
    max_seconds: float = 1800
    max_response_bytes: int = 2_000_000
    max_query_variants: int = 5
    requests_per_second: float = 2
    timeout: float = 15
    allow_private: bool = False
    respect_robots: bool = True
    discover_specs: bool = True
    browser: bool = False
    browser_pages: int = 30
    browser_interactions: bool = True
    max_interactions: int = 100
    capture_websockets: bool = False
    session_files: list[str] = field(default_factory=list)
    hidden_path_wordlist: str | None = None
    max_hidden_paths: int = 500
    form_testing: bool = False
    form_allowlist: list[str] = field(default_factory=list)
    allow_sensitive_form_tests: bool = False
    max_form_tests: int = 10
    ca_bundle: str | None = None
    seed_urls: list[str] = field(default_factory=list)
    headers_file: str | None = None
    imports: list[dict] = field(default_factory=list)

    def __post_init__(self):
        normalized = canonical_url(self.target)
        if not normalized:
            raise ValueError("target must be a complete HTTP(S) URL without credentials")
        self.target = normalized
        for name in ("max_requests", "max_endpoints", "max_depth", "max_response_bytes", "max_query_variants", "browser_pages", "max_interactions", "max_hidden_paths", "max_form_tests"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("timeout", "max_seconds", "requests_per_second"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number")
        if not 0.1 <= self.requests_per_second <= 20:
            raise ValueError("requests_per_second must be between 0.1 and 20")
        if self.session_files:
            if not isinstance(self.session_files, list) or len(self.session_files) > 20:
                raise ValueError("session_files must contain at most 20 paths")
            for path in self.session_files:
                candidate = Path(path)
                if not candidate.is_file() or candidate.stat().st_size > 20_000_000:
                    raise ValueError("Every session file must be an existing JSON file no larger than 20 MB")
        if self.hidden_path_wordlist:
            candidate = Path(self.hidden_path_wordlist)
            if not candidate.is_file() or candidate.stat().st_size > 5_000_000:
                raise ValueError("hidden_path_wordlist must be an existing file no larger than 5 MB")
        if self.capture_websockets or self.session_files or self.form_testing:
            self.browser = True
        if self.form_testing:
            if not self.allow_private:
                raise ValueError("form_testing requires --allow-private and an explicitly authorized private/staging target")
            if not self.form_allowlist:
                raise ValueError("form_testing requires at least one exact form_allowlist path")
        if self.allow_sensitive_form_tests and not self.form_testing:
            raise ValueError("allow_sensitive_form_tests requires form_testing")


class Scope:
    def __init__(self, config: Config):
        self.config = config
        self.origins = {origin(config.target)}
        for item in config.allowed_origins:
            url = canonical_url(item)
            if not url or urlsplit(url).path != "/" or urlsplit(url).query:
                raise ValueError("allowed_origins entries must be exact origins, e.g. https://api.example.com")
            self.origins.add(origin(url))

    def contains(self, url: str) -> bool:
        if origin(url) not in self.origins:
            return False
        path = unquote(unquote(urlsplit(url).path))
        normalized = posixpath.normpath(path)
        paths = {path, normalized + ("/" if path.endswith("/") and normalized != "/" else "")}
        return (not self.config.include_paths or all(any(fnmatch.fnmatchcase(path, p) for p in self.config.include_paths) for path in paths)) and not any(fnmatch.fnmatchcase(path, p) for path in paths for p in self.config.exclude_paths)

    def fetch_reason(self, url: str, method: str = "GET") -> str | None:
        if not self.contains(url):
            return "outside_scope"
        if method not in {"GET", "HEAD"}:
            return "non_read_method"
        decoded = unquote(unquote(url))
        if "{" in decoded or "}" in decoded:
            return "unresolved_template"
        if SIDE_EFFECT.search(decoded):
            return "possible_state_change"
        from .model import SECRET, parameter_names
        if any(SECRET.search(k) for k in parameter_names(url)):
            return "sensitive_query"
        return None

    def form_allowed(self, url: str, method: str) -> bool:
        if not self.config.form_testing or method not in {"GET", "POST"} or not self.contains(url):
            return False
        path = urlsplit(url).path or "/"
        return any(fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(url, pattern)
                   for pattern in self.config.form_allowlist)
