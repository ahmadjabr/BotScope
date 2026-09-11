from __future__ import annotations

import asyncio
import json
import re
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from .config import Scope
from .discovery import PageParser, control_hints, javascript_refs, json_refs, sitemap_refs, websocket_message_schema
from .importers import import_file, import_openapi, load_document
from .model import Inventory, STATIC, canonical_url, display_url, origin, safe_label
from .transport import BudgetExceeded, FetchError, Fetcher

SPEC_PATHS = ("/openapi.json", "/openapi.yaml", "/swagger.json", "/api-docs", "/v3/api-docs", "/api/openapi.json", "/swagger/v1/swagger.json")


class Scanner:
    def __init__(self, config):
        self.config = config
        self.scope = Scope(config)
        self.inventory = Inventory(self.scope, config.max_endpoints)
        self.fetcher = Fetcher(config, self.scope)
        self.queue = deque()
        self.queued, self.visited = set(), set()
        self.variants = Counter()
        self.skipped = Counter()
        self.robots: dict[str, RobotFileParser] = {}
        self.browser_candidates = []
        self.websocket_channels: dict[str, dict] = {}
        self.form_expected: set[str] = set()
        self.form_tests_submitted = 0
        self.form_tests_skipped = 0
        self.interactions_done = 0
        self.hidden_paths_enqueued = 0
        self.started = datetime.now(timezone.utc).isoformat()
        self.stop_reason = "frontier_exhausted"
        self.browser_result = {"enabled": config.browser, "pages_rendered": 0}

    def add_browser_candidate(self, url: str, source: str = "browser_candidate") -> None:
        """Queue a browser URL, retaining SPA fragments that HTTP canonicalization drops."""
        if url not in self.browser_candidates:
            self.browser_candidates.append(url)
            self.inventory.add(url.split("#", 1)[0], "GET", source,
                               evidence="Browser navigation candidate; route may be client-side")

    def record_websocket(self, websocket_url: str, direction: str = "channel", payload=None) -> None:
        """Record only a redacted WebSocket schema, never frame contents."""
        parts = urlsplit(websocket_url)
        if parts.scheme not in {"ws", "wss"} or not parts.hostname:
            return
        http_url = websocket_url.replace("ws://", "http://", 1).replace("wss://", "https://", 1)
        if not self.scope.contains(http_url):
            self.skipped["websocket_outside_scope"] += 1
            return
        display = display_url(http_url)
        channel = self.websocket_channels.setdefault(display, {"url": display, "frames": 0, "directions": {}, "schemas": []})
        if direction == "channel":
            channel["directions"].setdefault("channel", 0)
            return
        channel["frames"] += 1
        channel["directions"][direction] = channel["directions"].get(direction, 0) + 1
        schema = websocket_message_schema(payload)
        if schema not in channel["schemas"] and len(channel["schemas"]) < 100:
            channel["schemas"].append(schema)

    def form_request_allowed(self, url: str, method: str) -> bool:
        if not self.config.form_testing or method not in {"GET", "POST"}:
            return False
        canonical = canonical_url(url)
        if not canonical or canonical not in self.form_expected or not self.scope.form_allowed(canonical, method):
            return False
        self.form_expected.remove(canonical)
        self.form_tests_submitted += 1
        return True

    def begin_form_request(self, url: str, method: str) -> bool:
        canonical = canonical_url(url)
        if not canonical or not self.scope.form_allowed(canonical, method):
            self.form_tests_skipped += 1
            return False
        if self.form_tests_submitted + len(self.form_expected) >= self.config.max_form_tests:
            self.form_tests_skipped += 1
            return False
        self.form_expected.add(canonical)
        return True

    def load_hidden_paths(self) -> None:
        path = self.config.hidden_path_wordlist
        if not path:
            return
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            self.inventory.issue("Hidden-path wordlist could not be read; bounded path discovery was skipped.")
            return
        for raw in lines:
            if self.hidden_paths_enqueued >= self.config.max_hidden_paths:
                self.inventory.issue("Hidden-path limit reached; remaining wordlist entries were not queued.")
                break
            value = raw.strip()
            if not value or value.startswith("#") or any(c in value for c in "\\\x00\r\n"):
                continue
            value = value if value.startswith(("/", "http://", "https://")) else "/" + value
            candidate = urljoin(self.config.target, value)
            if origin(candidate) not in self.scope.origins:
                continue
            if self.enqueue(candidate, "hidden_path", depth=1,
                            evidence="Bounded authorized wordlist candidate; existence unverified"):
                self.hidden_paths_enqueued += 1

    def enqueue(self, url, source, depth=0, base="", method="GET", evidence=""):
        # Hash routes are client-side navigation targets. Keep the fragment for
        # Playwright while also inventorying the underlying HTTP document.
        browser_url = urljoin(base or self.config.target, url) if isinstance(url, str) else ""
        if "#" in browser_url and urlsplit(browser_url).fragment.startswith("/"):
            self.add_browser_candidate(browser_url, "spa_hash_seed" if source == "seed" else source)
        if base and not evidence:
            evidence = "Referenced from " + display_url(base)
        ep = self.inventory.add(url, method, source, base=base, evidence=evidence)
        if not ep:
            return None
        reason = self.scope.fetch_reason(ep.url, method)
        if reason:
            ep.fetch_state = reason
            self.skipped[reason] += 1
            return ep
        if depth > self.config.max_depth:
            ep.fetch_state = "depth_limit"
            self.skipped["depth_limit"] += 1
            return ep
        if ep.url in self.queued or ep.url in self.visited:
            return ep
        path = urlsplit(ep.url).path
        if STATIC.search(path) and not re.search(r"(?i)\.m?js$", path):
            ep.fetch_state = "static_asset_not_fetched"
            self.skipped["static_asset"] += 1
            return ep
        bucket = origin(ep.url) + path
        if self.variants[bucket] >= self.config.max_query_variants:
            self.skipped["query_variant_limit"] += 1
            self.inventory.issue("Query variation limit reached; pagination and parameter-dependent routes may be incomplete.")
            return ep
        self.variants[bucket] += 1
        self.queued.add(ep.url)
        self.queue.append((ep.url, depth))
        return ep

    def load_imports(self):
        for spec in self.config.imports:
            import_file(spec, self.inventory, self.config.target)

    def setup_robots(self):
        for site in sorted(self.scope.origins):
            robots = RobotFileParser()
            self.robots[site] = robots
            url = site + "/robots.txt"
            try:
                response = self.fetcher.get(url)
                self.visited.add(url)
                if response.status == 200 and not response.truncated:
                    robots.parse(response.text.splitlines())
                    for line in response.text.splitlines():
                        key, _, value = line.partition(":")
                        value = value.split("#", 1)[0].strip()
                        if key.lower().strip() == "sitemap":
                            self.enqueue(value, "robots_sitemap", base=site)
                        elif key.lower().strip() in {"allow", "disallow"} and value.startswith("/") and not any(c in value for c in "*$"):
                            self.enqueue(value, "robots_path", base=site, evidence="Path listed in robots.txt; existence unverified")
                elif response.status in {404, 410}:
                    robots.allow_all = True
                else:
                    robots.disallow_all = True
                    self.inventory.issue(f"robots.txt unavailable or restricted for {site}; crawl skipped when respect_robots is enabled.")
            except BudgetExceeded:
                self.stop_reason = "request_or_time_budget"
                return
            except FetchError as exc:
                robots.disallow_all = True
                self.inventory.issue(f"robots.txt could not be read for {site}: {exc}")

    def robots_allowed(self, url):
        return not self.config.respect_robots or self.robots.get(origin(url), RobotFileParser()).can_fetch("BotScope", url)

    def process(self, response, depth=0, source="crawl"):
        ep = self.inventory.add(response.url, "GET", source, status=response.status,
                                observed=True, content_type=response.headers.get("content-type", ""),
                                controls=control_hints(response.headers),
                                auth="request with configured credentials; enforcement unverified" if origin(response.url) in self.fetcher.headers else "response to request without configured credentials; session/auth enforcement unverified",
                                evidence=f"HTTP {response.status} observed during this scan")
        if ep:
            ep.fetch_state = "fetched"
        if response.truncated:
            self.inventory.issue("One or more responses exceeded the size limit; discovery used a truncated body.")
        if 300 <= response.status < 400 and response.headers.get("location"):
            self.enqueue(response.headers["location"], "redirect", depth + 1, base=response.url)
        if not 200 <= response.status < 300:
            return
        mime = response.headers.get("content-type", "").lower()
        path = urlsplit(response.url).path.lower()
        text = response.text
        try:
            if "html" in mime or text.lstrip().lower().startswith(("<!doctype html", "<html")):
                self.process_html(text, response.url, depth, source)
                if response.url not in self.browser_candidates:
                    self.browser_candidates.append(response.url)
            elif "javascript" in mime or path.endswith((".js", ".mjs")):
                for url, method, kind in javascript_refs(text):
                    self.enqueue(url, kind, depth + 1, base=response.url, method=method,
                                 evidence="Static JavaScript reference; execution and existence unverified")
            elif "xml" in mime or path.endswith(".xml"):
                for url, kind in sitemap_refs(text):
                    self.enqueue(url, kind, depth + (0 if kind == "sitemap_index" else 1), base=response.url)
            elif "json" in mime or "yaml" in mime or path.endswith((".json", ".yaml", ".yml")):
                doc = load_document(text)
                if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc):
                    import_openapi(doc, self.inventory, origin(response.url), "openapi_live", response.url)
                    for endpoint in list(self.inventory.endpoints.values()):
                        if "openapi_live" in endpoint.sources and endpoint.method == "GET":
                            self.enqueue(endpoint.url, "openapi_live", depth + 1)
                else:
                    for url in json_refs(doc):
                        self.enqueue(url, "json_link", depth + 1, base=response.url)
        except (ValueError, TypeError, KeyError, RecursionError, ExceptionGroup) as exc:
            self.inventory.issue(f"A response could not be parsed ({type(exc).__name__}); inspect discovery coverage.")
        except Exception as exc:
            # HTMLParser/ElementTree/YAML may have format-specific exception classes.
            self.inventory.issue(f"Unsupported or malformed response format ({type(exc).__name__}).")

    def process_html(self, text, url, depth, source):
        parser = PageParser(url)
        parser.feed(text)
        parser.close()
        for target, kind in parser.links:
            resolved = urljoin(parser.base, target)
            if urlsplit(resolved).fragment:
                if urlsplit(resolved).fragment.startswith("/"):
                    self.add_browser_candidate(resolved, "spa_hash_route")
                continue
            self.enqueue(target, kind if source == "crawl" else "browser_dom", depth + 1, base=parser.base)
        for target in parser.spa_routes:
            self.add_browser_candidate(urljoin(parser.base, target), "spa_hash_route")
        for form in parser.forms:
            ep = self.inventory.add(form.pop("url"), source="html_form" if source == "crawl" else "browser_form", base=parser.base,
                                    evidence="HTML form action, method and field names; form not submitted", **form)
            if ep:
                ep.fetch_state = "form_not_submitted"
                if "browser" not in ep.contexts:
                    ep.contexts.append("browser form")
                ep.controls.extend(h for h in control_hints({}, text) if h not in ep.controls)
        for script in parser.scripts:
            for target, method, kind in javascript_refs(script):
                self.enqueue(target, kind, depth + 1, base=parser.base, method=method,
                             evidence="Inline JavaScript literal; dynamic construction may be incomplete")

    def crawl(self):
        throttled = 0
        while self.queue:
            if self.fetcher.exhausted:
                self.stop_reason = "request_or_time_budget"
                break
            url, depth = self.queue.popleft()
            if url in self.visited:
                continue
            if not self.robots_allowed(url):
                self.skipped["robots_disallowed"] += 1
                ep = self.inventory.add(url)
                if ep:
                    ep.fetch_state = "robots_disallowed"
                continue
            self.visited.add(url)
            try:
                response = self.fetcher.get(url)
                self.process(response, depth)
                throttled = throttled + 1 if response.status == 429 else 0
                if throttled >= 3:
                    self.stop_reason = "repeated_throttling"
                    break
            except BudgetExceeded:
                self.stop_reason = "request_or_time_budget"
                break
            except FetchError as exc:
                self.skipped[str(exc)] += 1
                ep = self.inventory.add(url)
                if ep:
                    ep.fetch_state = str(exc)

    def run(self, offline=False):
        self.load_imports()
        if not offline:
            self.setup_robots()
            self.enqueue(self.config.target, "seed")
            for url in self.config.seed_urls:
                self.enqueue(url, "seed", base=self.config.target)
            for site in sorted(self.scope.origins):
                self.enqueue(site + "/sitemap.xml", "sitemap_probe")
                if self.config.discover_specs:
                    for path in SPEC_PATHS:
                        self.enqueue(site + path, "spec_probe", evidence="Common specification location; existence unverified")
            self.load_hidden_paths()
            self.crawl()
            if self.config.browser and not self.fetcher.exhausted and self.stop_reason != "repeated_throttling":
                from .browser import render_pages
                asyncio.run(render_pages(self))
                self.crawl()
        else:
            self.stop_reason = "offline_import_only"
        if self.queue:
            self.inventory.issue("The crawl frontier was not exhausted; increase the request/time budget or split the scope.")
        from .assessment import assess, catalogue
        endpoints = assess(self.inventory)
        gaps = ["Total site endpoint count is unknown; a crawl cannot certify 100% discovery.",
                "Business impact and control enforcement require application-owner validation; attacks were not executed.",
                "Unlinked, role-specific, mobile-only, feature-flagged and dynamically constructed routes need specifications, HARs or traffic inventories.",
                "GET requests can have side effects on poorly designed applications; review scope and exclusions before scanning production."]
        if not self.config.browser:
            gaps.append("JavaScript was analyzed statically; rendered SPA routes and runtime network requests were not observed.")
        if not self.config.imports:
            gaps.append("No offline inventories were supplied; authenticated and non-browser coverage is limited.")
        if self.inventory.rejected:
            gaps.append("Some discovered references were invalid or outside the explicit scope; review origins and imported server URLs.")
        return {"schema_version": "1.0", "tool_version": "0.1.0", "started_at": self.started,
                "finished_at": datetime.now(timezone.utc).isoformat(), "target": display_url(self.config.target),
                "scope": sorted(self.scope.origins), "mode": "offline" if offline else "discovery",
                "summary": {"endpoints": len(endpoints), "observed": sum(e["observed"] for e in endpoints),
                            "declared": sum(e["declared"] for e in endpoints),
                            "candidates": sum(e["suitability"] == "Recommended" for e in endpoints),
                            "priorities": dict(Counter(e["priority"] for e in endpoints))},
                "coverage": {"total_site_endpoints": None, "completion_percent": None,
                             "requests": self.fetcher.count, "stop_reason": self.stop_reason,
                             "remaining_queue": len(self.queue), "rejected_references": self.inventory.rejected,
                             "skipped": dict(self.skipped), "sources": dict(Counter(s.split(":")[0] for e in endpoints for s in e["sources"])),
                             "imports": self.inventory.imports, "browser": self.browser_result,
                             "websockets": list(self.websocket_channels.values()),
                             "forms": {"enabled": self.config.form_testing, "submitted": self.form_tests_submitted, "skipped": self.form_tests_skipped},
                             "hidden_paths": {"enabled": bool(self.config.hidden_path_wordlist), "queued": self.hidden_paths_enqueued, "limit": self.config.max_hidden_paths},
                             "limits": {k: getattr(self.config, k) for k in ("max_requests", "max_depth", "max_seconds", "max_endpoints", "max_query_variants", "max_interactions", "max_hidden_paths", "max_form_tests")},
                             "limitations": gaps, "issues": self.inventory.issues},
                "threat_catalogue": catalogue(), "endpoints": endpoints}
