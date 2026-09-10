from __future__ import annotations

import json
import re
from importlib.resources import files
from urllib.parse import urlsplit

from .model import STATIC, origin


def catalogue():
    return json.loads(files("botscope").joinpath("data/threats.json").read_text())


def matches(rule, text, ep):
    if rule.get("methods") and ep.method not in rule["methods"]:
        return False
    if rule.get("exclude") and re.search(rule["exclude"], text, re.I):
        return False
    return any(re.search(pattern, text, re.I) for pattern in rule["patterns"])


def assess(inventory):
    catalog = catalogue()
    endpoints = list(inventory.endpoints.values())
    declarations = []
    for ep in endpoints:
        if ep.declared:
            path = re.escape(urlsplit(ep.url).path)
            path = re.sub(r"\\\{[^{}]*?\\\}", "[^/]+", path)
            declarations.append((ep, re.compile("^" + path + "$")))
    for ep in endpoints:
        p = urlsplit(ep.url)
        route_text = " ".join([p.path, ep.operation] + ep.contexts)
        text = " ".join([route_text] + ep.parameters)
        # Split common operationId/field naming conventions as well as path segments.
        text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
        text = re.sub(r"[_./-]", " ", text)
        route_text = re.sub(r"[_./-]", " ", re.sub(r"([a-z])([A-Z])", r"\1 \2", route_text))
        ep.threats = []
        ep.validation = ["Confirm endpoint purpose, owner and legitimate clients.",
                         "Verify controls from policy and traffic evidence; a header or successful response does not prove enforcement."]
        if ep.observed:
            matched = any(other.method == ep.method and origin(other.url) == origin(ep.url) and pattern.fullmatch(p.path)
                          for other, pattern in declarations)
            ep.inventory_status = "Observed and declared" if matched else "Observed outside supplied specification" if declarations else "Observed; no specification baseline"
        elif ep.declared:
            ep.inventory_status = "Declared; not observed"
        else:
            ep.inventory_status = "Discovered; not observed"
        if ep.method == "UNKNOWN":
            ep.validation.insert(0, "Determine the actual HTTP method from API specifications or a HAR capture.")
        if STATIC.search(p.path):
            ep.classifications = ["Static asset"]
            ep.suitability, ep.priority, ep.score = "Usually unnecessary", "Informational", 5
            ep.recommendation = "Use caching/CDN and volumetric controls as appropriate; avoid applying interactive challenges to static assets by default."
            continue
        for rule in catalog["rules"]:
            match_text = route_text if rule.get("match_on") == "route" else text
            if matches(rule, match_text, ep):
                matched = next(re.search(pattern, match_text, re.I).group(0) for pattern in rule["patterns"] if re.search(pattern, match_text, re.I))
                ep.threats.append({"id": rule["id"], "name": rule["name"], "owasp": rule["owasp"],
                                   "scenario": rule["scenario"], "controls": rule["controls"],
                                   "validation": rule["validation"], "score": rule["score"],
                                   "status": "potential_exposure_not_exploit_verified",
                                   "basis": "Heuristic match: " + matched[:120]})
        if ep.controls and any("CAPTCHA" in h for h in ep.controls):
            ep.validation.append("Validate CAPTCHA server-side verification and coverage of the underlying API; no bypass test was performed.")
        ep.classifications = [t["name"] for t in ep.threats]
        ep.score = max((t["score"] for t in ep.threats), default=20)
        reliable_source = any(s.startswith(("openapi", "har", "html_form", "browser_form", "postman", "inventory", "csv", "xc", "graphql")) for s in ep.sources)
        ep.confidence = "high" if reliable_source and ep.observed and ep.threats else "medium" if reliable_source and ep.threats else "low"
        ep.suitability = "Recommended" if ep.threats else "Review"
        api = "/api" in p.path.lower() or any("json" in m for m in ep.content_types) or "graphql" in text.lower()
        if ep.client_type == "unknown":
            ep.client_type = "browser" if any("form" in s for s in ep.sources) and not api else "unknown"
        if re.search(r"\b(webhooks?|callbacks?|health|healthz|readyz|metrics|oauth|saml)\b", text, re.I) or ep.client_type == "service":
            ep.suitability = "Conditional"
            ep.recommendation = "Confirm machine-client usage. Use signature/replay validation, mTLS or OAuth where appropriate, identity quotas and anomaly monitoring. Interactive JavaScript/CAPTCHA challenges can break service and federation flows."
        elif api or ep.client_type in {"mobile", "mixed"}:
            ep.recommendation = "Evaluate bot protection with compatible web/mobile telemetry or API-side signals; add per-account/device/token quotas and business validation. Confirm all client types before choosing challenge behavior."
        elif ep.threats:
            ep.recommendation = "Prioritize this browser flow for bot telemetry and risk-based mitigation. Start with monitoring, validate legitimate-user impact, then tune challenges/blocking and per-identity limits."
        else:
            ep.recommendation = "Confirm business value and traffic patterns before deciding on dedicated bot protection; preserve legitimate search engines and integrations."
        if ep.method == "UNKNOWN":
            ep.suitability = "Verify method"
        if ep.statuses and all(s in {404, 410} for s in ep.statuses) and not ep.declared:
            ep.suitability, ep.priority, ep.score = "Verify existence", "Informational", 0
            ep.validation.append("Only not-found responses were observed; check stale links, soft 404s and access masking.")
        elif re.search(r"/(?:blog|docs|articles|help)/", p.path, re.I) and not reliable_source:
            ep.suitability, ep.score = "Review", min(ep.score, 30)
        if ep.priority != "Informational":
            ep.priority = "Critical" if ep.score >= 90 else "High" if ep.score >= 75 else "Medium" if ep.score >= 50 else "Low" if ep.threats else "Review"
        ep.validation.extend(dict.fromkeys(t["validation"] for t in ep.threats))
    return sorted((ep.export() for ep in endpoints), key=lambda e: (-e["score"], e["url"], e["method"]))
