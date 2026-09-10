from __future__ import annotations

import argparse
import json
import sys
from dataclasses import fields
from pathlib import Path

import yaml

from .assessment import catalogue
from .config import Config
from .report import write_reports
from .scanner import Scanner


def parser():
    p = argparse.ArgumentParser(prog="botscope", description="Discover web/API routes and assess potential bot abuse. No exploit testing.")
    p.add_argument("--version", action="version", version="BotScope 0.1.0")
    sub = p.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Crawl and/or import endpoint evidence")
    scan.add_argument("--config", type=Path)
    scan.add_argument("--target", help="Complete starting HTTP(S) URL")
    scan.add_argument("--allow-origin", dest="allowed_origins", action="append", help="Additional exact authorized origin; no implicit subdomains")
    scan.add_argument("--seed", dest="seed_urls", action="append", help="Additional starting URL")
    scan.add_argument("--exclude", dest="exclude_paths", action="append", help="Case-sensitive path glob to exclude")
    scan.add_argument("--max-requests", type=int)
    scan.add_argument("--max-depth", type=int)
    scan.add_argument("--max-seconds", type=float)
    scan.add_argument("--rate", dest="requests_per_second", type=float)
    scan.add_argument("--allow-private", action="store_true", default=None, help="Permit explicitly scoped private/loopback targets")
    scan.add_argument("--ignore-robots", action="store_true", help="Include routes excluded by robots.txt within your authorized scope")
    scan.add_argument("--browser", action="store_true", default=None, help="Render HTML and capture eligible runtime requests; requires Chromium")
    scan.add_argument("--headers-file", help="Private JSON mapping exact origins to request headers")
    scan.add_argument("--ca-bundle", help="Custom CA bundle for trusted enterprise TLS")
    scan.add_argument("--offline", action="store_true", help="Analyze supplied files without sending target requests")
    for kind in ("openapi", "har", "postman", "inventory", "urls"):
        scan.add_argument("--" + kind, action="append", type=Path, help=f"Import a local {kind} file (repeatable)")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium"], help="Optional CI exit code 3 for exposure at/above this priority")
    demo = sub.add_parser("demo", help="Generate a synthetic assessment without network access")
    for cmd in (scan, demo):
        cmd.add_argument("--output", type=Path, default=Path("reports/latest"))
        cmd.add_argument("--formats", default="json,html,csv", help="Comma-separated json,html,csv,xlsx,pdf (xlsx/pdf require reports extra)")
    sub.add_parser("catalogue", help="Print assessment scenarios and OWASP mapping")
    compare = sub.add_parser("compare", help="Compare two JSON reports without network access")
    compare.add_argument("--before", required=True, type=Path)
    compare.add_argument("--after", required=True, type=Path)
    compare.add_argument("--output", required=True, type=Path)
    return p


def config_from_args(args):
    values = {}
    if args.config:
        if args.config.stat().st_size > 1_000_000:
            raise ValueError("Configuration exceeds 1 MB")
        values = yaml.safe_load(args.config.read_text()) or {}
        if not isinstance(values, dict):
            raise ValueError("Configuration must be a mapping")
        values = dict(values)
        valid = {f.name for f in fields(Config)}
        if set(values) - valid:
            raise ValueError("Unknown configuration keys: " + ", ".join(sorted(set(values) - valid)))
        # File references in a config are relative to that config, not the shell cwd.
        root = args.config.resolve().parent
        for key in ("headers_file", "ca_bundle"):
            if values.get(key):
                values[key] = str(root / values[key])
        values["imports"] = [{**item, "path": str(root / item["path"])} for item in values.get("imports", [])]
    for item in fields(Config):
        value = getattr(args, item.name, None)
        if value is not None:
            values[item.name] = value
    if args.ignore_robots:
        values["respect_robots"] = False
    imports = list(values.get("imports", []))
    for kind in ("openapi", "har", "postman", "inventory", "urls"):
        for path in getattr(args, kind) or []:
            imports.append({"type": "csv" if kind == "inventory" and path.suffix.lower() == ".csv" else kind, "path": str(path)})
    values["imports"] = imports
    if not values.get("target"):
        raise ValueError("Supply --target or target in --config")
    if args.offline and not imports:
        raise ValueError("Offline mode requires at least one import")
    return Config(**values)


def demo_report():
    from .assessment import assess
    from .importers import import_inventory, import_openapi
    scanner = Scanner(Config(target="https://shop.example.test"))
    routes = {
        "/api/login": ("post", ["username", "password"]),
        "/api/register": ("post", ["email", "password", "referral"]),
        "/api/otp/send": ("post", ["phone", "purpose"]),
        "/api/payments/authorize": ("post", ["cardnumber", "cvv", "amount"]),
        "/api/cart/reserve": ("post", ["productId", "quantity"]),
        "/api/products": ("get", ["page", "limit"]),
        "/api/coupons/validate": ("post", ["coupon"]),
        "/api/search": ("get", ["query"]),
        "/api/graphql": ("post", ["query", "variables"]),
        "/api/reviews": ("post", ["rating", "comment"]),
        "/webhooks/payment": ("post", ["signature", "eventId"]),
        "/api/export": ("post", ["format", "filters"]),
        "/api/password/reset": ("post", ["email"]),
        "/api/appointments/hold": ("post", ["slotId"]),
        "/api/health": ("get", []),
    }
    doc = {"openapi": "3.1.0", "servers": [{"url": "https://shop.example.test"}],
           "paths": {path: {method: {"parameters": [{"name": field, "in": "query"} for field in params]}} for path, (method, params) in routes.items()}}
    import_openapi(doc, scanner.inventory, scanner.config.target, "openapi:synthetic")
    import_inventory([{"url": "https://shop.example.test" + path, "method": method.upper(), "observed": True, "status": 200,
                       "client_type": "service" if "webhook" in path else "unknown"}
                      for path, (method, params) in list(routes.items())[:11]], scanner.inventory, scanner.config.target, "inventory:synthetic")
    scanner.inventory.add("https://shop.example.test/assets/app.js", "GET", "synthetic", status=200, observed=True)
    scanner.inventory.add("https://shop.example.test/old-login", "GET", "synthetic", status=404, observed=True)
    scanner.inventory.add("https://shop.example.test/api/rewards/claim", "UNKNOWN", "javascript_literal")
    scanner.inventory.issue("SYNTHETIC DEMO: fictional endpoint data; no website was contacted.")
    report = scanner.run(offline=True)
    report["synthetic"] = True
    return report


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "catalogue":
            print(json.dumps(catalogue(), indent=2))
            return 0
        if args.command == "compare":
            before = json.loads(args.before.read_text())
            after = json.loads(args.after.read_text())
            if before.get("scope") != after.get("scope"):
                raise ValueError("Report scopes differ; compare equivalent scopes")
            a = {e["id"]: e for e in before["endpoints"]}
            b = {e["id"]: e for e in after["endpoints"]}
            result = {"note": "Missing endpoints may reflect changed inputs or coverage, not removal or remediation.",
                      "added": [b[k] for k in b.keys() - a.keys()],
                      "not_seen_in_latest": [a[k] for k in a.keys() - b.keys()],
                      "changed": [{"id": k, "url": b[k]["url"], "before_score": a[k]["score"], "after_score": b[k]["score"], "before_decision": a[k]["suitability"], "after_decision": b[k]["suitability"]}
                                  for k in a.keys() & b.keys() if (a[k]["score"], a[k]["suitability"]) != (b[k]["score"], b[k]["suitability"])]}
            args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            args.output.write_text(json.dumps(result, indent=2))
            args.output.chmod(0o600)
            print(f"Comparison written to {args.output}")
            return 0
        formats = [f.strip().lower() for f in args.formats.split(",")]
        if any(f not in {"json", "html", "csv", "xlsx", "pdf"} for f in formats):
            raise ValueError("Formats must be json,html,csv,xlsx,pdf")
        # Fail before crawling if a requested export cannot be produced.
        if "xlsx" in formats:
            import openpyxl  # noqa: F401
        if "pdf" in formats:
            import reportlab  # noqa: F401
        report = demo_report() if args.command == "demo" else Scanner(config_from_args(args)).run(offline=args.offline)
        paths = write_reports(report, args.output, formats)
        s = report["summary"]
        print(f"BotScope: {s['endpoints']} endpoints | {s['observed']} observed | {s['candidates']} protection candidates")
        print("Potential bot exposure only. Review report coverage and validate with application owners.")
        for path in paths:
            print(path)
        if args.command == "scan":
            if not any(e["observed"] or e["declared"] for e in report["endpoints"]):
                print("No observed or declared endpoints; review connectivity, scope and imports.", file=sys.stderr)
                return 2
            if report["coverage"]["browser"].get("error"):
                print("Browser discovery did not complete; partial reports were written.", file=sys.stderr)
                return 2
            threshold = {"critical": 90, "high": 75, "medium": 50}.get(args.fail_on)
            if threshold and any(ep["score"] >= threshold for ep in report["endpoints"]):
                return 3
        return 0
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, RecursionError) as exc:
        # Do not echo data-bearing parser exceptions from HARs or private configurations.
        print(f"BotScope input/output error ({type(exc).__name__}). Check paths, schema and configuration; see README examples.", file=sys.stderr)
        return 2
    except ImportError as exc:
        print(f"Missing optional dependency: {exc.name}. Install pip install '.[reports,browser]' as needed.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return 130
