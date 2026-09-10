"""Offline imports never replay requests, submit forms, or run collection scripts."""
from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from urllib.parse import urljoin

import yaml

from .discovery import body_parameter_names, control_hints
from .model import METHODS, canonical_url, safe_label

MAX_IMPORT_BYTES = 32_000_000


def load_document(text: str):
    if len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValueError("Input exceeds the 32 MB import limit; split the export")
    if text.lstrip().startswith(("{", "[")):
        return json.loads(text)
    if any(isinstance(token, yaml.tokens.AliasToken) for token in yaml.scan(text)):
        raise ValueError("YAML aliases are not supported; supply an expanded/bundled specification")
    return yaml.safe_load(text)


class Resolver:
    def __init__(self, document, inventory):
        self.document, self.inventory = document, inventory

    def resolve(self, value, seen=()):
        if not isinstance(value, dict) or "$ref" not in value:
            return value
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            self.inventory.issue("External OpenAPI references were not loaded; provide a bundled specification.")
            return {}
        if ref in seen or len(seen) > 20:
            return {}
        try:
            target = self.document
            for part in ref[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
            resolved = self.resolve(target, seen + (ref,))
            return {**resolved, **{k: v for k, v in value.items() if k != "$ref"}} if isinstance(resolved, dict) else {}
        except (KeyError, TypeError):
            self.inventory.issue("An internal OpenAPI reference could not be resolved.")
            return {}

    def fields(self, schema, depth=0, seen=None):
        seen = set() if seen is None else seen
        if depth > 12 or not isinstance(schema, dict) or id(schema) in seen:
            return set()
        seen.add(id(schema))
        schema = self.resolve(schema)
        names = set(schema.get("properties", {}))
        for child in schema.get("properties", {}).values():
            names.update(self.fields(child, depth + 1, seen))
        for item in ("allOf", "oneOf", "anyOf"):
            for child in schema.get(item, []):
                names.update(self.fields(child, depth + 1, seen))
        names.update(self.fields(schema.get("items", {}), depth + 1, seen))
        return names


def server_urls(servers, document_url, fallback):
    result = []
    for server in servers or []:
        if not isinstance(server, dict):
            continue
        url = server.get("url", "")
        for key, variable in server.get("variables", {}).items():
            if "default" in variable:
                url = url.replace("{" + key + "}", str(variable["default"]))
        if url:
            result.append(urljoin(document_url or fallback, url))
    return result or [fallback]


def import_openapi(doc, inventory, base_url, source="openapi", document_url=""):
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc):
        raise ValueError("Expected an OpenAPI 3.x or Swagger 2.0 document")
    resolver = Resolver(doc, inventory)
    if "swagger" in doc:
        scheme = (doc.get("schemes") or [base_url.split(":")[0]])[0]
        default_server = f"{scheme}://{doc['host']}{doc.get('basePath', '')}" if doc.get("host") else base_url.rstrip("/") + doc.get("basePath", "")
        default_servers = [{"url": default_server}]
    else:
        default_servers = doc.get("servers") or [{"url": "/"}]
    for path, raw_item in doc.get("paths", {}).items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        item = resolver.resolve(raw_item)
        if not isinstance(item, dict):
            continue
        for method, raw_op in item.items():
            if method.upper() not in METHODS - {"UNKNOWN", "TRACE", "CONNECT"}:
                continue
            op = resolver.resolve(raw_op)
            if not isinstance(op, dict):
                continue
            fields = set()
            for param in item.get("parameters", []) + op.get("parameters", []):
                param = resolver.resolve(param)
                if param.get("name"):
                    fields.add(param["name"])
                fields.update(resolver.fields(param.get("schema", {})))
            body = resolver.resolve(op.get("requestBody", {}))
            for media in body.get("content", {}).values():
                fields.update(resolver.fields(media.get("schema", {})))
            security = op.get("security", doc.get("security", []))
            auth = "declared:required" if security and {} not in security else "declared:optional_or_none"
            contexts = [op.get("operationId", ""), op.get("summary", "")] + op.get("tags", [])
            servers = op.get("servers", item.get("servers", default_servers))
            for server in server_urls(servers, document_url, base_url):
                inventory.add(server.rstrip("/") + path, method, source,
                              parameters=fields, contexts=contexts, auth=auth, declared=True,
                              evidence="Method and route declared in API specification")
    if doc.get("webhooks"):
        inventory.issue("OpenAPI webhook expressions require concrete inbound URLs; supply them through inventory import.")


def import_har(doc, inventory, base_url, source="har"):
    entries = doc.get("log", {}).get("entries") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise ValueError("Expected a HAR log.entries array")
    for entry in entries:
        request, response = entry.get("request", {}), entry.get("response", {})
        headers = {h.get("name", "").lower(): h.get("value", "") for h in request.get("headers", [])}
        rh = {h.get("name", "").lower(): h.get("value", "") for h in response.get("headers", [])}
        post = request.get("postData", {})
        fields = [p.get("name", "") for p in post.get("params", [])]
        fields += body_parameter_names(post.get("text", ""), post.get("mimeType", ""))
        operation, contexts = "", []
        try:
            payload = json.loads(post.get("text", "{}"))
            if isinstance(payload, dict) and isinstance(payload.get("query"), str):
                operation = payload.get("operationName") or ""
                match = re.match(r"\s*(query|mutation|subscription)\s*(\w+)?", payload["query"])
                if match:
                    operation = operation or match[2] or "anonymous"
                    contexts = ["graphql " + match[1]]
        except ValueError:
            pass
        inventory.add(request.get("url", ""), request.get("method", "UNKNOWN"), source,
                      base=base_url, operation=operation, contexts=contexts,
                      parameters=fields, status=response.get("status", 0),
                      content_type=rh.get("content-type", response.get("content", {}).get("mimeType", "")),
                      controls=control_hints(rh), observed=True,
                      auth="credentials present in captured request; enforcement unverified" if any(k in headers for k in ("authorization", "cookie", "x-api-key")) else "captured request without explicit credential headers",
                      evidence="Request recorded in imported HAR; response bodies and credentials discarded")


def import_postman(doc, inventory, base_url, source="postman", variables=None):
    if not isinstance(doc, dict) or "item" not in doc:
        raise ValueError("Expected a Postman collection")
    values = {v["key"]: str(v.get("value", "")) for v in doc.get("variable", []) if "key" in v}
    values.update(variables or {})
    def substitute(text):
        return re.sub(r"\{\{([^{}]+)\}\}", lambda m: values.get(m[1], m[0]), text)
    def walk(items, depth=0):
        if depth > 20:
            inventory.issue("Postman folder nesting limit reached.")
            return
        for item in items:
            if "item" in item:
                walk(item["item"], depth + 1)
            request = item.get("request")
            if not request:
                continue
            if isinstance(request, str):
                request = {"url": request}
            url = request.get("url", "")
            if isinstance(url, dict):
                url = url.get("raw") or (url.get("protocol", "https") + "://" + ".".join(url.get("host", [])) + "/" + "/".join(url.get("path", [])))
            url = substitute(url)
            if "{{" in url:
                inventory.issue("Unresolved Postman variables; supply variables in the import configuration.")
                continue
            body = request.get("body", {})
            fields = [p.get("key", "") for p in body.get("urlencoded", []) + body.get("formdata", [])]
            fields += body_parameter_names(body.get("raw", ""))
            inventory.add(url, request.get("method", "GET"), source, base=base_url,
                          parameters=fields, contexts=[item.get("name", "")], declared=True,
                          evidence="Request declared in Postman; scripts were not executed")
    walk(doc.get("item", []))


def import_inventory(rows, inventory, base_url, source="inventory", mapping=None):
    if isinstance(rows, dict):
        rows = rows.get("endpoints", rows.get("items", []))
    if not isinstance(rows, list):
        raise ValueError("Expected inventory rows or an endpoints array")
    mapping = mapping or {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        row = {**row, **{dest: row.get(src) for dest, src in mapping.items()}}
        url = row.get("url")
        if not url:
            host = row.get("host") or row.get("domain")
            base = (host if "://" in str(host) else "https://" + host) if host else base_url
            url = base.rstrip("/") + "/" + str(row.get("path", "")).lstrip("/")
        raw_fields = row.get("parameters") or []
        fields = re.split(r"[,;|]", raw_fields) if isinstance(raw_fields, str) else raw_fields
        observed = str(row.get("observed", "")).lower() in {"true", "1", "yes"}
        status = row.get("status") or row.get("status_code") or 0
        client = row.get("client_type", "unknown")
        if client not in {"browser", "mobile", "service", "mixed", "unknown"}:
            client = "unknown"
        inventory.add(url, row.get("method") or "UNKNOWN", source, base=base_url,
                      operation=row.get("operation") or "", parameters=fields,
                      contexts=[row.get("function") or ""],
                      auth=row.get("auth") or "", observed=observed,
                      declared=str(row.get("declared", "")).lower() in {"true", "1", "yes"},
                      status=int(status), client_type=client,
                      evidence="Endpoint supplied in inventory; validate export completeness with application owner")


def import_graphql(doc, inventory, base_url, source="graphql", endpoint=None):
    if not endpoint:
        raise ValueError("GraphQL import requires endpoint: the concrete GraphQL HTTP URL")
    schema = doc.get("data", doc).get("__schema", doc.get("__schema", {}))
    if not schema:
        raise ValueError("Expected a GraphQL introspection JSON result containing __schema")
    types = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
    for kind in ("query", "mutation", "subscription"):
        name = (schema.get(kind + "Type") or {}).get("name")
        for field in types.get(name, {}).get("fields", []) or []:
            inventory.add(endpoint, "POST", source, base=base_url,
                          operation=kind + ":" + field["name"],
                          parameters=[arg["name"] for arg in field.get("args", [])],
                          contexts=["graphql " + kind, field["name"]], declared=True,
                          evidence="GraphQL schema field declared; HTTP transport and operation usage require confirmation")
    inventory.issue("GraphQL HTTP transport is assumed POST; schema fields do not prove deployed operations or subscriptions transport.")


def import_file(spec, inventory, default_base):
    path = Path(spec["path"])
    if path.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError("Input exceeds 32 MB; split the export")
    text = path.read_text(encoding="utf-8-sig")
    kind = spec["type"].lower()
    base = spec.get("base_url", default_base)
    if not canonical_url(base):
        raise ValueError("Import base_url must be a valid HTTP(S) URL")
    source = kind + ":" + safe_label(path.name)
    before = len(inventory.endpoints)
    if kind == "urls":
        for line in text.splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                parts = line.strip().split(None, 1)
                method, url = parts if len(parts) == 2 and parts[0] in METHODS else ("UNKNOWN", line.strip())
                inventory.add(url, method, source, base=base, evidence="User-supplied route")
    elif kind in {"csv", "inventory", "xc"}:
        rows = list(csv.DictReader(io.StringIO(text))) if kind == "csv" or path.suffix.lower() == ".csv" else load_document(text)
        import_inventory(rows, inventory, base, source, spec.get("mapping"))
    else:
        doc = load_document(text)
        if kind == "openapi":
            import_openapi(doc, inventory, base, source, spec.get("document_url", ""))
        elif kind == "har":
            import_har(doc, inventory, base, source)
        elif kind == "postman":
            import_postman(doc, inventory, base, source, spec.get("variables"))
        elif kind == "graphql":
            import_graphql(doc, inventory, base, source, spec.get("endpoint"))
        else:
            raise ValueError(f"Unsupported import type: {kind}")
    inventory.imports.append({"type": kind, "file": safe_label(path.name), "new_endpoints": len(inventory.endpoints) - before})
