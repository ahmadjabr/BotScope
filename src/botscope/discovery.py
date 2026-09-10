from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from urllib.parse import urljoin

from .model import METHODS, safe_label


def control_hints(headers: dict, text: str = "") -> list[str]:
    result = []
    for name in headers:
        if "ratelimit" in name.lower() or name.lower() == "retry-after":
            result.append("Rate-limit response header observed; enforcement unverified")
    lower = text.lower()
    if any(s in lower for s in ("g-recaptcha", "h-captcha", "cf-turnstile", "recaptcha/api.js")):
        result.append("CAPTCHA/Turnstile markup observed; enforcement unverified")
    if any(s in lower for s in ("csrf", "xsrf")):
        result.append("CSRF marker observed; does not establish bot protection")
    return list(dict.fromkeys(result))


class PageParser(HTMLParser):
    def __init__(self, url: str):
        super().__init__(convert_charrefs=True)
        self.url, self.base = url, url
        self.links: list[tuple[str, str]] = []
        self.forms: list[dict] = []
        self.scripts: list[str] = []
        self.current_form = None
        self.in_script = False
        self.in_title = False
        self.title = ""
        self.script_buffer: list[str] = []
        self.has_base = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "base" and a.get("href") and not self.has_base:
            self.base, self.has_base = urljoin(self.url, a["href"]), True
        if tag in {"a", "area", "iframe", "frame", "link", "script"}:
            value = a.get("src") if tag in {"iframe", "frame", "script"} else a.get("href")
            if value:
                kind = "javascript_asset" if tag == "script" or (tag == "link" and a.get("rel") == "modulepreload") else "html_link"
                self.links.append((value, kind))
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"(?i)url\s*=\s*['\"]?([^'\"]+)", a.get("content", ""))
            if match:
                self.links.append((match[1].strip(), "meta_refresh"))
        if tag == "form":
            if self.current_form:
                self.forms.append(self.current_form)
            self.current_form = {"url": a.get("action", self.url), "method": a.get("method", "GET").upper(), "parameters": [], "contexts": [], "controls": []}
        if tag in {"input", "select", "textarea", "button"} and self.current_form is not None:
            if a.get("name"):
                self.current_form["parameters"].append(safe_label(a["name"]))
            if a.get("type") == "password":
                self.current_form["contexts"].append("password field")
            if a.get("type") == "email":
                self.current_form["contexts"].append("email field")
            if "csrf" in a.get("name", "").lower():
                self.current_form["controls"].append("CSRF field observed; not a bot control")
            if a.get("formaction"):
                self.forms.append({"url": a["formaction"], "method": a.get("formmethod", self.current_form["method"]).upper(), "parameters": self.current_form["parameters"], "contexts": self.current_form["contexts"], "controls": self.current_form["controls"]})
        if tag == "script":
            self.in_script, self.script_buffer = True, []
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None
        if tag == "script":
            self.in_script = False
            self.scripts.append("".join(self.script_buffer))
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_script:
            self.script_buffer.append(data)
        if self.in_title:
            self.title += data

    def close(self):
        super().close()
        if self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def javascript_refs(text: str) -> list[tuple[str, str, str]]:
    """Static literals only. Templates/unresolved methods remain inventory candidates."""
    result = []
    used = set()
    pattern = r"(?:fetch\s*\(|axios(?:\.(get|post|put|patch|delete|head|options))?\s*\()\s*['\"]([^'\"\n]+)['\"]([^;\n]{0,400})"
    for match in re.finditer(pattern, text):
        verb, url, tail = match.groups()
        method = re.search(r"method\s*:\s*['\"]([A-Za-z]+)['\"]", tail)
        is_fetch = match.group(0).lstrip().startswith("fetch")
        verb = (verb or (method.group(1) if method else ("GET" if is_fetch else "UNKNOWN"))).upper()
        result.append((url, verb, "javascript_call"))
        used.add(url)
    for match in re.finditer(r"\.open\s*\(\s*['\"]([A-Z]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", text):
        result.append((match[2], match[1], "javascript_call"))
        used.add(match[2])
    for match in re.finditer(r"['\"]((?:https?://|/)[^'\"\s<>]{1,1000})['\"]", text):
        url = match[1].replace("\\/", "/")
        if url not in used:
            result.append((url, "GET" if re.search(r"\.m?js(?:\?|$)", url) else "UNKNOWN", "javascript_literal"))
            used.add(url)
    return result[:5000]


def sitemap_refs(text: str) -> list[tuple[str, str]]:
    if re.search(r"(?i)<!DOCTYPE|<!ENTITY", text):
        raise ValueError("XML entity declarations are not supported")
    root = ET.fromstring(text)
    kind = "sitemap_index" if root.tag.rsplit("}", 1)[-1] == "sitemapindex" else "sitemap"
    return [(node.text.strip(), kind) for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "loc" and node.text][:20000]


def json_refs(value, depth=0) -> list[str]:
    if depth > 12:
        return []
    result = []
    if isinstance(value, dict):
        for key, item in list(value.items())[:2000]:
            if key.lower() in {"href", "url", "next", "previous", "next_page", "nextpage"} and isinstance(item, str):
                if item.startswith(("http://", "https://", "/")):
                    result.append(item)
            elif isinstance(item, (dict, list)):
                result.extend(json_refs(item, depth + 1))
    elif isinstance(value, list):
        for item in value[:1000]:
            result.extend(json_refs(item, depth + 1))
    return result[:5000]


def body_parameter_names(body: str, mime: str = "") -> list[str]:
    try:
        value = json.loads(body)
        names = set()
        def walk(obj, depth=0):
            if depth > 8:
                return
            if isinstance(obj, dict):
                for key, item in list(obj.items())[:200]:
                    names.add(safe_label(key))
                    walk(item, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:5]:
                    walk(item, depth + 1)
        walk(value)
        return sorted(names)
    except (ValueError, RecursionError):
        if "x-www-form-urlencoded" in mime:
            from urllib.parse import parse_qsl
            return [safe_label(k) for k, _ in parse_qsl(body, max_num_fields=1000)]
        return []
