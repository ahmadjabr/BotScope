import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from botscope.assessment import assess, catalogue
from botscope.config import Config, Scope
from botscope.discovery import PageParser, javascript_refs, sitemap_refs
from botscope.importers import import_graphql, import_har, import_inventory, import_openapi, import_postman
from botscope.model import Inventory, canonical_url, display_url
from botscope.transport import FetchError, Fetcher, read_headers, resolve_public


def inventory():
    return Inventory(Scope(Config(target="https://shop.example.test")))


class URLAndScopeTests(unittest.TestCase):
    def test_canonical_preserves_case_and_slash(self):
        self.assertEqual(canonical_url("https://SHOP.example.test:443/Login/?b=2#x"), "https://shop.example.test/Login/?b=2")

    def test_bad_urls(self):
        for value in ["file:///etc/passwd", "https://user:pass@shop.example.test", "http://x:99999", "https://good.test\\@bad.test/", "javascript:alert(1)"]:
            self.assertIsNone(canonical_url(value))

    def test_exact_origin(self):
        s = Scope(Config(target="https://shop.example.test"))
        for url in ["https://shop.example.test.evil.test", "https://api.shop.example.test", "http://shop.example.test", "https://shop.example.test:444"]:
            self.assertFalse(s.contains(url))
        self.assertTrue(s.contains("https://shop.example.test/api"))

    def test_no_auth_redirect_leak(self):
        s = Scope(Config(target="https://shop.example.test", allowed_origins=["https://api.example.test"]))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "auth.json"
            p.write_text(json.dumps({"https://shop.example.test": {"Authorization": "Bearer example-secret"}}))
            headers = read_headers(str(p), s)
            self.assertEqual(headers.get("https://api.example.test", {}), {})

    def test_suspicious_gets(self):
        s = Scope(Config(target="https://shop.example.test"))
        for url in ["/logout", "/api/delete?id=1", "/reset/123456", "/x?token=secret", "/%6cogout", "/api/{id}"]:
            self.assertIsNotNone(s.fetch_reason("https://shop.example.test" + url))
        self.assertEqual(s.fetch_reason("https://shop.example.test/api/login", "POST"), "non_read_method")

    def test_dot_segments_cannot_escape_path_scope(self):
        s = Scope(Config(target="https://shop.example.test", include_paths=["/api/*"], exclude_paths=["/api/private/*"]))
        self.assertFalse(s.contains("https://shop.example.test/api/../admin"))
        self.assertFalse(s.contains("https://shop.example.test/api/x/%2e%2e/private/data"))

    def test_report_redaction_retains_semantic_routes(self):
        self.assertEqual(display_url("https://shop.example.test/api/password/reset?email=person@example.test"), "https://shop.example.test/api/password/reset?email=[redacted]")
        self.assertNotIn("123456", display_url("https://shop.example.test/reset/123456"))

    def test_methods_and_query_names_deduplicate(self):
        inv = inventory()
        inv.add("/login?a=1", base="https://shop.example.test", method="GET")
        inv.add("/login?a=2", base="https://shop.example.test", method="GET")
        inv.add("/login?a=1", base="https://shop.example.test", method="POST")
        inv.add("/login?b=1", base="https://shop.example.test", method="GET")
        self.assertEqual(len(inv.endpoints), 3)

    def test_resource_limits(self):
        for kwargs in [{"max_depth": 0}, {"requests_per_second": float("nan")}, {"requests_per_second": 1e-10}, {"max_requests": True}]:
            with self.assertRaises(ValueError):
                Config(target="https://shop.example.test", **kwargs)

    def test_private_and_metadata_dns(self):
        for address, private in [("127.0.0.1", False), ("169.254.169.254", True), ("::ffff:127.0.0.1", False), ("224.0.0.1", True)]:
            with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))]):
                with self.assertRaises(FetchError):
                    resolve_public("example.test", 80, private)

    def test_mixed_public_private_dns_rejected(self):
        values = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80)) for ip in ["8.8.8.8", "10.0.0.1"]]
        with patch("socket.getaddrinfo", return_value=values):
            with self.assertRaises(FetchError):
                resolve_public("example.test", 80, False)


class DiscoveryTests(unittest.TestCase):
    def test_forms_fields_without_values(self):
        p = PageParser("https://shop.example.test/account/")
        p.feed('<base href="/v2/"><form method="post" action="login"><input name="password" value="SECRET" type="password"><button formaction="other">Go</button></form>')
        p.close()
        self.assertEqual(p.base, "https://shop.example.test/v2/")
        self.assertEqual(p.forms[-1]["parameters"], ["password"])
        self.assertNotIn("SECRET", json.dumps(p.forms))

    def test_js_method_uncertainty(self):
        refs = javascript_refs('fetch("/api/products"); axios.post("/api/login",{}); let a="/api/unknown";')
        self.assertIn(("/api/login", "POST", "javascript_call"), refs)
        self.assertIn(("/api/unknown", "UNKNOWN", "javascript_literal"), refs)

    def test_sitemap_namespace_and_entities(self):
        self.assertEqual(sitemap_refs('<urlset xmlns="x"><url><loc>https://shop.example.test/a</loc></url></urlset>')[0][0], "https://shop.example.test/a")
        with self.assertRaises(ValueError):
            sitemap_refs('<!DOCTYPE doc [<!ENTITY secret SYSTEM "file:///etc/passwd">]><doc>&secret;</doc>')


class ImportTests(unittest.TestCase):
    def test_openapi_refs_servers_and_auth_override(self):
        inv = inventory()
        doc = {"openapi": "3.1.0", "security": [{"bearer": []}], "servers": [{"url": "/v1"}], "paths": {
            "/login": {"post": {"security": [], "requestBody": {"$ref": "#/components/requestBodies/Login"}}},
            "/users/{id}": {"get": {}},
            "/other": {"get": {"servers": [{"url": "https://outside.test"}]}}},
            "components": {"requestBodies": {"Login": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/User"}}}}}, "schemas": {"User": {"properties": {"password": {"type": "string"}, "child": {"$ref": "#/components/schemas/User"}}}}}}
        import_openapi(doc, inv, "https://shop.example.test")
        eps = list(inv.endpoints.values())
        self.assertEqual(len(eps), 2)
        login = next(e for e in eps if e.method == "POST")
        self.assertEqual(login.url, "https://shop.example.test/v1/login")
        self.assertIn("password", login.parameters)
        self.assertEqual(login.auth, ["declared:optional_or_none"])
        self.assertGreater(inv.rejected, 0)

    def test_swagger_two_base_path(self):
        inv = inventory()
        import_openapi({"swagger": "2.0", "host": "shop.example.test", "schemes": ["https"], "basePath": "/api", "paths": {"/login": {"post": {}}}}, inv, "https://shop.example.test")
        self.assertEqual(next(iter(inv.endpoints.values())).url, "https://shop.example.test/api/login")

    def test_external_ref_not_loaded(self):
        inv = inventory()
        import_openapi({"openapi": "3.1.0", "paths": {"/x": {"$ref": "https://evil.test/schema"}}}, inv, "https://shop.example.test")
        self.assertTrue(inv.issues)

    def test_har_never_exports_credentials_or_bodies(self):
        inv = inventory()
        doc = {"log": {"entries": [{"request": {"url": "https://shop.example.test/login?token=QUERYSECRET", "method": "POST", "headers": [{"name": "Authorization", "value": "HEADERSECRET"}], "postData": {"text": '{"password":"BODYSECRET"}'}}, "response": {"status": 200, "content": {"text": "RESPONSESECRET"}}}]}}
        import_har(doc, inv, "https://shop.example.test")
        output = json.dumps(assess(inv))
        for secret in ["QUERYSECRET", "HEADERSECRET", "BODYSECRET", "RESPONSESECRET"]:
            self.assertNotIn(secret, output)
        self.assertIn("password", output)

    def test_postman_nested_variables_no_scripts(self):
        inv = inventory()
        doc = {"variable": [{"key": "base", "value": "https://shop.example.test"}], "item": [{"item": [{"name": "Login", "request": {"method": "POST", "url": "{{base}}/login"}, "event": [{"script": {"exec": ["throw new Error('must not run')"]}}]}]}]}
        import_postman(doc, inv, "https://shop.example.test")
        self.assertEqual(next(iter(inv.endpoints.values())).method, "POST")

    def test_graphql_fields_are_separate(self):
        inv = inventory()
        doc = {"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "Query", "fields": [{"name": "search", "args": [{"name": "term"}]}, {"name": "products", "args": []}]}]}}}
        import_graphql(doc, inv, "https://shop.example.test", endpoint="/graphql")
        self.assertEqual(len(inv.endpoints), 2)
        self.assertTrue(all(e.declared and not e.observed for e in inv.endpoints.values()))

    def test_inventory_field_mapping(self):
        inv = inventory()
        import_inventory([{"domain": "shop.example.test", "route": "/api/booking", "verb": "POST"}], inv, "https://shop.example.test", mapping={"path": "route", "method": "verb"})
        self.assertEqual(next(iter(inv.endpoints.values())).url, "https://shop.example.test/api/booking")


class AssessmentTests(unittest.TestCase):
    def result(self, path, method="POST", **kwargs):
        inv = inventory()
        inv.add(path, method, "openapi:test", base="https://shop.example.test", declared=True, **kwargs)
        return assess(inv)[0]

    def test_login_maps_both_credential_threats(self):
        r = self.result("/login", parameters=["username", "password"])
        ids = {t["id"] for t in r["threats"]}
        self.assertTrue({"BS-001", "BS-002"}.issubset(ids))
        self.assertNotIn("BS-020", ids)

    def test_signup_not_credential_stuffing(self):
        r = self.result("/register", parameters=["password"], contexts=["password field"])
        self.assertNotIn("BS-001", [t["id"] for t in r["threats"]])

    def test_webhook_not_carding(self):
        r = self.result("/webhooks/payment")
        self.assertEqual(r["suitability"], "Conditional")
        self.assertNotIn("BS-007", [t["id"] for t in r["threats"]])
        self.assertIn("BS-024", [t["id"] for t in r["threats"]])

    def test_assets_not_high_risk(self):
        r = self.result("/assets/login.js", "GET")
        self.assertEqual(r["priority"], "Informational")

    def test_no_fabricated_control_failure(self):
        r = self.result("/login")
        self.assertEqual(r["confidence"], "medium")
        self.assertTrue(all(t["status"] == "potential_exposure_not_exploit_verified" for t in r["threats"]))

    def test_unknown_method_not_recommended(self):
        self.assertEqual(self.result("/login", "UNKNOWN")["suitability"], "Verify method")

    def test_route_template_reconciliation(self):
        inv = inventory()
        inv.add("https://shop.example.test/users/{id}", "GET", "openapi", declared=True)
        inv.add("https://shop.example.test/users/123", "GET", "har", observed=True)
        r = next(e for e in assess(inv) if e["observed"])
        self.assertEqual(r["inventory_status"], "Observed and declared")

    def test_catalogue_full_and_consistent(self):
        data = catalogue()
        ids = {t["id"] for t in data["owasp"]}
        self.assertEqual(len(ids), 21)
        self.assertTrue(all(set(r["owasp"]).issubset(ids) for r in data["rules"]))
        self.assertEqual(len({r["id"] for r in data["rules"]}), len(data["rules"]))


if __name__ == "__main__":
    unittest.main()
