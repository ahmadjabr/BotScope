"""An intentionally small local site with known discovery and safety boundaries."""
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


@contextmanager
def site():
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append(("GET", self.path, self.headers.get("Authorization")))
            path = urlsplit(self.path).path
            status, mime, extra = 200, "text/html", {}
            if path == "/":
                body = '''<!doctype html><html><head><title>Fixture shop</title></head><body>
                <a href="/catalog?page=1">Products</a><a href="/private">Private</a>
                <a href="/logout">Logout</a><a href="/remove?id=3">Remove</a>
                <a href="/redirect">External redirect</a><a href="/missing">Missing</a>
                <a href="/account?token=NEVER-PRINT-THIS">Token</a>
                <form method="post" action="/api/login"><input name="username"><input name="password" type="password"></form>
                <form method="get" action="/search"><input name="q"></form>
                <script src="/assets/app.js"></script>
                <script>const x='/api/'+'runtime-products'; fetch(x); const f=document.createElement('form'); f.method='post'; f.action='/api/'+'runtime-login'; document.body.append(f);</script>
                </body></html>'''
            elif path == "/robots.txt":
                mime = "text/plain"
                body = "User-agent: *\nDisallow: /private\nSitemap: " + self.server.base + "/index.xml\n"
            elif path == "/index.xml":
                mime = "application/xml"
                body = '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>' + self.server.base + '/products.xml</loc></sitemap></sitemapindex>'
            elif path in {"/products.xml", "/sitemap.xml"}:
                mime = "application/xml"
                body = '<urlset><url><loc>' + self.server.base + '/sitemap-only</loc></url></urlset>'
            elif path == "/openapi.json":
                mime = "application/json"
                body = json.dumps({"openapi": "3.1.0", "servers": [{"url": self.server.base}], "security": [{"bearer": []}], "paths": {
                    "/api/payments": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Card"}}}}}},
                    "/api/users/{userId}": {"get": {}}, "/api/products": {"get": {"security": []}},
                    "/api/login": {"post": {}}},
                    "components": {"schemas": {"Card": {"type": "object", "properties": {"cardnumber": {"type": "string"}, "cvv": {"type": "string"}}}}}})
            elif path == "/assets/app.js":
                mime = "application/javascript"
                body = '''fetch('/api/products'); axios.post('/api/otp/send', {phone: 'dummy'}); var route='/api/unknown';'''
            elif path == "/redirect":
                status, body = 302, ""
                extra = {"Location": "http://169.254.169.254/latest/meta-data/"}
            elif path in {"/api/products", "/api/runtime-products"}:
                mime, body = "application/json", '{"items": [], "_links": {"next": "/json-only"}}'
                extra = {"X-RateLimit-Limit": "100"}
            elif path in {"/catalog", "/sitemap-only", "/json-only", "/private", "/logout", "/remove"}:
                body = '<html><body>Fixture content</body></html>'
            else:
                status, body = 404, "Not found"
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            requests.append(("POST", self.path, None))
            self.send_error(500, "Scanner must never POST")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.base, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
