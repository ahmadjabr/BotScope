"""Optional rendered discovery. Every HTTP request uses the same guarded transport."""
from __future__ import annotations

import asyncio

from .discovery import body_parameter_names
from .model import canonical_url
from .transport import FetchError


async def render_pages(scanner):
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        scanner.inventory.issue("Browser requested but Playwright is unavailable; install botscope[browser] and Chromium.")
        scanner.browser_result["error"] = "dependency_missing"
        return
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(service_workers="block", accept_downloads=False)
            async def intercept(route):
                request = route.request
                url = canonical_url(request.url)
                if not url:
                    await route.abort()
                    return
                ep = scanner.inventory.add(url, request.method, "browser_request",
                                           parameters=body_parameter_names(request.post_data or ""),
                                           evidence="Browser attempted request; only eligible GETs are sent")
                reason = scanner.scope.fetch_reason(url, request.method)
                if reason or not scanner.robots_allowed(url) or request.resource_type in {"image", "media", "font"}:
                    if ep:
                        ep.fetch_state = reason or "browser_policy_skipped"
                    await route.abort()
                    return
                try:
                    response = await asyncio.to_thread(scanner.fetcher.get, url, extra_headers=await request.all_headers())
                    scanner.visited.add(url)
                    scanner.process(response, source="browser_response")
                    headers = {k: v for k, v in response.headers.items() if k not in {"content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie"}}
                    # Cookies from a scan are not persisted. Supply explicit origin-bound credentials.
                    await route.fulfill(status=response.status, headers=headers, body=response.body)
                except FetchError as exc:
                    scanner.skipped[str(exc)] += 1
                    await route.abort()
            await context.route("**/*", intercept)
            # Do not establish websocket channels, including those opened from inline scripts.
            await context.route_web_socket("**/*", lambda ws: ws.close())
            page = await context.new_page()
            rendered = set()
            while len(rendered) < scanner.config.browser_pages and not scanner.fetcher.exhausted:
                candidates = [url for url in scanner.browser_candidates if url not in rendered]
                if not candidates:
                    break
                url = candidates[0]
                rendered.add(url)
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=int(scanner.config.timeout * 1000))
                    await page.wait_for_timeout(500)
                    scanner.process_html(await page.content(), page.url, 0, "browser")
                    scanner.browser_result["pages_rendered"] += 1
                except Exception:
                    scanner.inventory.issue("A browser page could not finish rendering; inspect authenticated/SPA coverage.")
            if any(url not in rendered for url in scanner.browser_candidates):
                scanner.inventory.issue("Browser page budget reached; not all discovered HTML pages were rendered.")
            await browser.close()
    except Exception as exc:
        scanner.browser_result["error"] = type(exc).__name__
        scanner.inventory.issue("Browser could not complete; install Chromium/system dependencies and review scope. Static/import results remain available.")
