"""Optional rendered discovery with safe, bounded browser interactions."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlsplit

from .discovery import body_parameter_names
from .model import canonical_url, safe_label
from .transport import FetchError


DANGEROUS = re.compile(
    r"(?i)(logout|sign\s*out|delete|remove|destroy|unsubscribe|purchase|checkout|pay|transfer|withdraw|send|resend|reset|revoke|cancel|approve|accept|reject|execute|trigger|submit|save|create|update|login|sign\s*in|register|otp|password|payment)"
)
NAVIGATION_WORDS = re.compile(r"(?i)(menu|nav|next|previous|back|tab|contact|about|home|profile|settings|products?|catalog|search|open|more)")
SENSITIVE_FIELD = re.compile(r"(?i)(password|passwd|token|secret|cookie|authorization|api[-_ ]?key|card|cvv|otp|code|session)")


def _safe_control(control: dict) -> bool:
    text = " ".join(str(control.get(k) or "") for k in ("text", "aria", "name", "id", "href"))
    if DANGEROUS.search(text) or control.get("inside_form"):
        return False
    if control.get("tag") == "a":
        href = str(control.get("href") or "")
        return bool(href) and not re.match(r"(?i)^(javascript:|mailto:|tel:)", href)
    if str(control.get("type") or "").lower() in {"submit", "reset"}:
        return False
    return bool(control.get("data_route") or control.get("data_href") or control.get("aria_controls") or NAVIGATION_WORDS.search(text))


def _form_value(name: str, field_type: str, index: int) -> str:
    hint = f"{name} {field_type}"
    if re.search(r"(?i)(email|e-mail)", hint):
        return f"botscope-test-{index}@example.invalid"
    if re.search(r"(?i)(number|range|count|quantity|page|limit|age)", hint):
        return "1"
    if re.search(r"(?i)(url|website|link)", hint):
        return "https://example.invalid/"
    if re.search(r"(?i)(phone|tel|mobile)", hint):
        return "0000000000"
    return f"BotScopeTest-{index}"


async def _control_snapshot(page):
    return await page.locator("a[href],button,[role='button']").evaluate_all(
        """els => els.map((el, index) => ({
          index, tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '',
          href: el.getAttribute('href') || '', text: (el.innerText || el.textContent || '').slice(0, 160),
          aria: el.getAttribute('aria-label') || '', name: el.getAttribute('name') || '',
          id: el.id || '', data_route: el.getAttribute('data-route') || '',
          data_href: el.getAttribute('data-href') || '', aria_controls: el.getAttribute('aria-controls') || '',
          inside_form: !!el.closest('form')
        }))"""
    )


async def _form_snapshot(page):
    return await page.locator("form").evaluate_all(
        """forms => forms.map((form, index) => ({
          index, action: form.getAttribute('action') || location.href,
          method: (form.getAttribute('method') || 'GET').toUpperCase(),
          fields: Array.from(form.elements).map(el => ({
            name: el.getAttribute('name') || el.id || '',
            type: (el.getAttribute('type') || el.tagName || '').toLowerCase(),
            value: el.value || '', required: !!el.required
          }))
        }))"""
    )


async def _inspect_page(page, page_url, scanner, session_result):
    try:
        controls = await _control_snapshot(page)
    except Exception:
        controls = []
    for control in controls:
        for value in (control.get("href"), control.get("data_route"), control.get("data_href")):
            if value and "#" in value:
                scanner.add_browser_candidate(urljoin(page_url, value), "spa_hash_route")
        if not scanner.config.browser_interactions or not _safe_control(control):
            continue
        if scanner.interactions_done >= scanner.config.max_interactions:
            break
        try:
            await page.goto(page_url, wait_until="domcontentloaded", timeout=int(scanner.config.timeout * 1000))
            locator = page.locator("a[href],button,[role='button']").nth(int(control["index"]))
            if not await locator.is_visible() or not await locator.is_enabled():
                continue
            await locator.click(no_wait_after=True, timeout=int(scanner.config.timeout * 1000))
            await page.wait_for_timeout(350)
            scanner.interactions_done += 1
            session_result["interactions"] += 1
            if page.url != page_url:
                scanner.add_browser_candidate(page.url, "browser_interaction")
            scanner.process_html(await page.content(), page.url, 0, "browser_interaction")
        except Exception:
            continue

    if not scanner.config.form_testing:
        return
    try:
        forms = await _form_snapshot(page)
    except Exception:
        forms = []
    for form in forms:
        action = urljoin(page_url, form.get("action") or page_url)
        method = str(form.get("method") or "GET").upper()
        if not scanner.scope.form_allowed(action, method):
            scanner.form_tests_skipped += 1
            continue
        fields = form.get("fields") or []
        if not scanner.config.allow_sensitive_form_tests and any(SENSITIVE_FIELD.search(str(f.get("name") or "")) for f in fields):
            scanner.form_tests_skipped += 1
            continue
        if not scanner.begin_form_request(action, method):
            continue
        try:
            await page.goto(page_url, wait_until="domcontentloaded", timeout=int(scanner.config.timeout * 1000))
            form_locator = page.locator("form").nth(int(form["index"]))
            for index, field in enumerate(fields, 1):
                name = str(field.get("name") or "")
                field_type = str(field.get("type") or "text").lower()
                if not name or field_type in {"hidden", "file", "submit", "button", "reset", "image"}:
                    continue
                locator = form_locator.locator(f"[name='{name.replace(chr(39), '')}']")
                if field_type == "select-one":
                    await locator.select_option(index=0)
                else:
                    await locator.fill(_form_value(name, field_type, index))
            await form_locator.evaluate("form => form.requestSubmit()")
            await page.wait_for_timeout(350)
            session_result["forms_tested"] += 1
            scanner.process_html(await page.content(), page.url, 0, "browser_form")
        except Exception:
            scanner.form_tests_skipped += 1
        finally:
            scanner.form_expected.discard(canonical_url(action) or action)


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
            sessions = [None] + list(scanner.config.session_files)
            for session_index, session_file in enumerate(sessions, 1):
                context_kwargs = {"service_workers": "block", "accept_downloads": False}
                if session_file:
                    context_kwargs["storage_state"] = str(session_file)
                context = await browser.new_context(**context_kwargs)
                session_result = {"id": f"session-{session_index}", "authenticated": bool(session_file), "pages_rendered": 0, "interactions": 0, "forms_tested": 0}
                scanner.browser_result.setdefault("sessions", []).append(session_result)

                async def intercept(route):
                    request = route.request
                    url = canonical_url(request.url)
                    if not url:
                        await route.abort()
                        return
                    ep = scanner.inventory.add(url, request.method, "browser_request", parameters=body_parameter_names(request.post_data or ""), evidence=f"Browser request from {session_result['id']}")
                    if request.method not in {"GET", "HEAD"}:
                        if scanner.form_request_allowed(url, request.method):
                            if ep:
                                ep.evidence.append("Submitted by explicitly allowlisted form test")
                            await route.continue_()
                        else:
                            if ep:
                                ep.fetch_state = "non_get_browser_request"
                            await route.abort()
                        return
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
                        await route.fulfill(status=response.status, headers=headers, body=response.body)
                    except FetchError as exc:
                        scanner.skipped[str(exc)] += 1
                        await route.abort()

                await context.route("**/*", intercept)
                if scanner.config.capture_websockets:
                    def websocket_handler(ws):
                        scanner.record_websocket(ws.url, "channel")
                        ws.on("framereceived", lambda payload: scanner.record_websocket(ws.url, "received", payload))
                        ws.on("framesent", lambda payload: scanner.record_websocket(ws.url, "sent", payload))
                    context.on("websocket", websocket_handler)
                else:
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
                        await _inspect_page(page, page.url, scanner, session_result)
                        session_result["pages_rendered"] += 1
                        scanner.browser_result["pages_rendered"] += 1
                    except Exception:
                        scanner.inventory.issue("A browser page could not finish rendering; inspect authenticated/SPA coverage.")
                if any(url not in rendered for url in scanner.browser_candidates):
                    scanner.inventory.issue(f"Browser page budget reached for {session_result['id']}; not all discovered HTML pages were rendered.")
                await context.close()
            await browser.close()
    except Exception as exc:
        scanner.browser_result["error"] = type(exc).__name__
        scanner.inventory.issue("Browser could not complete; install Chromium/system dependencies and review scope. Static/import results remain available.")
