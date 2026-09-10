# BotScope

**Find the web and API flows that should be considered for bot protection.**

BotScope combines crawling, JavaScript and rendered discovery with API specifications, HAR captures and endpoint inventories. It produces an evidence-led report with HTTP methods, potential bot abuse, priority, confidence, controls and application-owner validation steps.

This is an **exposure assessment and protection planning tool**. It does not claim to discover every route from a URL alone, prove exploitation, or verify that a bot product can be bypassed. For comprehensive coverage, combine the crawler with authenticated journeys, API schemas and traffic inventories.

## What is included

- **Web discovery:** links, forms and field names, redirects, robots paths, nested sitemaps, JavaScript assets, literal fetch/axios/XHR calls, JSON/HATEOAS links and optional rendered DOM/network discovery.
- **API evidence:** Swagger 2.0 / common OpenAPI 3.x structures, HAR, Postman collections, GraphQL introspection exports, URL lists and JSON/CSV inventories. Normalized F5 XC exports can be imported through field mappings.
- **25 assessment scenarios:** credential attacks, fake accounts, recovery/OTP abuse, carding, scraping, scalping, inventory denial, coupon/gift-card abuse, spam, reputation manipulation, cost/resource exhaustion, GraphQL and realtime abuse, and more. Includes the 21-category OWASP Automated Threat catalogue.
- **Clear decisions:** Recommended, Conditional, Verify method, Verify existence, Review, or Usually unnecessary. Browser, mobile and service-client guidance remain distinct.
- **Reports:** searchable/filterable HTML, JSON, CSV, optional Excel/PDF, and a protection planning CSV. All work locally; no hosted backend, paid API or LLM key is required.
- **Operational controls:** explicit scope, rate/request/time/depth limits, private-target opt-in, TLS validation, DNS pinning, data redaction and coverage gaps. No credential guessing or form submission.

## Quick start

Python **3.11+**:

```bash
git clone https://github.com/ahmadjabr/BotScope.git
cd BotScope
python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[reports,browser]'
python -m playwright install chromium
```

On a minimal Linux server, install Chromium's system dependencies with `python -m playwright install --with-deps chromium` using an account permitted to install packages. For static discovery only, install `'.[reports]'` and omit `--browser`.

**Try the synthetic demo first; it sends no network requests:**

```bash
botscope demo --output reports/demo --formats json,html,csv,xlsx,pdf
```

Open `reports/demo/report.html` locally. A fictional sample inventory and API specification are in [examples](examples).

**Scan an authorized site:**

```bash
botscope scan --target https://www.example.com \
  --allow-origin https://api.example.com \
  --browser --max-requests 3000 --max-depth 12 --max-seconds 3600 \
  --output reports/assessment --formats json,html,csv,xlsx,pdf
```

Replace the example origins with your authorized website/API origins. Additional subdomains are not automatically included. The default rate is two requests/second; rendering uses the same total request budget. Root and API origins are separate scope entries. For an internal site, add `--allow-private`. TLS checks remain enabled.

## Best coverage for work assessments

1. Obtain the expected web/API route inventory, bundled OpenAPI specs, mobile collections and known business flows from the application team.
2. Export sanitized endpoint metadata from API gateways/F5 XC and capture HAR journeys for representative anonymous and authenticated roles. Walk through search, login, signup, recovery, OTP, checkout/booking, rewards and other valuable flows in your own authorized browser.
3. Copy [examples/scan.yaml](examples/scan.yaml) to a private working directory. Set exact origins, seed URLs, exclusions, limits and imports. Config file paths are relative to that config.
4. Run BotScope, review the Coverage section and reconcile observed routes against supplied declarations.
5. Have owners validate critical/high candidates, legitimate client types and existing policy. Use the planning worksheet for monitoring, tuning and rollout.

```bash
botscope scan --config my-scan.yaml \
  --output reports/application --formats json,html,csv,xlsx,pdf
```

`robots.txt` can exclude useful routes. Respect is enabled by default; if your agreed assessment scope includes those routes, set `respect_robots: false` or use `--ignore-robots`. Method/scope/volume guards remain in effect. Increasing limits increases coverage opportunities, not a guarantee of completeness.

## Import-only assessment

Analyze supplied evidence without sending any target requests:

```bash
botscope scan --offline --target https://shop.example.test \
  --openapi examples/openapi.yaml --inventory examples/endpoints.csv \
  --output reports/imported --formats json,html,csv,xlsx,pdf
```

Repeat `--har`, `--openapi`, `--postman`, `--inventory` or `--urls` for multiple files. Imported files contribute inventory; saved request bodies, credentials and scripts are never replayed. Explicit `--seed` / `seed_urls` entries can be used to crawl eligible imported URLs in a live scan.

### F5 XC / gateway endpoint inventories

There is no live XC tenant connector in this release. Export/normalize endpoint metadata into CSV or JSON, then map columns. Native export schemas vary; do not assume an arbitrary XC response is directly supported.

```yaml
imports:
  - type: xc
    path: inputs/xc-endpoints.csv
    mapping:
      host: domain_name
      path: endpoint_path
      method: http_method
```

Normalized fields: `url` or `host` + `path`, `method`, `function`, `parameters` (list or semicolon-separated names), `operation`, `client_type` (`browser`, `mobile`, `service`, `mixed`, `unknown`), `observed`, `declared`, `status`, `auth`. Missing methods remain **UNKNOWN**. Only mark rows observed/declared if your source supports that claim. See [examples/endpoints.csv](examples/endpoints.csv).

### Authentication and GraphQL

Use a private JSON file based on [headers.example.json](examples/headers.example.json), then pass `--headers-file secrets/headers.json`. Credentials are bound to exact origins. Do not put tokens in CLI flags, config URLs or Git. BotScope does not perform interactive sign-in or refresh sessions. Per-role HARs are often the best evidence for hidden application flows.

For GraphQL, import a JSON introspection result obtained through an authorized process:

```yaml
imports:
  - type: graphql
    path: inputs/schema.json
    endpoint: https://api.example.com/graphql
```

The importer treats root schema fields as candidates with assumed POST transport; validate this assumption. It does not execute introspection, mutations or subscriptions. Runtime operation names from HAR are preserved. WebSocket message payloads are not inspected.

## Reading the report

Each endpoint includes URL/method/operation, source evidence, observed status codes, field names, authentication/control indicators, possible attack scenarios, OWASP mapping, a priority score, classification confidence, protection suitability and validation questions.

- **Priority is inherent exposure**, not exploit probability or a verified vulnerability severity.
- **Confidence concerns the classification**, not whether an attack would succeed.
- Missing rate-limit headers do not establish missing bot protection. A 200 response does not establish an unauthenticated API.
- Unknown methods, stale references, protected paths and static assets are handled separately.
- Observed routes outside a supplied specification need reconciliation; they are not automatically confirmed shadow APIs.
- The discovered count includes unresolved candidates and metadata probes. Total site count and coverage percentage remain unknown.

The F5-oriented protection worksheet is a planning aid, **not an importable XC policy**. It does not change tenant settings. Confirm client compatibility, path/method matches, deployment support and owners before enforcement. Full details: [methodology](docs/METHODOLOGY.md) and [security behavior](SECURITY.md).

## Docker

```bash
docker build -t botscope .
mkdir -p reports inputs secrets
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/reports:/reports" botscope \
  demo --output /reports/demo --formats json,html,csv,xlsx,pdf
```

Mount input/config/credential directories read-only when scanning. Run containers without privileged mode. For browser discovery, build `docker build -f Dockerfile.browser -t botscope-browser .` and add `--init --shm-size=1g` to `docker run`. The browser image is larger. The container's loopback address is its own network namespace; use a reachable explicitly authorized host for internal targets.

## Compare assessments and CI

```bash
botscope compare --before reports/day1/report.json \
  --after reports/day2/report.json --output reports/changes.json
botscope catalogue
python -m unittest discover -s tests -v
python -m build
```

Comparison flags added, not-seen-in-latest and score/decision changes. Missing routes may reflect changed inputs or coverage, not remediation.

Exit codes: `0` report completed; `2` input/dependency/output error, failed browser discovery, or no observed/declared endpoints; `3` optional `--fail-on critical|high|medium` exposure threshold reached; `130` interruption. Partial crawl coverage can still produce code 0: automation must inspect `coverage.stop_reason`, `issues` and queue remainder. GitHub CI checks Python 3.11/3.12/3.13, packaging, report exports and a separate Chromium integration job. Tests use only a local synthetic application.

## Project status

Initial release **0.1.0**. Suitable for piloting evidence collection and protection planning, with application-owner review. Rules are transparent and editable in `src/botscope/data/threats.json`; tests cover key false positives and request boundaries. No claim of universal attack coverage, production efficacy or zero false positives is made.

Licensed under the repository's existing [GPL-3.0 license](LICENSE). OWASP/F5 references are classification and integration guidance, not endorsements.
