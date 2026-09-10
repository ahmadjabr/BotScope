# Security and data handling

Run BotScope only against applications you are authorized to assess. Set exact origins and exclusions with the application owner. Use a dedicated test account when authenticated evidence is needed.

## Request behavior

- HTTP(S) origins are explicit: no automatic subdomain or scheme/port expansion.
- The crawler sends bounded GET requests. It does not submit forms, perform login attempts, execute imported scripts, replay request bodies, guess credentials or run load tests.
- Obvious state-changing paths and credential-bearing query parameters are inventoried but skipped. This is a heuristic: a badly designed GET endpoint can still change state. Exclude any application-specific sensitive routes before running a production scan.
- File imports are inventory-only. Live discovered links and live specification GET routes can be followed. Use explicit seeds when you want eligible imported routes crawled.
- `robots.txt` is respected by default, including fail-closed behavior when retrieval is restricted/unavailable. Within an authorized assessment, `respect_robots: false` or `--ignore-robots` can be used when the agreed scope includes those routes. The origins, method guards and request limits still apply.
- DNS results are validated and the connection is made directly to a validated numeric address with the original TLS SNI/hostname check. Redirects re-enter the same origin/path checks. Environment HTTP proxies are not used.
- Private/loopback addresses require `allow_private: true` / `--allow-private`; link-local, multicast, unspecified and known metadata addresses remain blocked. OS DNS resolution may outlast the configured per-request timeout.
- TLS validation stays enabled; use a trusted `ca_bundle` for enterprise CAs. There is no `--insecure` mode.
- HTML/JavaScript/JSON/XML responses are size-limited, including gzip expansion. XML entities and YAML aliases are rejected. Imports are capped at 32 MB and endpoint count is capped.

## Browser mode

Every intercepted HTTP request uses BotScope's scope, DNS validation, request budget and rate limiter. Non-GET methods are recorded and aborted. Service workers and WebSockets are blocked, and there are no automatic clicks or form submissions. Browser response cookies are not persisted; use origin-bound headers or HAR imports for authentication-dependent coverage. Routes requiring session negotiation or browser localStorage may not render correctly.

The browser executes target JavaScript and may consume more resources or requests than static discovery. Run it in a disposable environment with appropriate OS/container isolation. A missing browser dependency produces a coverage issue and nonzero CLI result instead of silently claiming rendered discovery succeeded.

## Sensitive files and reports

Store credentials under `secrets/`, exports under `inputs/` and generated reports under `reports/`; these locations are ignored by Git. Do not add real credentials or customer data to this public repository. A headers JSON file is keyed by exact origin; configured credentials are not forwarded to another origin. Request/response bodies, cookie values and authorization headers are not included in reports.

Reports remove query values and redact common token/email path patterns. This is not a universal DLP system: names or short identifiers embedded in paths, field names, endpoint descriptions or owner-provided metadata can still be sensitive. Review reports before external sharing. New report directories use mode 0700 and report files mode 0600 on supporting filesystems; existing directory permissions are not changed.

HTML outputs render untrusted data with text nodes and escape embedded JSON. A restrictive CSP prevents external report network requests. CSV/XLSX formula-leading values are escaped and untrusted workbook text is stored as strings. Temporary report files are atomically replaced where possible.

## Reporting a vulnerability

Do not post customer URLs, HAR contents, credentials or exploit details in a public issue. Use GitHub private vulnerability reporting if enabled on this repository, or contact the maintainer through an established private channel. Public issues may contain a sanitized description and a reproduction using the local test fixture.
