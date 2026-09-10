# Assessment methodology

BotScope answers: **Which discovered web/API flows should be considered for bot protection, why, and what should the application owner validate?** It does not certify that a bot attack succeeds or that an existing bot product fails.

## Discovery and endpoint identity

The inventory records exact origin, case-sensitive path, HTTP method, query parameter **names**, and GraphQL operation where supplied. Query values remain in memory only for eligible live navigation; they are removed from reports. Query values alone do not create a second inventory entry. Distinct methods, query-name sets and GraphQL operations remain separate. Trailing slashes remain distinct. `route_shape` is a convenience hint for numeric/UUID parameters, not an automatically deployable path rule.

Sources contribute different evidence:

| Source | What it can establish | What it cannot establish |
|---|---|---|
| HTML links, forms, robots and sitemaps | Advertised routes, form methods and input names | That a route exists, is reachable or accepts submissions |
| Static JavaScript | Literal fetch/axios/XHR references and route strings | Computed URLs, every bundle branch or runtime business flow |
| Rendered browser | Runtime DOM, attempted requests, eligible GET responses | Click-only flows, submitted forms, authenticated localStorage state, all mobile routes |
| OpenAPI / Swagger | Declared routes, methods, parameter names and authentication declarations | Deployment accuracy or enforced authentication |
| HAR | Captured request method/URL and response status | Every role or workflow, traffic volume, control effectiveness |
| Postman | Declared requests, variables and parameter names | Results of scripts or requests, which are not executed |
| GraphQL introspection file | Root operation fields and argument names | Real operation documents, actual POST/GET transport or subscriptions implementation |
| CSV / JSON / normalized XC export | Owner-supplied or traffic-derived endpoint evidence | Vendor-export completeness or verified protection policy |

Imported files are inventory inputs; their saved requests, credentials and bodies are not replayed. Use `seed_urls` to explicitly crawl eligible imported URLs. Live discovered OpenAPI GET routes can enter the crawl frontier. Placeholders are inventoried but never filled with guessed IDs. Forms are never submitted, even GET forms. Arbitrary wordlist brute forcing, subdomain scanning and external `$ref` fetching are not implemented.

Specifications support common Swagger 2.0 and OpenAPI 3.x path/operation structures, operation/path/root servers, default server variables, local JSON Pointer references, nested body field names and security overrides. This is not a full specification validator. Supply bundled JSON/YAML; external references, YAML aliases and OpenAPI webhook expressions require preprocessing or explicit inventory rows. OpenAPI 3.2 additional-operation constructs are not implemented.

GraphQL import enumerates schema fields as separate candidates at the supplied URL, with assumed POST transport. HAR operation names are preserved separately. Anonymous operations and different documents sharing an operation name can collapse; use traffic/schema review to reconcile them. BotScope does not send introspection, mutations, batch queries or subscription messages. WebSocket URLs should be supplied as the equivalent HTTP(S) handshake path; only handshake exposure is classified.

## Threat model

The shipped catalogue contains **25 assessment rules** mapped to the **21 OWASP Automated Threat categories**. Patterns match route/operation/function metadata; credential/payment rules also use parameter and form hints. Broad content metadata and response body values are not used to label every endpoint on a page. A match is a hypothesis, with its matching term, possible business impact, controls and a validation question.

Credential stuffing, password spraying/cracking, signup/referral farming, recovery abuse, OTP/SMS pumping, token guessing, carding/cracking, cashing out, scalping, inventory denial, scraping, coupon/gift-card enumeration, spam, reputation manipulation, paid-service consumption, resource exhaustion, sniping, expediting, aggregation, account/object enumeration, token/session abuse, GraphQL amplification, upload abuse, callback abuse and realtime abuse are included.

Fingerprinting (OAT-004), CAPTCHA defeat (OAT-009), vulnerability scanning (OAT-014) and footprinting (OAT-018) are cross-cutting review categories. Their inclusion in the catalogue is **not** a claim that BotScope validated or executed them. CAPTCHA markup adds a server-side validation question. SQL injection, XSS, BOLA/IDOR, authorization defects, malware and fraud-policy correctness require appropriate separate assessment; bot protection is only a complementary control.

## Scoring and confidence

Scores are analyst-defined **inherent exposure priority** from 0 to 100. The highest matching rule determines the endpoint score; multiple overlapping rules do not stack. They are not CVSS, measured attack probability or residual risk. `90–100` Critical, `75–89` High, `50–74` Medium; lower matched scores Low. Unclassified routes require Review. Static assets and observed-only not-found routes are Informational.

Confidence describes classification evidence:

- **High:** a matching hypothesis has structured/form evidence and an observed response or imported observation.
- **Medium:** structured/form evidence supports the hypothesis, but execution has not been observed.
- **Low:** only names/literals or unclassified evidence are available.

Observing HTTP 200 does not prove authentication is absent; it can be a login page, cached shell or soft 404. A 401/403 does not prove bot protection exists. A rate-limit header does not prove identity-based throttling or distributed-bot detection. Existing control indicators never automatically reduce the score.

## Decisions and rollout

`Recommended` means prioritize validation and protection planning. `Conditional` highlights service, federation, callback and health flows where interactive challenges can break legitimate behavior. `Verify method` and `Verify existence` prevent uncertain candidates from becoming enforcement rules. `Usually unnecessary` identifies static assets; business context may override that recommendation.

For web flows, include both the telemetry/instrumentation page and the valuable submission endpoint. For mixed web/mobile/API traffic, establish actual client types and compatible detection before choosing challenge behavior. For service clients, consider signed requests, replay protection, OAuth/mTLS, quotas and application controls.

The protection worksheet includes owner confirmation, path/method verification, legitimate-client tests and an initial **Monitor and validate** action. It is **not an F5 XC API payload** and does not modify tenant settings. Confirm supported deployment, licensing, namespace/LB, endpoint matching, telemetry injection and mobile SDK requirements in the current F5 documentation before implementation.

## Coverage and interpretation

The report records request budget, time/depth/query/browser limits, source counts, queue remainder, blocked/out-of-scope references, parsing issues and imports. `total_site_endpoints` and `completion_percent` are deliberately null. A completed queue means the configured discovery frontier was exhausted, not that every site route was found. The raw discovered count includes unresolved candidates and metadata probes; filter decisions/status to distinguish these from observed business endpoints.

"Observed outside supplied specification" means a method/path was not matched to the supplied baseline, which can itself be incomplete. It is a candidate for owner reconciliation, not proof of a shadow API. A route missing from a later report may reflect different credentials, inputs or coverage; comparison output does not call this remediation.

For the best coverage, combine anonymous and per-role HAR journeys, API gateway/XC traffic inventories from a representative period, bundled specifications, mobile/API client collections, multiple starting routes and rendered discovery. Confirm the expected route list with application owners. Preserve known good bots and business partners during rollout.

## References

- [OWASP Automated Threat ontology](https://github.com/OWASP/www-project-automated-threats-to-web-applications/blob/master/tab_ontology.md)
- [OpenAPI 3.1.1 specification](https://spec.openapis.org/oas/v3.1.1.html)
- [Swagger 2.0 specification](https://spec.openapis.org/oas/v2.0.html)
- [F5 Distributed Cloud Bot Defense documentation](https://docs.cloud.f5.com/docs-v2/bot-defense/how-tos/configure-bot-defense)
- [Playwright request interception](https://playwright.dev/python/docs/network)

OWASP names/identifiers are used for classification. Rule text and prioritization are BotScope's own assessment guidance; the project is not endorsed by OWASP or F5.
