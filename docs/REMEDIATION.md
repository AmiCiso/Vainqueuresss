# Remediation record

Each audit item was treated as a lead and checked against the supplied source before changing it.
"Executed" means run in the authoring sandbox (Node 22.23, headless Chromium, no network, no Express installed).
"Provided" means written but **not run** here.

## Audit assumptions that were corrected

| Audit lead | What the source shows |
|---|---|
| `.env` is exposed by `express.static(__dirname)` | Not shown. `serve-static` defaults to `dotfiles: 'ignore'`, so dotfiles (including `.env`) answer 404. That is documented behaviour; it could **not be demonstrated here** (Express cannot be installed offline). What the old code *did* serve, by reading it: `server.js`, `package.json`, `package-lock.json`, `README.md` and every other non-dotfile at the root. |
| Validator bypasses are SSRF | Not exploitable in the present design: the gateway sends user input only as *data* to two fixed provider endpoints and fetches no user-supplied target. Fixed as correctness/defence-in-depth; documented that any future fetcher needs DNS/IP validation, connection pinning, redirect-hop validation and egress controls. |
| Every `innerHTML` is XSS | Not asserted. Remaining `innerHTML` writes insert either static authored content (lessons, lab templates) or `escapeHtml`'d strings; every attacker-influenced value (URLs, nested destinations, provider fields, history) is written with `textContent`/DOM nodes. |
| Inline handlers/CSP | Confirmed: all inline handlers and the inline Tailwind config/style were removed so a strict CSP is possible. |

Additional defects found while implementing (not in the audit): no navigation below the `lg` breakpoint (mobile users could not reach Scanner/Academy/Labs/RT);
a third-party (flaticon) logo fallback in an inline `onerror`; legacy history keys holding raw URLs; a redaction leak where a token inside a URL-valued
query parameter was printed verbatim (caught by a test, fixed); lab submit buttons colliding with the tab handler (caught by the browser test);
`resolveApiBase` guessing `localhost:3000` on any other local port (broke `PORT=8080` under CSP); home page said 9 academy categories while 12 exist;
overclaiming copy (autonomous AI protection, "Deep Threat Inspection", engagement services).

## Checklist

| # | Requirement | Fix | Verification |
|---|---|---|---|
| 1 | One authoritative report | `src/report.js` (single model: id, timestamps, heuristic score/band, per-provider status+evidence, verdict, lookup state, limitations); banner/cards/history/counters/export all derive from it; history upserts by `scanId`; export disabled while pending and marked `incomplete` if forced | Executed: `controller.test.js` (provider-positive overrides 0 score, heuristic score preserved, no-match never erases strong findings, partial/unavailable/unconfigured never clean, report=history=export agreement, single history record), browser tests (banner, cards, history row, home counters, export JSON agree) |
| 2 | Sensitive URLs and disclosure | `url-policy.js`: userinfo rejected; best-effort sensitive detection; redaction; fragment never sent; path+query preserved; consent gate (local / without query / send anyway) enforced client **and** server (409); disclosure before lookup; local-only default; history stores redacted values only, 20 entries/30 days; legacy raw-URL keys purged | Executed: `url-policy.test.js`, `controller.test.js` (secret absent from state/history/storage/export), browser tests (no network in local mode or while awaiting consent; secret absent from DOM and localStorage; samples never external). Provided: HTTP 409 test |
| 3 | Restrict static hosting | Browser assets moved to `public/`; only it is served (`dotfiles:'ignore'`, no listing) | Executed: `layout.test.js` + `npm run check:layout` (public/ holds only allowed asset types; backend/manifests/docs/tests are outside). **Provided, not run:** `test/http/server.test.js` requests `/server.js`, `/package*.json`, `/.env*`, `/test/*`, `/src/*`, traversal and encoded-traversal paths and expects 403/404 |
| 4 | Async races | Generation token on every completion; abort of the superseded request (kept active through body read); badges reset at scan start; 429/validation/outage/malformed/timeout mapped to explicit statuses; no auto-retry (manual retry button only); honest states, no timers or percentages | Executed: stale success, stale failure, misbehaving transport that ignores abort, 429 not retried, 10 failure scenarios, body-read timeout; browser: pending state (no `%` text, export disabled), stale A vs B with real DOM; mutation check showed the stale-guard test fails when the guard is removed |
| 5 | Nested destinations | All query/fragment/path candidates analyzed; limits: 40 params, depth 3, 12 destinations, 3 decode rounds, 20 000 chars, 2048 each; duplicates/cycles recorded; truncation reported; evidence per destination (redacted); never fetched | Executed: `analysis.test.js` (harmless first destination cannot hide later one; single/double/triple encoding; path and fragment; limits; cycles; userinfo in nested; no secrets in evidence) |
| 6 | Host/IP validation | WHATWG normalization + one trailing dot + IANA special-purpose tables (IPv4, IPv6, mapped, NAT64, 6to4) in `ip.js`; one module shared by browser and gateway; `127.0.0.1`, `localhost.`, `[::ffff:127.0.0.1]`, `[::ffff:7f00:1]`, numeric tricks covered | Executed: `url-policy.test.js` incl. a differential test of the matcher against `node:net` BlockList with independently written CIDRs; service tests (403, nothing forwarded). Maintained parser note: the WHATWG `URL` parser does the canonicalization; ranges are table-driven |
| 7 | Heuristics | Correlated findings grouped (strongest full, others half, per-group caps, overlap explained); weights lowered for ext/HTTPS/IDN/UGC/bot/length/marketing; no TLS/DNS/campaign/OTP claims; trusted exemption limited to reputation-style rules and never for UGC; PSL via `psl` (private suffixes included; IP literals separate); MITRE tentative; demo IOCs labelled fixtures; labelled corpus | Executed: corpus (21 cases: benign/suspicious/adversarial), wording tests, exemption tests, PSL tests. Corpus pins behaviour only: **no accuracy claim** |
| 8 | Providers | Fixed endpoints; server-side secrets; bounded timeout; concurrent calls; response validation (`{}` = no match, other shapes `unexpected_response`); distinct auth/quota/timeout/network/unexpected/unconfigured; evidence kept; `/api/providers` never says "ready"; HMAC-keyed bounded cache honoring `cacheDuration`; request coalescing; usage limits documented | Executed: `providers.test.js`, `scan-service.test.js`. **Not executed:** any real Google/URLhaus call (no network, no keys). Docs consulted via web search on the day of authoring: Google Safe Browsing v4 usage limits (non-commercial), URLhaus API (Auth-Key, `query_status`) |
| 9 | Backend hardening | 400/413/415/403/405/429(+Retry-After)/404 JSON errors; configurable CORS (dev ports 3000/5500/5501; production same-origin); `TRUST_PROXY` hops/CIDRs (`true` refused); per-IP limiter with optional Redis store, bounded concurrency, per-provider budgets; strict CSP; headers kept/added; HSTS opt-in; `engines >=20.12` | Executed: config, CORS decision, CSP, budget/gate tests, status codes at the service layer. **Provided, not run:** the 11 Express tests (status codes, CORS, headers, rate limiting, trust-proxy behaviour). Redis store: provided, untested |
| 10 | Frontend structure | ES modules: url-policy, analysis, providers-client, report, history, controller, ui/*; no globals, no overridden functions; `addEventListener`/delegation only; storage validated | Executed: layout test (no inline script/handler/style), corrupted-storage unit and 6 browser shapes (`null`, `{}`, junk arrays, non-JSON, string, `[[]]`), blocked storage |
| 11 | Labs/education | Lab 04 buttons bound programmatically; quiz scores each question once; DMARC lab rewritten (aligned SPF **or** aligned DKIM; two messages); password lab no longer shows a naive bit count for patterned passwords and states assumptions; assistant labelled rule-based; contact form says nothing was sent and offers copy | Executed: unit + browser (button DOM has no `onclick`, exact attribute set, works; quiz cannot be inflated even by programmatic repeat clicks; DMARC explanation; password patterns; contact status) |
| 12 | Build and validation | esbuild bundle + Tailwind v4 compiler build (no CDN); `.env.example` placeholders; README; scripts | Executed: both builds; layout check; test suites below |

## Test tally

| Suite | Result | Notes |
|---|---|---|
| `npm run test:unit` | **93 / 93 passed** (executed) | providers 14, scan-service 13, url-policy 13, analysis 15, controller 23, history+labs 11, layout 4 |
| `npm run test:browser` | **31 / 31 passed** (executed) | headless Chromium only, desktop 1280 and mobile 390 widths, mocked providers via a harness that uses the real scan-service (not Express) |
| `npm run test:http` | 11 tests written, **0 executed** | `Cannot find package 'express'`: no network in the authoring sandbox |
| Mutation spot checks | 3 executed | removing the stale-response guard, breaking the Google `{}` rule, disabling nested-URL redaction each made tests fail, then were restored |
| `npm audit` | **not run** | no registry access; vulnerability status of the dependency tree is unknown |
| Real providers | **not contacted** | no network/keys |

Versions exercised: Node 22.23.4, psl 1.15.0, Tailwind 4.3.3, esbuild 0.28.2, Playwright 1.63 / Chromium 1243. Express 4.21.x and express-rate-limit 7.5 are declared but **were never loaded here**.

## Remaining limitations and follow-ups

1. Run `npm install`, commit the generated lockfile, then `npm test` (this executes the 11 Express tests) and `npm audit`.
2. Add real keys to `.env` and try one benign URL by hand to confirm Google and URLhaus credentials; `/api/providers` will show `last_lookup_answered` afterwards.
3. Evaluate Google Web Risk before any commercial use; confirm abuse.ch terms for your use.
4. Rate-limit store `redis` and provider budgets per instance are provided, not exercised.
5. Visual parity with the former Tailwind v3 CDN page was not measured (only eyeballed in screenshots); Google Fonts could not load offline.
6. Only Chromium was tested; keyboard and screen-reader behaviour were checked programmatically (labels, skip link, roles), not with assistive technology.
7. Heuristic thresholds and weights are unvalidated judgement calls; the corpus guards against regressions only.
