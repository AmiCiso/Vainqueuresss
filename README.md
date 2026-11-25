# VAINQUEURES site and VanQ threat scanner

VAINQUEURES is the parent brand. **VanQ** is the URL threat scanner, powered by the **VanQ Omni** local heuristic
engine. VAINQUEURES Academy, VAINQUEURES RT and AI Security are separate sections under the same brand.

## What exists today, and what does not

| Implemented | Not implemented (future ambitions only) |
|---|---|
| Local URL heuristics (27 documented indicators, nested-destination analysis, Public Suffix List aware) | Autonomous / machine-learning threat protection |
| Optional Google Safe Browsing + URLhaus lookups through the gateway | VirusTotal, page fetching, screenshots, redirect expansion |
| Unified scan report, redacted local history, JSON export | Verified, continuously updated threat feeds (preset examples are demonstration fixtures) |
| Rule-based assistant (keyword matching, no generative model) | Commissioned red-team engagements, 24/7 response |
| Academy (12 categories, quizzes), 9 labs, 5-stage RT roadmap | Contact-form delivery, accounts |

## Quick start

Requires **Node.js >= 20.12** (Node 22 LTS recommended).

```bash
npm install                  # runtime: express, express-rate-limit; build/dev: esbuild, tailwindcss, psl, playwright
cp .env.example .env         # then edit; keys are optional (see "Providers")
npm run build                # builds public/assets/app.js and public/assets/app.css
npm start                    # http://127.0.0.1:3000
```

Other commands

```bash
npm run dev                  # node --watch server.js
npm test                     # unit + HTTP integration tests (HTTP tests need `npm install`)
npm run test:unit            # pure-logic tests, no Express needed
npm run test:http            # real Express app, mocked providers
npm run test:browser         # Playwright; first run: npx playwright install chromium
npm run check:layout         # asserts public/ contains only browser assets
```

Production: `NODE_ENV=production npm run build && NODE_ENV=production npm start` behind HTTPS (see "Deployment").

> No `package-lock.json` is included in this delivery. It could not be generated offline. Run `npm install` once and
> commit the resulting lockfile; use `npm ci` afterwards. Run `npm audit` yourself: it was **not** run here.

## Architecture

```
server.js                    entry: loads env, builds config, starts Express
server/
  config.js                  env parsing (trust proxy, CORS origins, budgets, cache)
  policy.js                  pure CSP + CORS decision helpers (unit-tested)
  app.js                     Express wiring only: headers, CORS, rate limit, JSON parsing, routes, static
  scan-service.js            framework-free request logic: validation, consent gate, providers, caching
  providers.js               Google Safe Browsing + URLhaus adapters with response-shape validation
  net.js                     bounded fetch (abort covers body read), response size cap
  cache.js, guards.js        bounded HMAC-keyed cache + coalescing; concurrency gate; per-instance budgets
src/                         browser ES modules (bundled by esbuild)
  shared/url-policy.js       normalization, validation, host classification, sensitive-URL detection, redaction
  shared/ip.js               IPv4/IPv6 parsing and IANA special-purpose range classification
  analysis.js                pure heuristics (no DOM/network/clock)
  report.js                  the single authoritative scan-report model + verdict + export
  scan-controller.js         state machine with a generation token (stale responses are dropped)
  providers-client.js        gateway client: abortable, no auto-retry, response validation
  history.js                 validated, redacted, retention-limited localStorage
  labs-logic.js              DOM-free lab/quiz/progress logic
  ui/*.js                    DOM rendering (textContent, delegated listeners, no inline handlers)
  data/*.js                  academy, RT, assistant knowledge base, reference lists, demo fixtures
  styles/app.css             Tailwind v4 entry + pinned v3-equivalent palette
public/                      the ONLY directory served over HTTP
scripts/                     build-js.mjs, build-css.mjs, check-public-layout.mjs, run-tests.mjs
test/unit, test/http, test/browser, test/corpus.json
docs/                        REMEDIATION.md (finding -> fix -> verification)
```

## Verdict model

One report object drives the banner, provider cards, history row, counters and export.

* `Threat reported by provider` always wins when a provider returns a match, even if the local score is 0.
* Otherwise the heuristic band gives `High heuristic risk` (score >= 50), `Suspicious` (>= 25), `Minor indicators`, or
  `No local indicators detected`. The score is an uncalibrated 0-99 sum of weak indicators, never a probability.
* A provider "no match" never lowers a heuristic verdict. Outages, missing keys, timeouts, rate limits and
  unexpected responses are shown per provider and are never counted as clean.
* While a lookup is pending the banner is marked PROVISIONAL and export is disabled. Exports of unfinished reports
  (if produced programmatically) carry `exportStatus: "incomplete"`.

## Privacy behaviour

* **Default is local-only.** Nothing leaves the browser unless you select "Local analysis + external reputation lookup".
* Before external lookup the UI states that the URL (without its `#fragment`) goes to this site's server and is
  forwarded to Google Safe Browsing and URLhaus. Sample presets are always local-only.
* URLs with `user:pass@` are rejected. Likely-sensitive URLs (credential-like parameters, JWT/API-key-shaped values,
  account-flow tokens in the path, credential-like fragments, email addresses) pause for an explicit choice:
  keep local, send without the query string (less accurate), or send anyway. The server enforces the same gate
  (`409 sensitive_url_unacknowledged`). Detection is best-effort and **cannot recognise every secret**.
* Normalization policy for providers: scheme/host lowercased, one trailing dot stripped, default ports removed,
  fragment removed, **path and query preserved** (stripping the query would change the identity of the checked
  resource). Reserved/private/loopback hosts are never forwarded.
* History stores only redacted display values and verdict metadata: max 20 entries, 30 days. Tokens, credentials,
  fragments and exact URLs are never persisted, exported or logged. The exact URL exists only in memory during the
  active scan. Legacy keys (`vr_scan_history`, ...) from older builds are deleted on load.
* The gateway never logs URLs or bodies; the cache is keyed by HMAC digests (per-process random key) and stores only
  provider verdict metadata. Your hosting provider's own access logs are outside this software's control.

## Providers

* **Google Safe Browsing Lookup API v4** (`threatMatches:find`). Google restricts this API to **non-commercial use**
  and asks that warnings use qualified language and show "Advisory provided by Google" (rendered on a match). The
  data is "not perfect". Before any commercial deployment evaluate Google **Web Risk** (the commercial product) or
  Safe Browsing v5; this project does not migrate APIs or introduce paid services silently.
  Docs: https://developers.google.com/safe-browsing/v4/usage-limits
* **URLhaus (abuse.ch)** `POST https://urlhaus-api.abuse.ch/v1/url/` with an `Auth-Key` header. It lists URLs
  observed distributing malware; it is **not** a complete phishing detector, and "offline" listings are reported as
  such. Respect abuse.ch's terms of use and fair-use limits.
* `/api/providers` reports `configured` plus the last observed outcome. A configured key is **never** reported as
  "ready" or "verified"; no active probe is made (it would spend quota and send data).
* Responses are validated: Google's empty object `{}` is a legitimate no-match; any other unexpected shape is
  `unexpected_response`. Caching honors Google's `cacheDuration` for matches; "no match" uses a short local TTL.
* Endpoints are fixed allowlist constants; user input is only ever request data. No user-supplied target is fetched.

## Deployment

* **HTTPS/HSTS:** the app does not terminate TLS. Enforce HTTPS at the platform/proxy. Set `HSTS=on` only when every
  request is HTTPS; the app then sends `Strict-Transport-Security` on secure requests. The absence of an
  application-level HSTS header says nothing about whether your deployment sets one elsewhere.
* **Trust proxy:** set `TRUST_PROXY` to the exact number of proxy hops (or proxy IPs/CIDRs). `true` is refused.
  Leaving it unset behind a proxy makes all users share the proxy's IP for rate limiting.
* **CORS:** an allowlist for browsers only. It is not authentication and does nothing against curl or scripts.
  Production default is same-origin only. Dev defaults cover localhost/127.0.0.1 on ports 3000, 5500, 5501.
* **Rate limiting:** per-IP limiter (`express-rate-limit`), bounded provider concurrency with a queue, per-provider
  per-minute budgets and request coalescing. The in-memory store is correct for **one instance / development**. For
  several instances set `RATE_LIMIT_STORE=redis` and `REDIS_URL` (uses the optional `rate-limit-redis` + `redis`
  packages; Redis is the only extra infrastructure and is needed only for multi-instance deployments). Provider
  budgets remain per instance: set them to quota / instances.
* **CSP:** `script-src 'self'` (no inline script/handlers), styles from self + Google Fonts, `object-src 'none'`,
  `base-uri 'none'`, `frame-ancestors 'none'`. Google Fonts is the only third-party request; self-host the fonts
  and drop those two origins from the CSP if you do not want that disclosure to Google.
* **Static hosting:** only `public/` is served, dotfiles are ignored (Express `serve-static` default), no directory
  listing. If you serve `public/` from a CDN/static host instead, set `<meta name="vq-api-base">` and
  `CSP_CONNECT_EXTRA`/`ALLOWED_ORIGINS` accordingly.
* **Runtime:** Node >= 20.12 (declared in `engines`).

## Build notes

* JS: esbuild bundles `src/main.js` plus the `psl` package (Public Suffix List including private suffixes) into one
  file (~283 KiB, most of it PSL data; refresh with `npm update psl`).
* CSS: Tailwind CSS **v4** compiler API (`scripts/build-css.mjs`) replaces the runtime v3 CDN. The palette, shadow
  and font values the site used are pinned in `src/styles/app.css`. Pixel parity against the old CDN build was not
  measured. Classes must appear as literal strings in HTML/JS (the scanner collects tokens textually).
* The CSS output targets Chrome 111+/Safari 16.4+/Firefox 128+ (Tailwind v4 baseline).

## Testing: what is executed where

See `docs/REMEDIATION.md` for the exact tally of tests executed in the authoring environment versus tests provided
for you to run. The labeled corpus in `test/corpus.json` pins current heuristic behavior for regression; it is
**not** an accuracy measurement.

## Known limitations

* Heuristics inspect URL text only. No DNS, TLS, WHOIS, page content or reputation data is used locally.
* The UGC/shared-hosting list is curated by hand: the `psl` package merges ICANN and private sections without
  exposing which is which.
* Demonstration fixtures (`src/data/demo-fixtures.js`) are synthetic and unverified.
* MITRE ATT&CK mappings are tentative and inferred from URL text alone.
* Password lab and entropy language are teaching demonstrations, not strength meters.
* The contact form does not send anything and says so.

## If target fetching is ever added

Do **not** rely on hostname string checks. A fetching feature would require resolving DNS and validating every
resolved IP against the reserved ranges in `src/shared/ip.js`, pinning the connection to the validated IP,
validating every redirect hop the same way, restricting ports/schemes, bounding size/time, and enforcing egress
controls at the network layer. The current gateway does none of this because it never fetches user-supplied targets.
