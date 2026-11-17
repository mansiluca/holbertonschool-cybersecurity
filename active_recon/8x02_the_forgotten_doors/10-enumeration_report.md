# Enumeration Report, Driftwood
For: Ridgeline web testing team

## 1. Executive summary

Driftwood's external surface is not what a wordlist says it is. The production site
answers every unknown path with a 200 and a page-not-found body, so status-code
discovery reports the whole tree and finds nothing. Once the soft-404 was modelled,
one directory mattered: `/partner-portal`, and below it `/partner-portal/uploads/`
with `config.bak` in the clear.

The same pattern repeats higher up. On shared infrastructure, a host responds only
to its own name in the `Host` header: `admin-dev.driftwood.example`. It is not linked
from anywhere, appears in no scan and is invisible to a browser. That host serves a
single-page app whose lazy-loaded bundles name `/api/v2/internal/exports`, carry a
hardcoded AWS key, and point at `internal-api.driftwood.example`.

The API around that route has no floor plan. Sibling enumeration exposes
`/api/v2/internal/users`, which the JavaScript never names, and one parameter nobody
documented (`role`) changes the object returned: the endpoint behaves like two
endpoints depending on who asks. That is a missing authorization control, confirmed,
not exploited.

Operationally: the attack surface is a set of names that were supposed to be
forgotten, and the most valuable of them is written in the front end the vendor
ships to every visitor.

## 2. Mapped surface

| Layer | Finding | Evidence |
|---|---|---|
| Soft-404 | 200, len=1487, body "page not found" | baseline on three UUID paths |
| Content | `/partner-portal/` | breaks the soft-404 signature |
| Recursive | `/partner-portal/uploads/`, `config.bak` | extension inferred from `X-Powered-By` |
| vhost | `admin-dev.driftwood.example` | differs from the catch-all response |
| JavaScript | `/api/v2/internal/exports` in a lazy chunk | bundle crawl, chunk 7 |
| Secret | AWS access key `AKIA...` in the same chunk | regex on bundles |
| Internal host | `internal-api.driftwood.example` | host pattern, confirmed live |
| API | `/api/v2/internal/users`, `GET` | sibling of `exports`, undocumented |
| Parameter | `role` | behavior change, honored |
| CMS | user `editor.jdoe`, `booking-widget 2.3.1` | REST user listing, readme stable tag |

Fossils were ruled out, not reported: `/api/v1/legacy-bookings` answers 410 and the
external CDN and analytics hosts answer for everyone.

## 3. Tooling

Each script is standalone, takes a target on the command line, and reasons about the
response instead of spraying paths.

| Script | What it does | Re-run |
|---|---|---|
| `1-discovery_engine.py` | Baselines the not-found response from impossible paths, walks a wordlist, keeps only responses that break that signature | `./1-discovery_engine.py http://driftwood.example` |
| `2-recursive_discovery.py` | BFS over confirmed directories, per-depth baseline, extensions inferred from the headers | `./2-recursive_discovery.py http://driftwood.example [wordlist]` |
| `3-vhost_finder.py` | Baselines default and catch-all answers, fuzzes the `Host` header, classifies real hosts by differential | `./3-vhost_finder.py driftwood.example 10.10.10.8` |
| `4-js_recon.py` | Fetches every script and chunk, extracts routes across several patterns, resolves and deduplicates, pulls secrets | `./4-js_recon.py http://admin-dev.driftwood.example` |
| `5-js_triage.py` | Separates internal hosts from CDN noise, probes liveness, drops fossils, ranks live internal first | `./5-js_triage.py http://admin-dev.driftwood.example` |
| `6-api_mapper.py` | Enumerates siblings of a known route, discovers honored methods, follows routes named inside JSON responses | `./6-api_mapper.py http://admin-dev.driftwood.example/api/v2` |
| `7-param_finder.py` | Baselines an impossible parameter, then detects the status/length/timing/content change an honored parameter produces | `./7-param_finder.py http://admin-dev.driftwood.example/api/v2/internal/users` |
| `8-cms_enum.py` | Orchestrates CMS tooling, then enumerates users, pins exact plugin versions, maps them to the local vulnerability database | `./8-cms_enum.py http://blog.driftwood.example` |
| `9-chain.py` | Walks all layers and confirms the misconfiguration end to end | `./9-chain.py` |

## 4. The chain

1. `admin-dev.driftwood.example` answers by name only. Nothing links to it. A scan of
   the IP addresses sees the shared listener's default page.
2. Its front end ships the map: a lazy chunk references `/api/v2/internal/exports`.
   The same chunk carries an AWS access key that should never have reached a browser.
3. The API around that route is documented only by its own behavior:
   `/api/v2/internal/users` answers `GET` while never being named in the JavaScript.
4. `role` changes the response by an order of magnitude. The endpoint returns a
   different object depending on who asks, which is an authorization control missing
   rather than a bug in a handler.

Confirmed: missing authorization on `role`, present and reproducible. Not exploited:
no data was extracted beyond the delta that proves the behavior, and the key was not
used against any AWS endpoint.

## 5. Methodology and limitations

Confirmed by observation: the soft-404 signature, `/partner-portal/uploads/config.bak`,
the vhost differential, the endpoint in the lazy chunk, the undocumented sibling route,
the honored parameter and the CMS user and plugin version.

Identified but left unexploited: the hardcoded AWS key, the file reachable under
`/partner-portal/uploads/`, and the authorization gap itself. Confirming was the
mandate; leveraging belongs to the testing phase that follows this map, under its own
rules of engagement.

Limits of this work: one wordlist family, extensions inferred from headers only, no
authenticated surface (no credential was used to browse), no TLS inspection beyond
certificate presence, and no attempt at rate-limit or WAF evasion. Anything behind a
login, anything requiring a valid session, and anything reached only through
client-side rendering we did not execute remains unmapped. A second pass with an
authenticated session and the exported route list as a seed would go further.
