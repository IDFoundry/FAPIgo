# server scripts

Scripts to drive the authorization server under test against the OpenID
Foundation conformance suite and collect results.

- `generate-client-key/` — `go run ./conformance/server/scripts/generate-client-key`
  prints one throwaway ES256 keypair as two JWKS documents: a private
  one for the suite's plan config, a public one for
  `../oidf-config/*.config.json`.
- `generate-server-cert.sh` — writes a throwaway self-signed cert/key
  pair to `../certs/` for `conformance-as` to serve TLS with under
  `../docker-compose.yml`. See that file's header comment for why a
  self-signed cert is sufficient here — no CA or truststore wiring
  needed, because the suite's own outbound HTTP client trusts any
  certificate for calls to the implementation under test.
- `unblock-implicit-callback.py` — required alongside any headless
  `run-test-plan.py` run (see the "CI-style run" section below): works
  around a suite bug where its own scripted browser can't execute the
  JS that would otherwise unblock a waiting module.
- `retry-flaky-modules.py` — `conformance/scripts/run-all.sh` runs this
  automatically after any non-clean AS suite; not something you invoke
  by hand. Detects and auto-retries two known, non-deterministic
  suite-internal races so neither needs a full re-run, or gets mistaken
  for an AS regression, every time it happens: a stale implicit-submit
  callback from an already-abandoned module landing on the current
  alias owner, and a stale HTTP response (a /token grant error)
  delivered as the answer to an unrelated request on a GitHub Actions
  runner — see its own doc comment for the full forensic detail on why
  each is entirely a suite-internal race, never traced to cmd/conformance-as.

Everything runs via `../docker-compose.yml`, entirely locally — no
tunnel (ngrok etc.) required. That also makes this the same shape a
GitHub Actions job would use: bring up the suite and `conformance-as` as
containers on one Docker network, no external dependency or secret in
the loop.

**After every code change**, rebuild with `--no-cache` before trusting a
retest — `docker compose up -d --build --force-recreate <service>` has
been observed to silently reuse a stale cached `go build` layer even
though `--force-recreate` correctly replaces the *container*. If a fix
doesn't seem to take effect, don't assume the fix is wrong before
ruling this out:

```
docker compose build --no-cache <service>
docker compose up -d --force-recreate <service>
```

## Manual test run, end to end

1. Run the OIDF conformance suite locally, in a directory *outside*
   this repo (its own git history/build artifacts, no path coupling
   needed — `../docker-compose.yml` only references it by Docker
   network name):
   `git clone https://gitlab.com/openid/conformance-suite.git`, then
   `docker compose -f docker-compose-prebuilt.yml up` (uses prebuilt
   images — no local Maven/Java build needed; the other
   `docker-compose*.yml` files in that repo all expect you to build
   `./target/fapi-test-suite.jar` yourself first). Note the Docker
   network it created: `docker network ls` (usually
   `<suite-checkout-dir-name>_default`). It's reachable at
   `https://localhost.emobix.co.uk:8443`.
2. `go run ./conformance/server/scripts/generate-client-key` and
   `go run ./conformance/server/scripts/generate-client-key client2`
   — you need two keypairs, one per registered client (see step 4).
   Keep all four JWKS outputs handy.
3. `./generate-server-cert.sh`.
4. In the suite UI, create a new plan — **these are two distinct plans,
   not one plan with a response-mode variant** (verified against the
   suite's `FAPI2SPFinalTestPlan`/`FAPI2MessageSigningFinalTestPlan`
   source, not assumed):
   - Baseline run: **`fapi2-security-profile-final-test-plan`**
     ("FAPI2-Security-Profile-Final: Authorization server test").
     `fapi_request_method`/`fapi_response_mode` aren't selectable on
     this plan — it's hardcoded to unsigned/plain_response.
   - Message-signing run: **`fapi2-message-signing-final-test-plan`**
     ("FAPI2-Message-Signing-Final: Authorization server test"), with
     `fapi_request_method=signed_non_repudiation` and
     `fapi_response_mode=jarm`.

   Both need `client_auth_type=private_key_jwt`, `sender_constrain=dpop`,
   `fapi_profile=plain_fapi`, `openid=openid_connect`. Pick an alias.
   The plan config needs **both `client` and `client2` blocks** — some
   modules actively drive a second registered client against your AS
   (e.g. checking an authorization code is bound to the client that
   requested it), not just a formality. Paste the `client`/`client2`
   **private** JWKs from step 2 into their matching blocks, set a
   `client_id` for each, and note the alias's `.../callback` redirect
   URI (shared by both).
5. Fill in `../oidf-config/baseline.config.json` (or
   `message-signing.config.json`) — both `clients[0]` and `clients[1]`
   — with those client_ids, the redirect URI and the matching
   **public** JWKs from step 2 — see
   [../oidf-config/README.md](../oidf-config/README.md). The `issuer`
   is already set to this service's docker-compose hostname
   (`conformance-as-baseline` / `conformance-as-message-signing`) —
   leave it as-is unless you rename the service.
6. Set `server.discoveryUrl` in the suite plan to
   `https://conformance-as-baseline:8443/.well-known/openid-configuration`
   (swap the hostname for the message-signing run), and add the
   `resource` block the AS test plan's happy-flow module requires — see
   [../oidf-config/README.md](../oidf-config/README.md)'s "The
   `resource` block" section.
7. `export SUITE_NETWORK=<network from step 1>` (only needed if it
   isn't the default `conformance-suite_default`), then from this
   directory: `docker compose up --build conformance-as-baseline` (or
   `conformance-as-message-signing`, or both).
8. **Reaching the AS's consent page.** The suite sometimes shows a
   "visit `https://conformance-as-baseline:8443/authorize?...`" prompt
   for you to open — that hostname is Docker-internal and your own
   browser can't resolve it. Don't try to fix this with host
   networking: the suite's own `nginx` already publishes `0.0.0.0:8443`
   (every host interface), and a wildcard bind like that blocks any
   other container from also binding port 8443 on this host, on any
   address — loopback aliases included (found the hard way; see git
   history if curious). Two real options:
   - **One-off, right now:** substitute this file's published host
     port for the hostname — `conformance-as-baseline:8443` becomes
     `127.0.0.1:18443` (`18444` for message-signing) — and open that
     instead. Works because `/authorize` doesn't check the incoming
     `Host` header, and the self-signed cert already covers `127.0.0.1`
     as a SAN, so you'll only get the usual "not trusted" click-through.
   - **For the rest of the run:** add this to the plan config's
     top-level `browser` array so the suite's *own* in-container
     browser — already on this same Docker network, so it resolves
     `conformance-as-baseline` natively — drives consent itself, and
     the "visit this link" prompt stops appearing entirely (verified
     `commands` schema against the suite's own example configs, e.g.
     `scripts/test-configs-brazil/*-automated.json`; swap the hostname
     for the message-signing run):

     ```json
     "browser": [
       {
         "match": "https://conformance-as-baseline:8443/authorize*",
         "tasks": [
           {
             "task": "Consent",
             "match": "https://conformance-as-baseline:8443/authorize*",
             "commands": [
               ["click", "xpath", "//button[@name='decision' and @value='approve']", "optional"]
             ]
           }
         ]
       }
     ]
     ```

     The trailing `"optional"` matters: negative-parameter test modules
     deliberately drive requests this AS correctly rejects before ever
     rendering the consent form (e.g. an unsigned request sent directly
     to `/authorize`, bypassing PAR) — the page they land on is this
     AS's local HTML error page, which has no Approve button at all.
     Without `"optional"`, the suite's browser throws
     `NoSuchElementException` and fails those modules even though the
     AS behaved correctly; with it, the click just no-ops when there's
     nothing to click.

     **Do not add a blanket `wait`/`update-image-placeholder-optional`
     step here to auto-resolve the "upload a screenshot" review gate
     some negative-test modules block on** (`ExpectInvalidRequestUriErrorPage`
     and similar `createBrowserInteractionPlaceholder()` callers) — it
     was tried and reverted. The `-optional` suffix only makes the
     *placeholder-fill* tolerant of there being nothing pending; a `wait`
     whose regexp never matches within its timeout throws
     `TestFailureException` unconditionally
     (`BrowserControl.java`'s `wait` handler, `catch (TimeoutException ...)`
     always rethrows). Since both the consent page and this AS's local
     error page render at the same `/authorize` URL, a `wait` for the
     error page's `Authorization Error` marker times out — and fails the
     test — on every ordinary happy-path visit, not just the negative
     ones. The suite's own CI config that uses this idiom
     (`.gitlab-ci/local-provider-oidcc-conformance-config.json`) only
     gets away with it by scoping the `wait` inside a per-test-name
     `"override"` block, where the marker text is guaranteed to appear;
     applied blanket to every `/authorize` visit it isn't safe. Until
     that's implemented properly, use `POST
     /api/log/{testId}/images/{placeholder}` with a base64
     `data:image/png;base64,...` body against the placeholder ID from
     that test's own log — no auth needed against the suite's local
     devmode instance — to unblock one of these tests by hand. Running
     `scripts/unblock-implicit-callback.py` (see the CI-style run
     section below) does exactly this automatically for every module in
     a plan, so manual use of this endpoint is mostly only useful when
     poking at a single stuck module through the UI.

   - **`fapi2-security-profile-final-user-rejects-authentication`** is
     the one module that needs the *opposite* click: its own summary
     states the test requires the user to reject consent, expecting an
     `access_denied` error back — the AS already renders and correctly
     handles a Deny button (`cmd/conformance-as/consent_template.go`,
     `authorize.go`'s `handleDecision`), the default `browser` block
     above just never clicks it. Rather than changing the default
     Consent task (which every other module also relies on), add an
     `override` block scoped to just this one test name. `override` is
     a **top-level key in the same plan config JSON** — a sibling of
     `alias`/`client`/`client2`/`server`/`resource`/`browser`, *not*
     nested inside `browser`, and not in `oidf-config/*.config.json`
     (this AS's own client-registry file, which the suite never reads).
     Verified against the suite's own merge logic
     (`DBTestPlanService.java`): for the named module, every key inside
     its override object replaces the plan's top-level key of the same
     name, so this `browser` only takes effect for this one test:

     ```json
     "override": {
       "fapi2-security-profile-final-user-rejects-authentication": {
         "browser": [
           {
             "match": "https://conformance-as-baseline:8443/authorize*",
             "tasks": [
               {
                 "task": "Deny",
                 "match": "https://conformance-as-baseline:8443/authorize*",
                 "commands": [
                   ["click", "xpath", "//button[@name='decision' and @value='deny']", "optional"]
                 ]
               }
             ]
           }
         ]
       }
     }
     ```

     This module also runs the flow twice (first client, then a second
     registered client) — both visits hit the same `/authorize`
     pattern, so this one override covers both without any extra
     config.

## CI-style run (no browser, no human)

The suite ships its own headless CI runner,
`scripts/run-test-plan.py`, in the conformance-suite checkout from step
1 — it drives the same REST API as the UI: creates a plan, runs every
module in sequence, polls status, and exits non-zero on unexpected
failures. It needs the *suite plan config* as an actual file on disk
(the same JSON you'd otherwise paste into the UI in step 4) — save it
as `../oidf-config/baseline-plan.json` (message-signing:
`message-signing-plan.json`). Those filenames are gitignored (see
`.gitignore`'s comment) because, unlike `oidf-config/*.config.json`
(this AS's own config, public keys only), the plan config carries the
suite-side client's **private** keys.

Don't hand-assemble those files — this flow's alias, redirect URIs,
`resource` block and `browser`/`override` automation are all fixed,
known values (no interactive "pick an alias in the UI" step the way
the manual flow above has), so
`go run ./conformance/server/scripts/setup-config` generates both
`*-plan.json` files (and updates the matching `oidf-config/*.config.json`)
in one shot — see [../oidf-config/README.md](../oidf-config/README.md)'s
"Quick start". `conformance/scripts/run-all.sh`, which drives this
CI-style flow for all four suites at once, expects exactly the files
that command produces.

```
pip install -r <suite-checkout>/scripts/requirements.txt   # one-time: httpx, pyparsing
cd <suite-checkout>
./scripts/run-test-plan.py \
  'fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][openid=openid_connect]' \
  /path/to/fapigo/conformance/server/oidf-config/baseline-plan.json
```

With no `CONFORMANCE_SERVER` env var, it defaults to
`https://localhost.emobix.co.uk:8443/` — this same local suite instance
— and auto-detects dev mode, which also disables TLS verification, so
no extra flags are needed for a local run.

**This doesn't remove the need for the JS-stall poller.** It's still
the suite's own internal HtmlUnit-based scripted browser driving
consent, so the same `browser`/`override` config from the previous
section is just as required, and the same implicit-callback stall and
screenshot-review-placeholder gates still occur. Run
`scripts/unblock-implicit-callback.py <planId>` (this directory)
alongside `run-test-plan.py` — it POSTs the empty-body implicit-submit
callback HtmlUnit's broken JS never sends, and auto-fills any
screenshot-review placeholder with a blank image, for every module in
the plan:

```
./scripts/run-test-plan.py '<plan>[...]' <config.json> &
/path/to/fapigo/conformance/server/scripts/unblock-implicit-callback.py <planId>
```

`<planId>` is printed by `run-test-plan.py` itself ("Created test plan,
new id: ..."). **This is not optional infrastructure to route around
if you'd rather avoid it** — every suite version that supports
`fapi2-security-profile-final-test-plan` also carries the HtmlUnit
bug: confirmed by bisecting the suite's own git history, the last
release with the old, working Bootstrap (`release-v5.1.17`) predates
the FAPI2-Security-Profile-Final test plan's introduction entirely,
and the very next release (`v5.1.18`) added both the plan and the
Bootstrap bump that breaks HtmlUnit in the same commit range. There is
no version to pin to that has both. See the script's own doc comment
for the full mechanics and a caveat about one residual, non-AS
limitation (a couple of modules with multi-visit login semantics a
generic empty-body POST can't fully emulate).

**Known, accepted warnings**: `expected-warnings-baseline.json` and
`expected-skips-baseline.json` (this directory) tell `run-test-plan.py`
which non-`PASSED` results are expected, so it only exits non-zero for
genuinely new regressions — the same mechanism OIDF's own CI uses
(`.gitlab-ci/expected-failures-fapi.json` in the suite checkout; our
`attempt-reuse-authorization-code-after-one-second` entry mirrors one
of theirs almost verbatim — Authlete, OIDF's own reference AS, hits the
identical warning for the identical reason). Currently covers:
- `attempt-reuse-authorization-code-after-one-second`'s
  `EnsureHttpStatusCodeIs4xx` warning — this AS's access tokens are
  stateless, self-verifying JWTs (see `resource/verify.go`), so there's
  no revocation list a resource endpoint could consult; RFC 6749
  §4.1.2's "should revoke on detected code reuse" is a `SHOULD`, and the
  suite's own module text confirms not implementing it won't block
  certification.
Both plans' `client2` block requests `offline_access` alongside
`client`'s — `refresh-token` drives its own cross-client
refresh-token-binding check (client 1 must be rejected redeeming a
token issued to client 2) using client 2's own refresh token, which
only gets issued if client 2 actually has that scope; without it, the
module can't reach that check at all and reports `SKIPPED` instead of
running it (this used to be this file's third `expected-skips` entry,
before `client2`'s scope was corrected to include it).

Both plans also register a **third** client, `client_assertion_algorithm`
and `request_object_algorithm` both `PS256` (this AS's own
`algorithms.client_assertion`/`algorithms.request_object` policy lists
now include `PS256` alongside `ES256` to make that registration valid
at all — see `oidf-config/*.config.json`), used only via a per-module
`override` for `ensure-signed-client-assertion-with-RS256-fails` and
(message-signing only) `ensure-signed-request-object-with-RS256-fails`.
Both used to be permanent `SKIPPED` results: each needs its base
signing key to already declare a legitimate FAPI algorithm (ES256 or
PS256) so the *rest* of the flow — PAR, the browser consent step, and
for the request-object test, the request object's own valid signature
— succeeds normally, before the module narrowly swaps just the one
operation under test (the token-endpoint client assertion, or the
request object) to the disallowed RS256 and confirms the AS rejects
it. Since `client`/`client2` stay ES256-only exactly as every other
module needs, this had to be a genuinely separate, PS256-registered
client — a plan-config-only key swap on the existing client both
breaks every other module (the suite's own signing conditions reject a
`client.jwks` with more than one signing-capable key) and can't
satisfy `server.AlgorithmPolicy`'s per-client algorithm pinning
without an AS-side registration to match. See
`conformance/server/scripts/setup-config/main.go`'s own doc comments
(`generatePS256Key`, `patchConformanceASConfig`) for the full detail,
and this repo's own PR history for the live investigation that ruled
out the simpler approaches first.

```
./scripts/run-test-plan.py \
  --expected-failures-file /path/to/fapigo/conformance/server/expected-warnings-baseline.json \
  --expected-skips-file /path/to/fapigo/conformance/server/expected-skips-baseline.json \
  'fapi2-security-profile-final-test-plan[...]' \
  /path/to/fapigo/conformance/server/oidf-config/baseline-plan.json
```

If a run turns up a *new* warning or failure, don't add it here reflexively —
root-cause it first (most of the fixes in this AS's history started
exactly this way); only add an entry once it's confirmed to be a
deliberate, understood tradeoff rather than a bug.

The message-signing profile has its own analogous pair,
`expected-warnings-message-signing.json` and
`expected-skips-message-signing.json` — same two entries as baseline's,
plus one extra deterministic skip
(`ensure-signed-request-object-with-RS256-fails`, only reachable under a
profile that actually sends signed request objects).

### Running both profiles together

`run-test-plan.py`'s positional arguments accept more than one
`<test-plan-name> <configuration-file>` pair in a single invocation, and
since the baseline and message-signing plan configs use different
`alias` values (`gofapi-baseline` / `gofapi-msgsign`), the script gives
each its own queue and runs them **concurrently**, not one after the
other (verified against the script's own queue-per-alias source, not
assumed). One local suite instance, one poller (pass both plan ids to
`unblock-implicit-callback.py` — it accepts more than one), both AS
containers up — same setup as running them separately, just one
command:

```
./scripts/run-test-plan.py \
  --expected-failures-file /path/to/expected-warnings-combined.json \
  --expected-skips-file /path/to/expected-skips-combined.json \
  'fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][openid=openid_connect]' \
  /path/to/fapigo/conformance/server/oidf-config/baseline-plan.json \
  'fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][openid=openid_connect][fapi_request_method=signed_non_repudiation][fapi_response_mode=jarm]' \
  /path/to/fapigo/conformance/server/oidf-config/message-signing-plan.json
```

`--expected-failures-file`/`--expected-skips-file` each take only one
file, but every entry in both profiles' files is already scoped by
`configuration-filename`, so concatenating the two JSON arrays into a
combined file works correctly — each entry still only matches its own
profile's results. Generate that combined file on the fly rather than
committing a static copy, so there's one source of truth per profile
and nothing to keep in sync by hand:

```
python3 -c "
import json
a = json.load(open('expected-warnings-baseline.json'))
b = json.load(open('expected-warnings-message-signing.json'))
json.dump(a + b, open('/tmp/expected-warnings-combined.json', 'w'))
"
# same pattern for expected-skips-*.json
```

**When to use which**: reach for separate, single-profile runs while
debugging or iterating on a fix — a single plan's log is unambiguous
about which profile broke, and the poller has less concurrent traffic
to keep up with (a combined run has been observed to trip a suite-side
timing exception — `runInBackground called after
runFinalisationTaskInBackground()` — when the poller's unblock POST
lands just as a test finishes on its own and its alias moves to the
next test; a plain `--rerun <plan>:<module>` on the same combined
command re-verifies that one module in isolation). Use the combined run
as a faster (~2x wall-clock) final sanity check once both profiles are
already believed clean on their own — e.g. right before merging, or as
a periodic full-suite gate.

The docker-compose setup is deliberately shaped so a GitHub Actions job
can reuse this directly — same containers, same network-attach pattern,
`SUITE_NETWORK` and the client key/config just need to be generated in
the job instead of by hand.
