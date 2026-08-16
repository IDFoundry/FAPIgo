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
     that's implemented properly (or these modules are resolved
     manually), use `POST /api/log/{testId}/images/{placeholder}` with a
     base64 `data:image/png;base64,...` body against the placeholder ID
     from that test's own log — no auth needed against the suite's local
     devmode instance — to unblock one of these tests by hand.

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

```
pip install -r <suite-checkout>/scripts/requirements.txt   # one-time: httpx, pyparsing
cd <suite-checkout>
./scripts/run-test-plan.py \
  'fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][openid=openid_connect]' \
  /path/to/go-fapi/conformance/server/oidf-config/baseline-plan.json
```

With no `CONFORMANCE_SERVER` env var, it defaults to
`https://localhost.emobix.co.uk:8443/` — this same local suite instance
— and auto-detects dev mode, which also disables TLS verification, so
no extra flags are needed for a local run.

**This doesn't remove the need for the JS-stall poller.** It's still
the suite's own internal HtmlUnit-based scripted browser driving
consent, so the same `browser`/`override` config from the previous
section is just as required, and the same implicit-callback stall and
screenshot-review-placeholder gates still occur — keep
`unblock-implicit-callback.sh` (scratchpad) running alongside it.

**Known, accepted warnings**: `expected-warnings-baseline.json` and
`expected-skips-baseline.json` (this directory) tell `run-test-plan.py`
which non-`PASSED` results are expected, so it only exits non-zero for
genuinely new regressions — the same mechanism OIDF's own CI uses
(`.gitlab-ci/expected-failures-fapi.json` in the suite checkout; our
two entries mirror two of theirs almost verbatim — Authlete, OIDF's own
reference AS, hits the identical warnings for the identical reasons).
Currently covers:
- `attempt-reuse-authorization-code-after-one-second`'s
  `EnsureHttpStatusCodeIs4xx` warning — this AS's access tokens are
  stateless, self-verifying JWTs (see `resource/verify.go`), so there's
  no revocation list a resource endpoint could consult; RFC 6749
  §4.1.2's "should revoke on detected code reuse" is a `SHOULD`, and the
  suite's own module text confirms not implementing it won't block
  certification.
- `refresh-token`'s `FAPIEnsureServerConfigurationDoesNotSupportRefreshToken`
  warning and `SKIPPED` result — this variant's granted scope excludes
  `offline_access`, so no refresh token is issued; explicitly acceptable
  server policy per the suite's own message.
- `ensure-signed-client-assertion-with-RS256-fails`'s `SKIPPED` result —
  deterministic, not a flake: this test needs an RSA client key to sign
  an RS256 assertion, and this AS's clients are ES256-only by design (no
  RSA/PS256 support anywhere in the algorithm policy). The suite's own
  skip message confirms this doesn't block certification.

```
./scripts/run-test-plan.py \
  --expected-failures-file /path/to/go-fapi/conformance/server/expected-warnings-baseline.json \
  --expected-skips-file /path/to/go-fapi/conformance/server/expected-skips-baseline.json \
  'fapi2-security-profile-final-test-plan[...]' \
  /path/to/go-fapi/conformance/server/oidf-config/baseline-plan.json
```

If a run turns up a *new* warning or failure, don't add it here reflexively —
root-cause it first (most of the fixes in this AS's history started
exactly this way); only add an entry once it's confirmed to be a
deliberate, understood tradeoff rather than a bug.

The docker-compose setup is deliberately shaped so a GitHub Actions job
can reuse this directly — same containers, same network-attach pattern,
`SUITE_NETWORK` and the client key/config just need to be generated in
the job instead of by hand.
