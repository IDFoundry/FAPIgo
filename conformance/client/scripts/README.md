# client scripts

`cmd/conformance-client` (repo root) drives this module's `client`
package through a FAPI2 relying-party conformance test plan against a
locally running OIDF conformance suite. Unlike the server side
(`conformance/server`), there's no docker-compose setup, no browser
config, and no `oidf-config/*.json` to fill in — the driver is a single
self-contained Go binary that plays **both** roles a real conformance
run needs a human or a browser for:

- **The RP under test**, via `client` itself — real PAR, token, and
  (for the message-signing profile) request-object/JARM traffic against
  the suite's mock authorization server.
- **The "browser"**, by intercepting the `/authorize` redirect itself
  and reading its `Location` header directly rather than letting an
  `http.Client` follow it for real (see `followAuthorizationRedirect`'s
  doc comment in `main.go` — actually following it is a documented,
  suite-verified way to permanently wedge a module).

This is the architectural inverse of `conformance/server`'s setup: there,
the suite drives requests at this repo's hosted AS; here, this repo's
own driver drives requests at the suite's mock AS.

## Running it

The suite must already be running locally (see
[`../../server/scripts/README.md`](../../server/scripts/README.md)'s
step 1 if you don't have it up — `docker compose -f
docker-compose-prebuilt.yml up` from an OIDF `conformance-suite`
checkout, reachable at `https://localhost.emobix.co.uk:8443`). No AS
container, network attachment, or generated key file is needed on this
side — everything the driver's plan config needs (a throwaway ES256
keypair, a unique alias, the registered `client_id`/`redirect_uri`) is
generated in-process, once per run, and never persisted.

```
go run ./cmd/conformance-client -profile=baseline
go run ./cmd/conformance-client -profile=message-signing
go run ./cmd/conformance-client -profile=ciba
go run ./cmd/conformance-client -profile=ciba -mtls
```

- `-profile` selects which plan to run — `baseline`
  (`fapi2-security-profile-final-client-test-plan`, plain query-param
  authorization responses), `message-signing`
  (`fapi2-message-signing-final-client-test-plan`, signed request
  objects and JARM), or `ciba` (`fapi-ciba-id1-client-test-plan` — see
  its own section below; unlike the other two, most of its modules are
  expected to FAIL, for a confirmed, documented reason, not a driver
  bug). Defaults to `baseline`.
- `-mtls`, with `-profile=ciba` only: use `storage.SenderConstrainMTLS`
  (a throwaway self-signed client certificate) instead of DPoP — see
  this profile's own section below. Ignored for `baseline`/`message-signing`.
- `-suite` overrides the suite's base URL. Defaults to
  `https://localhost.emobix.co.uk:8443/`, the same dev-mode instance
  `conformance/server`'s own scripts target.

Each run creates one fresh plan (a random alias like
`gofapi-rp-driver-<suffix>`, so consecutive runs never collide) and
drives every module the plan returns, in the suite's own order,
printing a `=== summary ===` block at the end: one line per module, its
graded PASSED/FAILED/WARNING/etc. result, and — in `[driver: ...]` —
this driver's own error, if it hit one. For most of a plan's
negative-test modules, a driver-side error mid-flow (a rejected ID
token, a denied callback, a JARM signature failure, ...) is exactly the
point, not a bug — `client` detecting the problem and stopping *is* the
correct behavior the module is checking for. **The suite's own graded
result is always the actual verdict; this driver's own error or lack of
one never is** — see `awaitVerdict`'s doc comment in `main.go`.

A non-PASSED result needs its module's own log to diagnose, the same
way the AS side does: `GET
https://localhost.emobix.co.uk:8443/api/log/<moduleID>` (the module ID
appears in each summary line's suite-side URL, or via `plan-detail:
<url>` logged near the top of the run), or the suite's own web UI at
`plan-detail.html?plan=<planID>`.

## What each profile actually needs

Both profiles use `client_auth_type=private_key_jwt`,
`sender_constrain=dpop`, `fapi_profile=plain_fapi`,
`fapi_client_type=oidc` as plan variant selectors — the same shape as
the AS side's plans, confirmed empirically the same way (probing
`POST /api/plan` directly and reading the suite's own `400`
error body for a missing-variant complaint, not guessed from the AS
side's config alone). `message-signing` additionally needs
`fapi_request_method=signed_non_repudiation` and
`fapi_response_mode=jarm` set **explicitly** — the baseline plan
hardcodes both instead of exposing them as selectable variants, so
omitting them on the message-signing plan fails plan creation outright
rather than silently defaulting.

`message-signing` also registers a second client key
(`keys.RequestObjectSigning`, alongside the client-authentication key
every profile needs) in the plan config's `client.jwks`, and picks
`ES256` specifically out of the issuer's advertised
`request_object_signing_alg_values_supported` rather than taking its
first entry — the suite lists `PS256` first, which this driver's
ES256-only key manager can't sign with. If a future profile needs an
algorithm this driver doesn't generate a key for, extending
`ephemeralKeyManager` (`keymanager.go`) is the place to add it, not this
selection logic.

## Gotchas discovered building this driver

These were all real, previously-undetected bugs or suite-specific
quirks, found by driving a live module and reading either the suite's
own response/log or its Java source directly — worth knowing before
changing this driver or `client` itself:

- **Well-known URL construction** (`client/discover.go`): OIDC
  Discovery 1.0 §4.1 appends `/.well-known/openid-configuration`
  *after* the issuer's path; RFC 8414 §3.1 inserts it *before* — a real
  bug in `client`, invisible against every issuer this package had
  talked to before (empty issuer path, so both algorithms produced the
  same URL) until tested against a suite-hosted issuer with a genuine
  path component (`/test/a/<alias>/`).
- **Firing a request before the module is ready.** A module instance
  isn't usable immediately after `POST /api/runner` — the suite still
  has async setup to do. A request that arrives too early doesn't fail
  harmlessly; the module treats it as belonging to a later step and
  gets permanently stuck (`INTERRUPTED`, "Illegal test state change").
  `waitUntilWaiting` (`suite.go`) polls `GET /api/info/{id}` for
  `status == "WAITING"` first.
- **Following the `/authorize` redirect for real.** A standard
  `http.Client` auto-follows it straight to the suite's own
  `/test/a/<alias>/callback` route, which the suite does **not** expect
  an RP-under-test to visit directly (unlike the AS side, where the
  suite's *own* scripted browser visiting that same shape of URL is
  exactly what's expected) — it logs "Got unexpected HTTP call to
  callback" and permanently interrupts the module.
  `followAuthorizationRedirect` uses a `CheckRedirect` that returns
  `http.ErrUseLastResponse` and reads `Location` directly instead.
- **The happy-path module never finishes even after a successful token
  exchange and a `/userinfo` call.** `userInfoIsResourceEndpoint()` is
  `false` for plain FAPI2 in the suite's own
  `FAPI2ClientProfileBehavior` (only `true` for ConnectID/CBUAE
  variants this driver doesn't target) — the module specifically wants
  a GET against the profile's "accounts" resource endpoint, whose URL
  isn't part of standard OIDC discovery at all. The suite publishes it
  as an "exported value" — the same mechanism a human operator reads
  from the web UI — under `GET /api/runner/{id}`'s `"exposed"` map,
  keyed `accounts_endpoint`; `GET /api/info/{id}` never carries it.
  `fetchExposedValues` (`suite.go`) fetches it; `runModule` calls it
  when present.
- **DPoP nonce challenge/retry (RFC 9449 §8).** `client.ExchangeCode`
  originally had no support for it at all — a real gap, fixed in
  `client` itself (not this driver) since it's the token-endpoint call
  that needs the retry, not anything suite-specific.
- **JARM `exp` lifetime.** The suite's own JARM responses carry a
  10-minute `exp` (`GenerateJARMResponseClaims.java`:
  `Instant.now().plusSeconds(600)`) — a driver-configured
  `Limits.MaxJARMResponseLifetime` tighter than that rejects every
  legitimate response, not just the deliberately-expired negative-test
  ones.
- **RFC 9207 `iss` and JARM together.** A JARM response has no
  top-level `iss` *query parameter* to check — `iss` lives inside the
  signed JWT claims instead, already verified cryptographically by
  `jarm.Verify`. `client`'s RFC 9207 plain-mode `iss` check used to run
  unconditionally regardless of response mode, and `internal/jarm`'s
  claims parsing pops `iss` out of the parameters map entirely — so
  `Config.RequireAuthorizationResponseIss=true` rejected *every*
  legitimate JARM response as "missing iss". Fixed in `client` by
  scoping that check to plain-mode responses only.

## CIBA (`-profile=ciba`)

Drives `client.BeginBackchannelAuthentication`/
`PollBackchannelAuthentication` against the OIDF suite's
`fapi-ciba-id1-client-test-plan` (`ciba.go`, not `main.go`'s own
`runModule` — CIBA has no browser hop for that shape to apply to, so
`runCIBA`/`runCIBAModule` drive their own discover → begin → poll
sequence per module). Confirmed live, not assumed:
`FAPICIBARPProfileBehavior.requiresMtlsForBackchannelEndpoint()` is
`false` for `plain_fapi`, so — unlike the AS-side `fapi-ciba-id1-test-plan`,
which is entirely unreachable without MTLS support this module doesn't
have — the backchannel authentication step itself is genuinely
attemptable under `client_auth_type=private_key_jwt`.

**Result of a DPoP-only (`sender_constrain=dpop`) live run: 3 of 22
modules PASS, 19 FAIL** — for one single, confirmed, uniform reason,
not a grab-bag of unrelated issues:

- **PASS** (3): `fapi-ciba-id1-client-invalid-missing-authreqid-test`,
  `-invalid-missing-expiresin-test`, `-invalid-unknown-user-id-test` —
  each is a negative test for the *backchannel response itself*
  (`AbstractFAPICIBAClientTest.backchannelEndpointCallComplete()`
  fires the module's completion right after that one call), so none of
  them ever reach token exchange.
- **FAIL** (19, everything else — happy path, refresh token, polling-
  interval/slow-down, every id_token/token-endpoint negative test):
  `AbstractFAPICIBAClientTest.handleHttp`'s own routing hardcodes
  `case "token":` to throw "Token endpoint must be called over an mTLS
  secured connection using the token_endpoint found in
  mtls_endpoint_aliases" unconditionally — there is no non-MTLS branch
  for this case at all, unlike `case "backchannel":`, which is gated on
  the variant. So the token endpoint carries the same MTLS wall the
  AS-side plan has everywhere, even though the backchannel endpoint
  doesn't; every module that calls `PollBackchannelAuthentication` at
  least once hits it.

### `-mtls`: the genuine re-attempt

Once `client.Config.SenderConstrain` gained `storage.SenderConstrainMTLS`
support (RFC 8705 §3), the token-endpoint wall above was worth a real
re-attempt. `-profile=ciba -mtls` presents a throwaway self-signed
client certificate (`mtls.go`'s `selfSignedClientCert`) instead of a
DPoP proof, and redirects to `discovered.MTLSEndpointAliases` for the
token/backchannel calls once discovery advertises them.

**Confirmed live: the token-endpoint MTLS wall is fully resolved —
never hit again in a full run.** Every module that used to fail with
"Token endpoint must be called over an mTLS secured connection" now
genuinely reaches token exchange and performs this client's own real
ID-token validation duties: `fapi-ciba-id1-client-invalid-iss-test`
correctly rejects a bad `iss`, `-invalid-aud-test`/`-invalid-secondary-aud-test`
a bad `aud`, `-invalid-signature-test` a bad signature,
`-invalid-null-alg-test`/`-invalid-alternate-alg-test` a malformed or
disallowed `alg`, `-invalid-expired-exp-test` an expired token,
`-invalid-missing-aud-test`/`-invalid-missing-exp-test`/`-invalid-missing-iss-test`
a missing required claim — each one this client's own `ValidateIDToken`
catching exactly the fault the module name says, the same way it
already does against every other AS this module talks to.

The suite's own per-module grade for most of these is still FAIL, not
PASS — full credit for a negative ID-token test in this plan appears to
require more of the flow than this driver currently completes (e.g.
still calling the resource endpoint and reporting the client-side
rejection there), which wasn't chased further this pass. The 3
pre-token-exchange PASSes are unchanged. One run also caught a stale
"alias conflict" interruption on a module whose token exchange
succeeded slower than this driver's own `cibaMaxPolls` budget, purely a
same-process back-to-back-runs artifact of this driver (see other
gotchas already documented for this suite elsewhere in this repo), not
a protocol defect.

Not part of any automated pass/fail gate given the still-majority-FAILED
result either way — this section documents what a genuine attempt found,
the same rigor whether or not it fully passes.

Two gotchas specific to this plan, beyond the ones listed above for the
baseline/message-signing profiles:

- **`server.jwks` must be supplied explicitly in the plan config.**
  Unlike the baseline/message-signing plans' own
  `GenerateServerConfiguration`, this plan's `LoadServerJWKs` condition
  does not auto-generate the mock AS's own signing key — an omitted
  `server.jwks` fails every module immediately with "LoadServerJWKs:
  Couldn't find a JWK set in configuration", before the module ever
  reaches `WAITING` (confirmed live via `GET /api/log/{id}`, not
  guessed from the suite's Java source). `runCIBA` generates a fresh
  ES256 key for this role and encodes it as a full private JWK
  (`ecdsaPrivateJWK` in `ciba.go`) — this key belongs to the suite's
  mock AS, never to this driver, and plays no role beyond satisfying
  this one requirement. See the suite repo's own sample config,
  `scripts/test-configs-rp-against-op/fapi-ciba-rp-test-config.json`,
  for the same shape.
- **A CIBA-only client needed a real `client`/`internal/metadata`
  package fix, not just driver plumbing.** The suite's own CIBA mock AS advertises no
  `authorization_endpoint`/`pushed_authorization_request_endpoint` at
  all (it's CIBA-only), which `client.Discover`/`client.Config` didn't
  support before this was found live — see ARCHITECTURE.md's
  Conformance strategy section for the fix (Authorization/
  PushedAuthorizationRequest became a conditionally-required pair,
  mirroring `Endpoints.BackchannelAuthentication`'s own optionality).

## Extending this driver

The `driverProfile` map in `main.go` is the extension point for a new
plan: a `planName`, its variant selectors, which `client.Profile` it
needs, and (currently) whether it needs a request-object signing key.
`runModule` is written to be plan-agnostic — it doesn't hardcode a
module name or count, just loops over whatever `createPlan` reports the
plan actually contains — so a new profile entry is normally the only
change needed, unless the new plan exercises a `client` capability this
driver doesn't wire up yet (a new algorithm, a new resource endpoint
shape, ...).
