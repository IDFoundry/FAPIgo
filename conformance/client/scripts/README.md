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
go run ./cmd/conformance-client -profile=baseline -client-auth-mtls
go run ./cmd/conformance-client -profile=baseline -mtls
go run ./cmd/conformance-client -profile=baseline -mtls -client-auth-mtls
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
- `-mtls`, with `-profile=ciba` or `-profile=baseline`: use
  `storage.SenderConstrainMTLS` (RFC 8705 §3, a throwaway self-signed
  client certificate) instead of DPoP for sender-constraining — see
  this profile's own section below. Ignored/invalid for
  `message-signing`.
- `-client-auth-mtls`, with `-profile=baseline` only: register via
  `storage.ClientAuthMethodSelfSignedTLSClientAuth` (RFC 8705 §2)
  instead of `private_key_jwt` — this driver presents a certificate
  (`client_id` + certificate, no `client_assertion`) at PAR and token
  instead of a signed assertion. Orthogonal to `-mtls`; combine both
  for the MTLS+MTLS profile — see this profile's own section below. Not
  supported with `-profile=message-signing`/`ciba`.
- `-evidence-dir` writes one named log file per test module, in OIDF
  RP-certification evidence format, alongside the usual combined
  stdout log — see "Certification evidence" below. Empty (off) by
  default; unused by daily CI.
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

**Confirmed live: 22/22 PASS.** The token-endpoint MTLS wall is fully
resolved — never hit again in a full run — and every negative ID-token
module now gets full suite-graded credit, not just a correct driver-side
detection: `fapi-ciba-id1-client-invalid-iss-test` correctly rejects a
bad `iss`, `-invalid-aud-test`/`-invalid-secondary-aud-test` a bad
`aud`, `-invalid-signature-test` a bad signature,
`-invalid-null-alg-test`/`-invalid-alternate-alg-test` a malformed or
disallowed `alg`, `-invalid-expired-exp-test` an expired token,
`-invalid-iat-is-week-in-past-test` a stale `iat`,
`-invalid-missing-aud-test`/`-invalid-missing-exp-test`/`-invalid-missing-iss-test`
a missing required claim — each one this client's own `ValidateIDToken`
catching exactly the fault the module name says.

Getting here took four fixes, three in this driver and one genuine
`client`/`internal/token` gap — found by re-running this plan live and
tracing each non-PASS module's own suite-side log, not by inspecting
this driver's code in isolation:

- **This driver discarded the issued tokens outright
  (`case client.BackchannelAuthenticationApproved: _ = r.Tokens`) and
  never called the plan's own "accounts" resource endpoint.** Every
  module that reaches a successful token exchange — the happy path,
  `-valid-aud-as-array-test`, `-no-scope-in-token-endpoint-response-test`,
  `-respects-interval-test`, `-slow-down-test` — needs that call before
  the suite will ever mark it FINISHED (the same
  `accounts_endpoint`-as-an-"exported-value" mechanism `runModule`
  already uses for the baseline/message-signing profiles — see that
  gotcha above — CIBA just never had it wired in). Without it these
  modules sat in `WAITING` forever, confirmed live: still waiting after
  a 45-second driver timeout with a fully successful token exchange
  already logged. New `callAccountsEndpoint` (`ciba.go`) fetches the
  exported `accounts_endpoint` value and calls it — as a plain Bearer
  credential under `-mtls` (new `callProtectedResourceBearer`,
  `resource.go`), or DPoP-proofed otherwise, reusing the existing
  `dpopResourceClient`.
- **The plan config never registered this driver's own mTLS client
  certificate.** `EnsureClientCertificateMatches`
  (`net.openid.conformance.condition.as`) compares the certificate
  actually presented on the connection against a `client.certificate`
  value read straight out of the plan's own static config
  (`GetStaticClientConfiguration`/`configureClient` — confirmed by
  disassembling both, not assumed) — there is no other registration
  mechanism. Every `-mtls` request failed this check with "Couldn't
  find registered client certificate" until `runCIBA` PEM-encoded
  `selfSignedClientCert`'s own generated certificate and added it as
  `client.certificate` in the plan config JSON.
- **`clientID` was a fixed constant, unlike the already-randomized
  `alias`.** Under `-mtls`, per-module certificate registration is
  keyed by `client_id`, not `alias` — a fixed value let an orphaned
  module instance from an earlier, killed-mid-run driver process
  corrupt a fresh run's own registration under the same `client_id`,
  surfacing as the same `EnsureClientCertificateMatches` failures above
  even with the certificate now correctly registered. Both `client_id`
  and `alias` now share one random per-run suffix (`ciba.go` and, for
  the same reason even though not proven to bite it, `main.go`'s own
  browser-flow driver).
- **A genuine `client` gap, not a driver issue:**
  `internal/token.IDToken.Validate` never checked `iat` staleness at
  all — OIDC Core §3.1.3.7 step 10 explicitly permits an RP to reject a
  token whose `iat` is implausibly old. New `ErrIssuedAtTooOld`, bounded
  by the same `MaxLifetime` that already governs how far `exp` may sit
  in the future, applied symmetrically to how far `iat` may sit in the
  past — mirroring `internal/requestobject.VerifyPolicy`'s own
  nbf-vs-exp symmetry under one shared window.
- One run also caught a stale "alias conflict" interruption on a module
  whose token exchange succeeded slower than this driver's own
  `cibaMaxPolls` budget — a same-process back-to-back-runs artifact
  fully explained (and resolved) by the `awaitVerdict` timeout fix
  above, not a protocol defect of its own.

Now wired into `../scripts/run-all.sh` as its own "RP ciba-mtls" leg
(`cmd/conformance-client -profile=ciba -mtls`), the same clean-pass gate
the AS side gets — `run_rp_plan`'s own PASSED-count check requires
every module PASSED, no partial credit, so this only stayed wired in
because the result is a genuine 22/22.

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

## Client authentication mTLS (`-client-auth-mtls`)

The RP-side counterpart to `conformance/server`'s own AS
client-auth-mtls profile — RFC 8705 §2 certificate-based client
authentication, this time with this driver playing the RP under test
against the suite's own mock AS. Reuses `-profile=baseline`'s plan
(`fapi2-security-profile-final-client-test-plan`), just with
`client_auth_type=mtls` instead of `private_key_jwt`; `sender_constrain`
stays `dpop`, the same orthogonality the AS side established.

**Confirmed live: 22/22 PASS, on the first attempt** — no driver fixes
needed, unlike every other mTLS re-attempt in this repo's conformance
history. The library groundwork was already complete on both sides
before this driver flag existed at all: `client.Config.ClientAuthMethod`
(RFC 8705 §2, PR #182) already builds a plain `client_id` form
parameter instead of a signed assertion at PAR and token, and the AS
side's own `verifyDPoPAtEitherEndpoint` fix (found chasing the AS-side
client-auth-mtls profile, see `../server/oidf-config/README.md`'s own
section) already covers a DPoP proof presented at an mTLS-alias URL —
exactly what this driver's own token/PAR calls need once they switch to
the alias.

Mechanically, this reuses `mtls.go`'s existing `-profile=ciba -mtls`
machinery almost entirely unchanged: `selfSignedClientCert` generates
the throwaway certificate, `mtlsSuiteHTTPClient` presents it on every
outbound connection (including this driver's own calls to the suite's
control API — already proven safe by the CIBA `-mtls` precedent), and
the certificate's PEM encoding is registered as the plan config's
`client.certificate` value, the same field
`EnsureClientCertificateMatches` (`net.openid.conformance.condition.as`)
reads to validate whatever certificate is actually presented on the
connection — confirmed by disassembly to be the same generic condition
FAPI2's own `checkMtlsCertificate` calls for `client_auth_type=mtls`,
regardless of whether the variant conceptually means
"self-signed" or "CA-issued" from this repo's own more precise
`storage.ClientAuthMethod` split; the suite draws no such distinction
on the RP-test side either (confirmed by disassembling
`net.openid.conformance.variant.ClientAuthType` — a single generic
`MTLS` value, matching the equivalent finding on the AS side).

One addition beyond the CIBA `-mtls` precedent:
`applyMTLSEndpointAliasesForClientAuth` (`mtls.go`) overrides both
`Endpoints.Token` *and* `Endpoints.PushedAuthorizationRequest` with
their discovered `mtls_endpoint_aliases` values — CIBA's own
`applyMTLSEndpointAliases` only ever needed Token/BackchannelAuthentication,
since sender-constraining binds only at token-issuance time (RFC 8705
§3 has no PAR-time pre-commitment concept), but certificate-based
client *authentication* is checked at every endpoint that authenticates
a client, PAR included — the same asymmetry `server/par.go`'s own
`authenticateClient` enforces on the AS side.

No `client.Config.Algorithms.ClientAuthentication`/plan-config
`client.jwks` entry is built under this flag at all: RFC 8705 §2 client
authentication carries no signed assertion, so there is nothing for
either side to sign or verify there — mirroring
`client/jwks.go`'s own conditional omission of the
`ClientAuthentication`-purpose key from `PublicJWKS` under a
non-`private_key_jwt` `ClientAuthMethod`.

## Sender-constrain mTLS (`-mtls` with `-profile=baseline`)

The RP-side counterpart to `conformance/server`'s own AS mtls profile
— RFC 8705 §3 sender-constraining on the ordinary baseline plan, this
time with this driver playing the RP under test. Reuses
`-profile=baseline`'s plan, just with `sender_constrain=mtls` instead
of `dpop`; `client_auth_type` stays `private_key_jwt` unless combined
with `-client-auth-mtls` below. Closes the "FAPI2SP RP private key +
MTLS" register profile — previously unreachable, since `-mtls` was
hardcoded to `-profile=ciba` only (see `run-all.sh`'s own header
comment for the history).

Mechanically this is `run()` (`main.go`) gaining the same
`selfSignedClientCert`/`mtlsSuiteHTTPClient`/`client.certificate`
machinery `-client-auth-mtls` already had, generalized behind a shared
`clientAuthMTLS || senderConstrainMTLS` condition — one certificate
covers both axes when combined, since RFC 8705 doesn't require separate
certificates for §2 client auth vs. §3 binding, and the suite's own
`EnsureClientCertificateMatches` condition reads the same
`client.certificate` plan-config value regardless of which axis
triggered the check. `runModule` sets `cfg.SenderConstrain =
storage.SenderConstrainMTLS` and calls `applyMTLSEndpointAliases`
(Token only — RFC 8705 §3 has no PAR-time pre-commitment concept, so
unlike client authentication this never touches PAR), and the
happy-path resource call switches to `callProtectedResourceBearer`
(already built for CIBA `-mtls`, reused here unchanged) instead of a
DPoP-proofed call.

`-mtls -client-auth-mtls` together (both flags) exercises "FAPI2SP RP
MTLS + MTLS" — the last of the four FAPI2SP auth×sender-constrain
combos, and the last one this driver was missing.

**Confirmed live: 20/20 PASS for both `-mtls` alone and `-mtls
-client-auth-mtls` together, on the first attempt** — unlike every
other mTLS re-attempt in this repo's conformance history, no driver
fixes were needed here: all the underlying pieces
(`client.Config.SenderConstrain`, `applyMTLSEndpointAliases`,
`callProtectedResourceBearer`) already existed from the CIBA `-mtls`
work, and `applyMTLSEndpointAliasesForClientAuth` from
`-client-auth-mtls`'s own — this was purely a matter of wiring the
existing pieces together behind the generalized flag.

## Certification evidence (`-evidence-dir`)

OIDF's RP certification process needs, for every test, evidence of
what the client itself actually did — the suite grades the protocol
interaction it can observe, but can't see inside the client under test,
so a bare PASSED/FAILED grade alone isn't sufficient evidence for
submission. OIDF's own guidance is explicit that this needs to be one
appropriately-named file per test (e.g.
`fapi2-client-test-invalid-iss.log`), not one combined log covering the
whole run, and that a log which doesn't demonstrate the client's own
behavior can result in a request to retest.

`-evidence-dir=<path>` writes exactly that: one file per test module
into `<path>`, named after the module's own suite-assigned test name
(`writeEvidence`, `evidence.go`), containing:

```
TEST: <test name>
RESULT: <suite-graded verdict>
DRIVER: <this driver's own step/error, or a statement that the flow
         completed without error>
SUITE LOG: <suite base URL>api/log/<module ID>
```

The `DRIVER` line is exactly the same text this driver has always
produced for negative-test modules (e.g. "complete authorization: jarm:
signature verification failed") — this flag just gives each one its own
named file instead of interleaving all of them into one shared stdout
log. `-evidence-dir` is opt-in and unused by daily CI (`conformance.yml`
only runs against a local suite instance, never
`certification.openid.net` — see below), so it adds no new artifacts to
the automated daily run.

**Workflow for an actual certification run:** OIDF requires certification
evidence to come from the OIDF-hosted production suite at
`certification.openid.net`, not a local instance — and explicitly
recommends against automating runs against it, reserving local suite
runs (everything else in this README) for development.

The invocation this section used to suggest — pointing `-suite` straight
at the hosted suite and letting this driver self-generate a plan the
same way it does locally — does **not** work against the real hosted
suite: confirmed live, `POST /api/plan` there requires an authenticated
session this driver has no support for, and (separately) the hosted
suite requires a plan to be created through its own guided web UI
first, with a fixed alias/`client_id`/certificate registered up front —
not something this driver can create on its own. This was cross-checked
against OIDF's own official reference RP client
(`gitlab.com/openid/sample-openbanking-client-nodejs`), which takes its
issuer/accounts-endpoint/certificate as fixed, literal config rather
than fetching or generating any of it.

**`-issuer` mode (`fixed_identity.go`)** is what actually works: create
the plan through the hosted UI first (selecting the same
client-auth-type/sender-constrain/profile variants this driver's own
`-mtls`/`-client-auth-mtls`/`-profile` flags represent), note the
`issuer`/`accounts_endpoint` values the UI's own "Exported Values" panel
shows (identical across every module in the plan — they're derived from
the plan's fixed alias, not the module), then drive one module at a
time:

```
go run ./cmd/conformance-client -suite=https://certification.openid.net/ \
    -profile=baseline -mtls -client-auth-mtls \
    -issuer=https://www.certification.openid.net/test/a/<your-alias>/ \
    -client-id=<registered client_id> \
    -redirect-uri=<registered redirect_uri> \
    -accounts-endpoint=<the plan's exported accounts_endpoint> \
    -client-cert=./client.pem -client-key=./client.key \
    -test-name=<module under test> \
    -scope="openid" \
    -evidence-dir=./evidence/mtls-mtls
```

`-client-cert`/`-client-key` are required whenever `-mtls`/
`-client-auth-mtls` is set — the certificate must be the exact one
already registered with the suite through the UI, not a
driver-generated throwaway; `tls.LoadX509KeyPair` loads it. Repeat once
per module under test (the suite attributes traffic to whichever module
is currently "waiting" for that alias, the same shared-alias-routing
behavior the AS side of this repo already relies on) and once per
profile being certified.

**`-scope` must exactly match the plan's own configured scope on the
suite** (defaults to `"openid"`; some plans add e.g. `offline_access`).
Confirmed live: on a mismatch, the hosted suite doesn't send a normal
OAuth `error=invalid_scope` redirect back to `redirect_uri` — it
redirects to its own internal log-detail page instead (a bare
`log=<id>` query string), which this driver has no way to distinguish
from a malformed response and reports as `authorization response is
missing iss`. If you hit that error, check the suite's own log viewer
for the run before assuming it's an RFC 9207 problem — it's very
likely a `-scope` mismatch instead. Each module instance is also
single-shot: after any attempt (success or failure), restart/re-arm it
in the UI before running the driver against it again, or discovery
itself starts 400ing.

**No suite-graded verdict is available in this mode** — there's no
suite module ID to poll a result from, since no plan/module REST call
ever happens. The suite's own plan-detail page in the hosted UI is the
source of truth for PASS/FAIL, the same way OIDF's own downloaded
results ZIP has always been the authoritative certification evidence;
this driver's evidence file is, as it always has been, supplementary
evidence of what the client itself did, not a substitute for it.

**Not yet supported in `-issuer` mode**: a fixed client JWKS loaded from
a file, needed for the `private_key_jwt` profiles (private key+DPoP,
private key+MTLS) — `-issuer` mode today only has a working credential
path for `client_auth_type=mtls` (`-client-auth-mtls`, with or without
`-mtls`), since that credential is certificate-only and needs no signed
assertion. `keys.NewKeyManagerFromSigners` (`keys/signer_keymanager.go`)
is the existing, already-tested mechanism this would build on when
needed — see `ARCHITECTURE.md`/`GETTING_STARTED.md`.

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
