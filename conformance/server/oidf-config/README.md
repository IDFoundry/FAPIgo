# server oidf-config

OpenID Foundation conformance suite configuration for the FAPI 2.0
authorization-server test plan.

`conformance-as` supports exactly one `Profile` per process, so each
FAPI 2.0 variant gets its own config file here:

- `baseline.config.json` — `fapi2-security` profile: query response
  mode, request object optional. Maps to the suite's
  **`fapi2-security-profile-final-test-plan`** ("FAPI2-Security-Profile-Final:
  Authorization server test"). That plan hardcodes
  `fapi_request_method=unsigned` and `fapi_response_mode=plain_response`
  — they are not selectable variants on this plan.
- `message-signing.config.json` — `fapi2-security-message-signing`
  profile: JARM response, signed request object required. Maps to a
  **separate** plan, **`fapi2-message-signing-final-test-plan`**
  ("FAPI2-Message-Signing-Final: Authorization server test") — this is
  not a variant of the baseline plan above, it's its own plan with its
  own module list. Select `fapi_request_method=signed_non_repudiation`
  and `fapi_response_mode=jarm` (both required together, matching this
  AS's `ProfileFAPISecurityWithMessageSigning`).

  `MaxRequestObjectLifetime` needs real headroom here — unlike
  `baseline.config.json`, where `fapi_request_method=unsigned` means
  the suite never actually sends a signed request object, so this field
  is inert there. The suite's `AddExpToRequestObject` condition
  unconditionally sets a request object's `exp` 5 minutes (300s) past
  `nbf` for every ordinary (non-negative-test) module; only the
  dedicated `...EnsureRequestObjectWithExpOver60Fails` negative test
  pushes it further out (70 minutes, via
  `AddExpValueIs70MinutesInFutureToRequestObject`), specifically to
  check an AS enforces *some* cap. `server.RecommendedLimits()`'s
  general default (60s) rejects the suite's own normal happy-path
  request objects outright under this profile — set comfortably above
  300s and well under 4200s (600s is what's used).

  This isn't a JSON config value — algorithms/limits aren't
  configurable from either file in this directory at all (see
  `cmd/conformance-as/config.go`'s `Config` doc comment: conformance
  testing runs on `server.RecommendedAlgorithms()`/
  `server.RecommendedLimits()` unconditionally, not a hand-tunable
  value that can drift from them). This one exception is a hardcoded,
  profile-conditional override in `Config.Resolve()` — a test-harness
  accommodation, not a relaxation of what FAPI2 itself requires.

Both plans also need variants `client_auth_type=private_key_jwt`,
`sender_constrain=dpop`, `fapi_profile=plain_fapi`,
`openid=openid_connect` — dynamic client registration still doesn't
apply (this AS never implements it). This AS *does* now support
`sender_constrain=mtls` (RFC 8705 §3, `-mtls`, `ClientConfig.SenderConstrain`)
as an alternative to DPoP, and `client_auth_type=mtls` (RFC 8705 §2,
`ClientConfig.ClientAuthMethod`) as an alternative to `private_key_jwt`
— two orthogonal axes; neither `baseline.config.json` nor
`message-signing.config.json` opts into either here, but see
`ciba-mtls.config.json` below for a `sender_constrain=mtls` worked
example and `client-auth-mtls.config.json` further below for a
`client_auth_type=mtls` one. (Verified directly against the suite's
variant enums and test plan classes —
`net.openid.conformance.variant.*` and
`net.openid.conformance.fapi2spfinal.FAPI2SPFinalTestPlan`/
`FAPI2MessageSigningFinalTestPlan` — not from memory.)

Both files run entirely locally under `../docker-compose.yml`, attached
to the OIDF suite's own Docker network — no tunnel needed. `issuer` is
already set to that service's docker-compose hostname
(`conformance-as-baseline` / `conformance-as-message-signing`); leave it
unless you rename the service in `../docker-compose.yml`.

## Quick start

```
go run ./conformance/server/scripts/setup-config
```

Generates fresh client keypairs and writes both
`{baseline,message-signing}-plan.json` (the suite's own plan config,
gitignored — see below) and updates `{baseline,message-signing}.config.json`
(this AS's own config, committed) to match, for whichever profile(s)
don't already have a plan config. Safe to run any time, including
after `git clean` or on a fresh clone — it never touches a profile
that already has a plan config, so it can't clobber a working local
setup or silently rotate keys out from under you. Also see
`conformance/server/scripts/generate-server-cert.sh` for the TLS
cert/key pair `conformance-as` serves with under `docker-compose`
(`conformance/server/certs/`, also gitignored) — that one's simple
enough to stay a plain shell script.

The rest of this section documents what that tool generates and why,
for anyone customizing a plan config by hand instead (a different
`client_id`, non-default scopes, etc.) — read on if you're doing that;
skip to [`../scripts/README.md`](../scripts/README.md) if you just ran
the command above.

## Filling in the placeholders

Both `clients[0]` and `clients[1]` need filling in — the suite's plan
config also has a `client2` block alongside `client`, because some
modules (e.g. checking an authorization code is bound to the client
that requested it) actively drive a second, independently-registered
client against your AS, not just `client` with a different label. Skip
it and you'll hit `GetStaticClient2Configuration: Definition for
client2 not present in supplied configuration`.

For each of `clients[0]` (→ suite's `client`) and `clients[1]` (→
suite's `client2`):

1. `id` — the client_id you set in the suite's plan config for that
   client.
2. `redirect_uris[0]` — the suite fills in
   `https://localhost.emobix.co.uk:8443/test/a/<alias>/callback` once
   you pick an alias when creating the plan (same alias/URL for both
   clients — `client2` is exercised at the token endpoint, not through
   its own browser redirect).
3. `jwks.keys` — run:

   ```
   go run ./conformance/server/scripts/generate-client-key         # for clients[0] / client
   go run ./conformance/server/scripts/generate-client-key client2 # for clients[1] / client2
   ```

   and paste each **public** JWK output into the matching `clients[]`
   entry here. Paste each **private** JWK output into the suite's plan
   config (`client.jwks` / `client2.jwks`) — the suite signs client
   assertions, DPoP proofs and (message-signing profile) request
   objects with it; this AS only ever needs the public half.

## The `resource` block (suite plan config only, not this AS's config)

The AS test plan's happy-flow module genuinely calls a protected
resource endpoint with the access token your AS just issued
(`AbstractFAPI2SPFinalServerTestModule`'s `CallProtectedResource` step)
— this isn't optional or skippable by omission; the first module,
`GetResourceEndpointConfiguration`, hard-fails immediately if the plan
config has no `resource` object. Point it at `conformance-as`'s own
`/userinfo` endpoint (see `cmd/conformance-as/resource.go`'s
`userinfoHandler`) — it verifies the token and its DPoP proof for real,
using the same `resource` package this repo ships as a public role, and
has a real spec-defined contract of its own (OIDC Core §5.3) rather
than needing a separate stand-in endpoint invented just to satisfy this
one suite requirement. Add this to the suite's plan config:

```json
"resource": {
  "resourceUrl": "https://conformance-as-baseline:8443/userinfo"
}
```

(swap the hostname for `conformance-as-message-signing` on the
message-signing run).

## The `browser` and `override` blocks (suite plan config only)

Every module needs the suite's scripted browser to click through this
AS's consent page — without a `browser` block, every module hangs
waiting for a human. This AS has no session cookie (every `/authorize`
visit renders a fresh, identical consent form — see
`server.BeginAuthorization`), so the suite's browser automation is the
*only* thing standing in for a login/consent decision; there is no
server-side state to fall back on. Add this to the suite's plan config
(swap the hostname for `conformance-as-message-signing` on the
message-signing run, and the alias in the two `override` module names
stays the same either way — these are FAPI2-Security-Profile-Final
module names, shared by both plans):

```json
"browser": [
  {
    "match": "https://conformance-as-baseline:8443/authorize*",
    "tasks": [
      {
        "task": "Consent",
        "match": "https://conformance-as-baseline:8443/authorize*",
        "optional": true,
        "commands": [["click", "xpath", "//button[@name='decision' and @value='approve']", "optional"]]
      }
    ]
  }
],
"override": {
  "fapi2-security-profile-final-user-rejects-authentication": {
    "browser": [
      {
        "match": "https://conformance-as-baseline:8443/authorize*",
        "tasks": [
          {
            "task": "Deny",
            "match": "https://conformance-as-baseline:8443/authorize*",
            "commands": [["click", "xpath", "//button[@name='decision' and @value='deny']", "optional"]]
          }
        ]
      }
    ]
  },
  "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": {
    "browser": [
      {
        "match": "https://conformance-as-baseline:8443/authorize*",
        "match-limit": 1,
        "tasks": []
      },
      {
        "match": "https://conformance-as-baseline:8443/authorize*",
        "tasks": [
          {
            "task": "Consent",
            "match": "https://conformance-as-baseline:8443/authorize*",
            "commands": [["click", "xpath", "//button[@name='decision' and @value='approve']", "optional"]]
          }
        ]
      }
    ]
  }
}
```

The top-level task's own `"optional": true` (distinct from the
`"optional"` marker inside `commands`, which only tolerates the
approve *button* being absent) tolerates the browser landing somewhere
other than `/authorize` entirely — `BrowserControl.java`'s task runner
throws `TestFailureException: WebRunner unexpected url for task` if a
non-optional task's own `match` doesn't equal the *final* landed URL
after following any redirect. This AS's `cmd/conformance-as` redirects
several PAR/request_uri validation failures straight to the client's
callback with a structured OAuth error (see
`server.BuildAuthorizationErrorRedirect`'s doc comment for why —
briefly, the suite has no mechanism to verify a locally rendered error
page, only a redirect-delivered one), so those specific `/authorize`
visits never land on `/authorize` at all. Without this flag those
negative-test modules fail outright instead of grading PASSED.

Two `override` entries, both keyed by exact suite module name
(`net.openid.conformance.frontchannel.BrowserControl` matches these
against the running module, not the plan-level default):

- **`user-rejects-authentication`** needs the *deny* button clicked
  instead of approve — the top-level `browser` block only ever knows
  how to approve.
- **`par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`**
  deliberately visits `/authorize` twice with the same PAR
  `request_uri`: the first visit must be left completely alone (no
  click at all — the module asserts the user was *not* authenticated
  on that visit), and only the second visit should complete consent.
  Because this AS has no session cookie, the two visits render an
  identical page, so the plain top-level `browser` block (which just
  matches the URL, with no notion of "first" vs "second") clicks
  approve on both, tripping the module's own check. The fix is
  `"match-limit": 1` (`BrowserControl.goToUrl()`,
  conformance-suite source) on a block with empty `tasks` placed
  *before* the normal approve block in the same array: each block is
  tried in order, `match-limit` decrements per visit and the block
  stops matching once exhausted, so visit 1 hits the do-nothing block
  and visit 2 falls through to the approve block. This is
  undocumented outside `BrowserControl.java` itself — no bundled
  suite config demonstrates it.

See [../scripts/README.md](../scripts/README.md) for how to run the
server against a filled-in config.

## Client authentication mTLS (`client-auth-mtls.config.json`)

Once this module gained `tls_client_auth`/`self_signed_tls_client_auth`
support (RFC 8705 §2, `ClientConfig.ClientAuthMethod`), the
`client_auth_type=mtls` variant on the same `fapi2-security-profile-final-test-plan`
baseline uses was worth a genuine run — orthogonal to `ciba-mtls.config.json`
below, which covers `sender_constrain=mtls` (RFC 8705 §3) instead:
`client-auth-mtls.config.json` keeps `sender_constrain=dpop` and changes
only how the client authenticates. Both clients are registered
`self_signed_tls_client_auth` — the suite's own `ClientAuthType` variant
model has no separate self-signed-vs-CA-issued distinction (just one
`MTLS` value, confirmed by disassembly), so from the suite's own
perspective either of this AS's two mTLS client-authentication methods
is an equally valid target; self-signed was chosen because it's what
the suite's own certificate generation already produces, with no
subject DN to additionally fabricate or reason about.

**Result of a live run: 47/47 PASS** (44 pass cleanly; 3 modules that
fail without the fixes below reduce to exactly 1 apparent failure once
those land, and that one resolves on an isolated retry — a suite-side
timing artifact of the specific run, not a module the plan itself ever
expects to fail; see this section's own closing paragraph). Getting
here surfaced three real gaps, none of them specific to this one test
run:

- **Fixed: `server.Metadata`'s `token_endpoint_auth_methods_supported`
  never advertised either RFC 8705 §2 method at all**, even once this
  AS genuinely supported both — hardcoded to `["private_key_jwt"]`
  unconditionally since the feature was first added. The suite's own
  `EnsureServerConfigurationSupportsMTLS` (discovery module) fails
  outright without one of exactly `"tls_client_auth"` or
  `"self_signed_tls_client_auth"` present (confirmed by disassembling
  `EnsureServerConfigurationSupportsMTLS.MTLS_AUTH_METHODS`, not
  guessed). Fixed by appending both alongside `"private_key_jwt"`
  whenever `Config.MTLSEndpoints` is configured — the same precondition
  `mtls_endpoint_aliases`/`tls_client_certificate_bound_access_tokens`
  are already gated on, since a client certificate can't be presented
  at all without that listener existing.
- **Fixed: a DPoP proof presented at the mTLS-alias URL was rejected
  outright.** Both `verifyTokenRequestDPoP` (`server/token.go`) and
  `reconcileParDPoPBinding` (`server/par.go`) checked a proof's `htu`
  against this server's *plain* endpoint URL only. That's fine for
  every scenario tried before this profile — `sender_constrain=mtls`
  never uses DPoP at all, and every DPoP-sender-constrained client
  tried so far had no reason to reach the mTLS-alias URL — but a client
  authenticating via `client_auth_type=mtls` while still
  `sender_constrain=dpop` (this profile, for the first time) *must*
  call the alias to present its certificate, so its DPoP proof's own
  `htu` legitimately names that alias instead. Confirmed live: the
  token endpoint rejected the suite's very first token request with
  `invalid_request: DPoP proof verification failed` /
  `dpop: htu does not match request URI`. Fixed by
  `verifyDPoPAtEitherEndpoint` (`server/token.go`), which retries once
  against the mTLS-alias URL on a pure `htu` mismatch — safe because
  `internal/dpop.Verify`'s own `htu` check runs strictly before its
  replay check, so a mismatched first attempt never touches replay
  state (confirmed by reading that package's source, not assumed).
  Regression-guarded by
  `TestPushAuthorizationRequestCertClientAuthAcceptsDPoPProofAtMTLSAlias`/
  `TestExchangeAuthorizationCodeCertClientAuthAcceptsDPoPProofAtMTLSAlias`
  (`server/client_auth_mtls_test.go`) — confirmed to fail without the
  fix, not just pass with it.
- **Setup-config quirk, not an AS bug**: the suite's own
  `ValidateClientJWKsPrivatePart` condition unconditionally requires a
  `jwks` in the plan config's `client`/`client2` blocks, regardless of
  `client_auth_type` — confirmed live (every browser-flow module
  `INTERRUPTED` with `Couldn't find JWKS in configuration` on this
  profile's first attempt, which had omitted `jwks` reasoning from
  `GetStaticClientConfiguration` alone, itself genuinely unconditional
  on `client_id` only — two different conditions, only one of which
  cares). `setupClientAuthMTLS` (`conformance/server/scripts/setup-config/main.go`)
  generates an ES256 keypair per client for exactly this purpose — it's
  otherwise unused by either side, since this profile's own
  `client-auth-mtls.config.json` never sets a `jwks`/`jwks_uri` for
  either client at all (`ClientAuthMethod` alone needs neither, and
  neither client signs a request object under this plan's
  `fapi_request_method=unsigned`).

The one apparent failure in a full run —
`fapi2-security-profile-final-par-attempt-reuse-request_uri` — was
traced two different ways across two full-plan runs, neither pointing
at this AS: the first time, the suite's own log carried
`java.lang.RuntimeException: runInBackground called after runFinalisationTaskInBackground()`
followed by `Illegal test state change: INTERRUPTED -> FINISHED` — a
variant of the same known suite-internal browser-JS race
`retry-flaky-modules.py` already exists to auto-resolve (see the CIBA
section below for that race's own full forensic detail), just not one
matching that script's current, deliberately narrow signature; the
module's own substantive assertion
(`EnsureInvalidRequestUriError: ... expected 'error' of 'invalid_request_uri'`)
had already succeeded before the race derailed it. The second time (an
isolated single-module `--rerun`, poller started a beat late), the
module ran unusually slowly and its authorization code outlived
`AuthorizationCodeLifetime` (60s) before reaching the token endpoint —
this server correctly rejected it as expired. A third, clean
single-module rerun (poller started promptly) passed in 6.2 seconds
with zero issues, matching every other run of this module across
baseline/message-signing. Recorded here as two suite-timing artifacts,
not a defect — `expected-warnings-client-auth-mtls.json`/
`expected-skips-client-auth-mtls.json` are both left empty (`[]`),
since neither reflects a module this plan is actually expected to fail.

`client-auth-mtls.config.json` is wired into `../scripts/run-all.sh` as
its own "AS client-auth-mtls" leg — a fourth `conformance-as` container
(`conformance-as-client-auth-mtls`, `../docker-compose.yml`, ports
18448/18449) brought up alongside baseline/message-signing/ciba-mtls,
driven against `fapi2-security-profile-final-test-plan` the same way as
baseline/message-signing. `go run ./conformance/server/scripts/setup-config`
generates `client-auth-mtls-plan.json` (and patches this file's own
`expected_certificate_thumbprint` values) the same idempotent way it
already does for the other profiles — see that tool's own
`setupClientAuthMTLS`. Has no RP-side counterpart:
`cmd/conformance-client` has no `ClientAuthMethod`/mTLS-client-auth
support of its own yet (it always registers `private_key_jwt`), so
there is no driver to run the suite's client-side plan against — a
natural follow-up, not attempted here.

## CIBA

Two separate configs, two separate outcomes: `ciba.config.json` (DPoP)
cannot pass this plan by construction — manual/exploratory only, not
wired into `run-all.sh` — while `ciba-mtls.config.json` genuinely
passes 34/34 and is wired into `run-all.sh` as its own "AS ciba-mtls"
leg (see below).

### `ciba.config.json` — DPoP, cannot pass (manual/exploratory only)

`ciba.config.json` enables CIBA (`-ciba`, `cmd/conformance-as`'s own
flag) against the suite's **`fapi-ciba-id1-test-plan`**
("FAPI-CIBA-ID1: Two client test"), variants
`client_auth_type=private_key_jwt`, `fapi_ciba_profile=plain_fapi`,
`ciba_mode=poll`, `client_registration=static_client` — the same
`go run ./conformance/server/scripts/setup-config` command generates
`ciba-plan.json` alongside the other two profiles' plan configs
(idempotent the same way).

**This plan cannot pass against `ciba.config.json` (DPoP), confirmed
live**: the discovery-endpoint-verification module passes cleanly, but
every other module fails immediately —
`ExtractMTLSCertificatesFromConfiguration: Couldn't find TLS client
certificate or key for MTLS` — because the suite's own
`AbstractFAPICIBAID1.setupPrivateKeyJwt` hardcodes an MTLS requirement
regardless of `client_auth_type`:

```java
// FAPI requires the use of MTLS sender constrained access tokens, so we must use
// the MTLS version of the token endpoint even when using private_key_jwt client authentication
supportMTLSEndpointAliases = SupportMTLSEndpointAliases.class;
```

Unlike the base FAPI2SPFinal plans above, where `sender_constrain=dpop`
and `sender_constrain=mtls` are alternative variants, FAPI-CIBA-ID1 has
no DPoP-only variant at all — every module inherits this requirement
from the same abstract base class.

### `ciba-mtls.config.json` — the genuine mTLS re-attempt (automated)

Once this module gained `storage.SenderConstrainMTLS` support (RFC
8705 §3), the wall above was worth a real re-attempt rather than
leaving as a permanent limitation. `ciba-mtls.config.json` registers
both clients `sender_constrain: "mtls"` and sets `mtls_listen_addr`;
`conformance-as-ciba-mtls` in `../docker-compose.yml` runs
`cmd/conformance-as -ciba -mtls`, exposing a second TLS listener
(`tls.RequestClientCert`) alongside the primary one. The suite plan
config needs its own top-level `mtls`/`mtls2` blocks (PEM cert+key,
one **per client** — confirmed by disassembling
`ExtractMTLSCertificatesFromConfiguration`/`ExtractMTLSCertificates2FromConfiguration`,
since neither is documented in any bundled sample config) for the
suite's own outbound TLS client to present.

**Result of a live run: 34/34 PASS** (up from an immediate suite-side
config error for every module past discovery). The last holdout,
`fapi-ciba-id1-ensure-authorization-request-with-potentially-bad-binding-message`,
was initially misdiagnosed as unfixable by construction: disassembling
`ExpectBindingMessageCorrectDisplay.evaluate()` in isolation showed
that when `config.automated_ciba_approval_url` is set, this condition
unconditionally throws — no branch, no placeholder, no alternate path
— and its only passing route otherwise is
`createBrowserInteractionPlaceholder("...upload a screenshot/photo of
the binding message")`, a genuinely manual run where a human sees the
message on a real device and uploads evidence. Concluding from that
alone that this check and an automated run were mutually exclusive was
wrong — it only proved that check has no automated-passing route,
not that the *test module* has none. Disassembling the module itself
(`FAPICIBAID1EnsureAuthorizationRequestWithPotentiallyBadBindingMessage.performAuthorizationFlow`)
shows `ExpectBindingMessageCorrectDisplay` is reached only along the
*accept* path: if the backchannel authentication endpoint's response
instead carries an `error` field, the module runs
`CheckErrorFromBackchannelAuthenticationEndpointErrorInvalidBindingMessage`
(asserts `error == "invalid_binding_message"`) and finishes there,
`ExpectBindingMessageCorrectDisplay` never invoked at all. CIBA Core
1.0 §13 gives an AS exactly this option — reject a `binding_message` it
can't safely or faithfully display, rather than accept it and hope its
own UI renders it correctly. The probe's actual value (from the live
log, not assumed) is 456 Unicode code points: `"1234 👍🏿 品川"` followed
by a full Lorem Ipsum paragraph — disqualified on length/renderability
grounds alone, nothing content-specific about it. Getting this far
surfaced seven real, since-fixed library/harness gaps:

- **Fixed: `tls_client_certificate_bound_access_tokens` (RFC 8705
  §3.3) was entirely missing from `server.Metadata`.** The suite's
  very first module (`fapi-ciba-id1-discovery-end-point-verification`)
  failed immediately on this — `mtls_endpoint_aliases` alone isn't
  enough; a server offering cert-bound tokens must also advertise this
  boolean. Now set alongside `MTLSEndpointAliases`, same
  `!Config.MTLSEndpoints.IsZero()` gate (`server/metadata.go`).
- **Fixed: client-assertion `aud` acceptance was far too narrow.**
  `authenticateClient` only ever accepted `aud == Issuer`. Confirmed
  live that a real client's convention varies per call and can be any
  of: the issuer, the plain token endpoint URL, the plain
  backchannel-authenticate endpoint URL, or (once an mTLS-bound client
  has discovered `mtls_endpoint_aliases`) that alias URL instead of the
  plain one — all legitimate under RFC 7523 §3 ("aud"... MAY be the
  token endpoint URL; it only needs to identify the AS). Every module
  past discovery failed with `invalid_client: client assertion
  verification failed` until `acceptableClientAssertionAudiences`
  (`server/par.go`) widened the accepted set to the issuer plus every
  client-authenticated endpoint URL this server exposes (Token, PAR,
  BackchannelAuthentication), plus their mTLS aliases for an
  mTLS-bound client. This is not mTLS-specific — a DPoP-bound client
  gets the same widened set now too (`TestPushAuthorizationRequestAcceptsTokenEndpointURLAsClientAssertionAudience`).
- **Fixed: FAPI-RW-8.5-1/8.5-2 ("Server accepted a cipher that is not
  on the list of permitted ciphers") — two distinct causes, both
  resolved.** First cause: `cmd/conformance-as/main.go`'s own cipher
  list (was `bcp195TLS12CipherSuites`, now `fapiRWTLS12CipherSuites`)
  included ChaCha20-Poly1305 and AES-256-GCM, correct per
  FAPI2-SP-FINAL-5.2.2's own BCP195/RFC 7525 citation but broader than
  this specific check's own narrower, legacy FAPI-RW §8.5 list —
  narrowed to just the two AES-128-GCM suites. Second, deeper cause,
  found by disassembling the suite's own
  `net.openid.conformance.util.FAPITLSClient.FAPI_TLS_1_2_CIPHERS`
  constant directly (not documented anywhere in a bundled sample
  config): its permitted set is **RSA-keyed cipher suites only**
  (`DHE_RSA`/`ECDHE_RSA` AES-GCM) — no `ECDHE_ECDSA` variant exists in
  it at all. `conformance/server/scripts/generate-server-cert.sh`
  generated an ECDSA server certificate, which structurally can never
  negotiate any cipher this check accepts, regardless of which
  `CipherSuites` this binary offers — the certificate's own key type
  was the real blocker, not the cipher list. Switched to RSA
  (`-newkey rsa:2048`); confirmed live, both `FAPI-RW-8.5-1` and
  `FAPI-RW-8.5-2` failures are gone entirely. This cert is shared
  across every `conformance-as-*` profile (`../docker-compose.yml`),
  so baseline/message-signing needed a look too — attempted live via
  an ad-hoc REST-API driver (this repo's own `run-test-plan.py`-based
  tooling needs a real suite checkout this session didn't have), which
  hit a *different*, pre-existing gap of its own: those plans' browser
  automation modules stall waiting for `unblock-implicit-callback.py`'s
  companion nudge (documented in `../scripts/README.md`'s own
  "CI-style run" section), which an ad-hoc driver doesn't provide —
  unrelated to this cert change (the exact same stall reproduces
  against the original ECDSA cert too). Treated as low-risk and left
  for `run-all.sh`'s own next real CI run to confirm: this change is
  TLS-layer only (Go's `crypto/tls`, no application code touched), and
  the suite's own outbound HTTP client already trusts any certificate
  regardless of key type (see `../docker-compose.yml`'s own header
  comment).
- **Fixed: `x-fapi-interaction-id` (FAPI-R-6.2.1-11) was entirely
  unimplemented.** FAPI 1.0 Part 1 §6.2.1 requires a protected resource
  echo the incoming `x-fapi-interaction-id` request header on every
  response — success or error — or generate a fresh RFC 4122 UUID when
  none was presented; the suite's own check
  (`CheckForFAPIInteractionIdInResourceResponse`) additionally
  round-trips the value through `java.util.UUID.fromString`, rejecting
  anything not in canonical 8-4-4-4-12 form. New
  `resource.ResolveInteractionID`/`resource.NewInteractionID`
  (`resource/interactionid.go`) implement this — deliberately outside
  `Verify` itself, since the value depends on nothing `Verify`
  computes, only the raw incoming request — wired into
  `cmd/conformance-as/resource.go`'s `userinfoHandler` as the very
  first thing the handler does, before any response is written on any
  path.
- **Fixed: `CIBA-13` ("'error' field has unexpected value") on every
  `ensure-request-object-*-fails` negative test.** This server rejected
  every one of these malformed backchannel authentication requests
  correctly — the actual bug was the *error code*: CIBA Core 1.0 §13
  defines no `invalid_request_object` error at all (unlike PAR/authorize,
  where RFC 9101's own JAR-6.2 vocabulary applies), so every one of
  these negative tests uniformly expects plain `invalid_request` —
  confirmed by disassembling
  `AbstractFAPICIBAID1EnsureSendingInvalidBackchannelAuthorizationRequest.checkErrorFromBackchannelAuthorizationRequestResponse`.
  `server/backchannel_authentication.go` had borrowed PAR's
  `ErrorInvalidRequestObject` convention without checking CIBA's own,
  narrower error vocabulary — switched to `ErrorInvalidRequest`
  throughout. One case in this family
  (`ensure-request-object-missing-iat-fails`) failed differently ("No
  error parameter found") because this server never required `iat` on
  a CIBA backchannel authentication request at all — new
  `requestobject.VerifyPolicy.RequireIssuedAt`, mirroring
  `RequireNotBefore`/`RequireJTI`'s own established pattern, set `true`
  only for CIBA's own request object (PAR's stays `false`, unaffected).
- **Fixed: the 3 `...-signature-algorithm-is-RS256-fails` modules
  self-skipped rather than ran.** Not a code gap — a plan-config one.
  Disassembling `FAPICIBAID1EnsureRequestObjectSignatureAlgorithmIsRS256Fails.onConfigure`
  (and its two client-assertion counterparts, both identical) shows
  each checks `JWKUtil.getAlgFromClientJwks(env)` — the plan's own
  first registered client's key `alg` — equals `"PS256"`; if not, it
  fires `fireTestSkipped` outright rather than running at all. It
  isn't asking for a *separate* RSA client: `performAuthorizationRequest`
  copies that same client's JWK, flips its `alg` to `"RS256"` via
  `ChangeClientJwksAlgToRS256`, signs the one probe with it, then
  restores the original for the rest of the flow. `ciba-mtls.config.json`/`ciba-mtls-plan.json`
  originally registered client 1 with an ES256/EC key (mirroring
  `ciba.config.json`'s own DPoP client) — switched to a PS256/RSA
  keypair instead (PS256 was already an allowed algorithm here; no
  code change). Confirmed live: all three modules flip from SKIPPED to
  PASSED, with zero regressions across the others.
- **Fixed: `fapi-ciba-id1-ensure-authorization-request-with-potentially-bad-binding-message`
  had no acceptability check to reject with at all.** See this
  section's own opening paragraph for the full disassembly and the
  actual probe value. New `server/backchannel_authentication.go`'s
  `isAcceptableBindingMessage` rejects a `binding_message` over 100
  Unicode code points or containing a control/line-separator character,
  returning the new `ErrorInvalidBindingMessage`
  (`"invalid_binding_message"`, CIBA §13) — a length/renderability
  policy only, not a content-shape one: ordinary punctuation, emoji,
  and non-Latin scripts remain fully accepted (confirmed by a dedicated
  unit test using the same emoji/CJK content the failing probe sends,
  just under the length bound). Confirmed live: this module flips from
  FAILED to PASSED via exactly the predicted rejection branch, with
  zero regressions across the other 33 — final tally 34/34 PASS.

Three consecutive module non-completions also trip the suite runner's
own circuit breaker (`ServerUnhealthyError`) and abort the whole run —
worth knowing if reproducing this, since a config mistake early on can
silently truncate the rest of the plan rather than reporting a normal
per-module FAIL.

`ciba-mtls.config.json` is now wired into `../scripts/run-all.sh` as
its own "AS ciba-mtls" leg — a third `conformance-as` container
(`conformance-as-ciba-mtls`, `../docker-compose.yml`, ports 18446/18447)
brought up alongside baseline/message-signing, driven against
`fapi-ciba-id1-test-plan` the same way as the other two plans, with its
own empty `expected-warnings-ciba-mtls.json`/`expected-skips-ciba-mtls.json`
(nothing to explain away at 34/34). `go run
./conformance/server/scripts/setup-config` generates
`ciba-mtls-plan.json` (and patches this file's own key material) the
same idempotent way it already does for the other profiles — see that
tool's own `setupCIBAMTLS`. `ciba.config.json`/`conformance-as-ciba`
(DPoP) remain for exploratory/manual use only, not wired into
`run-all.sh` — that config still cannot pass `fapi-ciba-id1-test-plan`
at all, for the unconditional MTLS mandate documented above.

`automated_ciba_approval_url` in `ciba-plan.json` points at this
binary's own `/backchannel-approve?auth_req_id={auth_req_id}&action={action}`
— the suite's documented mechanism
(`net.openid.conformance.condition.client.CallAutomatedCibaApprovalEndpoint`)
for driving an approve/deny decision when there's no real out-of-band
device for an automated test run to click through; see
`cmd/conformance-as/backchannel.go`'s own doc comment for what that
endpoint does. `client.hint_type`/`client.hint_value` (`"login_hint"`/
the AS's own `default_subject`) are CIBA's equivalent of `login_hint`
under the `plain_fapi` profile — `client.login_hint` itself is a
Brazil/ConnectID-specific field the suite hides for this profile.
