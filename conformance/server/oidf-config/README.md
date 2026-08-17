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

  `limits.max_request_object_lifetime_seconds` needs real headroom here
  — unlike `baseline.config.json`, where `fapi_request_method=unsigned`
  means the suite never actually sends a signed request object, so this
  field is inert. The suite's `AddExpToRequestObject` condition
  unconditionally sets a request object's `exp` 5 minutes (300s) past
  `nbf` for every ordinary (non-negative-test) module; only the
  dedicated `...EnsureRequestObjectWithExpOver60Fails` negative test
  pushes it further out (70 minutes, via
  `AddExpValueIs70MinutesInFutureToRequestObject`), specifically to
  check an AS enforces *some* cap. A value copied from
  `baseline.config.json` (60s, itself never actually exercised there)
  rejects the suite's own normal happy-path request objects outright —
  set this comfortably above 300s and well under 4200s (600 is what
  this file uses) rather than reusing baseline's number.

Both plans also need variants `client_auth_type=private_key_jwt`,
`sender_constrain=dpop`, `fapi_profile=plain_fapi`,
`openid=openid_connect` — this AS never implements mTLS or DCR, so
`client_auth_type=mtls`/`sender_constrain=mtls`/DCR modules don't apply
(see [ARCHITECTURE.md](../../../ARCHITECTURE.md#conformance-strategy)).
(Verified directly against the suite's variant enums and test plan
classes — `net.openid.conformance.variant.*` and
`net.openid.conformance.fapi2spfinal.FAPI2SPFinalTestPlan`/
`FAPI2MessageSigningFinalTestPlan` — not from memory.)

Both files run entirely locally under `../docker-compose.yml`, attached
to the OIDF suite's own Docker network — no tunnel needed. `issuer` is
already set to that service's docker-compose hostname
(`conformance-as-baseline` / `conformance-as-message-signing`); leave it
unless you rename the service in `../docker-compose.yml`.

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
config has no `resource` object. `conformance-as` now serves a stand-in
`GET /accounts` endpoint for exactly this (see
`cmd/conformance-as/resource.go`) — it verifies the token and its DPoP
proof for real, using the same `resource` package this repo ships as a
public role. Add this to the suite's plan config:

```json
"resource": {
  "resourceUrl": "https://conformance-as-baseline:8443/accounts"
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
