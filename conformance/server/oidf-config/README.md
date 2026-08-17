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

See [../scripts/README.md](../scripts/README.md) for how to run the
server against a filled-in config.
