# Getting started: standing up an authorization server and resource server

This walks through wiring `server.Server` end to end — configuration,
dependencies, client registration, and the one piece every integration
has to build itself: the login/consent flow — then through wiring
`resource.Verifier`, the separate role that actually verifies a
presented access token against a protected API (step 7). `cmd/conformance-as`
is a complete, working reference implementing every piece described
here (plus the full HTTP surface — PAR, token, JWKS, metadata — which
this guide doesn't reproduce); read it alongside this doc, or just
study it directly and treat this as the map.

## 1. Dependencies: use the reference implementations to start

`server.New` requires eleven dependencies — a client repository,
transaction/grant/replay stores, a key manager, a client key source, an
access-token issuer, a revocation sink, a client-certificate trust
choice, a clock, a randomness source — with no implicit defaults for
any of them (plus an audit sink, required
only under `AssuranceProduction` — see step 2's `Assurance` field).
Writing real, production-shaped persistence and key management for all
of that is real work, and not the place to start. Two packages exist
specifically so you don't have to do it before you can run anything:

- **`storage/memstore`** — in-memory `ClientRepository`, `TransactionStore`,
  `GrantStore`, `ReplayStore`, `RevocationStore`, and `AccessTokenStore`
  (only needed for opaque access tokens — see step 4).
- **`keys/ephemeral`** — in-memory `KeyManager` and `ClientKeySource`.

**Both are development/testing only. Never production** — see each
package's own doc comment for exactly why (non-durable, no expiry GC,
keys regenerated and lost on every restart). `server.New` already
refuses both under `server.AssuranceProduction` — `memstore`'s stores
don't implement `storage.StoreAssurance` and `ephemeral`'s key manager
doesn't implement `keys.KeyCustodyAssurance`, which that assurance
level requires — and `client.New` refuses `ephemeral` keys the same way.
That's not a gap, it's what stops them from being used in production
by accident. When you're ready for a real deployment, this
is the seam: implement the same interfaces (`storage.ClientRepository`
and friends, `keys.KeyManager`, `keys.ClientKeySource`) against real
persistence and a real key store (KMS/HSM), and swap them in — nothing
else in this guide changes. For `keys.KeyManager` specifically, you may
not need to implement anything at all: `keys.NewKeyManagerFromSigners`
adapts any `crypto.Signer` — what most HSM/KMS Go client wrappers
already implement — directly into a `KeyManager`; see `keys/doc.go`.
Pass it `keys.DeclareCustody(keys.KeyCustody{Durable: true})` (plus
`CrossInstanceConsistent` if every instance shares the keys) to state
how those keys are held — production assurance requires the
declaration, and only you know the answer.

## 2. Build a `Config`

Every field below is required — `server.New` rejects a zero value for
any of them, on purpose (see `server/doc.go`: "no implicit defaults, no
silently-installed in-memory store"). `Algorithms` and `Limits` hold
many fields with no sane universal default, so
`server.RecommendedAlgorithms()` and `server.RecommendedLimits()` exist
as an explicit, deliberate starting point — each field is documented
with exactly how it's grounded (a direct FAPI 2.0 Security Profile Final
or RFC 9449 requirement, versus this module's own conservative
operational choice, clearly labeled either way — see `server/presets.go`).
Calling them is as much a choice as writing the values yourself; `New`
never reaches for them on its own. Override any field your own security
policy calls for.

```go
cfg := server.Config{
	Issuer: issuer, // fapi.ParseIssuerURL("https://as.example.com")
	Endpoints: server.Endpoints{
		Authorization:              authorizeURL,
		Token:                      tokenURL,
		PushedAuthorizationRequest: parURL,
		JWKS:                       jwksURL,
	},
	Profile:    server.ProfileFAPISecurity, // or ProfileFAPISecurityWithMessageSigning
	Algorithms: server.RecommendedAlgorithms(),
	Limits:     server.RecommendedLimits(),
	Assurance:  server.AssuranceDevelopment, // AssuranceProduction once your real deps are ready
}
```

Under `ProfileFAPISecurityWithMessageSigning`, `Algorithms.JARM` is
required too.

Most `Limits` fields are lifetimes and clock tolerances. One is a size:
`Limits.MaxIDTokenClaimsBytes` (4096 in `RecommendedLimits()`) caps the
total size of the non-standard claims in an ID token, so the server
never issues one larger than relying parties accept — this module's own
client rejects a compact token over 16 KiB by default. See [Adding
claims to tokens](#adding-claims-to-tokens) for what counts against it,
and raise it only alongside your relying parties' own limits.

## 3. Register at least one client

```go
client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
	ID:                       "demo-client",
	RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example.com/callback"},
	ClientAssertionAlgorithm: fapi.ES256,
	AllowedScopes:            []string{"openid", "accounts"},
})
```

`"openid"` isn't required by this library at all: an ID token is only
ever issued alongside the access token when the *granted* scope happens
to include `"openid"` (see `server`'s own package doc comment) — this
walkthrough includes it, and wires `keys.IDTokenSigning` in step 4,
purely because that's the more complete example to show. A deployment
that only needs access tokens — no identity layer — can drop `"openid"`
from `AllowedScopes` entirely and run as plain OAuth 2.0 + FAPI 2.0;
nothing else here changes.

## 4. Wire `Dependencies` and construct the server

```go
keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
	keys.AccessTokenSigning: fapi.ES256,
	keys.IDTokenSigning:     fapi.ES256,
})

clientKeys, err := ephemeral.NewClientKeySource(fetcher, []ephemeral.ClientKeySpec{
	{ClientID: "demo-client", JWKS: theClientsJWKSDocument},
	// or JWKSURI: "https://rp.example.com/.well-known/jwks.json" to fetch live instead
})

// JWT (RFC 9068) is the default, ship-in-the-box access-token format —
// self-contained, verified locally by a resource server against this
// AS's published JWKS, with no callback to this AS at verify time.
// server.NewOpaqueAccessTokens(store) is the storage-backed
// alternative — e.g. a resource server co-located with this AS, or one
// with live access to the same storage backend. This is not a
// revocation-related choice: Dependencies.Revocation below is required
// and wired identically either way.
accessTokens, err := server.NewJWTAccessTokens(keyManager, fapi.ES256)

deps := server.Dependencies{
	Clients:      memstore.NewClientRepository([]storage.RegisteredClient{client}),
	Transactions: memstore.NewTransactionStore(),
	Grants:       memstore.NewGrantStore(),
	Replay:       memstore.NewReplayStore(),
	ClientKeys:   clientKeys,
	Keys:         keyManager,
	AccessTokens: accessTokens,
	// Lets this server revoke a token it already issued when it later
	// detects the authorization code that produced it being reused
	// (RFC 6749 §4.1.2), and revoke a whole grant with RevokeGrant
	// (step 5). Pass server.NoRevocation{} instead to explicitly
	// decline — see its doc comment for why declining must be a
	// conscious choice, not a silent default; RevokeGrant then refuses.
	Revocation: memstore.NewRevocationStore(),
	// Whether this package re-verifies an mTLS client certificate's
	// chain itself. NoClientCertificateChainTrust{} declines — right when
	// no client uses mTLS, or when your TLS termination already verifies
	// the chain; server.TrustedClientCAs{Roots: pool, Revocation: ...}
	// has this package check it against pool, and whether it has been
	// revoked (server.ClientCertificateCRLs, for example), instead.
	ClientCertificateTrust: server.NoClientCertificateChainTrust{},
	Clock:                  server.SystemClock{},
	Random:                 rand.Reader, // crypto/rand; production assurance requires exactly this reader
}

srv, err := server.New(cfg, deps)
```

(`fetcher` is a `*fapihttp.Client` — only needed if any client's keys
are fetched live via `JWKSURI` rather than supplied inline; pass `nil`
if every client uses inline `JWKS`.)

**Whichever access-token format you pick here, the resource server that
verifies these tokens must be wired to match** — `resource.JWTAccessTokens`
for `server.JWTAccessTokens`, `resource.OpaqueAccessTokens{Store: ...}`
(the same `Store` instance, if co-located) for
`server.OpaqueAccessTokens` — see step 7. The two sides agreeing on
format isn't checked for you: nothing stops you from constructing an AS
that issues opaque tokens and a resource server that only knows how to
verify JWTs, and every verification will fail with no compile-time
signal that they were ever mismatched. `cmd/conformance-as/wiring.go`
shows both sides wired consistently, switched on one runtime flag.

## 5. The one piece that's genuinely yours: the login flow

Everything above is config and plumbing. This is the actual decision
point, and the library deliberately has zero opinion about it — no
bundled login page, no assumed auth method. `BeginAuthorization`
(called from your `/authorize` handler once a client's pushed request
has been redeemed) returns one of three outcomes; the one that matters
here is `InteractionRequired`:

```go
// The request's client_id and request_uri, refusing a repeated one:
// render that error locally, never as a redirect.
req, err := server.BeginAuthorizationRequestFromHTTP(r)
if err != nil {
	// render err locally
}
action, err := srv.BeginAuthorization(ctx, req)

switch a := action.(type) {
case server.InteractionRequired:
	// Render whatever UI you want here — a password form, an SSO
	// redirect, WebAuthn, a magic link. a.Interaction carries the
	// client ID, requested scope, an unauthenticated login_hint to
	// help pre-fill it, and the client's authentication requirements:
	// ACRValues (how strongly to authenticate) and, when HasMaxAge,
	// MaxAge (how recent the authentication must be — re-authenticate
	// a user whose existing session is older). a.Handle must come back
	// to CompleteAuthorization once the user is done.
case server.RedirectResponse:
	// no interaction needed — redirect the browser to a.Destination
case server.LocalErrorResponse:
	// render a.Error locally
}
```

Once you've actually authenticated the user (checked their password,
verified their SSO assertion, whatever), conclude the interaction:

```go
subjectID, _ := server.NewSubjectID(theRealAuthenticatedUserID)
subject, _ := server.NewAuthenticatedSubject(subjectID)
// When the user actually authenticated — not time.Now() when you reuse
// an existing session: CompleteAuthorization answers login_required
// when this is older than the client's max_age.
authCtx, _ := server.NewAuthenticationContext(userAuthenticatedAt, acr, amr)

result := server.Authorize(subject, authCtx, server.GrantedAuthorization{
	Scope: whateverScopesTheUserActuallyApproved,
	// Optional: extra claims for the ID token only (never the access
	// token), each value already JSON-encoded. Server-managed names
	// (iss, sub, aud, nonce, acr, ...) are rejected.
	IDTokenClaims: map[string]json.RawMessage{"sub_type": json.RawMessage(`"user"`)},
	// Identity claims the client asked for with the OIDC "claims"
	// parameter (a.Interaction.RequestedClaims) that the user agreed to
	// release. Nil releases none.
	ApprovedIdentityClaims: whicheverRequestedClaimsTheUserApproved,
	// Optional: your own ID for this grant, to withdraw it later with
	// srv.RevokeGrant — for a "connected apps" page, say. It refuses
	// the grant's refresh token and every access token issued from it.
	GrantID: yourOwnIDForThisGrant,
})
// or: server.Deny("user declined") / server.AuthenticationFailed("bad credentials")

authResult, err := srv.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
	Handle: handle, // the same InteractionHandle from step above
	Result: result,
})

switch r := authResult.(type) {
case server.AuthorizationRedirect:
	// redirect the browser to r.Destination() — carries the code (or an error)
case server.AuthorizationLocalError:
	// render r.Error locally
}
```

**Bind the interaction handle to the browser.** `CompleteAuthorization`
accepts a handle from whoever presents it, so a login UI that carries it
in a form field and signs users in from an existing session cookie is
open to consent CSRF: a malicious client starts its own authorization,
puts its handle in a self-submitting form on its own page, and a
signed-in victim's browser approves it, sending that client a code for
the victim's account. Set the handle (`a.Handle.String()`) in an
HttpOnly, Secure, SameSite cookie when the browser reaches `/authorize`,
read it back with `server.ParseInteractionHandle` when the form is
submitted, and protect that form with your usual CSRF defence. See
`server.InteractionHandle`'s doc comment.

**Keep the interaction until the form comes back.** The submission
needs `a.Interaction` again: the scope, the requested claims and any
authorization details the user is approving. Encode it with
`a.Interaction.MarshalText()` and keep it with the handle, somewhere only
your application can write: a server-side session, or a cookie you
seal. Restore it with `server.ParseInteractionRequest`. Then any
instance can handle the submission, not only the one that began the
authorization. A modified copy can't widen the grant, since
`CompleteAuthorization` checks it against the request the server
stored.

`server/interactioncookie` does both in one encrypted cookie:
`Set(w, a.Handle, a.Interaction, now)` at `/authorize`, `Read(r, now)`
when the form comes back, and `Clear(w)` once it's done. It's AES-GCM
under keys every instance shares (the first seals, all open, so keys
rotate), with the `__Host-` prefix. An interaction too large for a
cookie — large authorization details, say — gets `ErrTooLarge`: keep
that one in a server-side session instead. It's no CSRF defence: the
form still needs one. The demos under `examples/` use it.

`cmd/conformance-as/authorize.go` is a complete, working version of
exactly this — read it for the full picture of the GET (render the
form) and POST (handle the submission) halves of a real HTTP flow. Its
handle bridge is not one to copy: it carries the handle in a hidden form
field, which is only tolerable because it authenticates nobody — use
the cookie binding above instead. Its own login form
(`consent_template.go`) is a deliberate non-example: a free-text "type
any username" field with no real authentication behind it, because this
binary exists to drive OIDF conformance testing, not to demonstrate
login UI. Building the real authentication step is the one part of this
whole guide that's actually yours to write.

### Adding claims to tokens

Beyond the standard claims (`iss`, `sub`, `aud`, `acr`, `amr`, ...),
there are three ways a claim gets into a token. They differ in who
decides and where the claim lands, so pick by what you need:

| You want to... | Use | Lands in |
|---|---|---|
| Add claims you decide at login (e.g. a subject type, or who is acting on an entity's behalf) | `GrantedAuthorization.IDTokenClaims` | ID token only |
| Return identity claims (`name`, `email`, ...) the client asks for via the OIDC `claims` parameter, once the user approves them | `Dependencies.IdentityClaims` (`server.IdentityClaimsSource`) plus `GrantedAuthorization.ApprovedIdentityClaims` | ID token and/or UserInfo, per request |
| Carry a value the client sent as a custom authorization request parameter | `extension.Definition` with `ReturnInTokenClaims` | Access token and ID token |

`IDTokenClaims` values are JSON-encoded, and server-managed names
(`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`,
`at_hash`, `azp`, `c_hash`, `s_hash`, `jti`, `nbf`, `cnf`) are rejected. On a name
collision the more specific source wins: `IDTokenClaims` over identity
claims over extension claims. All three are carried forward to ID
tokens re-issued on refresh, with no storage change on your side.

All three share one size budget, `Limits.MaxIDTokenClaimsBytes` (each
claim's name plus its JSON-encoded value). `CompleteAuthorization`
rejects `IDTokenClaims` that exceed it on their own, before anything is
stored; the token endpoint rejects the merged total, as `server_error`,
if identity or extension claims push it over — identity claims are only
resolved there.

## 6. The rest of the HTTP surface

`server.Server` has no built-in HTTP layer — every endpoint is a plain
handler you write, calling the corresponding method
(`PushAuthorizationRequest`, `ExchangeAuthorizationCode`,
`RefreshAccessToken`, `Metadata`, `PublicJWKS`, and, when you enable
them, `RequestClientCredentialsToken` and the CIBA methods). `cmd/conformance-as/router.go`
shows the complete routing table on a bare `net/http.ServeMux` — no
framework dependency required, though nothing here stops you from using
one. `cmd/conformance-as/token.go`, `par.go`, `metadata.go` and
`jwks.go` are the corresponding handler implementations to read
alongside `authorize.go`.

**Serving a grant this package doesn't.** To serve another grant type
at the same token endpoint — OpenID4VCI's `pre-authorized_code`, say —
read the request once with `server.TokenEndpointRequestFromHTTP` and
switch on `GrantType()`. For your own grant, take its form with
`Parameters()`, authenticate the client with `AuthenticateAttestedClient`
(`req.AttestedClientAuthentication()`), and check its DPoP proof or
client certificate with `VerifyTokenRequestBinding`: the same checks,
and the same replay records, as this package's own grants. List the
grant type in `Config.AdditionalGrantTypes` so `Metadata` advertises
it. Whether the client may use the grant, and the grant itself, stay
yours.

## 7. Wire the resource server: verifying access tokens

`resource.Verifier` is FAPI 2.0's third role, a deliberately separate
package from `server` rather than a mode of it — verifying a presented
access token is inseparable from the HTTP request it arrived on, so
`Verify(ctx, VerifyRequest{Method, URL, Authorization, DPoPProofs, PeerCertificate})` is
the only entry point, never a bare `VerifyJWT`. In a real deployment
this is usually a wholly separate service protecting its own API;
`cmd/conformance-as` only co-locates it in the same binary because the
OIDF suite's AS test plan needs a protected-resource endpoint to call
(`resource.go`) — read that file alongside this section either way.

### Build a `Config`

```go
cfg := resource.Config{
	Limits: resource.Limits{
		MaxDPoPProofAge: time.Minute,     // how old a DPoP proof's iat may be
		MaxClockSkew:    5 * time.Second, // tolerance either direction
	},
}
```

Both fields are required — `NewVerifier` rejects a zero `MaxDPoPProofAge`
or negative `MaxClockSkew`, the same "no implicit default" discipline
`server.Config` follows.

### Wire `Dependencies`

**Hosting the protected endpoints in the authorization server's own
process** (a UserInfo endpoint, say)? Then skip the rest of this
section: `serverresource.NewVerifier` builds the verifier from the
`server.Config` and `server.Dependencies` step 4 built, taking the
access-token format, revocation store, replay store, clock and DPoP
limits from them so they always match, and failing if the revocation
store can't be checked from the resource side:

```go
// cfg and deps: the server.Config and server.Dependencies from steps 2 and 4.
verifier, err := serverresource.NewVerifier(cfg, deps, serverresource.Options{})
```

A resource server deployed on its own wires `Dependencies` itself:

**The access-token format must match whatever the authorization server
actually issues** — this is exactly the coupling step 4 flagged, and
the reason this section exists at all. Pick the side matching your AS:

```go
// If the AS issues JWTAccessTokens: resolve its verification key(s),
// typically by fetching its published JWKS live (or, for a resource
// server in the AS's own process, keys.NewLocalIssuerKeys(issuer,
// keyManager), which reads the AS's key manager directly).
issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, asJWKSURL, 10*time.Minute)
accessTokens, err := resource.NewJWTAccessTokens(
	issuerKeys, asIssuer, asIssuer.String(), // audience: matches server/accesstoken.go's own self-addressed aud claim
	fapi.ES256, 5*time.Minute, // must be >= the AS's own Limits.AccessTokenLifetime
	8, // max candidate keys tried per token — size to your AS's own key-rotation overlap, not a library default
)

// If the AS issues OpaqueAccessTokens instead: the *same*
// storage.AccessTokenStore instance the AS writes to — only realistic
// if this resource server shares that storage backend with the AS
// (co-located, or a real shared database).
// accessTokens, err := resource.NewOpaqueAccessTokens(sameAccessTokenStore)
```

`asIssuer`/`asJWKSURL` are the authorization server's own issuer/JWKS
`fapi.URL` values — the same `issuer`/`Endpoints.JWKS` step 2 built, if
this resource server is co-located with that AS; otherwise wherever
that AS's own metadata publishes them.

`Dependencies.Revocation` needs the same care as the access-token
format: if the AS revokes a token on detected authorization-code reuse
(RFC 6749 §4.1.2 — step 4's `Revocation` field), or revokes a whole
grant with `RevokeGrant`, this resource server must see that revocation
too, or it will keep accepting a token the AS has already disowned. Wire it to the *same* `RevocationSink`/
`RevocationChecker` pair the AS uses — `memstore.NewRevocationStore()`
already implements both, if co-located — or `resource.NoRevocation{}`
to explicitly decline (matching `server.NoRevocation{}`'s own
reasoning for why declining must be a conscious choice).

```go
deps := resource.Dependencies{
	AccessTokens: accessTokens,
	Replay:       memstore.NewReplayStore(), // DPoP proof jti reuse — its own instance; may differ from the AS's
	Revocation:   revocationStore,           // the same instance the AS writes to
	Clock:        resource.SystemClock{},
}

verifier, err := resource.NewVerifier(cfg, deps)
```

### Verify a request

```go
// protectedResourceURL: this endpoint's own fixed external URL — see
// below, never r.URL.
authCtx, err := verifier.Verify(ctx, resource.VerifyRequestFromHTTP(r, protectedResourceURL))
```

On success, `authCtx.Subject`/`ClientID`/`Scopes`/`Claims` are what your
API handler needs to authorize the call. On failure, `err` is always a
`*resource.Error`, and `resource.WriteError` sends it as the RFC 6750 /
RFC 9449 response: the status, a `WWW-Authenticate` challenge in the
scheme the request used, and the error body. A request with no
credentials at all gets 401 and a challenge with no error code, as RFC
6750 §3.1 asks. `Unwrap()` is for logs only, never the response:

```go
if err != nil {
	resource.WriteError(w, err)
	return
}
```

`resource.VerifyRequestFromHTTP` fills in every field of the
`VerifyRequest` from `r`: the method, the `Authorization` header, every
`DPoP` header and the TLS client certificate. Building the struct by
hand compiles just as well with a field left out, and then fails only
for the clients that need it — which is why the constructor exists.

The one thing it takes from you is the URL: this endpoint's own fixed,
externally-visible URL (it's the DPoP proof's expected `htu`) — never
inferred from the incoming request's `Host` header, the same reasoning
`server.Endpoints` is never inferred from a request either. For a route
with path parameters, copy a fixed origin and set its `Path` from
`r.URL.Path`.

`DPoPProofs` carries every raw "DPoP" header value the request
carried — `r.Header.Values("DPoP")`, never `r.Header.Get("DPoP")`,
which silently returns only the first of several duplicate headers.
`Verify` itself rejects a request that carried more than one (RFC 9449
§7.1), so there's no adapter-side check to write here.

`PeerCertificate` is the TLS client certificate the request arrived
with: an access token bound to a certificate (RFC 8705) is refused
without it. The constructor reads it from `r.TLS`; behind a proxy that
terminates TLS, set it afterwards from however the proxy forwards the
certificate.

That's the whole surface: `resource.Verifier` has no other public entry
point. Everything above `Verify` — routing, and what the protected API
actually returns — is your own handler, same as step 5's login flow was
yours to build for `server`.

## 8. Run it

`cmd/conformance-as` is the complete version of all of the above,
runnable directly:

```sh
go run ./conformance/server/scripts/setup-config   # generates a throwaway local config + keys
./conformance/server/scripts/generate-server-cert.sh
go run ./cmd/conformance-as -config <path> -cert <path> -key <path>
```

See `conformance/server/scripts/README.md` for the full local setup
procedure (it's written for conformance-suite testing, but the binary
it runs is the same one this guide has been describing).

## 9. Rotating a signing key

`keys.KeyManager` never dictates a key's lifecycle — that's your
`Dependencies.Keys` implementation's own concern — but doing it without
a verification gap needs your implementation to also satisfy
`keys.RotatingKeyManager` (see `keys/doc.go`), and needs the steps done
in the right order:

1. Provision the new key wherever your `KeyManager` sources keys from
   (a new KMS key version, a new HSM slot, …). Don't touch `Sign` or
   `PublicKey` yet — both should still resolve to the outgoing key.
2. Implement `keys.RotatingKeyManager` on your `KeyManager` (if it
   doesn't already) so `PublicKeys` returns **both** the outgoing and
   the new key. Deploy this alone first: `PublicJWKS()` now advertises
   both kids, but `Sign` still uses the outgoing one, so nothing a
   verifier does today changes yet — this step is purely "let every
   consumer's JWKS cache catch up before it matters."
3. Wait out whatever cache TTL the parties verifying your tokens use
   for your JWKS — this module's own `keys.NewJWKSIssuerKeySource` (a
   client resolving your keys) refetches promptly on an unrecognized
   kid, but you may have consumers you don't control caching longer.
   When in doubt, wait longer than you think you need to; this step
   costs nothing but time.
4. Cut `Sign`/`PublicKey` over to the new key. New ID tokens, JWT
   access tokens, and (under `ProfileFAPISecurityWithMessageSigning`)
   JARM responses are now signed with it. Keep `PublicKeys` returning
   both keys — this is the step every already-issued-but-not-yet-
   expired token depends on.
5. Keep publishing the outgoing key from `PublicKeys` for at least as
   long as the longest-lived artifact signed under it can still be
   presented for verification, counted from the moment you cut over in
   step 4, not from when you started: `Limits.IDTokenLifetime`, and
   `Limits.AccessTokenLifetime` too if `Dependencies.AccessTokens` is
   `JWTAccessTokens` (opaque access tokens aren't signed, so they don't
   count). `Limits.JARMResponseLifetime` bounds the same thing for JARM,
   though in practice a JARM response is verified once at the redirect
   callback and essentially never again later in its nominal lifetime,
   so it's the lowest-risk of the three. Drop the outgoing key from
   `PublicKeys` any sooner than this and you'll reject a token that's
   still legitimately valid.
6. Only after that window has fully elapsed, stop returning the
   outgoing key from `PublicKey`/`PublicKeys`, and only then destroy or
   retire it in your KMS/HSM — never the other way around.

The mirror case — a **client** rotating its own ID-token/UserInfo
decryption key (`keys.Decrypter`, `keys.ECDHAgreer`/`KeyDecrypter` — see
`keys/doc.go`) — isn't covered by this guide (it's `client`'s
dependency, not `server`'s), but the direction of control is reversed
in a way worth knowing about: there's no `Limits` field to bound the
overlap by, because it isn't this server's own artifact aging out —
it's whichever authorization server(s) the client talks to, and how
long *they* cache the client's registered encryption key before
picking up its new one. A rotating client should keep decrypting under
its outgoing key (a backend that selects by the `keyID`
`UnwrapRequest` carries) for as long as it's willing to assume some AS
might still hold a stale cached copy of its JWKS — inherently a guess,
not a number this module can compute for you.
