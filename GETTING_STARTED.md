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

`server.New` requires ten dependencies — a client repository,
transaction/grant/replay stores, a key manager, a client key source, an
access-token issuer, a revocation sink, a clock, a randomness source —
with no implicit defaults for any of them (plus an audit sink, required
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
refuses `memstore`'s stores under `server.AssuranceProduction` (they
don't implement `storage.StoreAssurance`, which that assurance level
requires) — that's not a gap, it's what stops them from being used in
production by accident. When you're ready for a real deployment, this
is the seam: implement the same interfaces (`storage.ClientRepository`
and friends, `keys.KeyManager`, `keys.ClientKeySource`) against real
persistence and a real key store (KMS/HSM), and swap them in — nothing
else in this guide changes. For `keys.KeyManager` specifically, you may
not need to implement anything at all: `keys.NewKeyManagerFromSigners`
adapts any `crypto.Signer` — what most HSM/KMS Go client wrappers
already implement — directly into a `KeyManager`; see `keys/doc.go`.

## 2. Build a `Config`

Every field below is required — `server.New` rejects a zero value for
any of them, on purpose (see `server/doc.go`: "no implicit defaults, no
silently-installed in-memory store"). `Algorithms` and `Limits` are five
and nine fields respectively with no sane universal default, so
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
	Assurance: server.AssuranceDevelopment, // AssuranceProduction once your real deps are ready
}
```

Under `ProfileFAPISecurityWithMessageSigning`, `Algorithms.JARM` is
required too.

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
	// (RFC 6749 §4.1.2). Pass server.NoRevocation{} instead to
	// explicitly decline — see its doc comment for why declining must
	// be a conscious choice, not a silent default.
	Revocation: memstore.NewRevocationStore(),
	Clock:      server.SystemClock{},
	Random:     rand.Reader,
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
action, err := srv.BeginAuthorization(ctx, server.BeginAuthorizationRequest{
	RequestURI: requestURI, // from the incoming request_uri query parameter
	ClientID:   clientID,
})

switch a := action.(type) {
case server.InteractionRequired:
	// Render whatever UI you want here — a password form, an SSO
	// redirect, WebAuthn, a magic link. a.Interaction carries the
	// client ID, requested scope, and an unauthenticated login_hint
	// to help pre-fill it. a.Handle must come back to
	// CompleteAuthorization once the user is done.
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
authCtx, _ := server.NewAuthenticationContext(time.Now(), acr, amr)

result := server.Authorize(subject, authCtx, server.GrantedAuthorization{
	Scope: whateverScopesTheUserActuallyApproved,
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

`cmd/conformance-as/authorize.go` is a complete, working version of
exactly this — read it for the full picture, including how it bridges
an `InteractionHandle` across the GET (render the form) and POST
(handle the submission) halves of a real HTTP flow. Its own login form
(`consent_template.go`) is a deliberate non-example: a free-text "type
any username" field with no real authentication behind it, because this
binary exists to drive OIDF conformance testing, not to demonstrate
login UI. Building the real authentication step is the one part of this
whole guide that's actually yours to write.

## 6. The rest of the HTTP surface

`server.Server` has no built-in HTTP layer — every endpoint is a plain
handler you write, calling the corresponding method
(`PushAuthorizationRequest`, `ExchangeAuthorizationCode`,
`RefreshAccessToken`, `Metadata`, `PublicJWKS`). `cmd/conformance-as/router.go`
shows the complete routing table on a bare `net/http.ServeMux` — no
framework dependency required, though nothing here stops you from using
one. `cmd/conformance-as/token.go`, `par.go`, `metadata.go` and
`jwks.go` are the corresponding handler implementations to read
alongside `authorize.go`.

## 7. Wire the resource server: verifying access tokens

`resource.Verifier` is FAPI 2.0's third role, a deliberately separate
package from `server` rather than a mode of it — verifying a presented
access token is inseparable from the HTTP request it arrived on, so
`Verify(ctx, VerifyRequest{Method, URL, Authorization, DPoPProof})` is
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

**The access-token format must match whatever the authorization server
actually issues** — this is exactly the coupling step 4 flagged, and
the reason this section exists at all. Pick the side matching your AS:

```go
// If the AS issues JWTAccessTokens: resolve its verification key(s),
// typically by fetching its published JWKS live (or, for a co-located
// deployment, an IssuerKeySource reading the key manager directly, the
// way cmd/conformance-as's own selfIssuerKeySource does).
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
(RFC 6749 §4.1.2 — step 4's `Revocation` field), this resource server
must see that revocation too, or it will keep accepting a token the AS
has already disowned. Wire it to the *same* `RevocationSink`/
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
authCtx, err := verifier.Verify(ctx, resource.VerifyRequest{
	Method:        r.Method,
	URL:           protectedResourceURL, // this endpoint's own fixed external URL — see below, never r.URL
	Authorization: r.Header.Get("Authorization"),
	DPoPProof:     dpopProof,             // see below — not simply r.Header.Get("DPoP")
})
```

On success, `authCtx.Subject`/`ClientID`/`Scopes`/`Claims` are what your
API handler needs to authorize the call. On failure, `err` is always a
`*resource.Error` — `Code()`/`PublicDescription()`/`HTTPStatus()` are
safe to put directly into an RFC 6750 `WWW-Authenticate` challenge and
response body; `Unwrap()` is for logs only, never the response:

```go
func writeResourceError(w http.ResponseWriter, err error) {
	resErr, ok := err.(*resource.Error)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("WWW-Authenticate", `DPoP error="`+string(resErr.Code())+`"`)
	http.Error(w, resErr.PublicDescription(), resErr.HTTPStatus())
}
```

Two easy-to-miss details `cmd/conformance-as/resource.go` gets right
that are worth copying: `URL` must be this endpoint's own fixed,
externally-visible URL (it's the DPoP proof's expected `htu`) — never
inferred from the incoming request's `Host` header, the same reasoning
`server.Endpoints` is never inferred from a request either. And
`DPoPProof` expects exactly one string, but `http.Header.Get("DPoP")`
silently returns only the first of several duplicate headers — a
smuggled second header would slip past unnoticed. Check
`r.Header.Values("DPoP")` yourself and reject the request before ever
calling `Verify` if there's more than one, exactly like that file's own
`singleDPoPHeader` helper.

That's the whole surface: `resource.Verifier` has no other public entry
point. Everything above `Verify` — routing, `WWW-Authenticate` framing,
what the protected API actually returns — is your own handler, same as
step 5's login flow was yours to build for `server`.

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
