# Getting started: standing up an authorization server

This walks through wiring `server.Server` end to end — configuration,
dependencies, client registration, and the one piece every integration
has to build itself: the login/consent flow. `cmd/conformance-as` is a
complete, working reference implementing every piece described here
(plus the full HTTP surface — PAR, token, JWKS, metadata — which this
guide doesn't reproduce); read it alongside this doc, or just study it
directly and treat this as the map.

## 1. Dependencies: use the reference implementations to start

`server.New` requires nine dependencies — a client repository,
transaction/grant/replay stores, a key manager, a client key source, a
clock, a randomness source — with no implicit defaults for any of them.
Writing real, production-shaped persistence and key management for all
of that is real work, and not the place to start. Two packages exist
specifically so you don't have to do it before you can run anything:

- **`storage/memstore`** — in-memory `ClientRepository`, `TransactionStore`,
  `GrantStore`, `ReplayStore`.
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
else in this guide changes.

## 2. Build a `Config`

Every field below is required — `server.New` rejects a zero value for
any of them, on purpose (see `server/doc.go`: "no implicit defaults, no
silently-installed in-memory store"). There's no sane default duration
to guess for you; pick values that match your own security policy.

```go
cfg := server.Config{
	Issuer: issuer, // fapi.ParseIssuerURL("https://as.example.com")
	Endpoints: server.Endpoints{
		Authorization:              authorizeURL,
		Token:                      tokenURL,
		PushedAuthorizationRequest: parURL,
		JWKS:                       jwksURL,
	},
	Profile: server.ProfileFAPISecurity, // or ProfileFAPISecurityWithMessageSigning
	Algorithms: server.AlgorithmPolicy{
		ClientAssertion: server.AlgorithmSet{fapi.ES256},
		RequestObject:   server.AlgorithmSet{fapi.ES256},
		AccessToken:     fapi.ES256,
		IDToken:         fapi.ES256,
	},
	Limits: server.Limits{
		PushedRequestLifetime:      90 * time.Second,
		MaxClientAssertionLifetime: time.Minute,
		MaxRequestObjectLifetime:   time.Minute,
		InteractionLifetime:        5 * time.Minute,
		AuthorizationCodeLifetime:  time.Minute,
		AccessTokenLifetime:        5 * time.Minute,
		IDTokenLifetime:            5 * time.Minute,
		RefreshTokenLifetime:       24 * time.Hour,
		MaxDPoPProofAge:            time.Minute,
		MaxClockSkew:               5 * time.Second,
	},
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

deps := server.Dependencies{
	Clients:      memstore.NewClientRepository([]storage.RegisteredClient{client}),
	Transactions: memstore.NewTransactionStore(),
	Grants:       memstore.NewGrantStore(),
	Replay:       memstore.NewReplayStore(),
	ClientKeys:   clientKeys,
	Keys:         keyManager,
	Clock:        server.SystemClock{},
	Random:       rand.Reader,
}

srv, err := server.New(cfg, deps)
```

(`fetcher` is a `*fapihttp.Client` — only needed if any client's keys
are fetched live via `JWKSURI` rather than supplied inline; pass `nil`
if every client uses inline `JWKS`.)

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

## 7. Run it

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
